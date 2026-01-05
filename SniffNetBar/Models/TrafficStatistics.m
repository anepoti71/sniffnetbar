//
//  TrafficStatistics.m
//  SniffNetBar
//
//  Traffic statistics tracking
//

#import "TrafficStatistics.h"
#import "PacketInfo.h"
#import "ExpiringCache.h"
#import "Logger.h"
#import "ProcessLookup.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <SystemConfiguration/SystemConfiguration.h>

// Cache size limits
static const NSUInteger kMaxHostCacheSize = 1000;
static const NSUInteger kMaxConnectionCacheSize = 1000;
static const NSUInteger kMaxHostnameCacheSize = 500;
static const NSTimeInterval kCacheExpirationTime = 3600; // 1 hour
static const NSTimeInterval kCleanupInterval = 300; // 5 minutes
static const NSTimeInterval kDNSLookupTimeout = 5.0; // 5 seconds
static const long kMaxConcurrentDNSLookups = 8;
static const NSUInteger kMaxProcessCacheSize = 500;
static const NSTimeInterval kProcessCacheExpirationTime = 300.0; // 5 minutes

// Special marker for failed DNS lookups
static NSString * const kDNSLookupFailedMarker = @"__DNS_FAILED__";

@interface TrafficStatistics ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, HostTraffic *> *hostStats;
@property (nonatomic, strong) NSMutableDictionary<NSString *, ConnectionTraffic *> *connectionStats;
@property (nonatomic, assign) uint64_t totalBytes;
@property (nonatomic, assign) uint64_t incomingBytes;
@property (nonatomic, assign) uint64_t outgoingBytes;
@property (nonatomic, assign) uint64_t totalPackets;
@property (nonatomic, strong) NSMutableSet<NSString *> *localAddresses;
@property (nonatomic, strong) SNBExpiringCache<NSString *, NSString *> *hostnameCache;
@property (nonatomic, strong) SNBExpiringCache<NSString *, id> *processCache;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSObject *> *dnsLookupLocks;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSObject *> *processLookupLocks;
@property (nonatomic, strong) dispatch_queue_t dnsLookupQueue;
@property (nonatomic, strong) dispatch_semaphore_t dnsLookupSemaphore;
@property (nonatomic, strong) dispatch_queue_t statsQueue;
@property (nonatomic, strong) NSDate *lastUpdateTime;
@property (nonatomic, assign) uint64_t lastTotalBytes;
@property (nonatomic, strong) NSTimer *cleanupTimer;
@property (nonatomic, strong) NSArray<HostTraffic *> *cachedTopHosts;
@property (nonatomic, strong) NSArray<ConnectionTraffic *> *cachedTopConnections;
@property (nonatomic, assign) BOOL statsCacheDirty;
@property (nonatomic, assign) uint64_t lastSampleTotalBytes;
@property (nonatomic, strong) NSDate *lastSampleTime;
@property (nonatomic, assign) uint64_t cachedBytesPerSecond;
@property (nonatomic, strong) NSTimer *samplingTimer;
@end

@implementation TrafficStatistics

- (instancetype)init {
    self = [super init];
    if (self) {
        _hostStats = [NSMutableDictionary dictionary];
        _connectionStats = [NSMutableDictionary dictionary];
        _hostnameCache = [[SNBExpiringCache alloc] initWithMaxSize:kMaxHostnameCacheSize
                                                expirationInterval:kCacheExpirationTime];
        _processCache = [[SNBExpiringCache alloc] initWithMaxSize:kMaxProcessCacheSize
                                              expirationInterval:kProcessCacheExpirationTime];
        _dnsLookupLocks = [NSMutableDictionary dictionary];
        _processLookupLocks = [NSMutableDictionary dictionary];
        _dnsLookupQueue = dispatch_queue_create("com.sniffnetbar.dnslookup", DISPATCH_QUEUE_CONCURRENT);
        _dnsLookupSemaphore = dispatch_semaphore_create(kMaxConcurrentDNSLookups);
        _statsQueue = dispatch_queue_create("com.sniffnetbar.stats", DISPATCH_QUEUE_SERIAL);
        _localAddresses = [NSMutableSet set];
        _statsCacheDirty = YES;
        [self loadLocalAddresses];

        // Set up periodic cleanup timer
        __weak typeof(self) weakSelf = self;
        _cleanupTimer = [NSTimer scheduledTimerWithTimeInterval:kCleanupInterval
                                                         repeats:YES
                                                           block:^(NSTimer *timer) {
            [weakSelf performCacheCleanup];
        }];
        _samplingTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                         repeats:YES
                                                           block:^(NSTimer *timer) {
            [weakSelf sampleBytesPerSecond];
        }];
    }
    return self;
}

- (void)dealloc {
    [_cleanupTimer invalidate];
    [_samplingTimer invalidate];
}

- (void)loadLocalAddresses {
    // Get local network interfaces
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) == 0) {
        struct ifaddrs *interface;
        for (interface = interfaces; interface != NULL; interface = interface->ifa_next) {
            if (interface->ifa_addr == NULL) continue;
            
            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)interface->ifa_addr;
                char addr[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &sin->sin_addr, addr, INET_ADDRSTRLEN)) {
                    [self.localAddresses addObject:[NSString stringWithUTF8String:addr]];
                }
            } else if (interface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)interface->ifa_addr;
                char addr[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, addr, INET6_ADDRSTRLEN)) {
                    [self.localAddresses addObject:[NSString stringWithUTF8String:addr]];
                }
            }
        }
        freeifaddrs(interfaces);
    }
    
    // Add loopback addresses
    [self.localAddresses addObject:@"127.0.0.1"];
    [self.localAddresses addObject:@"::1"];
}

- (BOOL)isLocalAddress:(NSString *)address {
    return [self.localAddresses containsObject:address];
}

- (void)performCacheCleanup {
    dispatch_async(self.statsQueue, ^{
        NSUInteger expiredCount = [self.hostnameCache cleanupAndReturnExpiredCount];

        // If host stats exceed max, remove entries with least traffic
        if (self.hostStats.count > kMaxHostCacheSize) {
            NSArray<HostTraffic *> *sortedHosts = [self.hostStats.allValues sortedArrayUsingComparator:^NSComparisonResult(HostTraffic *obj1, HostTraffic *obj2) {
                if (obj1.bytes < obj2.bytes) return NSOrderedAscending;
                if (obj1.bytes > obj2.bytes) return NSOrderedDescending;
                return NSOrderedSame;
            }];
            NSUInteger toRemove = self.hostStats.count - kMaxHostCacheSize;
            for (NSUInteger i = 0; i < toRemove && i < sortedHosts.count; i++) {
                [self.hostStats removeObjectForKey:sortedHosts[i].address];
            }
            self.statsCacheDirty = YES;
        }

        // If connection stats exceed max, remove entries with least traffic
        if (self.connectionStats.count > kMaxConnectionCacheSize) {
            NSArray<ConnectionTraffic *> *sortedConnections = [self.connectionStats.allValues sortedArrayUsingComparator:^NSComparisonResult(ConnectionTraffic *obj1, ConnectionTraffic *obj2) {
                if (obj1.bytes < obj2.bytes) return NSOrderedAscending;
                if (obj1.bytes > obj2.bytes) return NSOrderedDescending;
                return NSOrderedSame;
            }];
            NSUInteger toRemove = self.connectionStats.count - kMaxConnectionCacheSize;
            for (NSUInteger i = 0; i < toRemove && i < sortedConnections.count; i++) {
                ConnectionTraffic *conn = sortedConnections[i];
                NSString *key = [NSString stringWithFormat:@"%@->%@", conn.sourceAddress, conn.destinationAddress];
                [self.connectionStats removeObjectForKey:key];
            }
            self.statsCacheDirty = YES;
        }

        if (expiredCount > 0 || self.statsCacheDirty) {
            SNBLogDebug("Cache cleanup: removed %lu expired hostnames, %lu hosts, %lu connections",
                  (unsigned long)expiredCount,
                  (unsigned long)MAX(0, (NSInteger)self.hostStats.count - (NSInteger)kMaxHostCacheSize),
                  (unsigned long)MAX(0, (NSInteger)self.connectionStats.count - (NSInteger)kMaxConnectionCacheSize));
        }
    });
}

- (void)processPacket:(PacketInfo *)packetInfo {
    if (!packetInfo || packetInfo.totalBytes == 0) {
        return;
    }
    
    dispatch_async(self.statsQueue, ^{
        self.totalBytes += packetInfo.totalBytes;
        self.totalPackets++;
        self.statsCacheDirty = YES;  // Mark cache as dirty

        // Determine traffic direction
        BOOL isIncoming = [self isLocalAddress:packetInfo.destinationAddress];
        BOOL isOutgoing = [self isLocalAddress:packetInfo.sourceAddress];
        
        // If both are local or neither is local, use port comparison for loopback
        if (isIncoming && isOutgoing) {
            // Both local - use port comparison like the Rust code
            if (packetInfo.sourcePort > 0 && packetInfo.destinationPort > 0) {
                isIncoming = packetInfo.sourcePort < packetInfo.destinationPort;
                isOutgoing = !isIncoming;
            }
        } else if (!isIncoming && !isOutgoing) {
            // Neither local (shouldn't happen, but handle it)
            isIncoming = YES;
            isOutgoing = NO;
        }
        
        if (isIncoming) {
            self.incomingBytes += packetInfo.totalBytes;
        } else {
            self.outgoingBytes += packetInfo.totalBytes;
        }
        
        // Track host statistics
        NSString *remoteAddress = isIncoming ? packetInfo.sourceAddress : packetInfo.destinationAddress;
        if (remoteAddress && remoteAddress.length > 0) {
            HostTraffic *host = self.hostStats[remoteAddress];
            if (!host) {
                host = [[HostTraffic alloc] init];
                host.address = remoteAddress;
                NSString *cachedHostname = [self.hostnameCache objectForKey:remoteAddress];

                // Check if we have a cached result (including negative results)
                if (cachedHostname) {
                    // If it's a failed lookup marker, don't set hostname (leave it nil)
                    if (![cachedHostname isEqualToString:kDNSLookupFailedMarker]) {
                        host.hostname = cachedHostname;
                    }
                } else {
                    // Perform reverse DNS lookup asynchronously
                    __weak typeof(self) weakSelf = self;
                    [self performReverseDNSLookup:remoteAddress completion:^(NSString *hostname) {
                        __strong typeof(weakSelf) strongSelf = weakSelf;
                        if (!strongSelf) return;

                        dispatch_async(strongSelf.statsQueue, ^{
                            if (hostname) {
                                // Cache successful lookup
                                [strongSelf.hostnameCache setObject:hostname forKey:remoteAddress];
                                HostTraffic *h = strongSelf.hostStats[remoteAddress];
                                if (h) {
                                    h.hostname = hostname;
                                }
                            } else {
                                // Cache negative result to avoid repeated failed lookups
                                [strongSelf.hostnameCache setObject:kDNSLookupFailedMarker forKey:remoteAddress];
                            }
                        });
                    }];
                }
                self.hostStats[remoteAddress] = host;
            }
            host.bytes += packetInfo.totalBytes;
            host.packetCount++;
        }

        // Track connection statistics (use destination->source for inbound)
        NSString *connectionSource = isIncoming ? packetInfo.destinationAddress : packetInfo.sourceAddress;
        NSString *connectionDestination = isIncoming ? packetInfo.sourceAddress : packetInfo.destinationAddress;
        NSInteger connectionSourcePort = isIncoming ? packetInfo.destinationPort : packetInfo.sourcePort;
        NSInteger connectionDestinationPort = isIncoming ? packetInfo.sourcePort : packetInfo.destinationPort;

        if (connectionSource.length > 0 && connectionDestination.length > 0) {
            NSString *connectionKey = [NSString stringWithFormat:@"%@:%ld->%@:%ld",
                                       connectionSource, (long)connectionSourcePort,
                                       connectionDestination, (long)connectionDestinationPort];
            ConnectionTraffic *connection = self.connectionStats[connectionKey];
            if (!connection) {
                connection = [[ConnectionTraffic alloc] init];
                connection.sourceAddress = connectionSource;
                connection.destinationAddress = connectionDestination;
                connection.sourcePort = connectionSourcePort;
                connection.destinationPort = connectionDestinationPort;
                self.connectionStats[connectionKey] = connection;

                // Lookup process information asynchronously
                // Only lookup for outgoing connections (where source is local)
                if (!isIncoming && connectionSourcePort > 0 && connectionDestinationPort > 0) {
                    BOOL shouldLookupProcess = YES;
                    id cachedProcess = [self.processCache objectForKey:connectionKey];
                    if (cachedProcess && cachedProcess != [NSNull null]) {
                        ProcessInfo *processInfo = (ProcessInfo *)cachedProcess;
                        connection.processName = processInfo.processName;
                        connection.processPID = processInfo.pid;
                        shouldLookupProcess = NO;
                    } else if (cachedProcess == [NSNull null]) {
                        shouldLookupProcess = NO;
                    }

                    if (shouldLookupProcess) {
                    SNBLogInfo("Process lookup: %@:%ld -> %@:%ld",
                          connectionSource, (long)connectionSourcePort,
                          connectionDestination, (long)connectionDestinationPort);
                    __weak typeof(self) weakSelf = self;
                    [self performProcessLookup:connectionSource
                                    sourcePort:connectionSourcePort
                                   destination:connectionDestination
                               destinationPort:connectionDestinationPort
                                    completion:^(ProcessInfo *processInfo) {
                        __strong typeof(weakSelf) strongSelf = weakSelf;
                        if (!strongSelf) return;

                        dispatch_async(strongSelf.statsQueue, ^{
                            ConnectionTraffic *conn = strongSelf.connectionStats[connectionKey];
                            if (conn && processInfo) {
                                SNBLogInfo("✓ Found process: %@ (PID %d) for %@:%ld -> %@:%ld",
                                      processInfo.processName, processInfo.pid,
                                      connectionSource, (long)connectionSourcePort,
                                      connectionDestination, (long)connectionDestinationPort);
                                conn.processName = processInfo.processName;
                                conn.processPID = processInfo.pid;
                                [strongSelf.processCache setObject:processInfo forKey:connectionKey];
                            } else if (conn) {
                                SNBLogInfo("✗ No process found for connection %@", connectionKey);
                                [strongSelf.processCache setObject:[NSNull null] forKey:connectionKey];
                            }
                        });
                    }];
                    }
                } else {
                    if (isIncoming) {
                        SNBLogInfo("Skipping process lookup for incoming connection");
                    }
                }
            }
            connection.bytes += packetInfo.totalBytes;
            connection.packetCount++;
        }
    });
}

- (void)performReverseDNSLookup:(NSString *)address completion:(void (^)(NSString *))completion {
    // Get or create a dedicated lock object for this address
    NSObject *lock = nil;
    @synchronized(self.dnsLookupLocks) {
        lock = self.dnsLookupLocks[address];
        if (!lock) {
            lock = [[NSObject alloc] init];
            self.dnsLookupLocks[address] = lock;
        }
    }

    dispatch_group_t group = dispatch_group_create();
    dispatch_group_enter(group);

    __block NSString *resultHostname = nil;
    __block BOOL lookupCompleted = NO;

    void (^finish)(NSString *hostname, BOOL logTimeout) = ^(NSString *hostname, BOOL logTimeout) {
        @synchronized(lock) {
            if (lookupCompleted) {
                return;
            }
            lookupCompleted = YES;
            if (logTimeout) {
                SNBLogWarn("DNS lookup timeout (%.0fs) for %{" SNB_IP_PRIVACY "}@", kDNSLookupTimeout, address);
            }
            resultHostname = hostname;
            dispatch_group_leave(group);
            dispatch_semaphore_signal(self.dnsLookupSemaphore);
        }
    };

    // Perform DNS lookup on background queue
    dispatch_async(self.dnsLookupQueue, ^{
        dispatch_semaphore_wait(self.dnsLookupSemaphore, DISPATCH_TIME_FOREVER);
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr *sa;
        socklen_t salen;

        if (inet_pton(AF_INET, address.UTF8String, &sin.sin_addr) == 1) {
            sin.sin_family = AF_INET;
            sa = (struct sockaddr *)&sin;
            salen = sizeof(sin);
        } else if (inet_pton(AF_INET6, address.UTF8String, &sin6.sin6_addr) == 1) {
            sin6.sin6_family = AF_INET6;
            sa = (struct sockaddr *)&sin6;
            salen = sizeof(sin6);
        } else {
            finish(nil, NO);
            return;
        }

        char hostname[NI_MAXHOST];
        int result = getnameinfo(sa, salen, hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);

        if (result == 0) {
            finish([NSString stringWithUTF8String:hostname], NO);
            return;
        }
        finish(nil, NO);
    });

    // Set up timeout (5 seconds)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kDNSLookupTimeout * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        finish(nil, YES);
    });

    // Wait for completion or timeout, then call completion handler
    dispatch_group_notify(group, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        completion(resultHostname);
        @synchronized(self.dnsLookupLocks) {
            if (self.dnsLookupLocks[address] == lock) {
                [self.dnsLookupLocks removeObjectForKey:address];
            }
        }
    });
}

- (void)performProcessLookup:(NSString *)sourceAddress
                  sourcePort:(NSInteger)sourcePort
                 destination:(NSString *)destinationAddress
             destinationPort:(NSInteger)destinationPort
                  completion:(void (^)(ProcessInfo *))completion {
    // Create unique key for this connection
    NSString *lookupKey = [NSString stringWithFormat:@"%@:%ld->%@:%ld",
                           sourceAddress, (long)sourcePort,
                           destinationAddress, (long)destinationPort];

    // Get or create lock for this lookup
    NSObject *lock = nil;
    @synchronized(self.processLookupLocks) {
        lock = self.processLookupLocks[lookupKey];
        if (!lock) {
            lock = [[NSObject alloc] init];
            self.processLookupLocks[lookupKey] = lock;
        } else {
            // Lookup already in progress
            return;
        }
    }

    [ProcessLookup lookupProcessForConnectionWithSource:sourceAddress
                                             sourcePort:sourcePort
                                            destination:destinationAddress
                                        destinationPort:destinationPort
                                             completion:^(ProcessInfo *processInfo) {
        if (completion) {
            completion(processInfo);
        }

        // Clean up lock
        @synchronized(self.processLookupLocks) {
            if (self.processLookupLocks[lookupKey] == lock) {
                [self.processLookupLocks removeObjectForKey:lookupKey];
            }
        }
    }];
}

- (TrafficStats *)currentStatsLocked {
    TrafficStats *stats = [[TrafficStats alloc] init];
    stats.totalBytes = self.totalBytes;
    stats.incomingBytes = self.incomingBytes;
    stats.outgoingBytes = self.outgoingBytes;
    stats.totalPackets = self.totalPackets;
    stats.bytesPerSecond = self.cachedBytesPerSecond;

    // Use cached sorted results if available and cache is clean
    if (self.statsCacheDirty || !self.cachedTopHosts || !self.cachedTopConnections) {
        // Get top hosts sorted by bytes
        NSArray<HostTraffic *> *hosts = [self.hostStats.allValues sortedArrayUsingComparator:^NSComparisonResult(HostTraffic *obj1, HostTraffic *obj2) {
            if (obj1.bytes > obj2.bytes) {
                return NSOrderedAscending;
            } else if (obj1.bytes < obj2.bytes) {
                return NSOrderedDescending;
            }
            return NSOrderedSame;
        }];
        self.cachedTopHosts = hosts;

        NSArray<ConnectionTraffic *> *connections = [self.connectionStats.allValues sortedArrayUsingComparator:^NSComparisonResult(ConnectionTraffic *obj1, ConnectionTraffic *obj2) {
            if (obj1.bytes > obj2.bytes) {
                return NSOrderedAscending;
            } else if (obj1.bytes < obj2.bytes) {
                return NSOrderedDescending;
            }
            return NSOrderedSame;
        }];
        self.cachedTopConnections = connections;
        self.statsCacheDirty = NO;
    }

    stats.topHosts = self.cachedTopHosts;
    stats.topConnections = self.cachedTopConnections;
    return stats;
}

- (TrafficStats *)getCurrentStats {
    __block TrafficStats *stats = nil;

    dispatch_sync(self.statsQueue, ^{
        stats = [self currentStatsLocked];
    });

    return stats;
}

- (void)getCurrentStatsWithCompletion:(void (^)(TrafficStats *stats))completion {
    if (!completion) {
        return;
    }

    __weak typeof(self) weakSelf = self;
    dispatch_async(self.statsQueue, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        TrafficStats *stats = [strongSelf currentStatsLocked];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(stats);
        });
    });
}

- (void)reset {
    dispatch_async(self.statsQueue, ^{
        self.totalBytes = 0;
        self.incomingBytes = 0;
        self.outgoingBytes = 0;
        self.totalPackets = 0;
        [self.hostStats removeAllObjects];
        [self.connectionStats removeAllObjects];
        self.lastUpdateTime = nil;
        self.lastTotalBytes = 0;
        self.cachedTopHosts = nil;
        self.cachedTopConnections = nil;
        self.statsCacheDirty = YES;
        self.lastSampleTime = nil;
        self.lastSampleTotalBytes = 0;
        self.cachedBytesPerSecond = 0;
    });
}

- (void)sampleBytesPerSecond {
    dispatch_async(self.statsQueue, ^{
        NSDate *now = [NSDate date];
        if (self.lastSampleTime) {
            NSTimeInterval elapsed = [now timeIntervalSinceDate:self.lastSampleTime];
            if (elapsed > 0) {
                uint64_t bytesDiff = self.totalBytes - self.lastSampleTotalBytes;
                self.cachedBytesPerSecond = (uint64_t)(bytesDiff / elapsed);
            }
        }
        self.lastSampleTime = now;
        self.lastSampleTotalBytes = self.totalBytes;
    });
}

@end

@implementation TrafficStats
@end

@implementation HostTraffic
@end

@implementation ConnectionTraffic
@end
