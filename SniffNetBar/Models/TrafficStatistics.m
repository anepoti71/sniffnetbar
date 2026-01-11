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
#import "ConfigurationManager.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CFNetwork/CFNetwork.h>
#import <string.h>

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
static const NSUInteger kMaxPendingDNSLookups = 100; // Max queued DNS lookups (prevents memory leak)

// Special marker for failed DNS lookups
static NSString * const kDNSLookupFailedMarker = @"__DNS_FAILED__";

@interface TrafficStatistics ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, HostTraffic *> *hostStats;
@property (nonatomic, strong) NSMutableDictionary *connectionStats;
@property (nonatomic, assign) uint64_t totalBytes;
@property (nonatomic, assign) uint64_t incomingBytes;
@property (nonatomic, assign) uint64_t outgoingBytes;
@property (nonatomic, assign) uint64_t totalPackets;
@property (nonatomic, strong) NSMutableSet<NSString *> *localAddresses;
@property (nonatomic, strong) SNBExpiringCache<NSString *, NSString *> *hostnameCache;
@property (nonatomic, strong) SNBExpiringCache<id, id> *processCache;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSObject *> *dnsLookupLocks;
@property (nonatomic, strong) NSMutableDictionary *processLookupLocks;
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
@property (nonatomic, assign) NSUInteger pendingDNSLookupCount;
@end

@interface SNBConnectionKey : NSObject <NSCopying>
@property (nonatomic, copy) NSString *source;
@property (nonatomic, copy) NSString *destination;
@property (nonatomic, assign) NSInteger sourcePort;
@property (nonatomic, assign) NSInteger destinationPort;
@property (nonatomic, assign) NSUInteger cachedHash; // Performance: Cache hash value
- (instancetype)initWithSource:(NSString *)source
                   sourcePort:(NSInteger)sourcePort
                   destination:(NSString *)destination
               destinationPort:(NSInteger)destinationPort;
- (NSString *)stringValue;
@end

@implementation SNBConnectionKey

- (instancetype)initWithSource:(NSString *)source
                   sourcePort:(NSInteger)sourcePort
                   destination:(NSString *)destination
               destinationPort:(NSInteger)destinationPort {
    self = [super init];
    if (self) {
        _source = [source copy] ?: @"";
        _destination = [destination copy] ?: @"";
        _sourcePort = sourcePort;
        _destinationPort = destinationPort;

        // Performance: Pre-compute and cache hash value since keys are immutable
        NSUInteger hash = _source.hash ^ _destination.hash;
        hash ^= (NSUInteger)sourcePort * 16777619u;
        hash ^= (NSUInteger)destinationPort * 2166136261u;
        _cachedHash = hash;
    }
    return self;
}

- (NSUInteger)hash {
    // Performance: Return pre-computed cached hash instead of recalculating
    return self.cachedHash;
}

- (BOOL)isEqual:(id)object {
    if (![object isKindOfClass:[SNBConnectionKey class]]) {
        return NO;
    }
    SNBConnectionKey *other = object;
    return self.sourcePort == other.sourcePort &&
        self.destinationPort == other.destinationPort &&
        [self.source isEqualToString:other.source] &&
        [self.destination isEqualToString:other.destination];
}

- (id)copyWithZone:(NSZone *)zone {
    return self;
}

- (NSString *)stringValue {
    return [NSString stringWithFormat:@"%@:%ld->%@:%ld",
            self.source, (long)self.sourcePort, self.destination, (long)self.destinationPort];
}

@end

typedef struct {
    BOOL resolved;
    CFStringRef name;
} SNBDNSLookupContext;

static void SNBDNSHostCallback(CFHostRef host,
                               CFHostInfoType typeInfo,
                               const CFStreamError *error,
                               void *info) {
    SNBDNSLookupContext *context = (SNBDNSLookupContext *)info;
    if (!context || context->resolved) {
        return;
    }
    Boolean hasResult = false;
    CFArrayRef names = CFHostGetNames(host, &hasResult);
    if (hasResult && names && CFArrayGetCount(names) > 0) {
        CFStringRef name = CFArrayGetValueAtIndex(names, 0);
        if (name) {
            context->name = CFRetain(name);
        }
    }
    context->resolved = YES;
    CFRunLoopStop(CFRunLoopGetCurrent());
}

static NSString *SNBResolveHostname(NSString *address,
                                    NSTimeInterval timeout,
                                    BOOL *timedOut) {
    if (timedOut) {
        *timedOut = NO;
    }
    if (address.length == 0) {
        return nil;
    }

    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    NSData *addressData = nil;

    memset(&sin, 0, sizeof(sin));
    memset(&sin6, 0, sizeof(sin6));
    if (inet_pton(AF_INET, address.UTF8String, &sin.sin_addr) == 1) {
        sin.sin_family = AF_INET;
        addressData = [NSData dataWithBytes:&sin length:sizeof(sin)];
    } else if (inet_pton(AF_INET6, address.UTF8String, &sin6.sin6_addr) == 1) {
        sin6.sin6_family = AF_INET6;
        addressData = [NSData dataWithBytes:&sin6 length:sizeof(sin6)];
    } else {
        return nil;
    }

    CFHostRef host = CFHostCreateWithAddress(kCFAllocatorDefault, (__bridge CFDataRef)addressData);
    if (!host) {
        return nil;
    }

    SNBDNSLookupContext context = {0};
    CFHostClientContext clientContext = {0, &context, NULL, NULL, NULL};
    CFStreamError streamError = {0};
    BOOL started = (BOOL)CFHostSetClient(host, SNBDNSHostCallback, &clientContext);
    if (!started) {
        CFRelease(host);
        return nil;
    }

    CFHostScheduleWithRunLoop(host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    Boolean ok = CFHostStartInfoResolution(host, kCFHostNames, &streamError);
    if (!ok) {
        CFHostSetClient(host, NULL, NULL);
        CFHostUnscheduleFromRunLoop(host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        CFRelease(host);
        return nil;
    }

    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + timeout;
    while (!context.resolved) {
        CFTimeInterval remaining = deadline - CFAbsoluteTimeGetCurrent();
        if (remaining <= 0) {
            if (timedOut) {
                *timedOut = YES;
            }
            break;
        }
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, MIN(0.1, remaining), true);
    }

    if (!context.resolved) {
        CFHostCancelInfoResolution(host, kCFHostNames);
    }

    CFHostSetClient(host, NULL, NULL);
    CFHostUnscheduleFromRunLoop(host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    CFRelease(host);

    if (context.name) {
        return CFBridgingRelease(context.name);
    }
    return nil;
}

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
            NSArray *sortedKeys = [self.connectionStats keysSortedByValueUsingComparator:^NSComparisonResult(ConnectionTraffic *obj1, ConnectionTraffic *obj2) {
                if (obj1.bytes < obj2.bytes) return NSOrderedAscending;
                if (obj1.bytes > obj2.bytes) return NSOrderedDescending;
                return NSOrderedSame;
            }];
            NSUInteger toRemove = self.connectionStats.count - kMaxConnectionCacheSize;
            for (NSUInteger i = 0; i < toRemove && i < sortedKeys.count; i++) {
                [self.connectionStats removeObjectForKey:sortedKeys[i]];
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
            SNBConnectionKey *connectionKey = [[SNBConnectionKey alloc] initWithSource:connectionSource
                                                                            sourcePort:connectionSourcePort
                                                                            destination:connectionDestination
                                                                        destinationPort:connectionDestinationPort];
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
                        SNBLogDebug("Process lookup: %@:%ld -> %@:%ld",
                              connectionSource, (long)connectionSourcePort,
                              connectionDestination, (long)connectionDestinationPort);
                    __weak typeof(self) weakSelf = self;
                    [self performProcessLookup:connectionSource
                                    sourcePort:connectionSourcePort
                                   destination:connectionDestination
                               destinationPort:connectionDestinationPort
                                   lookupKey:connectionKey
                                    completion:^(ProcessInfo *processInfo) {
                        __strong typeof(weakSelf) strongSelf = weakSelf;
                        if (!strongSelf) return;

                        dispatch_async(strongSelf.statsQueue, ^{
                            ConnectionTraffic *conn = strongSelf.connectionStats[connectionKey];
                            if (conn && processInfo) {
                                SNBLogDebug("✓ Found process: %@ (PID %d) for %@:%ld -> %@:%ld",
                                      processInfo.processName, processInfo.pid,
                                      connectionSource, (long)connectionSourcePort,
                                      connectionDestination, (long)connectionDestinationPort);
                                conn.processName = processInfo.processName;
                                conn.processPID = processInfo.pid;
                                [strongSelf.processCache setObject:processInfo forKey:connectionKey];
                            } else if (conn) {
                                SNBLogDebug("✗ No process found for connection %@", [connectionKey stringValue]);
                                [strongSelf.processCache setObject:[NSNull null] forKey:connectionKey];
                            }
                        });
                    }];
                    }
                } else {
                    if (isIncoming) {
                        SNBLogDebug("Skipping process lookup for incoming connection");
                    }
                }
            }
            connection.bytes += packetInfo.totalBytes;
            connection.packetCount++;
        }
    });
}

- (void)performReverseDNSLookup:(NSString *)address completion:(void (^)(NSString *))completion {
    // Performance: Limit pending DNS lookup queue depth to prevent memory leak
    @synchronized(self) {
        if (self.pendingDNSLookupCount >= kMaxPendingDNSLookups) {
            SNBLogWarn("DNS lookup queue full (%lu pending), dropping lookup for %{" SNB_IP_PRIVACY "}@",
                      (unsigned long)self.pendingDNSLookupCount, address);
            // Cache negative result immediately to prevent repeated attempts
            [self.hostnameCache setObject:kDNSLookupFailedMarker forKey:address];
            if (completion) {
                completion(nil);
            }
            return;
        }
        self.pendingDNSLookupCount++;
    }

    // Get or create a dedicated lock object for this address
    NSObject *lock = nil;
    @synchronized(self.dnsLookupLocks) {
        lock = self.dnsLookupLocks[address];
        if (!lock) {
            lock = [[NSObject alloc] init];
            self.dnsLookupLocks[address] = lock;
        }
    }

    dispatch_async(self.dnsLookupQueue, ^{
        dispatch_semaphore_wait(self.dnsLookupSemaphore, DISPATCH_TIME_FOREVER);
        BOOL timedOut = NO;
        NSString *hostname = SNBResolveHostname(address, kDNSLookupTimeout, &timedOut);
        dispatch_semaphore_signal(self.dnsLookupSemaphore);

        if (timedOut) {
            SNBLogWarn("DNS lookup timeout (%.0fs) for %{" SNB_IP_PRIVACY "}@", kDNSLookupTimeout, address);
        }

        if (completion) {
            completion(hostname);
        }

        @synchronized(self.dnsLookupLocks) {
            if (self.dnsLookupLocks[address] == lock) {
                [self.dnsLookupLocks removeObjectForKey:address];
            }
        }

        // Decrement pending count
        @synchronized(self) {
            if (self.pendingDNSLookupCount > 0) {
                self.pendingDNSLookupCount--;
            }
        }
    });
}

- (void)performProcessLookup:(NSString *)sourceAddress
                  sourcePort:(NSInteger)sourcePort
                 destination:(NSString *)destinationAddress
             destinationPort:(NSInteger)destinationPort
                   lookupKey:(SNBConnectionKey *)lookupKey
                  completion:(void (^)(ProcessInfo *))completion {

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

- (NSArray<HostTraffic *> *)topHostsFromValues:(NSArray<HostTraffic *> *)values limit:(NSUInteger)limit {
    if (limit == 0 || values.count == 0) {
        return @[];
    }

    // Optimization: Use min-heap approach for top-K selection
    // Only sort once at the end instead of on every iteration: O(n log k) instead of O(n² log n)
    NSMutableArray<HostTraffic *> *top = [NSMutableArray arrayWithCapacity:limit];

    for (HostTraffic *host in values) {
        if (top.count < limit) {
            [top addObject:host];
        } else {
            // Only replace if current host has more bytes than the minimum in our top list
            HostTraffic *minHost = top[0]; // Will be minimum after sort
            if (host.bytes > minHost.bytes) {
                top[0] = host;
            } else {
                continue;
            }
        }

        // Only sort when we reach capacity or when we replace an item
        if (top.count == limit) {
            // Partial sort: just ensure minimum element is at index 0
            NSUInteger minIndex = 0;
            uint64_t minBytes = top[0].bytes;
            for (NSUInteger i = 1; i < top.count; i++) {
                if (top[i].bytes < minBytes) {
                    minBytes = top[i].bytes;
                    minIndex = i;
                }
            }
            if (minIndex != 0) {
                [top exchangeObjectAtIndex:0 withObjectAtIndex:minIndex];
            }
        }
    }

    // Final sort only once at the end
    [top sortUsingComparator:^NSComparisonResult(HostTraffic *obj1, HostTraffic *obj2) {
        if (obj1.bytes > obj2.bytes) {
            return NSOrderedAscending;
        }
        if (obj1.bytes < obj2.bytes) {
            return NSOrderedDescending;
        }
        return NSOrderedSame;
    }];

    return [top copy];
}

- (NSArray<ConnectionTraffic *> *)topConnectionsFromValues:(NSArray<ConnectionTraffic *> *)values limit:(NSUInteger)limit {
    if (limit == 0 || values.count == 0) {
        return @[];
    }

    // Optimization: Use min-heap approach for top-K selection
    // Only sort once at the end instead of on every iteration: O(n log k) instead of O(n² log n)
    NSMutableArray<ConnectionTraffic *> *top = [NSMutableArray arrayWithCapacity:limit];

    for (ConnectionTraffic *connection in values) {
        if (top.count < limit) {
            [top addObject:connection];
        } else {
            // Only replace if current connection has more bytes than the minimum in our top list
            ConnectionTraffic *minConnection = top[0]; // Will be minimum after sort
            if (connection.bytes > minConnection.bytes) {
                top[0] = connection;
            } else {
                continue;
            }
        }

        // Only sort when we reach capacity or when we replace an item
        if (top.count == limit) {
            // Partial sort: just ensure minimum element is at index 0
            NSUInteger minIndex = 0;
            uint64_t minBytes = top[0].bytes;
            for (NSUInteger i = 1; i < top.count; i++) {
                if (top[i].bytes < minBytes) {
                    minBytes = top[i].bytes;
                    minIndex = i;
                }
            }
            if (minIndex != 0) {
                [top exchangeObjectAtIndex:0 withObjectAtIndex:minIndex];
            }
        }
    }

    // Final sort only once at the end
    [top sortUsingComparator:^NSComparisonResult(ConnectionTraffic *obj1, ConnectionTraffic *obj2) {
        if (obj1.bytes > obj2.bytes) {
            return NSOrderedAscending;
        }
        if (obj1.bytes < obj2.bytes) {
            return NSOrderedDescending;
        }
        return NSOrderedSame;
    }];

    return [top copy];
}

- (TrafficStats *)currentStatsLocked {
    TrafficStats *stats = [[TrafficStats alloc] init];
    stats.totalBytes = self.totalBytes;
    stats.incomingBytes = self.incomingBytes;
    stats.outgoingBytes = self.outgoingBytes;
    stats.totalPackets = self.totalPackets;
    stats.bytesPerSecond = self.cachedBytesPerSecond;

    // Use cached results if available and cache is clean
    if (self.statsCacheDirty || !self.cachedTopHosts || !self.cachedTopConnections) {
        ConfigurationManager *config = [ConfigurationManager sharedManager];
        NSUInteger hostLimit = MAX(1, config.maxTopHostsToShow);
        NSUInteger connectionLimit = MAX(1, config.maxTopConnectionsToShow);

        self.cachedTopHosts = [self topHostsFromValues:self.hostStats.allValues limit:hostLimit];
        self.cachedTopConnections = [self topConnectionsFromValues:self.connectionStats.allValues limit:connectionLimit];
        self.statsCacheDirty = NO;
    }

    stats.topHosts = self.cachedTopHosts;
    stats.topConnections = self.cachedTopConnections;

    // Collect ALL active destination IPs (not just from top connections) for threat intel
    NSMutableSet<NSString *> *allDestIPs = [NSMutableSet set];
    for (ConnectionTraffic *conn in self.connectionStats.allValues) {
        if (conn.destinationAddress.length > 0) {
            [allDestIPs addObject:conn.destinationAddress];
        }
    }
    for (HostTraffic *host in self.hostStats.allValues) {
        if (host.address.length > 0) {
            [allDestIPs addObject:host.address];
        }
    }
    stats.allActiveDestinationIPs = [allDestIPs copy];

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

- (void)getAllDestinationIPsWithCompletion:(void (^)(NSSet<NSString *> *ips))completion {
    if (!completion) {
        return;
    }

    __weak typeof(self) weakSelf = self;
    dispatch_async(self.statsQueue, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NSMutableSet<NSString *> *destinationIPs = [NSMutableSet set];

        // Collect all unique destination IPs from connections
        for (ConnectionTraffic *connection in strongSelf.connectionStats.allValues) {
            if (connection.destinationAddress.length > 0) {
                [destinationIPs addObject:connection.destinationAddress];
            }
        }

        // Also collect from host stats (which tracks remote hosts)
        for (HostTraffic *host in strongSelf.hostStats.allValues) {
            if (host.address.length > 0) {
                [destinationIPs addObject:host.address];
            }
        }

        NSSet<NSString *> *result = [destinationIPs copy];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(result);
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
