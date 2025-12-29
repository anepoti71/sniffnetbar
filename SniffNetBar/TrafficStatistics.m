//
//  TrafficStatistics.m
//  SniffNetBar
//
//  Traffic statistics tracking
//

#import "TrafficStatistics.h"
#import "PacketInfo.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <netdb.h>
#import <SystemConfiguration/SystemConfiguration.h>

@interface TrafficStatistics ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, HostTraffic *> *hostStats;
@property (nonatomic, strong) NSMutableDictionary<NSString *, ConnectionTraffic *> *connectionStats;
@property (nonatomic, assign) uint64_t totalBytes;
@property (nonatomic, assign) uint64_t incomingBytes;
@property (nonatomic, assign) uint64_t outgoingBytes;
@property (nonatomic, assign) uint64_t totalPackets;
@property (nonatomic, strong) NSMutableSet<NSString *> *localAddresses;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *hostnameCache;
@property (nonatomic, strong) dispatch_queue_t statsQueue;
@property (nonatomic, strong) NSDate *lastUpdateTime;
@property (nonatomic, assign) uint64_t lastTotalBytes;
@end

@implementation TrafficStatistics

- (instancetype)init {
    self = [super init];
    if (self) {
        _hostStats = [NSMutableDictionary dictionary];
        _connectionStats = [NSMutableDictionary dictionary];
        _hostnameCache = [NSMutableDictionary dictionary];
        _statsQueue = dispatch_queue_create("com.sniffnetbar.stats", DISPATCH_QUEUE_SERIAL);
        _localAddresses = [NSMutableSet set];
        [self loadLocalAddresses];
    }
    return self;
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

- (void)processPacket:(PacketInfo *)packetInfo {
    if (!packetInfo || packetInfo.totalBytes == 0) {
        return;
    }
    
    dispatch_async(self.statsQueue, ^{
        self.totalBytes += packetInfo.totalBytes;
        self.totalPackets++;
        
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
                host.hostname = self.hostnameCache[remoteAddress];
                if (!host.hostname) {
                    // Perform reverse DNS lookup asynchronously
                    [self performReverseDNSLookup:remoteAddress completion:^(NSString *hostname) {
                        dispatch_async(self.statsQueue, ^{
                            if (hostname) {
                                self.hostnameCache[remoteAddress] = hostname;
                                HostTraffic *h = self.hostStats[remoteAddress];
                                if (h) {
                                    h.hostname = hostname;
                                }
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
        if (connectionSource.length > 0 && connectionDestination.length > 0) {
            NSString *connectionKey = [NSString stringWithFormat:@"%@->%@", connectionSource, connectionDestination];
            ConnectionTraffic *connection = self.connectionStats[connectionKey];
            if (!connection) {
                connection = [[ConnectionTraffic alloc] init];
                connection.sourceAddress = connectionSource;
                connection.destinationAddress = connectionDestination;
                self.connectionStats[connectionKey] = connection;
            }
            connection.bytes += packetInfo.totalBytes;
            connection.packetCount++;
        }
    });
}

- (void)performReverseDNSLookup:(NSString *)address completion:(void (^)(NSString *))completion {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
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
            completion(nil);
            return;
        }
        
        char hostname[NI_MAXHOST];
        int result = getnameinfo(sa, salen, hostname, NI_MAXHOST, NULL, 0, NI_NAMEREQD);
        if (result == 0) {
            NSString *hostnameStr = [NSString stringWithUTF8String:hostname];
            completion(hostnameStr);
        } else {
            completion(nil);
        }
    });
}

- (TrafficStats *)getCurrentStats {
    __block TrafficStats *stats = [[TrafficStats alloc] init];
    
    dispatch_sync(self.statsQueue, ^{
        stats.totalBytes = self.totalBytes;
        stats.incomingBytes = self.incomingBytes;
        stats.outgoingBytes = self.outgoingBytes;
        stats.totalPackets = self.totalPackets;
        
        // Calculate bytes per second
        NSDate *now = [NSDate date];
        if (self.lastUpdateTime) {
            NSTimeInterval elapsed = [now timeIntervalSinceDate:self.lastUpdateTime];
            if (elapsed > 0) {
                uint64_t bytesDiff = self.totalBytes - self.lastTotalBytes;
                stats.bytesPerSecond = (uint64_t)(bytesDiff / elapsed);
            }
        }
        self.lastUpdateTime = now;
        self.lastTotalBytes = self.totalBytes;
        
        // Get top hosts sorted by bytes
        NSArray<HostTraffic *> *hosts = [self.hostStats.allValues sortedArrayUsingComparator:^NSComparisonResult(HostTraffic *obj1, HostTraffic *obj2) {
            if (obj1.bytes > obj2.bytes) {
                return NSOrderedAscending;
            } else if (obj1.bytes < obj2.bytes) {
                return NSOrderedDescending;
            }
            return NSOrderedSame;
        }];
        stats.topHosts = hosts;

        NSArray<ConnectionTraffic *> *connections = [self.connectionStats.allValues sortedArrayUsingComparator:^NSComparisonResult(ConnectionTraffic *obj1, ConnectionTraffic *obj2) {
            if (obj1.bytes > obj2.bytes) {
                return NSOrderedAscending;
            } else if (obj1.bytes < obj2.bytes) {
                return NSOrderedDescending;
            }
            return NSOrderedSame;
        }];
        stats.topConnections = connections;
    });
    
    return stats;
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
    });
}

@end

@implementation TrafficStats
@end

@implementation HostTraffic
@end

@implementation ConnectionTraffic
@end
