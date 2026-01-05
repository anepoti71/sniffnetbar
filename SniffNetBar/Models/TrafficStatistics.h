//
//  TrafficStatistics.h
//  SniffNetBar
//
//  Traffic statistics tracking
//

#import <Foundation/Foundation.h>

@class PacketInfo, TrafficStats, HostTraffic, ConnectionTraffic;

@interface TrafficStatistics : NSObject

- (void)processPacket:(PacketInfo *)packetInfo;
- (TrafficStats *)getCurrentStats;
- (void)getCurrentStatsWithCompletion:(void (^)(TrafficStats *stats))completion;
- (void)reset;

@end

@interface TrafficStats : NSObject

@property (nonatomic, assign) uint64_t totalBytes;
@property (nonatomic, assign) uint64_t incomingBytes;
@property (nonatomic, assign) uint64_t outgoingBytes;
@property (nonatomic, assign) uint64_t totalPackets;
@property (nonatomic, assign) uint64_t bytesPerSecond;
@property (nonatomic, strong) NSArray<HostTraffic *> *topHosts;
@property (nonatomic, strong) NSArray<ConnectionTraffic *> *topConnections;

@end

@interface HostTraffic : NSObject

@property (nonatomic, strong) NSString *address;
@property (nonatomic, strong) NSString *hostname;
@property (nonatomic, assign) uint64_t bytes;
@property (nonatomic, assign) NSInteger packetCount;

@end

@interface ConnectionTraffic : NSObject

@property (nonatomic, strong) NSString *sourceAddress;
@property (nonatomic, strong) NSString *destinationAddress;
@property (nonatomic, assign) NSInteger sourcePort;
@property (nonatomic, assign) NSInteger destinationPort;
@property (nonatomic, assign) uint64_t bytes;
@property (nonatomic, assign) NSInteger packetCount;
@property (nonatomic, strong, nullable) NSString *processName;
@property (nonatomic, assign) pid_t processPID;

@end
