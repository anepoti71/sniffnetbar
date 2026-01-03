//
//  AnomalyStore.h
//  SniffNetBar
//
//  Local persistence for anomaly detection features and scores
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SNBAnomalyStore : NSObject

+ (NSString *)defaultDatabasePath;
+ (NSString *)defaultModelPath;
+ (NSString *)defaultCoreMLModelPath;
+ (NSString *)applicationSupportDirectoryPath;

- (instancetype)init;

- (NSInteger)seenCountForIP:(NSString *)ipAddress;

- (void)recordWindowForIP:(NSString *)ipAddress
              windowStart:(NSTimeInterval)windowStart
                  dstPort:(NSInteger)dstPort
                    proto:(NSInteger)proto
               totalBytes:(double)totalBytes
             totalPackets:(double)totalPackets
          uniqueSrcPorts:(double)uniqueSrcPorts
                flowCount:(double)flowCount
             avgPktSize:(double)avgPktSize
          bytesPerFlow:(double)bytesPerFlow
            pktsPerFlow:(double)pktsPerFlow
              burstiness:(double)burstiness
                 isNewDst:(BOOL)isNewDst
                isRareDst:(BOOL)isRareDst
                   score:(double)score;

@end

NS_ASSUME_NONNULL_END
