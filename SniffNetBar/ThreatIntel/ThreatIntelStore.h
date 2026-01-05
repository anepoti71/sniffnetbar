//
//  ThreatIntelStore.h
//  SniffNetBar
//
//  SQLite persistence for threat intelligence results
//

#import <Foundation/Foundation.h>
#import "ThreatIntelModels.h"

NS_ASSUME_NONNULL_BEGIN

@interface ThreatIntelStore : NSObject

- (instancetype)initWithTTLSeconds:(NSTimeInterval)ttlSeconds;

/// Fetch a persisted response if not expired.
- (TIEnrichmentResponse * _Nullable)responseForIndicator:(TIIndicator *)indicator;

/// Persist a response with TTL starting from now.
- (void)storeResponse:(TIEnrichmentResponse *)response;

/// Remove expired entries.
- (void)purgeExpired;

@end

NS_ASSUME_NONNULL_END
