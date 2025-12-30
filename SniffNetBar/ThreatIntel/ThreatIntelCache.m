//
//  ThreatIntelCache.m
//  SniffNetBar
//

#import "ThreatIntelCache.h"
#import "ConfigurationManager.h"

@interface TICacheEntry : NSObject
@property (nonatomic, strong) TIResult *result;
@property (nonatomic, strong) NSDate *cachedAt;
@property (nonatomic, strong) NSDate *expiresAt;
@property (nonatomic, strong) NSDate *accessedAt;
@end

@implementation TICacheEntry
@end

@interface ThreatIntelCache ()
@property (nonatomic, strong) NSMutableDictionary<NSString *, TICacheEntry *> *cache;
@property (nonatomic, assign) NSInteger maxSize;
@property (nonatomic, assign) NSInteger hits;
@property (nonatomic, assign) NSInteger misses;
@property (nonatomic, strong) dispatch_queue_t cacheQueue;
@end

@implementation ThreatIntelCache

- (instancetype)initWithMaxSize:(NSInteger)maxSize {
    self = [super init];
    if (self) {
        _maxSize = maxSize;
        _cache = [NSMutableDictionary dictionary];
        _hits = 0;
        _misses = 0;
        _cacheQueue = dispatch_queue_create("com.sniffnetbar.threatintel.cache", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (NSString *)keyForProvider:(NSString *)provider indicator:(TIIndicator *)indicator {
    return [NSString stringWithFormat:@"%@:%ld:%@", provider, (long)indicator.type, indicator.value];
}

- (TIResult *)getResultForProvider:(NSString *)provider indicator:(TIIndicator *)indicator {
    __block TIResult *result = nil;

    dispatch_sync(self.cacheQueue, ^{
        NSString *key = [self keyForProvider:provider indicator:indicator];
        TICacheEntry *entry = self.cache[key];

        if (entry) {
            NSDate *now = [NSDate date];

            // Check expiration
            if ([now compare:entry.expiresAt] == NSOrderedDescending) {
                // Expired, remove
                [self.cache removeObjectForKey:key];
                self.misses++;
                SNBLog(@"ThreatIntelCache: Expired entry for %@", key);
                return;
            }

            // Valid entry
            entry.accessedAt = now;
            result = entry.result;
            self.hits++;
            SNBLog(@"ThreatIntelCache: Hit for %@", key);
        } else {
            self.misses++;
            SNBLog(@"ThreatIntelCache: Miss for %@", key);
        }
    });

    return result;
}

- (void)setResult:(TIResult *)result {
    dispatch_async(self.cacheQueue, ^{
        NSString *key = [self keyForProvider:result.providerName indicator:result.indicator];

        TICacheEntry *entry = [[TICacheEntry alloc] init];
        entry.result = result;
        entry.cachedAt = [NSDate date];
        entry.expiresAt = result.metadata.expiresAt;
        entry.accessedAt = [NSDate date];

        self.cache[key] = entry;
        SNBLog(@"ThreatIntelCache: Cached %@ (expires: %@)", key, entry.expiresAt);

        // Evict LRU if over capacity
        if (self.cache.count > self.maxSize) {
            [self evictLRU];
        }
    });
}

- (BOOL)isStaleForProvider:(NSString *)provider
                 indicator:(TIIndicator *)indicator
            refreshWindow:(NSTimeInterval)refreshWindow {
    __block BOOL isStale = YES;

    dispatch_sync(self.cacheQueue, ^{
        NSString *key = [self keyForProvider:provider indicator:indicator];
        TICacheEntry *entry = self.cache[key];

        if (entry) {
            NSDate *now = [NSDate date];
            NSTimeInterval timeUntilExpiry = [entry.expiresAt timeIntervalSinceDate:now];
            isStale = timeUntilExpiry <= refreshWindow;
        }
    });

    return isStale;
}

- (void)invalidateProvider:(NSString *)provider indicator:(TIIndicator *)indicator {
    dispatch_async(self.cacheQueue, ^{
        if (provider && indicator) {
            NSString *key = [self keyForProvider:provider indicator:indicator];
            [self.cache removeObjectForKey:key];
            SNBLog(@"ThreatIntelCache: Invalidated %@", key);
        } else if (provider) {
            // Remove all entries for provider
            NSArray *keys = [self.cache allKeys];
            for (NSString *key in keys) {
                if ([key hasPrefix:[NSString stringWithFormat:@"%@:", provider]]) {
                    [self.cache removeObjectForKey:key];
                }
            }
            SNBLog(@"ThreatIntelCache: Invalidated all entries for provider %@", provider);
        } else {
            [self clear];
        }
    });
}

- (void)clear {
    dispatch_async(self.cacheQueue, ^{
        [self.cache removeAllObjects];
        SNBLog(@"ThreatIntelCache: Cleared all entries");
    });
}

- (NSInteger)size {
    __block NSInteger count = 0;
    dispatch_sync(self.cacheQueue, ^{
        count = self.cache.count;
    });
    return count;
}

- (double)hitRate {
    __block double rate = 0.0;
    dispatch_sync(self.cacheQueue, ^{
        NSInteger total = self.hits + self.misses;
        if (total > 0) {
            rate = (double)self.hits / (double)total;
        }
    });
    return rate;
}

- (void)evictLRU {
    // Find least recently accessed entry
    TICacheEntry *lruEntry = nil;
    NSString *lruKey = nil;

    for (NSString *key in self.cache) {
        TICacheEntry *entry = self.cache[key];
        if (!lruEntry || [entry.accessedAt compare:lruEntry.accessedAt] == NSOrderedAscending) {
            lruEntry = entry;
            lruKey = key;
        }
    }

    if (lruKey) {
        [self.cache removeObjectForKey:lruKey];
        SNBLog(@"ThreatIntelCache: Evicted LRU entry %@", lruKey);
    }
}

@end
