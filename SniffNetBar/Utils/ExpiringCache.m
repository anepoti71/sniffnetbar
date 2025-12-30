//
//  ExpiringCache.m
//  SniffNetBar
//

#import "ExpiringCache.h"

@interface SNBExpiringCache ()
@property (nonatomic, strong) NSMutableDictionary *values;
@property (nonatomic, strong) NSMutableDictionary<id, NSDate *> *timestamps;
@property (nonatomic, assign) NSUInteger maxSize;
@property (nonatomic, assign) NSTimeInterval expirationInterval;
@end

@implementation SNBExpiringCache

- (instancetype)initWithMaxSize:(NSUInteger)maxSize
             expirationInterval:(NSTimeInterval)expirationInterval {
    self = [super init];
    if (self) {
        _values = [NSMutableDictionary dictionary];
        _timestamps = [NSMutableDictionary dictionary];
        _maxSize = maxSize;
        _expirationInterval = expirationInterval;
    }
    return self;
}

- (id)objectForKey:(id)key {
    if (!key) {
        return nil;
    }
    NSDate *timestamp = self.timestamps[key];
    if (!timestamp) {
        return nil;
    }
    if (self.expirationInterval > 0 &&
        [[NSDate date] timeIntervalSinceDate:timestamp] > self.expirationInterval) {
        [self.values removeObjectForKey:key];
        [self.timestamps removeObjectForKey:key];
        return nil;
    }
    return self.values[key];
}

- (void)setObject:(id)object forKey:(id)key {
    if (!key || !object) {
        return;
    }
    self.values[key] = object;
    self.timestamps[key] = [NSDate date];
}

- (void)removeObjectForKey:(id)key {
    if (!key) {
        return;
    }
    [self.values removeObjectForKey:key];
    [self.timestamps removeObjectForKey:key];
}

- (void)removeAllObjects {
    [self.values removeAllObjects];
    [self.timestamps removeAllObjects];
}

- (NSUInteger)cleanupAndReturnExpiredCount {
    NSDate *now = [NSDate date];
    NSMutableArray *expiredKeys = [NSMutableArray array];
    for (id key in self.timestamps) {
        NSDate *timestamp = self.timestamps[key];
        if (self.expirationInterval > 0 &&
            [now timeIntervalSinceDate:timestamp] > self.expirationInterval) {
            [expiredKeys addObject:key];
        }
    }

    for (id key in expiredKeys) {
        [self.values removeObjectForKey:key];
        [self.timestamps removeObjectForKey:key];
    }

    if (self.maxSize > 0 && self.values.count > self.maxSize) {
        NSArray *sortedKeys = [self.timestamps keysSortedByValueUsingComparator:^NSComparisonResult(NSDate *obj1, NSDate *obj2) {
            return [obj1 compare:obj2];
        }];
        NSUInteger toRemove = self.values.count - self.maxSize;
        for (NSUInteger i = 0; i < toRemove && i < sortedKeys.count; i++) {
            id key = sortedKeys[i];
            [self.values removeObjectForKey:key];
            [self.timestamps removeObjectForKey:key];
        }
    }

    return expiredKeys.count;
}

@end
