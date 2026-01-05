//
//  NetworkAssetMonitor.m
//  SniffNetBar
//
//  Passive network asset monitor using ARP table snapshots
//

#import "NetworkAssetMonitor.h"
#import "UserDefaultsKeys.h"
#import "Logger.h"

static const NSTimeInterval kAssetMonitorInterval = 30.0;
static const NSTimeInterval kRecentNewAssetTTL = 300.0; // 5 minutes

@implementation SNBNetworkAsset
@end

@interface SNBNetworkAssetMonitor ()
@property (nonatomic, strong) dispatch_queue_t workQueue;
@property (nonatomic, strong) dispatch_source_t timer;
@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBNetworkAsset *> *assetsByMAC;
@property (nonatomic, strong) NSMutableArray<SNBNetworkAsset *> *recentNewAssets;
@property (nonatomic, strong) NSMutableSet<NSString *> *knownMACs;
@property (nonatomic, assign) BOOL shouldSeedKnown;
@property (atomic, copy) NSArray<SNBNetworkAsset *> *assetsSnapshotCache;
@property (atomic, copy) NSArray<SNBNetworkAsset *> *recentNewAssetsSnapshotCache;
@end

@implementation SNBNetworkAssetMonitor

- (instancetype)init {
    self = [super init];
    if (self) {
        _workQueue = dispatch_queue_create("com.sniffnetbar.assetmonitor", DISPATCH_QUEUE_SERIAL);
        _assetsByMAC = [[NSMutableDictionary alloc] init];
        _recentNewAssets = [[NSMutableArray alloc] init];
        _knownMACs = [[NSMutableSet alloc] init];
        _shouldSeedKnown = NO;
        _assetsSnapshotCache = @[];
        _recentNewAssetsSnapshotCache = @[];
        [self loadKnownDevices];
    }
    return self;
}

- (void)start {
    if (self.timer) {
        return;
    }
    self.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.workQueue);
    dispatch_source_set_timer(self.timer,
                              dispatch_time(DISPATCH_TIME_NOW, 0),
                              (uint64_t)(kAssetMonitorInterval * NSEC_PER_SEC),
                              (uint64_t)(1.0 * NSEC_PER_SEC));
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(self.timer, ^{
        [weakSelf refresh];
    });
    dispatch_resume(self.timer);
}

- (void)stop {
    if (self.timer) {
        dispatch_source_cancel(self.timer);
        self.timer = nil;
    }
}

- (void)setEnabled:(BOOL)enabled {
    if (_enabled == enabled) {
        return;
    }
    _enabled = enabled;
    if (enabled) {
        if (self.knownMACs.count == 0) {
            self.shouldSeedKnown = YES;
        }
        [self start];
        [self refresh];
    } else {
        [self stop];
    }
}

- (void)refresh {
    if (!self.enabled) {
        return;
    }

    dispatch_async(self.workQueue, ^{
        NSArray<SNBNetworkAsset *> *snapshot = [self loadAssetsFromARP];
        if (snapshot.count == 0) {
            return;
        }

        NSDate *now = [NSDate date];
        NSMutableArray<SNBNetworkAsset *> *newAssets = [NSMutableArray array];

        for (SNBNetworkAsset *asset in snapshot) {
            SNBNetworkAsset *existing = self.assetsByMAC[asset.macAddress];
            if (existing) {
                existing.ipAddress = asset.ipAddress;
                existing.hostname = asset.hostname;
                existing.lastSeen = now;
                existing.isNew = NO;
            } else {
                asset.lastSeen = now;
                asset.isNew = NO;
                self.assetsByMAC[asset.macAddress] = asset;
                if (!self.shouldSeedKnown && ![self.knownMACs containsObject:asset.macAddress]) {
                    asset.isNew = YES;
                    [newAssets addObject:asset];
                }
            }
        }

        if (self.shouldSeedKnown && self.knownMACs.count == 0) {
            for (SNBNetworkAsset *asset in snapshot) {
                [self.knownMACs addObject:asset.macAddress];
            }
            [self persistKnownDevices];
            self.shouldSeedKnown = NO;
            return;
        }

        if (newAssets.count > 0) {
            for (SNBNetworkAsset *asset in newAssets) {
                [self.knownMACs addObject:asset.macAddress];
                [self.recentNewAssets addObject:asset];
            }
            [self persistKnownDevices];
            [self pruneRecentNewAssets];
            [self notifyNewAssets:newAssets];
        } else {
            [self pruneRecentNewAssets];
        }

        self.assetsSnapshotCache = [self.assetsByMAC.allValues copy];
        self.recentNewAssetsSnapshotCache = [self.recentNewAssets copy];

        if (self.onAssetsUpdated) {
            self.onAssetsUpdated(self.assetsSnapshotCache, self.recentNewAssetsSnapshotCache);
        }
    });
}

- (NSArray<SNBNetworkAsset *> *)assetsSnapshot {
    return self.assetsSnapshotCache ?: @[];
}

- (NSArray<SNBNetworkAsset *> *)recentNewAssetsSnapshot {
    return self.recentNewAssetsSnapshotCache ?: @[];
}

#pragma mark - ARP parsing

- (NSArray<SNBNetworkAsset *> *)loadAssetsFromARP {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/sbin/arp";
    task.arguments = @[@"-a"];

    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    task.standardError = pipe;

    @try {
        [task launch];
    } @catch (NSException *exception) {
        SNBLogWarn("Asset monitor: failed to run arp");
        return @[];
    }

    NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
    [task waitUntilExit];

    if (data.length == 0) {
        return @[];
    }

    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (output.length == 0) {
        return @[];
    }

    NSRegularExpression *regex =
        [NSRegularExpression regularExpressionWithPattern:@"^(\\S+) \\(([^)]+)\\) at ([0-9a-fA-F:]+|\\(incomplete\\))"
                                                  options:NSRegularExpressionAnchorsMatchLines
                                                    error:nil];
    NSArray<NSTextCheckingResult *> *matches = [regex matchesInString:output
                                                              options:0
                                                                range:NSMakeRange(0, output.length)];
    NSMutableArray<SNBNetworkAsset *> *assets = [NSMutableArray array];
    for (NSTextCheckingResult *match in matches) {
        if (match.numberOfRanges < 4) {
            continue;
        }
        NSString *host = [output substringWithRange:[match rangeAtIndex:1]];
        NSString *ip = [output substringWithRange:[match rangeAtIndex:2]];
        NSString *mac = [output substringWithRange:[match rangeAtIndex:3]];
        if ([mac isEqualToString:@"(incomplete)"]) {
            continue;
        }

        SNBNetworkAsset *asset = [[SNBNetworkAsset alloc] init];
        asset.ipAddress = ip;
        asset.macAddress = [mac lowercaseString];
        asset.hostname = [host isEqualToString:@"?"] ? @"" : host;
        asset.lastSeen = [NSDate date];
        [assets addObject:asset];
    }
    return assets;
}

#pragma mark - Known device persistence

- (void)loadKnownDevices {
    NSArray *stored = [[NSUserDefaults standardUserDefaults] arrayForKey:SNBUserDefaultsKeyKnownNetworkDevices];
    for (id value in stored) {
        if ([value isKindOfClass:[NSString class]]) {
            [self.knownMACs addObject:[(NSString *)value lowercaseString]];
        }
    }
}

- (void)persistKnownDevices {
    NSArray *values = [self.knownMACs allObjects];
    [[NSUserDefaults standardUserDefaults] setObject:values forKey:SNBUserDefaultsKeyKnownNetworkDevices];
}

#pragma mark - Alerts

- (void)notifyNewAssets:(NSArray<SNBNetworkAsset *> *)assets {
    dispatch_async(dispatch_get_main_queue(), ^{
        for (SNBNetworkAsset *asset in assets) {
            NSUserNotification *notification = [[NSUserNotification alloc] init];
            notification.title = @"New device detected";
            NSString *name = asset.hostname.length > 0 ? asset.hostname : asset.ipAddress;
            notification.informativeText = [NSString stringWithFormat:@"%@ (%@)", name, asset.macAddress];
            [[NSUserNotificationCenter defaultUserNotificationCenter] deliverNotification:notification];
        }
    });
}

- (void)pruneRecentNewAssets {
    NSDate *now = [NSDate date];
    NSMutableArray<SNBNetworkAsset *> *filtered = [NSMutableArray array];
    for (SNBNetworkAsset *asset in self.recentNewAssets) {
        if ([now timeIntervalSinceDate:asset.lastSeen] <= kRecentNewAssetTTL) {
            [filtered addObject:asset];
        }
    }
    self.recentNewAssets = filtered;
}

@end
