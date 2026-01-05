//
//  NetworkAssetMonitor.m
//  SniffNetBar
//
//  Passive network asset monitor using ARP table snapshots
//

#import "NetworkAssetMonitor.h"
#import "UserDefaultsKeys.h"
#import "Logger.h"
#import <arpa/inet.h>
#import <netdb.h>

static const NSTimeInterval kAssetMonitorInterval = 30.0;
static const NSTimeInterval kRecentNewAssetTTL = 300.0; // 5 minutes

@implementation SNBNetworkAsset
@end

@interface SNBNetworkAssetMonitor () <NSNetServiceBrowserDelegate, NSNetServiceDelegate>
@property (nonatomic, strong) dispatch_queue_t workQueue;
@property (nonatomic, strong) dispatch_source_t timer;
@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBNetworkAsset *> *assetsByMAC;
@property (nonatomic, strong) NSMutableArray<SNBNetworkAsset *> *recentNewAssets;
@property (nonatomic, strong) NSMutableSet<NSString *> *knownMACs;
@property (nonatomic, assign) BOOL shouldSeedKnown;
@property (atomic, copy) NSArray<SNBNetworkAsset *> *assetsSnapshotCache;
@property (atomic, copy) NSArray<SNBNetworkAsset *> *recentNewAssetsSnapshotCache;
@property (nonatomic, copy) NSDictionary<NSString *, NSString *> *ouiVendors;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *bonjourHostnames;
@property (nonatomic, strong) NSMutableArray<NSNetServiceBrowser *> *serviceBrowsers;
@property (nonatomic, strong) NSMutableSet<NSNetService *> *resolvingServices;
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
        _bonjourHostnames = [[NSMutableDictionary alloc] init];
        _serviceBrowsers = [[NSMutableArray alloc] init];
        _resolvingServices = [[NSMutableSet alloc] init];
        [self loadKnownDevices];
        [self loadOUIVendors];
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
    [self startBonjourDiscovery];
}

- (void)stop {
    if (self.timer) {
        dispatch_source_cancel(self.timer);
        self.timer = nil;
    }
    [self stopBonjourDiscovery];
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
                // Prefer Bonjour hostname if available
                if (asset.hostname.length > 0 && ![asset.hostname isEqualToString:@""]) {
                    existing.hostname = asset.hostname;
                }
                existing.vendor = asset.vendor;
                if (asset.bonjourName.length > 0) {
                    existing.bonjourName = asset.bonjourName;
                }
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

        // Resolve hostname using multiple methods
        if ([host isEqualToString:@"?"]) {
            // Check Bonjour cache first, then fall back to DNS
            asset.hostname = [self resolveHostnameForIPAddress:ip] ?: @"";
        } else {
            asset.hostname = host;
        }

        asset.vendor = [self resolveVendorForMAC:asset.macAddress] ?: @"";

        // Check if we have Bonjour info for this IP
        @synchronized(self.bonjourHostnames) {
            NSString *bonjourHostname = self.bonjourHostnames[ip];
            if (bonjourHostname.length > 0) {
                // Prefer Bonjour hostname for .local domains
                if (asset.hostname.length == 0 || [asset.hostname isEqualToString:@""]) {
                    asset.hostname = bonjourHostname;
                }
            }
        }

        asset.lastSeen = [NSDate date];
        SNBLogDebug("Asset: IP=%@ MAC=%@ Host='%@' Vendor='%@'",
                   asset.ipAddress, asset.macAddress, asset.hostname, asset.vendor);
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
            NSString *name = asset.hostname.length > 0 ? asset.hostname
                : (asset.vendor.length > 0 ? asset.vendor : asset.ipAddress);
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

#pragma mark - OUI vendor lookup

- (void)loadOUIVendors {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"oui" ofType:@"csv"];
    if (path.length == 0) {
        self.ouiVendors = @{};
        return;
    }

    NSError *error = nil;
    NSString *contents = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&error];
    if (!contents || error) {
        SNBLogThreatIntelWarn("Failed to load OUI data: %{public}@", error.localizedDescription);
        self.ouiVendors = @{};
        return;
    }

    NSMutableDictionary<NSString *, NSString *> *vendors = [NSMutableDictionary dictionary];
    NSArray<NSString *> *lines = [contents componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString *line in lines) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (trimmed.length == 0 || [trimmed hasPrefix:@"#"]) {
            continue;
        }
        NSRange comma = [trimmed rangeOfString:@","];
        if (comma.location == NSNotFound) {
            continue;
        }
        NSString *oui = [[trimmed substringToIndex:comma.location]
                         stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *vendor = [[trimmed substringFromIndex:comma.location + 1]
                            stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        NSString *normalized = [self normalizedOUI:oui];
        if (normalized.length == 6 && vendor.length > 0) {
            vendors[normalized] = vendor;
        }
    }
    self.ouiVendors = vendors;
}

- (NSString *)resolveVendorForMAC:(NSString *)macAddress {
    if (macAddress.length == 0 || self.ouiVendors.count == 0) {
        return nil;
    }
    NSString *normalized = [self normalizedOUI:macAddress];
    if (normalized.length != 6) {
        return nil;
    }
    return self.ouiVendors[normalized];
}

- (NSString *)normalizedOUI:(NSString *)value {
    if (value.length == 0) {
        return @"";
    }
    NSMutableString *hex = [NSMutableString string];
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) {
            [hex appendFormat:@"%C", c];
        }
    }
    if (hex.length < 6) {
        return @"";
    }
    NSString *prefix = [[hex substringToIndex:6] uppercaseString];
    return prefix;
}

#pragma mark - Hostname resolution

- (NSString *)resolveHostnameForIPAddress:(NSString *)ipAddress {
    if (ipAddress.length == 0) {
        return nil;
    }

    // First check if we have a Bonjour hostname for this IP
    @synchronized(self.bonjourHostnames) {
        NSString *bonjourName = self.bonjourHostnames[ipAddress];
        if (bonjourName.length > 0) {
            return bonjourName;
        }
    }

    // Fall back to DNS reverse lookup
    char host[NI_MAXHOST];
    memset(host, 0, sizeof(host));

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));

    if (inet_pton(AF_INET, ipAddress.UTF8String, &((struct sockaddr_in *)&addr)->sin_addr) == 1) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
        ipv4->sin_family = AF_INET;
        // Try without NI_NAMEREQD first to be less strict
        if (getnameinfo((struct sockaddr *)ipv4, sizeof(struct sockaddr_in),
                        host, sizeof(host), NULL, 0, 0) == 0) {
            NSString *result = [NSString stringWithUTF8String:host];
            // Don't return if it's just the IP address again
            if (![result isEqualToString:ipAddress]) {
                return result;
            }
        }
        return nil;
    }

    if (inet_pton(AF_INET6, ipAddress.UTF8String, &((struct sockaddr_in6 *)&addr)->sin6_addr) == 1) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
        ipv6->sin6_family = AF_INET6;
        if (getnameinfo((struct sockaddr *)ipv6, sizeof(struct sockaddr_in6),
                        host, sizeof(host), NULL, 0, 0) == 0) {
            NSString *result = [NSString stringWithUTF8String:host];
            if (![result isEqualToString:ipAddress]) {
                return result;
            }
        }
    }

    return nil;
}

#pragma mark - Bonjour Discovery

- (void)startBonjourDiscovery {
    dispatch_async(dispatch_get_main_queue(), ^{
        // Browse for common services that reveal device hostnames
        NSArray<NSString *> *serviceTypes = @[
            @"_ssh._tcp.",          // SSH servers
            @"_afpovertcp._tcp.",   // Apple File Protocol
            @"_smb._tcp.",          // SMB/CIFS
            @"_http._tcp.",         // HTTP servers
            @"_airplay._tcp.",      // AirPlay
            @"_homekit._tcp.",      // HomeKit
            @"_companion-link._tcp.", // Apple Companion Link
            @"_device-info._tcp."   // Device Info
        ];

        for (NSString *serviceType in serviceTypes) {
            NSNetServiceBrowser *browser = [[NSNetServiceBrowser alloc] init];
            browser.delegate = self;
            [browser searchForServicesOfType:serviceType inDomain:@"local."];
            [self.serviceBrowsers addObject:browser];
        }

        SNBLogInfo("Started Bonjour discovery for %lu service types", (unsigned long)serviceTypes.count);
    });
}

- (void)stopBonjourDiscovery {
    dispatch_async(dispatch_get_main_queue(), ^{
        for (NSNetServiceBrowser *browser in self.serviceBrowsers) {
            [browser stop];
        }
        [self.serviceBrowsers removeAllObjects];

        for (NSNetService *service in self.resolvingServices) {
            [service stop];
        }
        [self.resolvingServices removeAllObjects];

        SNBLogInfo("Stopped Bonjour discovery");
    });
}

#pragma mark - NSNetServiceBrowserDelegate

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser
           didFindService:(NSNetService *)service
               moreComing:(BOOL)moreComing {
    // Resolve the service to get its IP address and hostname
    service.delegate = self;
    [self.resolvingServices addObject:service];
    [service resolveWithTimeout:5.0];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser
         didRemoveService:(NSNetService *)service
               moreComing:(BOOL)moreComing {
    // Service is no longer available
    [self.resolvingServices removeObject:service];
}

- (void)netServiceBrowserDidStopSearch:(NSNetServiceBrowser *)browser {
    SNBLogDebug("Bonjour browser stopped");
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser
             didNotSearch:(NSDictionary<NSString *, NSNumber *> *)errorDict {
    SNBLogWarn("Bonjour browser failed: %@", errorDict);
}

#pragma mark - NSNetServiceDelegate

- (void)netServiceDidResolveAddress:(NSNetService *)service {
    // Extract IP addresses from the service
    for (NSData *addressData in service.addresses) {
        struct sockaddr *addr = (struct sockaddr *)addressData.bytes;

        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip));
            NSString *ipAddress = [NSString stringWithUTF8String:ip];

            // Store the hostname for this IP
            NSString *hostname = service.hostName;
            if (hostname.length > 0) {
                // Remove .local. suffix if present
                if ([hostname hasSuffix:@".local."]) {
                    hostname = [hostname substringToIndex:hostname.length - 7];
                } else if ([hostname hasSuffix:@".local"]) {
                    hostname = [hostname substringToIndex:hostname.length - 6];
                }

                @synchronized(self.bonjourHostnames) {
                    self.bonjourHostnames[ipAddress] = hostname;
                    SNBLogDebug("Bonjour: %@ -> %@ (%@)", ipAddress, hostname, service.type);
                }

                // Update existing asset if found
                dispatch_async(self.workQueue, ^{
                    BOOL updated = NO;
                    for (SNBNetworkAsset *asset in self.assetsByMAC.allValues) {
                        if ([asset.ipAddress isEqualToString:ipAddress]) {
                            if (asset.hostname.length == 0 || [asset.hostname isEqualToString:@"?"]) {
                                asset.hostname = hostname;
                                asset.bonjourName = service.name;
                                updated = YES;
                                SNBLogDebug("Updated asset %@ with Bonjour hostname: %@", ipAddress, hostname);
                            }
                        }
                    }
                    if (updated) {
                        self.assetsSnapshotCache = [self.assetsByMAC.allValues copy];
                        // Notify UI of the update
                        if (self.onAssetsUpdated) {
                            self.onAssetsUpdated(self.assetsSnapshotCache, self.recentNewAssetsSnapshotCache);
                        }
                    }
                });
            }
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, sizeof(ip));
            NSString *ipAddress = [NSString stringWithUTF8String:ip];

            NSString *hostname = service.hostName;
            if (hostname.length > 0) {
                if ([hostname hasSuffix:@".local."]) {
                    hostname = [hostname substringToIndex:hostname.length - 7];
                } else if ([hostname hasSuffix:@".local"]) {
                    hostname = [hostname substringToIndex:hostname.length - 6];
                }

                @synchronized(self.bonjourHostnames) {
                    self.bonjourHostnames[ipAddress] = hostname;
                    SNBLogDebug("Bonjour: %@ -> %@ (%@)", ipAddress, hostname, service.type);
                }

                dispatch_async(self.workQueue, ^{
                    BOOL updated = NO;
                    for (SNBNetworkAsset *asset in self.assetsByMAC.allValues) {
                        if ([asset.ipAddress isEqualToString:ipAddress]) {
                            if (asset.hostname.length == 0 || [asset.hostname isEqualToString:@"?"]) {
                                asset.hostname = hostname;
                                asset.bonjourName = service.name;
                                updated = YES;
                                SNBLogDebug("Updated asset %@ with Bonjour hostname: %@", ipAddress, hostname);
                            }
                        }
                    }
                    if (updated) {
                        self.assetsSnapshotCache = [self.assetsByMAC.allValues copy];
                        // Notify UI of the update
                        if (self.onAssetsUpdated) {
                            self.onAssetsUpdated(self.assetsSnapshotCache, self.recentNewAssetsSnapshotCache);
                        }
                    }
                });
            }
        }
    }

    [self.resolvingServices removeObject:service];
}

- (void)netService:(NSNetService *)service didNotResolve:(NSDictionary<NSString *, NSNumber *> *)errorDict {
    SNBLogDebug("Failed to resolve service %@: %@", service.name, errorDict);
    [self.resolvingServices removeObject:service];
}

@end
