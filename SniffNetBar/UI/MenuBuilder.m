//
//  MenuBuilder.m
//  SniffNetBar
//

#import "MenuBuilder.h"
#import "MenuBuilder+ThreatDisplay.h"
#import "ByteFormatter.h"
#import "ConfigurationManager.h"
#import "MapMenuView.h"
#import "NetworkDevice.h"
#import "ThreatIntelModels.h"
#import "TrafficStatistics.h"
#import "UserDefaultsKeys.h"
#import "NetworkAssetMonitor.h"
#import "IPAddressUtilities.h"
#import <ifaddrs.h>
#import <arpa/inet.h>
#import "Logger.h"

static NSString *SNBStoredDeviceName(void) {
    NSString *storedName = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeySelectedNetworkDevice];
    if (storedName.length > 0) {
        return storedName;
    }

    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                      NSUserDomainMask,
                                                                      YES);
    if (paths.count == 0) {
        return nil;
    }
    NSString *directory = [paths.firstObject stringByAppendingPathComponent:@"SniffNetBar"];
    NSString *path = [directory stringByAppendingPathComponent:@"SelectedNetworkDevice.plist"];
    NSDictionary<NSString *, id> *stored = [NSDictionary dictionaryWithContentsOfFile:path];
    NSString *fileName = stored[@"name"];
    if (fileName.length > 0) {
        [[NSUserDefaults standardUserDefaults] setObject:fileName forKey:SNBUserDefaultsKeySelectedNetworkDevice];
        return fileName;
    }
    return nil;
}

@interface MenuBuilder ()
@property (nonatomic, strong) NSMenu *statusMenu;
@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) ConfigurationManager *configuration;
@property (nonatomic, strong) MapMenuView *mapMenuView;
@property (nonatomic, strong) NSMenuItem *mapMenuItem;
@property (nonatomic, weak) NSMenu *visualizationSubmenu;
@property (nonatomic, copy, readwrite) NSString *mapProviderName;
@property (nonatomic, assign, readwrite) BOOL menuIsOpen;
@property (nonatomic, assign) uint64_t lastTotalBytes;
@property (nonatomic, assign) uint64_t lastBytesPerSecond;
@property (nonatomic, assign) NSUInteger lastTopHostsCount;
@property (nonatomic, assign) NSUInteger lastTopConnectionsCount;
@property (nonatomic, assign) CFAbsoluteTime lastVisualizationRefreshTime;

// Performance: Cache menu items to avoid recreation
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMenuItem *> *cachedMenuItems;
@property (nonatomic, assign) BOOL menuStructureBuilt;
@property (nonatomic, assign) NSUInteger lastDeviceCount;
@property (nonatomic, assign) BOOL lastThreatIntelEnabled;
@property (nonatomic, assign) BOOL lastAssetMonitorEnabled;
@property (nonatomic, copy) NSString *selectedDeviceDisplayName;

// Helper method for provider summary (used by category)
- (NSString *)providerSummaryForResponse:(TIEnrichmentResponse *)response;
@end

@implementation MenuBuilder

// Performance: Increase refresh interval to reduce menu rebuilds
static const CFAbsoluteTime kVisualizationRefreshIntervalSeconds = 10.0;  // Was 5.0
static const CFAbsoluteTime kLocalIPCacheTTLSeconds = 60.0;

static NSSet<NSString *> *SNBLocalIPAddresses(void) {
    static NSSet<NSString *> *cached = nil;
    static CFAbsoluteTime lastFetch = 0;
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (cached && (now - lastFetch) < kLocalIPCacheTTLSeconds) {
        return cached;
    }

    NSMutableSet<NSString *> *addresses = [NSMutableSet set];
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {
        for (struct ifaddrs *ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;
            int family = ifa->ifa_addr->sa_family;
            if (family == AF_INET) {
                char addr[INET_ADDRSTRLEN];
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                if (inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof(addr))) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            } else if (family == AF_INET6) {
                char addr[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, addr, sizeof(addr))) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            }
        }
        freeifaddrs(interfaces);
    }

    [addresses addObject:@"127.0.0.1"];
    [addresses addObject:@"::1"];

    cached = [addresses copy];
    lastFetch = now;
    return cached;
}

- (instancetype)initWithMenu:(NSMenu *)menu
                  statusItem:(NSStatusItem *)statusItem
               configuration:(ConfigurationManager *)configuration {
    self = [super init];
    if (self) {
        _statusMenu = menu;
        _statusItem = statusItem;
        _configuration = configuration;
        _statsReportAvailable = NO;
        _cachedMenuItems = [NSMutableDictionary dictionary];
        _menuStructureBuilt = NO;

        // Expandable sections - collapsed by default for cleaner UI
        _showCleanConnections = NO;
        _showAllAssets = NO;
        _showProviderDetails = NO;

        // Load persisted settings from NSUserDefaults
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];

        // Load visualization settings (default: YES for top hosts/connections, NO for map)
        if ([defaults objectForKey:SNBUserDefaultsKeyShowTopHosts]) {
            _showTopHosts = [defaults boolForKey:SNBUserDefaultsKeyShowTopHosts];
        } else {
            _showTopHosts = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeyShowTopConnections]) {
            _showTopConnections = [defaults boolForKey:SNBUserDefaultsKeyShowTopConnections];
        } else {
            _showTopConnections = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeyShowMap]) {
            _showMap = [defaults boolForKey:SNBUserDefaultsKeyShowMap];
        } else {
            _showMap = NO;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeyDailyStatisticsEnabled]) {
            _dailyStatsEnabled = [defaults boolForKey:SNBUserDefaultsKeyDailyStatisticsEnabled];
        } else {
            _dailyStatsEnabled = YES;
        }

        NSString *savedProvider = [defaults stringForKey:SNBUserDefaultsKeyMapProvider];
        _mapProviderName = savedProvider.length > 0 ? savedProvider : configuration.defaultMapProvider;

        // Load section expansion states (default: all expanded)
        if ([defaults objectForKey:SNBUserDefaultsKeySectionThreatsExpanded]) {
            _sectionThreatsExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionThreatsExpanded];
        } else {
            _sectionThreatsExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionNetworkActivityExpanded]) {
            _sectionNetworkActivityExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionNetworkActivityExpanded];
        } else {
            _sectionNetworkActivityExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionNetworkDevicesExpanded]) {
            _sectionNetworkDevicesExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionNetworkDevicesExpanded];
        } else {
            _sectionNetworkDevicesExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionTopHostsExpanded]) {
            _sectionTopHostsExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionTopHostsExpanded];
        } else {
            _sectionTopHostsExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionTopConnectionsExpanded]) {
            _sectionTopConnectionsExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionTopConnectionsExpanded];
        } else {
            _sectionTopConnectionsExpanded = YES;
        }

        if ([defaults objectForKey:SNBUserDefaultsKeySectionNetworkAssetsExpanded]) {
            _sectionNetworkAssetsExpanded = [defaults boolForKey:SNBUserDefaultsKeySectionNetworkAssetsExpanded];
        } else {
            _sectionNetworkAssetsExpanded = YES;
        }
    }
    return self;
}

#pragma mark - Property Setters with Persistence

- (void)setShowTopHosts:(BOOL)showTopHosts {
    if (_showTopHosts != showTopHosts) {
        _showTopHosts = showTopHosts;
        [[NSUserDefaults standardUserDefaults] setBool:showTopHosts forKey:SNBUserDefaultsKeyShowTopHosts];
    }
}

- (void)setShowTopConnections:(BOOL)showTopConnections {
    if (_showTopConnections != showTopConnections) {
        _showTopConnections = showTopConnections;
        [[NSUserDefaults standardUserDefaults] setBool:showTopConnections forKey:SNBUserDefaultsKeyShowTopConnections];
    }
}

- (void)setShowMap:(BOOL)showMap {
    if (_showMap != showMap) {
        _showMap = showMap;
        [[NSUserDefaults standardUserDefaults] setBool:showMap forKey:SNBUserDefaultsKeyShowMap];
    }
}

- (void)setDailyStatsEnabled:(BOOL)dailyStatsEnabled {
    if (_dailyStatsEnabled != dailyStatsEnabled) {
        _dailyStatsEnabled = dailyStatsEnabled;
        [[NSUserDefaults standardUserDefaults] setBool:dailyStatsEnabled forKey:SNBUserDefaultsKeyDailyStatisticsEnabled];
    }
}

- (void)setSectionThreatsExpanded:(BOOL)sectionThreatsExpanded {
    if (_sectionThreatsExpanded != sectionThreatsExpanded) {
        _sectionThreatsExpanded = sectionThreatsExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionThreatsExpanded forKey:SNBUserDefaultsKeySectionThreatsExpanded];
    }
}

- (void)setSectionNetworkActivityExpanded:(BOOL)sectionNetworkActivityExpanded {
    if (_sectionNetworkActivityExpanded != sectionNetworkActivityExpanded) {
        _sectionNetworkActivityExpanded = sectionNetworkActivityExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionNetworkActivityExpanded forKey:SNBUserDefaultsKeySectionNetworkActivityExpanded];
    }
}

- (void)setSectionNetworkDevicesExpanded:(BOOL)sectionNetworkDevicesExpanded {
    if (_sectionNetworkDevicesExpanded != sectionNetworkDevicesExpanded) {
        _sectionNetworkDevicesExpanded = sectionNetworkDevicesExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionNetworkDevicesExpanded forKey:SNBUserDefaultsKeySectionNetworkDevicesExpanded];
    }
}

- (void)setSectionTopHostsExpanded:(BOOL)sectionTopHostsExpanded {
    if (_sectionTopHostsExpanded != sectionTopHostsExpanded) {
        _sectionTopHostsExpanded = sectionTopHostsExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionTopHostsExpanded forKey:SNBUserDefaultsKeySectionTopHostsExpanded];
    }
}

- (void)setSectionTopConnectionsExpanded:(BOOL)sectionTopConnectionsExpanded {
    if (_sectionTopConnectionsExpanded != sectionTopConnectionsExpanded) {
        _sectionTopConnectionsExpanded = sectionTopConnectionsExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionTopConnectionsExpanded forKey:SNBUserDefaultsKeySectionTopConnectionsExpanded];
    }
}

- (void)setSectionNetworkAssetsExpanded:(BOOL)sectionNetworkAssetsExpanded {
    if (_sectionNetworkAssetsExpanded != sectionNetworkAssetsExpanded) {
        _sectionNetworkAssetsExpanded = sectionNetworkAssetsExpanded;
        [[NSUserDefaults standardUserDefaults] setBool:sectionNetworkAssetsExpanded forKey:SNBUserDefaultsKeySectionNetworkAssetsExpanded];
    }
}

#pragma mark - Helper Methods

- (NSString *)truncatedMenuTitle:(NSString *)title maxWidth:(CGFloat)maxWidth {
    if (title.length == 0 || maxWidth <= 0) {
        return title;
    }
    NSFont *font = [NSFont menuFontOfSize:0.0];
    NSDictionary *attributes = @{ NSFontAttributeName: font };
    CGFloat availableWidth = maxWidth - 60.0;
    if (availableWidth <= 0) {
        return title;
    }
    if ([title sizeWithAttributes:attributes].width <= availableWidth) {
        return title;
    }
    NSString *ellipsis = @"...";
    CGFloat ellipsisWidth = [ellipsis sizeWithAttributes:attributes].width;
    if (ellipsisWidth >= availableWidth) {
        return ellipsis;
    }
    NSUInteger low = 0;
    NSUInteger high = title.length;
    while (low < high) {
        NSUInteger mid = (low + high + 1) / 2;
        NSString *candidate = [[title substringToIndex:mid] stringByAppendingString:ellipsis];
        if ([candidate sizeWithAttributes:attributes].width <= availableWidth) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    if (low == 0) {
        return ellipsis;
    }
    NSString *prefix = [title substringToIndex:low];
    return [prefix stringByAppendingString:ellipsis];
}

- (void)truncateMenuItemsInMenu:(NSMenu *)menu maxWidth:(CGFloat)maxWidth {
    if (maxWidth <= 0 || !menu) {
        return;
    }
    for (NSMenuItem *item in menu.itemArray) {
        if (item.isSeparatorItem) {
            continue;
        }
        if (item.submenu) {
            [self truncateMenuItemsInMenu:item.submenu maxWidth:maxWidth];
        }
        if (item.view || item.title.length == 0) {
            continue;
        }
        item.title = [self truncatedMenuTitle:item.title maxWidth:maxWidth];
    }
}

- (NSMenuItem *)fixedWidthTitleItemWithTitle:(NSString *)title width:(CGFloat)width {
    if (width <= 0) {
        NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title ?: @"" action:nil keyEquivalent:@""];
        item.enabled = NO;
        return item;
    }

    NSFont *font = [NSFont menuFontOfSize:0.0];
    NSTextField *label = [NSTextField labelWithString:title ?: @""];
    label.font = font;
    label.alignment = NSTextAlignmentLeft;
    label.lineBreakMode = NSLineBreakByTruncatingTail;
    [label sizeToFit];

    CGFloat paddingX = 12.0;
    CGFloat paddingY = 3.0;
    CGFloat viewHeight = label.frame.size.height + paddingY * 2.0;
    NSView *container = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, width, viewHeight)];

    CGFloat labelWidth = MAX(0.0, width - paddingX * 2.0);
    label.frame = NSMakeRect(paddingX, paddingY, labelWidth, label.frame.size.height);
    [container addSubview:label];

    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
    item.view = container;
    item.enabled = NO;
    return item;
}

- (NSArray<ConnectionTraffic *> *)connectionsForMapFromStats:(TrafficStats *)stats {
    NSArray<ConnectionTraffic *> *allConnections = stats.topConnections ?: @[];
    if (allConnections.count == 0) {
        return @[];
    }

    // Deduplicate connections by destination IP and filter to public IPs only
    // Map visualization only shows connections to public (geolocatable) IPs
    // This count matches what's actually displayed on the map
    NSMutableDictionary<NSString *, ConnectionTraffic *> *uniquePublicDestinations = [NSMutableDictionary dictionary];
    for (ConnectionTraffic *conn in allConnections) {
        NSString *destIP = conn.destinationAddress;
        if (destIP.length > 0 && [IPAddressUtilities isPublicIPAddress:destIP]) {
            if (!uniquePublicDestinations[destIP]) {
                uniquePublicDestinations[destIP] = conn;
            }
        }
    }

    // Return deduplicated public connections (matching map display)
    return [uniquePublicDestinations allValues];
}

#pragma mark - Threat Sorting Helpers

- (NSInteger)severityRankForVerdict:(TIThreatVerdict)verdict {
    switch (verdict) {
        case TIThreatVerdictMalicious:
            return 3;
        case TIThreatVerdictSuspicious:
            return 2;
        case TIThreatVerdictUnknown:
            return 1;
        case TIThreatVerdictClean:
            return 0;
    }
}

- (NSArray<NSString *> *)sortedThreatIPsFromResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)results {
    NSArray<NSString *> *ips = [results allKeys];
    return [ips sortedArrayUsingComparator:^NSComparisonResult(NSString *ip1, NSString *ip2) {
        TIScoringResult *score1 = results[ip1].scoringResult;
        TIScoringResult *score2 = results[ip2].scoringResult;
        NSInteger rank1 = score1 ? [self severityRankForVerdict:score1.verdict] : -1;
        NSInteger rank2 = score2 ? [self severityRankForVerdict:score2.verdict] : -1;
        if (rank1 != rank2) {
            return rank1 > rank2 ? NSOrderedAscending : NSOrderedDescending;
        }
        NSInteger scoreValue1 = score1 ? score1.finalScore : 0;
        NSInteger scoreValue2 = score2 ? score2.finalScore : 0;
        if (scoreValue1 != scoreValue2) {
            return scoreValue1 > scoreValue2 ? NSOrderedAscending : NSOrderedDescending;
        }
        return [ip1 compare:ip2];
    }];
}

- (NSArray<NSDictionary *> *)maliciousConnectionsFromStats:(TrafficStats *)stats
                                      threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults {
    if (!stats || threatIntelResults.count == 0) {
        return @[];
    }
    NSMutableArray<NSDictionary *> *malicious = [NSMutableArray array];
    for (ConnectionTraffic *connection in stats.topConnections) {
        TIEnrichmentResponse *srcResponse = threatIntelResults[connection.sourceAddress];
        TIEnrichmentResponse *dstResponse = threatIntelResults[connection.destinationAddress];
        TIScoringResult *srcScore = srcResponse.scoringResult;
        TIScoringResult *dstScore = dstResponse.scoringResult;

        TIEnrichmentResponse *bestResponse = nil;
        NSString *indicator = nil;
        NSInteger bestScore = 0;

        if (dstScore && dstScore.finalScore > 0) {
            bestResponse = dstResponse;
            indicator = connection.destinationAddress;
            bestScore = dstScore.finalScore;
        }
        if (srcScore && srcScore.finalScore > 0 && srcScore.finalScore > bestScore) {
            bestResponse = srcResponse;
            indicator = connection.sourceAddress;
            bestScore = srcScore.finalScore;
        }

        if (bestResponse) {
            [malicious addObject:@{
                @"connection": connection,
                @"response": bestResponse,
                @"indicator": indicator ?: @"",
                @"score": @(bestScore)
            }];
        }
    }

    if (malicious.count == 0) {
        return @[];
    }
    return [malicious sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
        NSInteger score1 = [obj1[@"score"] integerValue];
        NSInteger score2 = [obj2[@"score"] integerValue];
        if (score1 == score2) {
            return NSOrderedSame;
        }
        return score1 > score2 ? NSOrderedAscending : NSOrderedDescending;
    }];
}

- (NSString *)providerSummaryForResponse:(TIEnrichmentResponse *)response {
    if (!response || response.providerResults.count == 0) {
        return @"Unknown";
    }
    NSMutableArray<NSString *> *providers = [NSMutableArray array];
    for (TIResult *result in response.providerResults) {
        if (result.providerName.length == 0) {
            continue;
        }
        if (result.verdict) {
            NSString *hitLabel = result.verdict.hit ? @"hit" : @"no hit";
            [providers addObject:[NSString stringWithFormat:@"%@ (%@ %ld%%)",
                                  result.providerName,
                                  hitLabel,
                                  (long)result.verdict.confidence]];
        } else {
            [providers addObject:result.providerName];
        }
    }
    if (providers.count == 0) {
        return @"Unknown";
    }
    return [providers componentsJoinedByString:@", "];
}

- (NSString *)severityBadgeForVerdict:(TIThreatVerdict)verdict {
    switch (verdict) {
        case TIThreatVerdictMalicious:
            return @"[HIGH]";
        case TIThreatVerdictSuspicious:
            return @"[MED]";
        case TIThreatVerdictUnknown:
            return @"[LOW]";
        case TIThreatVerdictClean:
            return @"[OK]";
    }
}

- (NSMenuItem *)threatBadgeItemWithIP:(NSString *)ip scoring:(TIScoringResult *)scoring {
    NSString *badge = [self severityBadgeForVerdict:scoring.verdict];
    NSString *title = [NSString stringWithFormat:@"%@ %@ (%ld)", badge, ip, (long)scoring.finalScore];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
    item.enabled = NO;

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:title];
    NSFont *font = [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold];
    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, title.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:[scoring verdictColor] range:NSMakeRange(0, title.length)];
    item.attributedTitle = attrString;

    return item;
}

#pragma mark - Styled Menu Item Helpers

- (NSMenuItem *)collapsibleSectionHeaderWithTitle:(NSString *)title
                                        expanded:(BOOL)expanded
                                          action:(SEL)action
                                          target:(id)target {
    NSString *indicator = expanded ? @"▼" : @"▶";
    NSString *fullTitle = [NSString stringWithFormat:@"%@ %@", indicator, title];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:fullTitle action:action keyEquivalent:@""];
    item.target = target;
    item.enabled = YES;

    NSFont *font = [NSFont boldSystemFontOfSize:13.0];
    NSColor *color = [NSColor secondaryLabelColor];

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:fullTitle];
    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, fullTitle.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, fullTitle.length)];
    item.attributedTitle = attrString;

    return item;
}

- (NSMenuItem *)styledMenuItemWithTitle:(NSString *)title style:(NSString *)style {
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
    item.enabled = NO;

    NSFont *font;
    NSColor *color;

    if ([style isEqualToString:@"header"]) {
        // Bold header style
        font = [NSFont boldSystemFontOfSize:13.0];
        color = [NSColor labelColor];
    } else if ([style isEqualToString:@"subheader"]) {
        // Medium weight subheader
        font = [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold];
        color = [NSColor secondaryLabelColor];
    } else if ([style isEqualToString:@"data"]) {
        // Monospaced for data
        font = [NSFont monospacedSystemFontOfSize:11.0 weight:NSFontWeightRegular];
        color = [NSColor labelColor];
    } else {
        // Default
        font = [NSFont menuFontOfSize:0.0];
        color = [NSColor labelColor];
    }

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:title];
    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, title.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, title.length)];
    item.attributedTitle = attrString;

    return item;
}

- (NSMenuItem *)styledStatItemWithLabel:(NSString *)label value:(NSString *)value color:(NSColor *)color {
    NSString *fullText = [NSString stringWithFormat:@"%@  %@", label, value];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:fullText action:nil keyEquivalent:@""];
    item.enabled = NO;

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:fullText];

    // Label in regular font
    NSFont *labelFont = [NSFont systemFontOfSize:12.0 weight:NSFontWeightMedium];
    [attrString addAttribute:NSFontAttributeName value:labelFont range:NSMakeRange(0, label.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:[NSColor secondaryLabelColor] range:NSMakeRange(0, label.length)];

    // Value in monospaced font with color
    NSFont *valueFont = [NSFont monospacedSystemFontOfSize:12.0 weight:NSFontWeightSemibold];
    NSRange valueRange = NSMakeRange(label.length, value.length + 2); // +2 for the spaces
    [attrString addAttribute:NSFontAttributeName value:valueFont range:valueRange];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:valueRange];

    item.attributedTitle = attrString;
    return item;
}

- (NSMenuItem *)coloredStatItemWithLabel:(NSString *)label value:(NSString *)value color:(NSColor *)color {
    NSString *fullText = [NSString stringWithFormat:@"%@  %@", label, value];
    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:fullText action:nil keyEquivalent:@""];
    item.enabled = NO;

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:fullText];

    // Label (including arrow) in colored font
    NSFont *labelFont = [NSFont systemFontOfSize:12.0 weight:NSFontWeightMedium];
    [attrString addAttribute:NSFontAttributeName value:labelFont range:NSMakeRange(0, label.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, label.length)];

    // Value in monospaced font with same color
    NSFont *valueFont = [NSFont monospacedSystemFontOfSize:12.0 weight:NSFontWeightSemibold];
    NSRange valueRange = NSMakeRange(label.length, value.length + 2); // +2 for the spaces
    [attrString addAttribute:NSFontAttributeName value:valueFont range:valueRange];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:valueRange];

    item.attributedTitle = attrString;
    return item;
}

- (void)updateStatusWithStats:(TrafficStats *)stats selectedDevice:(NetworkDevice *)selectedDevice {
    // Create attributed string with colored arrows for incoming/outgoing traffic
    NSMutableAttributedString *statusDisplay = [[NSMutableAttributedString alloc] init];

    // Add device name if available
    NSString *deviceName = selectedDevice.name ?: SNBStoredDeviceName();
    if (deviceName.length > 0) {
        NSString *prefix = [NSString stringWithFormat:@"[%@] ", deviceName];
        NSAttributedString *deviceAttr = [[NSAttributedString alloc] initWithString:prefix];
        [statusDisplay appendAttributedString:deviceAttr];
    }

    // Add download arrow in green
    NSString *downloadArrow = @"↓ ";
    NSColor *downloadColor = [NSColor colorWithCalibratedRed:0.2 green:0.7 blue:0.3 alpha:1.0];
    NSAttributedString *downloadAttr = [[NSAttributedString alloc]
        initWithString:downloadArrow
        attributes:@{NSForegroundColorAttributeName: downloadColor}];
    [statusDisplay appendAttributedString:downloadAttr];

    // Add incoming bytes
    NSString *incomingStr = [SNBByteFormatter stringFromBytes:stats.incomingBytes];
    NSAttributedString *incomingAttr = [[NSAttributedString alloc] initWithString:incomingStr];
    [statusDisplay appendAttributedString:incomingAttr];

    // Add separator
    NSAttributedString *separatorAttr = [[NSAttributedString alloc] initWithString:@"  "];
    [statusDisplay appendAttributedString:separatorAttr];

    // Add upload arrow in blue
    NSString *uploadArrow = @"↑ ";
    NSColor *uploadColor = [NSColor colorWithCalibratedRed:0.2 green:0.5 blue:1.0 alpha:1.0];
    NSAttributedString *uploadAttr = [[NSAttributedString alloc]
        initWithString:uploadArrow
        attributes:@{NSForegroundColorAttributeName: uploadColor}];
    [statusDisplay appendAttributedString:uploadAttr];

    // Add outgoing bytes
    NSString *outgoingStr = [SNBByteFormatter stringFromBytes:stats.outgoingBytes];
    NSAttributedString *outgoingAttr = [[NSAttributedString alloc] initWithString:outgoingStr];
    [statusDisplay appendAttributedString:outgoingAttr];

    self.statusItem.button.attributedTitle = statusDisplay;
}

// Performance: Check if menu data needs updating
- (BOOL)shouldRefreshMenuDataWithStats:(TrafficStats *)stats {
    // When menu is closed, only update every 10% change to reduce work
    if (!self.menuIsOpen) {
        if (self.lastTotalBytes > 0) {
            double changePercent = fabs((double)(stats.totalBytes - self.lastTotalBytes) / (double)self.lastTotalBytes);
            return changePercent > 0.10;  // 10% threshold
        }
        return YES;
    }

    // When menu is open, always refresh (but throttled by caller)
    return YES;
}

- (void)updateMenuWithStats:(TrafficStats *)stats
                    devices:(NSArray<NetworkDevice *> *)devices
             selectedDevice:(NetworkDevice *)selectedDevice
         threatIntelEnabled:(BOOL)threatIntelEnabled
     threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
        threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                 cacheStats:(NSDictionary *)cacheStats
        assetMonitorEnabled:(BOOL)assetMonitorEnabled
             networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
           recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                     target:(id)target {

    // Performance: Skip rebuild when menu is closed and no significant changes
    if (!self.menuIsOpen && ![self shouldRefreshMenuDataWithStats:stats]) {
        return;
    }

    // Update tracking values
    self.lastTotalBytes = stats.totalBytes;
    self.lastBytesPerSecond = stats.bytesPerSecond;
    self.lastTopHostsCount = stats.topHosts.count;
    self.lastTopConnectionsCount = stats.topConnections.count;

    [self.statusMenu removeAllItems];

    ConfigurationManager *config = self.configuration;

    NSMenuItem *settingsItem = [[NSMenuItem alloc] initWithTitle:@"Settings" action:nil keyEquivalent:@""];
    NSMenu *settingsSubmenu = [[NSMenu alloc] init];
    settingsItem.submenu = settingsSubmenu;
    [self.statusMenu addItem:settingsItem];

    NSMenuItem *deviceMenu = [[NSMenuItem alloc] initWithTitle:@"Network Interface" action:nil keyEquivalent:@""];
    NSMenu *deviceSubmenu = [[NSMenu alloc] init];
    NSString *uiSelectedDeviceName = selectedDevice.name ?: SNBStoredDeviceName();
    NSString *selectedInterfaceTitle = nil;
    if (selectedDevice) {
        selectedInterfaceTitle = selectedDevice.displayName ?: selectedDevice.name;
    }
    if (selectedInterfaceTitle.length == 0) {
        selectedInterfaceTitle = SNBStoredDeviceName();
    }
    self.selectedDeviceDisplayName = selectedInterfaceTitle;
    NSArray<NetworkDevice *> *deviceList = devices ?: @[];

    SNBLogUIDebug("Building device menu: selectedDevice=%s, storedDevice=%s, uiSelectedDeviceName=%s",
                  selectedDevice.name ? selectedDevice.name.UTF8String : "(nil)",
                  SNBStoredDeviceName() ? SNBStoredDeviceName().UTF8String : "(nil)",
                  uiSelectedDeviceName ? uiSelectedDeviceName.UTF8String : "(nil)");

    for (NetworkDevice *device in deviceList) {
        NSMenuItem *deviceItem = [[NSMenuItem alloc] initWithTitle:[device displayName]
                                                            action:@selector(deviceSelected:)
                                                     keyEquivalent:@""];
        deviceItem.target = target;
        deviceItem.representedObject = device;
        if (uiSelectedDeviceName.length > 0 && [device.name isEqualToString:uiSelectedDeviceName]) {
            deviceItem.state = NSControlStateValueOn;
            SNBLogUIDebug("Set checkmark on device: %s", device.name.UTF8String);
        }
        [deviceSubmenu addItem:deviceItem];
    }

    deviceMenu.submenu = deviceSubmenu;
    [settingsSubmenu addItem:deviceMenu];
    NSMenuItem *providerItem = [[NSMenuItem alloc] initWithTitle:@"GeoLocation Provider" action:nil keyEquivalent:@""];
    NSMenu *providerSubmenu = [[NSMenu alloc] init];
    NSArray<NSString *> *providers = @[@"ip-api.com", @"ipinfo.io", @"Custom (UserDefaults)"];
    for (NSString *provider in providers) {
        NSMenuItem *providerMenuItem = [[NSMenuItem alloc] initWithTitle:provider
                                                                  action:@selector(selectMapProvider:)
                                                           keyEquivalent:@""];
        providerMenuItem.target = target;
        providerMenuItem.representedObject = provider;
        NSString *providerValue = [provider isEqualToString:@"Custom (UserDefaults)"] ? @"custom" : provider;
        if ([self.mapProviderName isEqualToString:providerValue]) {
            providerMenuItem.state = NSControlStateValueOn;
        }
        [providerSubmenu addItem:providerMenuItem];
    }
    providerItem.submenu = providerSubmenu;
    [settingsSubmenu addItem:providerItem];
    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *toggleHosts = [[NSMenuItem alloc] initWithTitle:@"Show Top Hosts by Traffic"
                                                         action:@selector(toggleShowTopHosts:)
                                                  keyEquivalent:@""];
    toggleHosts.target = target;
    toggleHosts.state = self.showTopHosts ? NSControlStateValueOn : NSControlStateValueOff;
    NSMenuItem *toggleConnections = [[NSMenuItem alloc] initWithTitle:@"Show Top Connections by Traffic"
                                                               action:@selector(toggleShowTopConnections:)
                                                        keyEquivalent:@""];
    toggleConnections.target = target;
    toggleConnections.state = self.showTopConnections ? NSControlStateValueOn : NSControlStateValueOff;
    NSMenuItem *toggleMap = [[NSMenuItem alloc] initWithTitle:@"Show Map Visualization"
                                                       action:@selector(toggleShowMap:)
                                                keyEquivalent:@""];
    toggleMap.target = target;
    toggleMap.state = self.showMap ? NSControlStateValueOn : NSControlStateValueOff;

    [settingsSubmenu addItem:toggleHosts];
    [settingsSubmenu addItem:toggleConnections];
    [settingsSubmenu addItem:toggleMap];
    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *toggleThreatIntel = [[NSMenuItem alloc] initWithTitle:@"Enable Threat Intelligence"
                                                               action:@selector(toggleThreatIntel:)
                                                        keyEquivalent:@""];
    toggleThreatIntel.target = target;
    toggleThreatIntel.state = threatIntelEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:toggleThreatIntel];
    NSMenuItem *toggleAssetMonitor = [[NSMenuItem alloc] initWithTitle:@"Monitor Network Assets"
                                                                action:@selector(toggleAssetMonitor:)
                                                         keyEquivalent:@""];
    toggleAssetMonitor.target = target;
    toggleAssetMonitor.state = assetMonitorEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:toggleAssetMonitor];

    NSMenuItem *toggleDailyStats = [[NSMenuItem alloc] initWithTitle:@"Enable Daily Statistics"
                                                              action:@selector(toggleDailyStatistics:)
                                                       keyEquivalent:@""];
    toggleDailyStats.target = target;
    toggleDailyStats.state = self.dailyStatsEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [settingsSubmenu addItem:toggleDailyStats];

    NSMenuItem *openReport = [[NSMenuItem alloc] initWithTitle:@"Open Statistics Report"
                                                        action:@selector(openStatisticsReport:)
                                                 keyEquivalent:@""];
    openReport.target = target;
    openReport.enabled = self.statsReportAvailable;
    [settingsSubmenu addItem:openReport];

    // Add separator before reset button
    [settingsSubmenu addItem:[NSMenuItem separatorItem]];

    // Add Reset Statistics button
    NSMenuItem *resetItem = [[NSMenuItem alloc] initWithTitle:@"Reset Statistics"
                                                       action:@selector(resetStatistics:)
                                                keyEquivalent:@""];
    resetItem.target = target;
    [settingsSubmenu addItem:resetItem];

    NSMenuItem *visualizationItem = [[NSMenuItem alloc] initWithTitle:@"Visualization" action:nil keyEquivalent:@""];
    NSMenu *visualizationSubmenu = [[NSMenu alloc] init];
    visualizationItem.submenu = visualizationSubmenu;
    self.visualizationSubmenu = visualizationSubmenu;
    [self.statusMenu addItem:visualizationItem];
    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    [self rebuildVisualizationMenuWithStats:stats
                        threatIntelEnabled:threatIntelEnabled
                   threatIntelStatusMessage:threatIntelStatusMessage
                       threatIntelResults:threatIntelResults
                                cacheStats:cacheStats
                      assetMonitorEnabled:assetMonitorEnabled
                           networkAssets:networkAssets
                         recentNewAssets:recentNewAssets];

    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *aboutItem = [[NSMenuItem alloc] initWithTitle:@"About" action:nil keyEquivalent:@""];
    NSMenu *aboutSubmenu = [[NSMenu alloc] init];
    NSString *versionTitle = [NSString stringWithFormat:@"Version %@", config.appVersion];
    NSMenuItem *versionItem = [[NSMenuItem alloc] initWithTitle:versionTitle action:nil keyEquivalent:@""];
    versionItem.enabled = NO;
    [aboutSubmenu addItem:versionItem];
    aboutItem.submenu = aboutSubmenu;
    [self.statusMenu addItem:aboutItem];

    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"];
    [self.statusMenu addItem:quitItem];

    [self updateStatusWithStats:stats selectedDevice:selectedDevice];
    [self truncateMenuItemsInMenu:self.statusMenu maxWidth:config.menuFixedWidth];

    if (self.showMap && self.menuIsOpen && self.mapMenuView) {
        [self.mapMenuView updateWithConnections:[self connectionsForMapFromStats:stats]];
    }
}

- (NSMenuItem *)mapMenuItemIfNeeded {
    if (!self.menuIsOpen) {
        return nil;
    }
    if (!self.mapMenuItem) {
        ConfigurationManager *config = self.configuration;
        self.mapMenuView = [[MapMenuView alloc] initWithFrame:NSMakeRect(0, 0, config.menuFixedWidth, config.mapMenuViewHeight)];
        self.mapMenuView.providerName = self.mapProviderName;
        self.mapMenuView.translatesAutoresizingMaskIntoConstraints = NO;

        self.mapMenuItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
        self.mapMenuItem.view = self.mapMenuView;

        [self.mapMenuView addConstraint:[NSLayoutConstraint constraintWithItem:self.mapMenuView
                                                                     attribute:NSLayoutAttributeWidth
                                                                     relatedBy:NSLayoutRelationEqual
                                                                        toItem:nil
                                                                     attribute:NSLayoutAttributeNotAnAttribute
                                                                    multiplier:1.0
                                                                      constant:config.menuFixedWidth]];
        [self.mapMenuView addConstraint:[NSLayoutConstraint constraintWithItem:self.mapMenuView
                                                                     attribute:NSLayoutAttributeHeight
                                                                     relatedBy:NSLayoutRelationEqual
                                                                        toItem:nil
                                                                     attribute:NSLayoutAttributeNotAnAttribute
                                                                    multiplier:1.0
                                                                      constant:config.mapMenuViewHeight]];

        SNBLogUIDebug("Map menu view created with constraints: width=%.0f, height=%.0f",
               config.menuFixedWidth, config.mapMenuViewHeight);
    }
    return self.mapMenuItem;
}

- (void)tearDownMapMenuItem {
    if (self.mapMenuItem) {
        self.mapMenuItem.view = nil;
        self.mapMenuItem = nil;
        self.mapMenuView = nil;
        SNBLogUIDebug("Map menu view released");
    }
}

- (void)menuWillOpenWithStats:(TrafficStats *)stats {
    self.menuIsOpen = YES;
    SNBLogUIDebug("Status menu opened");
    if (self.showMap && self.mapMenuView) {
        [self.mapMenuView updateWithConnections:[self connectionsForMapFromStats:stats]];
    }
}

- (void)refreshVisualizationWithStats:(TrafficStats *)stats
                  threatIntelEnabled:(BOOL)threatIntelEnabled
              threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
                 threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                          cacheStats:(NSDictionary *)cacheStats
                assetMonitorEnabled:(BOOL)assetMonitorEnabled
                     networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                   recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets {
    if (!self.menuIsOpen || !self.visualizationSubmenu) {
        return;
    }

    // Avoid rebuilding live menus to prevent blinking and keep interactive views usable.
    if (self.showMap && self.mapMenuView) {
        [self.mapMenuView updateWithConnections:[self connectionsForMapFromStats:stats]];
    }

    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (now - self.lastVisualizationRefreshTime < kVisualizationRefreshIntervalSeconds) {
        return;
    }
    self.lastVisualizationRefreshTime = now;

    // Performance: Use differential update instead of full rebuild
    [self updateVisualizationMenuWithStats:stats
                        threatIntelEnabled:threatIntelEnabled
                   threatIntelStatusMessage:threatIntelStatusMessage
                       threatIntelResults:threatIntelResults
                                cacheStats:cacheStats
                      assetMonitorEnabled:assetMonitorEnabled
                           networkAssets:networkAssets
                         recentNewAssets:recentNewAssets];
}

- (void)menuDidClose {
    self.menuIsOpen = NO;
    SNBLogUIDebug("Status menu closed");
    [self tearDownMapMenuItem];
    self.visualizationSubmenu = nil;
}

- (void)selectMapProviderWithName:(NSString *)providerName stats:(TrafficStats *)stats {
    if (providerName.length == 0) {
        return;
    }
    NSString *providerValue = [providerName isEqualToString:@"Custom (UserDefaults)"] ? @"custom" : providerName;
    self.mapProviderName = providerValue;
    [[NSUserDefaults standardUserDefaults] setObject:self.mapProviderName
                                              forKey:SNBUserDefaultsKeyMapProvider];
    SNBLogUIDebug("Map provider selected: %{public}@", self.mapProviderName);
    if (self.mapMenuView) {
        self.mapMenuView.providerName = self.mapProviderName;
        if (self.showMap && stats) {
            [self.mapMenuView updateWithConnections:[self connectionsForMapFromStats:stats]];
        }
    }
}

// Performance: Wrapper that adds caching and throttling to rebuild
- (void)updateVisualizationMenuWithStats:(TrafficStats *)stats
                      threatIntelEnabled:(BOOL)threatIntelEnabled
                 threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
                     threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                              cacheStats:(NSDictionary *)cacheStats
                    assetMonitorEnabled:(BOOL)assetMonitorEnabled
                         networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                       recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets {
    // Performance: Just call rebuild with reduced frequency (10s instead of 5s)
    // The real optimization is in refreshVisualizationWithStats throttling
    [self rebuildVisualizationMenuWithStats:stats
                        threatIntelEnabled:threatIntelEnabled
                   threatIntelStatusMessage:threatIntelStatusMessage
                       threatIntelResults:threatIntelResults
                                cacheStats:cacheStats
                      assetMonitorEnabled:assetMonitorEnabled
                           networkAssets:networkAssets
                         recentNewAssets:recentNewAssets];
    [self truncateMenuItemsInMenu:self.visualizationSubmenu maxWidth:self.configuration.menuFixedWidth];
}

- (void)rebuildVisualizationMenuWithStats:(TrafficStats *)stats
                      threatIntelEnabled:(BOOL)threatIntelEnabled
                 threatIntelStatusMessage:(NSString *)threatIntelStatusMessage
                     threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                              cacheStats:(NSDictionary *)cacheStats
                    assetMonitorEnabled:(BOOL)assetMonitorEnabled
                         networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                       recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets {
    NSMenu *visualizationSubmenu = self.visualizationSubmenu;
    if (!visualizationSubmenu) {
        return;
    }

    [visualizationSubmenu removeAllItems];
    ConfigurationManager *config = self.configuration;

    NSMenu *detailsSubmenu = [[NSMenu alloc] init];
    NSMenuItem *detailsItem = [[NSMenuItem alloc] initWithTitle:@"Details" action:nil keyEquivalent:@""];
    detailsItem.submenu = detailsSubmenu;

    // ============================================================================
    // PHASE 1 & 2: Unified Threat Display with Severity Grouping
    // ============================================================================

    [visualizationSubmenu addItem:[self collapsibleSectionHeaderWithTitle:@"ACTIVE THREATS"
                                                                  expanded:self.sectionThreatsExpanded
                                                                    action:@selector(toggleSectionThreats)
                                                                    target:self]];

    if (self.sectionThreatsExpanded) {
        if (!threatIntelEnabled) {
            NSMenuItem *disabledItem = [[NSMenuItem alloc] initWithTitle:@"✓ Threat Intel: Off"
                                                                 action:nil
                                                          keyEquivalent:@""];
            disabledItem.enabled = NO;
            [visualizationSubmenu addItem:disabledItem];
        } else if (threatIntelStatusMessage.length > 0 && (threatIntelResults == nil || threatIntelResults.count == 0)) {
            NSMenuItem *unavailableItem = [[NSMenuItem alloc] initWithTitle:threatIntelStatusMessage
                                                                     action:nil
                                                              keyEquivalent:@""];
            unavailableItem.enabled = NO;
            [visualizationSubmenu addItem:unavailableItem];
        } else if (threatIntelResults == nil || threatIntelResults.count == 0) {
            NSMenuItem *scanningItem = [[NSMenuItem alloc] initWithTitle:@"⟳ Scanning connections..."
                                                              action:nil
                                                       keyEquivalent:@""];
            scanningItem.enabled = NO;
            [visualizationSubmenu addItem:scanningItem];
        } else {
        // Get ALL active destination IPs for accurate threat detection
        NSSet<NSString *> *activeDestIPs = stats.allActiveDestinationIPs ?: [NSSet set];

        // Categorize threats by severity level (High/Medium/Low)
        NSDictionary<NSNumber *, NSArray<ThreatInfo *> *> *categorizedThreats =
            [self categorizeThreats:threatIntelResults activeIPs:activeDestIPs stats:stats];

        NSArray<ThreatInfo *> *highThreats = categorizedThreats[@(ThreatSeverityHigh)] ?: @[];
        NSArray<ThreatInfo *> *mediumThreats = categorizedThreats[@(ThreatSeverityMedium)] ?: @[];
        NSArray<ThreatInfo *> *lowThreats = categorizedThreats[@(ThreatSeverityLow)] ?: @[];

        // Separate active from historical
        NSMutableArray<ThreatInfo *> *activeHighThreats = [NSMutableArray array];
        NSMutableArray<ThreatInfo *> *historicalThreats = [NSMutableArray array];
        for (ThreatInfo *threat in highThreats) {
            if (threat.isActive) {
                [activeHighThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSMutableArray<ThreatInfo *> *activeMediumThreats = [NSMutableArray array];
        for (ThreatInfo *threat in mediumThreats) {
            if (threat.isActive) {
                [activeMediumThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSMutableArray<ThreatInfo *> *activeLowThreats = [NSMutableArray array];
        for (ThreatInfo *threat in lowThreats) {
            if (threat.isActive) {
                [activeLowThreats addObject:threat];
            } else {
                [historicalThreats addObject:threat];
            }
        }

        NSUInteger totalActiveThreats = activeHighThreats.count + activeMediumThreats.count + activeLowThreats.count;

        // Show threat summary
        if (totalActiveThreats > 0) {
            // Summary count with breakdown
            NSString *summaryTitle;
            if (activeHighThreats.count > 0 && activeMediumThreats.count > 0) {
                summaryTitle = [NSString stringWithFormat:@"⚠️  %lu Active Threat%@ (%lu High, %lu Med)",
                               (unsigned long)totalActiveThreats,
                               totalActiveThreats == 1 ? @"" : @"s",
                               (unsigned long)activeHighThreats.count,
                               (unsigned long)activeMediumThreats.count];
            } else if (activeHighThreats.count > 0) {
                summaryTitle = [NSString stringWithFormat:@"⚠️  %lu High Severity Threat%@",
                               (unsigned long)activeHighThreats.count,
                               activeHighThreats.count == 1 ? @"" : @"s"];
            } else {
                summaryTitle = [NSString stringWithFormat:@"⚠️  %lu Active Threat%@",
                               (unsigned long)totalActiveThreats,
                               totalActiveThreats == 1 ? @"" : @"s"];
            }

            NSMenuItem *alertItem = [[NSMenuItem alloc] initWithTitle:summaryTitle
                                                              action:nil
                                                       keyEquivalent:@""];
            alertItem.enabled = NO;
            NSFont *boldFont = [NSFont boldSystemFontOfSize:13.0];
            NSDictionary *attributes = @{NSFontAttributeName: boldFont,
                                       NSForegroundColorAttributeName: [NSColor systemRedColor]};
            alertItem.attributedTitle = [[NSAttributedString alloc] initWithString:summaryTitle
                                                                        attributes:attributes];
            [visualizationSubmenu addItem:alertItem];

            // HIGH SEVERITY THREATS (Always visible)
            if (activeHighThreats.count > 0) {
                [visualizationSubmenu addItem:[self severityHeaderForLevel:ThreatSeverityHigh count:activeHighThreats.count]];

                for (ThreatInfo *threat in activeHighThreats) {
                    [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:threat]];
                    [visualizationSubmenu addItem:[self threatDetailItemForThreat:threat]];
                    NSMenuItem *connItem = [self threatConnectionItemForThreat:threat];
                    if (connItem) {
                        [visualizationSubmenu addItem:connItem];
                    }
                }
            }

            // MEDIUM SEVERITY THREATS (Always visible)
            if (activeMediumThreats.count > 0) {
                [visualizationSubmenu addItem:[self severityHeaderForLevel:ThreatSeverityMedium count:activeMediumThreats.count]];

                for (ThreatInfo *threat in activeMediumThreats) {
                    [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:threat]];
                    [visualizationSubmenu addItem:[self threatDetailItemForThreat:threat]];
                    NSMenuItem *connItem = [self threatConnectionItemForThreat:threat];
                    if (connItem) {
                        [visualizationSubmenu addItem:connItem];
                    }
                }
            }

            // LOW SEVERITY THREATS (Expandable - collapsed by default)
            if (activeLowThreats.count > 0) {
                NSString *expandIndicator = self.showLowSeverityThreats ? @"▼" : @"▶";
                NSString *lowTitle = [NSString stringWithFormat:@"%@ 🟢 LOW SEVERITY (%lu)",
                                     expandIndicator, (unsigned long)activeLowThreats.count];
                NSMenuItem *lowToggle = [[NSMenuItem alloc] initWithTitle:lowTitle
                                                                  action:@selector(toggleShowLowSeverityThreats)
                                                           keyEquivalent:@""];
                lowToggle.target = self;
                [visualizationSubmenu addItem:lowToggle];

                if (self.showLowSeverityThreats) {
                    for (ThreatInfo *threat in activeLowThreats) {
                        [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:threat]];
                        [visualizationSubmenu addItem:[self threatDetailItemForThreat:threat]];
                    }
                }
            }

        } else {
            NSMenuItem *cleanItem = [[NSMenuItem alloc] initWithTitle:@"✓ No Active Threats"
                                                              action:nil
                                                       keyEquivalent:@""];
            cleanItem.enabled = NO;
            NSFont *systemFont = [NSFont systemFontOfSize:[NSFont systemFontSize]];
            NSDictionary *attributes = @{NSFontAttributeName: systemFont,
                                       NSForegroundColorAttributeName: [NSColor systemGreenColor]};
            cleanItem.attributedTitle = [[NSAttributedString alloc] initWithString:cleanItem.title
                                                                        attributes:attributes];
            [visualizationSubmenu addItem:cleanItem];
        }

        // HISTORICAL THREATS (Expandable - collapsed by default)
        if (historicalThreats.count > 0) {
            NSString *expandIndicator = self.showHistoricalThreats ? @"▼" : @"▶";
            NSString *histTitle = [NSString stringWithFormat:@"%@ Previous Threats (%lu closed)",
                                  expandIndicator, (unsigned long)historicalThreats.count];
            NSMenuItem *histToggle = [[NSMenuItem alloc] initWithTitle:histTitle
                                                                action:@selector(toggleShowHistoricalThreats)
                                                         keyEquivalent:@""];
            histToggle.target = self;
            [visualizationSubmenu addItem:histToggle];

            if (self.showHistoricalThreats) {
                for (ThreatInfo *threat in historicalThreats) {
                    [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:threat]];
                    [visualizationSubmenu addItem:[self threatDetailItemForThreat:threat]];
                }
            }
        }

        // CLEAN CONNECTIONS (Expandable - collapsed by default)
        NSMutableArray<NSString *> *activeCleanIPs = [NSMutableArray array];
        for (NSString *ip in threatIntelResults) {
            TIEnrichmentResponse *response = threatIntelResults[ip];
            TIScoringResult *scoring = response.scoringResult;
            if (scoring && scoring.verdict == TIThreatVerdictClean && [activeDestIPs containsObject:ip]) {
                [activeCleanIPs addObject:ip];
            }
        }

        if (activeCleanIPs.count > 0) {
            NSString *expandIndicator = self.showCleanConnections ? @"▼" : @"▶";
            NSString *cleanTitle = [NSString stringWithFormat:@"%@ Clean Connections (%lu)",
                                   expandIndicator, (unsigned long)activeCleanIPs.count];
            NSMenuItem *cleanToggle = [[NSMenuItem alloc] initWithTitle:cleanTitle
                                                                action:@selector(toggleShowCleanConnections)
                                                         keyEquivalent:@""];
            cleanToggle.target = self;
            [visualizationSubmenu addItem:cleanToggle];

            if (self.showCleanConnections) {
                NSUInteger limit = MIN(10, activeCleanIPs.count);
                for (NSUInteger i = 0; i < limit; i++) {
                    NSString *ip = activeCleanIPs[i];
                    TIEnrichmentResponse *response = threatIntelResults[ip];

                    // Create ThreatInfo for clean connection to use enhanced display
                    ThreatInfo *cleanInfo = [[ThreatInfo alloc] init];
                    cleanInfo.ipAddress = ip;
                    cleanInfo.response = response;
                    cleanInfo.severityLevel = ThreatSeverityNone;
                    cleanInfo.score = 0;
                    cleanInfo.isActive = YES;
                    cleanInfo.totalBytes = [self totalBytesForIP:ip inStats:stats];

                    NSArray<ConnectionTraffic *> *connections = [self connectionsForIP:ip inStats:stats];
                    cleanInfo.connectionCount = connections.count;
                    if (connections.count > 0) {
                        cleanInfo.primaryConnection = connections[0];
                    }

                    // Display using enhanced format (3 lines)
                    [visualizationSubmenu addItem:[self enhancedThreatItemForThreat:cleanInfo]];
                    [visualizationSubmenu addItem:[self threatDetailItemForThreat:cleanInfo]];
                    NSMenuItem *connItem = [self threatConnectionItemForThreat:cleanInfo];
                    if (connItem) {
                        [visualizationSubmenu addItem:connItem];
                    }
                }
                if (activeCleanIPs.count > limit) {
                    NSMenuItem *moreItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  ... and %lu more",
                                                                             (unsigned long)(activeCleanIPs.count - limit)]
                                                                     action:nil
                                                              keyEquivalent:@""];
                    moreItem.enabled = NO;
                    [visualizationSubmenu addItem:moreItem];
                }
            }
        }

        // Provider status (expandable)
        if (self.showProviderDetails) {
            [visualizationSubmenu addItem:[NSMenuItem separatorItem]];
            [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"Provider Details" style:@"subheader"]];
            if (cacheStats) {
                NSString *sizeStr = [NSString stringWithFormat:@"%@", cacheStats[@"size"]];
                NSString *hitRateStr = [NSString stringWithFormat:@"%.1f%%", [cacheStats[@"hitRate"] doubleValue] * 100];
                NSString *statsStr = [NSString stringWithFormat:@"  Cache: %@ entries, %@ hit rate", sizeStr, hitRateStr];
                NSMenuItem *statsItem = [[NSMenuItem alloc] initWithTitle:statsStr action:nil keyEquivalent:@""];
                statsItem.enabled = NO;
                [visualizationSubmenu addItem:statsItem];
            }
        }
        }
    }

    [visualizationSubmenu addItem:[NSMenuItem separatorItem]];

    // Network Snapshot - Current Activity (everything above shows ONLY active connections)
    [visualizationSubmenu addItem:[self collapsibleSectionHeaderWithTitle:@"NETWORK ACTIVITY"
                                                                  expanded:self.sectionNetworkActivityExpanded
                                                                    action:@selector(toggleSectionNetworkActivity)
                                                                    target:self]];

    if (self.sectionNetworkActivityExpanded) {
        NSString *rateStr = [SNBByteFormatter stringFromBytes:stats.bytesPerSecond];
        [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Rate" value:[NSString stringWithFormat:@"%@/s", rateStr]
                                                             color:[NSColor labelColor]]];
        NSString *totalBytesStr = [SNBByteFormatter stringFromBytes:stats.totalBytes];
        [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Total" value:totalBytesStr color:[NSColor labelColor]]];

        // Active connection counts - show both total and geolocated on same line
        NSArray<ConnectionTraffic *> *mapConnections = [self connectionsForMapFromStats:stats];
        NSUInteger totalPublicConnections = mapConnections.count;

        // Update map with current connections to ensure drawnConnectionCount is current
        if (self.showMap && self.mapMenuView) {
            [self.mapMenuView updateWithConnections:mapConnections];
        }
        NSUInteger geolocatedConnections = self.mapMenuView ? self.mapMenuView.drawnConnectionCount : 0;

        // Combine connections and geolocated on one line: "Connections  8  (6 Geolocated)"
        NSString *connectionsValue = [NSString stringWithFormat:@"%lu  (%lu Geolocated)",
                                      (unsigned long)totalPublicConnections,
                                      (unsigned long)geolocatedConnections];
        [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Active Connections" value:connectionsValue
                                                             color:[NSColor secondaryLabelColor]]];

        NSString *hostsStr = [NSString stringWithFormat:@"%lu", (unsigned long)stats.topHosts.count];
        [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Hosts" value:hostsStr
                                                             color:[NSColor secondaryLabelColor]]];
    }

    [visualizationSubmenu addItem:[NSMenuItem separatorItem]];

    // Asset Monitor - Collapsible
    [visualizationSubmenu addItem:[self collapsibleSectionHeaderWithTitle:@"NETWORK DEVICES"
                                                                  expanded:self.sectionNetworkDevicesExpanded
                                                                    action:@selector(toggleSectionNetworkDevices)
                                                                    target:self]];

    if (self.sectionNetworkDevicesExpanded) {
        if (!assetMonitorEnabled) {
        NSMenuItem *disabledItem = [[NSMenuItem alloc] initWithTitle:@"✓ Asset Monitor: Off"
                                                             action:nil
                                                      keyEquivalent:@""];
        disabledItem.enabled = NO;
        [visualizationSubmenu addItem:disabledItem];
    } else if (networkAssets.count == 0) {
        NSMenuItem *emptyItem = [[NSMenuItem alloc] initWithTitle:@"⟳ Scanning network..."
                                                          action:nil
                                                   keyEquivalent:@""];
        emptyItem.enabled = NO;
        [visualizationSubmenu addItem:emptyItem];
    } else {
        // Show device count summary
        NSString *newBadge = recentNewAssets.count > 0 ? [NSString stringWithFormat:@" (%lu new)", (unsigned long)recentNewAssets.count] : @"";
        NSString *summaryStr = [NSString stringWithFormat:@"%lu Device%@%@",
                               (unsigned long)networkAssets.count,
                               networkAssets.count == 1 ? @"" : @"s",
                               newBadge];
        [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Total" value:summaryStr
                                                             color:[NSColor labelColor]]];

        // Always show new devices (important!)
        if (recentNewAssets.count > 0) {
            [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"New Devices" style:@"subheader"]];
            NSUInteger limit = MIN(3, recentNewAssets.count);
            for (NSUInteger i = 0; i < limit; i++) {
                SNBNetworkAsset *asset = recentNewAssets[i];

                // Build display name with hostname, vendor, and IP
                NSString *line;
                if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                    line = [NSString stringWithFormat:@"  🆕 %@ (%@)", asset.hostname, asset.vendor];
                } else if (asset.hostname.length > 0) {
                    line = [NSString stringWithFormat:@"  🆕 %@", asset.hostname];
                } else if (asset.vendor.length > 0) {
                    line = [NSString stringWithFormat:@"  🆕 %@ - %@", asset.vendor, asset.ipAddress];
                } else {
                    line = [NSString stringWithFormat:@"  🆕 %@", asset.ipAddress];
                }

                NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
                item.enabled = NO;
                [visualizationSubmenu addItem:item];
            }
            if (recentNewAssets.count > limit) {
                NSMenuItem *moreNewItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  ... and %lu more new",
                                                                            (unsigned long)(recentNewAssets.count - limit)]
                                                                    action:nil
                                                             keyEquivalent:@""];
                moreNewItem.enabled = NO;
                [visualizationSubmenu addItem:moreNewItem];
            }
        }

        // Expandable all devices section
        if (networkAssets.count > recentNewAssets.count) {
            NSString *expandIndicator = self.showAllAssets ? @"▼" : @"▶";
            NSUInteger knownCount = networkAssets.count - recentNewAssets.count;
            NSString *allAssetsTitle = [NSString stringWithFormat:@"%@ Show %lu Known Device%@",
                                       expandIndicator,
                                       (unsigned long)knownCount,
                                       knownCount == 1 ? @"" : @"s"];
            NSMenuItem *assetsToggle = [[NSMenuItem alloc] initWithTitle:allAssetsTitle
                                                                 action:@selector(toggleShowAllAssets)
                                                          keyEquivalent:@""];
            assetsToggle.target = self;
            [visualizationSubmenu addItem:assetsToggle];

            if (self.showAllAssets) {
                NSSet *newAssetIPs = [NSSet setWithArray:[recentNewAssets valueForKey:@"ipAddress"]];
                NSMutableArray<SNBNetworkAsset *> *knownAssets = [NSMutableArray array];
                for (SNBNetworkAsset *asset in networkAssets) {
                    if (![newAssetIPs containsObject:asset.ipAddress]) {
                        [knownAssets addObject:asset];
                    }
                }

                NSUInteger limit = MIN(10, knownAssets.count);
                for (NSUInteger i = 0; i < limit; i++) {
                    SNBNetworkAsset *asset = knownAssets[i];
                    NSString *line;
                    if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                        line = [NSString stringWithFormat:@"  %@ (%@)", asset.hostname, asset.vendor];
                    } else if (asset.hostname.length > 0) {
                        line = [NSString stringWithFormat:@"  %@", asset.hostname];
                    } else if (asset.vendor.length > 0) {
                        line = [NSString stringWithFormat:@"  %@ - %@", asset.vendor, asset.ipAddress];
                    } else {
                        line = [NSString stringWithFormat:@"  %@", asset.ipAddress];
                    }
                    NSMenuItem *assetItem = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
                    assetItem.enabled = NO;
                    [visualizationSubmenu addItem:assetItem];
                }
                if (knownAssets.count > limit) {
                    NSMenuItem *moreItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  ... and %lu more",
                                                                             (unsigned long)(knownAssets.count - limit)]
                                                                     action:nil
                                                              keyEquivalent:@""];
                    moreItem.enabled = NO;
                    [visualizationSubmenu addItem:moreItem];
                }
            }
        }
        }
    }

    [visualizationSubmenu addItem:[NSMenuItem separatorItem]];
    [visualizationSubmenu addItem:detailsItem];

    // Details submenu content
    if (self.showMap && self.menuIsOpen) {
        if (self.mapMenuItem.menu && self.mapMenuItem.menu != detailsSubmenu) {
            [self.mapMenuItem.menu removeItem:self.mapMenuItem];
        }
        NSMenuItem *mapItem = [self mapMenuItemIfNeeded];
        if (mapItem) {
            [detailsSubmenu addItem:mapItem];
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        }
    } else {
        [self tearDownMapMenuItem];
    }

    NSString *incomingStr = [SNBByteFormatter stringFromBytes:stats.incomingBytes];
    NSMenuItem *incomingItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"↓ Incoming: %@", incomingStr]
                                                          action:nil
                                                   keyEquivalent:@""];
    incomingItem.enabled = NO;
    [detailsSubmenu addItem:incomingItem];

    NSString *outgoingStr = [SNBByteFormatter stringFromBytes:stats.outgoingBytes];
    NSMenuItem *outgoingItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"↑ Outgoing: %@", outgoingStr]
                                                          action:nil
                                                   keyEquivalent:@""];
    outgoingItem.enabled = NO;
    [detailsSubmenu addItem:outgoingItem];

    NSString *totalBytesStr = [SNBByteFormatter stringFromBytes:stats.totalBytes];
    NSMenuItem *bytesItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Total: %@", totalBytesStr]
                                                       action:nil
                                                keyEquivalent:@""];
    bytesItem.enabled = NO;
    [detailsSubmenu addItem:bytesItem];

    NSString *packetsStr = [NSString stringWithFormat:@"%llu", stats.totalPackets];
    NSMenuItem *packetsItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Packets: %@", packetsStr]
                                                         action:nil
                                                  keyEquivalent:@""];
    packetsItem.enabled = NO;
    [detailsSubmenu addItem:packetsItem];

    if (self.showTopHosts && stats.topHosts.count > 0) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        [detailsSubmenu addItem:[self collapsibleSectionHeaderWithTitle:@"TOP HOSTS by Traffic"
                                                                expanded:self.sectionTopHostsExpanded
                                                                  action:@selector(toggleSectionTopHosts)
                                                                  target:self]];

        if (self.sectionTopHostsExpanded) {
            NSInteger count = MIN(config.maxTopHostsToShow, stats.topHosts.count);
            for (NSInteger i = 0; i < count; i++) {
                HostTraffic *host = stats.topHosts[i];
                NSString *hostName = host.hostname.length > 0 ? host.hostname : @"";
                NSString *hostDisplay = hostName.length > 0 ? [NSString stringWithFormat:@"%@ (%@)", hostName, host.address] : host.address;
                NSString *bytesStr = [SNBByteFormatter stringFromBytes:host.bytes];

                NSString *fullText = [NSString stringWithFormat:@"  %@ - %@", hostDisplay, bytesStr];
                NSMenuItem *hostItem = [[NSMenuItem alloc] initWithTitle:fullText action:nil keyEquivalent:@""];
                hostItem.enabled = NO;
                [detailsSubmenu addItem:hostItem];
            }
        }
    }

    if (self.showTopConnections && stats.topConnections.count > 0) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        [detailsSubmenu addItem:[self collapsibleSectionHeaderWithTitle:@"TOP CONNECTIONS by Traffic"
                                                                expanded:self.sectionTopConnectionsExpanded
                                                                  action:@selector(toggleSectionTopConnections)
                                                                  target:self]];

        if (self.sectionTopConnectionsExpanded) {
            NSInteger count = MIN(config.maxTopConnectionsToShow, stats.topConnections.count);
            for (NSInteger i = 0; i < count; i++) {
                ConnectionTraffic *connection = stats.topConnections[i];
                NSString *bytesStr = [SNBByteFormatter stringFromBytes:connection.bytes];

                NSString *fullText = [NSString stringWithFormat:@"  %@:%ld → %@:%ld - %@",
                           connection.sourceAddress,
                           (long)connection.sourcePort,
                           connection.destinationAddress,
                           (long)connection.destinationPort,
                           bytesStr];

                NSMenuItem *connectionItem = [[NSMenuItem alloc] initWithTitle:fullText action:nil keyEquivalent:@""];
                connectionItem.enabled = NO;
                [detailsSubmenu addItem:connectionItem];
            }
        }
    }

    if (assetMonitorEnabled && networkAssets.count > 0) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        NSString *networkDevicesTitle = @"NETWORK DEVICES";
        if (self.selectedDeviceDisplayName.length > 0) {
            networkDevicesTitle = [NSString stringWithFormat:@"NETWORK DEVICES (%@)", self.selectedDeviceDisplayName];
        }
        [detailsSubmenu addItem:[self collapsibleSectionHeaderWithTitle:networkDevicesTitle
                                                                expanded:self.sectionNetworkAssetsExpanded
                                                                  action:@selector(toggleSectionNetworkAssets)
                                                                  target:self]];

        if (self.sectionNetworkAssetsExpanded) {
            NSSet<NSString *> *localIPs = SNBLocalIPAddresses();
            NSUInteger limit = MIN(10, networkAssets.count);
            for (NSUInteger i = 0; i < limit; i++) {
                SNBNetworkAsset *asset = networkAssets[i];

                // Build display name with hostname and vendor
                NSString *line;
                BOOL isLocal = [localIPs containsObject:asset.ipAddress];
                NSString *suffix = isLocal ? @" (This Mac)" : @"";

                if (asset.hostname.length > 0 && asset.vendor.length > 0) {
                    // Show: hostname (vendor) - IP
                    line = [NSString stringWithFormat:@"  %@ (%@) - %@%@",
                           asset.hostname, asset.vendor, asset.ipAddress, suffix];
                } else if (asset.hostname.length > 0) {
                    // Show: hostname - IP
                    line = [NSString stringWithFormat:@"  %@ - %@%@",
                           asset.hostname, asset.ipAddress, suffix];
                } else if (asset.vendor.length > 0) {
                    // Show: vendor - IP
                    line = [NSString stringWithFormat:@"  %@ - %@%@",
                           asset.vendor, asset.ipAddress, suffix];
                } else {
                    // Show: IP only (no duplicate)
                    line = [NSString stringWithFormat:@"  %@%@", asset.ipAddress, suffix];
                }
                NSMenuItem *assetItem = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
                assetItem.enabled = NO;
                [detailsSubmenu addItem:assetItem];
            }
        }
    }

    if (threatIntelEnabled && threatIntelStatusMessage.length > 0 &&
        (threatIntelResults == nil || threatIntelResults.count == 0)) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *threatTitle = [[NSMenuItem alloc] initWithTitle:@"THREAT INTELLIGENCE" action:nil keyEquivalent:@""];
        threatTitle.enabled = NO;
        [detailsSubmenu addItem:threatTitle];

        NSMenuItem *statusItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  %@", threatIntelStatusMessage]
                                                            action:nil
                                                     keyEquivalent:@""];
        statusItem.enabled = NO;
        [detailsSubmenu addItem:statusItem];
    } else if (threatIntelEnabled && threatIntelResults.count > 0) {
        // Build set of active destination IPs
        // Note: The old THREAT INTELLIGENCE display has been removed.
        // See the new "ACTIVE THREATS" section in the main Visualization menu
        // for the enhanced severity-based threat display.

        NSArray<NSDictionary *> *maliciousConnections = [self maliciousConnectionsFromStats:stats
                                                                        threatIntelResults:threatIntelResults];
        if (maliciousConnections.count > 0) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
            NSMenuItem *maliciousTitle = [[NSMenuItem alloc] initWithTitle:@"MALICIOUS CONNECTIONS"
                                                                    action:nil
                                                             keyEquivalent:@""];
            maliciousTitle.enabled = NO;
            [detailsSubmenu addItem:maliciousTitle];

            NSInteger limit = MIN(config.maxTopConnectionsToShow, maliciousConnections.count);
            for (NSInteger i = 0; i < limit; i++) {
                NSDictionary *entry = maliciousConnections[i];
                ConnectionTraffic *connection = entry[@"connection"];
                TIEnrichmentResponse *response = entry[@"response"];
                NSString *indicator = entry[@"indicator"] ?: @"";
                TIScoringResult *scoring = response.scoringResult;
                NSString *bytesStr = [SNBByteFormatter stringFromBytes:connection.bytes];
                NSString *providers = [self providerSummaryForResponse:response];
                NSString *processInfo = @"";
                if (connection.processName.length > 0 && connection.processPID > 0) {
                    processInfo = [NSString stringWithFormat:@" [%@:%d]", connection.processName, connection.processPID];
                }
                NSString *indicatorText = indicator.length > 0 ? [NSString stringWithFormat:@"indicator %@", indicator] : @"indicator unknown";
                NSString *displayStr = [NSString stringWithFormat:@"  %@:%ld -> %@:%ld - %@ - score %ld - %@%@",
                                        connection.sourceAddress,
                                        (long)connection.sourcePort,
                                        connection.destinationAddress,
                                        (long)connection.destinationPort,
                                        bytesStr,
                                        (long)scoring.finalScore,
                                        indicatorText,
                                        processInfo];
                NSMenuItem *maliciousItem = [[NSMenuItem alloc] initWithTitle:displayStr
                                                                      action:nil
                                                               keyEquivalent:@""];
                maliciousItem.enabled = NO;
                [detailsSubmenu addItem:maliciousItem];

                NSString *providerLine = [NSString stringWithFormat:@"    Providers: %@", providers];
                NSMenuItem *providersItem = [[NSMenuItem alloc] initWithTitle:providerLine
                                                                       action:nil
                                                                keyEquivalent:@""];
                providersItem.enabled = NO;
                [detailsSubmenu addItem:providersItem];
            }
            if (maliciousConnections.count > limit) {
                NSMenuItem *moreItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"  ... and %lu more",
                                                                         (unsigned long)(maliciousConnections.count - limit)]
                                                                 action:nil
                                                          keyEquivalent:@""];
                moreItem.enabled = NO;
                [detailsSubmenu addItem:moreItem];
            }
        }

        if (cacheStats) {
            [detailsSubmenu addItem:[NSMenuItem separatorItem]];
            NSString *sizeStr = [NSString stringWithFormat:@"%@", cacheStats[@"size"]];
            NSString *hitRateStr = [NSString stringWithFormat:@"%.1f%%", [cacheStats[@"hitRate"] doubleValue] * 100];
            NSString *statsStr = [NSString stringWithFormat:@"Cache: %@ entries - %@ hit rate", sizeStr, hitRateStr];

            NSMenuItem *statsItem = [[NSMenuItem alloc] initWithTitle:statsStr action:nil keyEquivalent:@""];
            statsItem.enabled = NO;
            [detailsSubmenu addItem:statsItem];
        }
    }
}

#pragma mark - Expandable Section Toggles

- (void)toggleShowCleanConnections {
    self.showCleanConnections = !self.showCleanConnections;
    SNBLogUIDebug("Toggled clean connections: %d", self.showCleanConnections);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleShowAllAssets {
    self.showAllAssets = !self.showAllAssets;
    SNBLogUIDebug("Toggled show all assets: %d", self.showAllAssets);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleShowProviderDetails {
    self.showProviderDetails = !self.showProviderDetails;
    SNBLogUIDebug("Toggled provider details: %d", self.showProviderDetails);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleShowLowSeverityThreats {
    self.showLowSeverityThreats = !self.showLowSeverityThreats;
    SNBLogUIDebug("Toggled low severity threats: %d", self.showLowSeverityThreats);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleShowHistoricalThreats {
    self.showHistoricalThreats = !self.showHistoricalThreats;
    SNBLogUIDebug("Toggled historical threats: %d", self.showHistoricalThreats);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

#pragma mark - Main Section Toggles

- (void)toggleSectionThreats {
    self.sectionThreatsExpanded = !self.sectionThreatsExpanded;
    SNBLogUIDebug("Toggled threats section: %d", self.sectionThreatsExpanded);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleSectionNetworkActivity {
    self.sectionNetworkActivityExpanded = !self.sectionNetworkActivityExpanded;
    SNBLogUIDebug("Toggled network activity section: %d", self.sectionNetworkActivityExpanded);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleSectionNetworkDevices {
    self.sectionNetworkDevicesExpanded = !self.sectionNetworkDevicesExpanded;
    SNBLogUIDebug("Toggled network devices section: %d", self.sectionNetworkDevicesExpanded);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleSectionTopHosts {
    self.sectionTopHostsExpanded = !self.sectionTopHostsExpanded;
    SNBLogUIDebug("Toggled top hosts section: %d", self.sectionTopHostsExpanded);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleSectionTopConnections {
    self.sectionTopConnectionsExpanded = !self.sectionTopConnectionsExpanded;
    SNBLogUIDebug("Toggled top connections section: %d", self.sectionTopConnectionsExpanded);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

- (void)toggleSectionNetworkAssets {
    self.sectionNetworkAssetsExpanded = !self.sectionNetworkAssetsExpanded;
    SNBLogUIDebug("Toggled network assets section: %d", self.sectionNetworkAssetsExpanded);
    if ([self.delegate respondsToSelector:@selector(menuBuilderNeedsVisualizationRefresh:)]) {
        [self.delegate menuBuilderNeedsVisualizationRefresh:self];
    }
}

@end
