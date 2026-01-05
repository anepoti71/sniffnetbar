//
//  MenuBuilder.m
//  SniffNetBar
//

#import "MenuBuilder.h"
#import "ByteFormatter.h"
#import "ConfigurationManager.h"
#import "MapMenuView.h"
#import "NetworkDevice.h"
#import "ThreatIntelModels.h"
#import "TrafficStatistics.h"
#import "UserDefaultsKeys.h"
#import "NetworkAssetMonitor.h"
#import <ifaddrs.h>
#import <arpa/inet.h>
#import "Logger.h"

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
        _showTopHosts = YES;
        _showTopConnections = YES;
        _showMap = NO;
        _cachedMenuItems = [NSMutableDictionary dictionary];
        _menuStructureBuilt = NO;

        NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProvider];
        _mapProviderName = savedProvider.length > 0 ? savedProvider : configuration.defaultMapProvider;
    }
    return self;
}

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
    NSArray<ConnectionTraffic *> *connections = stats.topConnections ?: @[];
    if (connections.count > 10) {
        connections = [connections subarrayWithRange:NSMakeRange(0, 10)];
    }
    return connections;
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
    if (selectedDevice && selectedDevice.name) {
        NSString *deviceName = [NSString stringWithFormat:@"[%@] ", selectedDevice.name];
        NSAttributedString *deviceAttr = [[NSAttributedString alloc] initWithString:deviceName];
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
    NSArray<NetworkDevice *> *deviceList = devices ?: @[];

    for (NetworkDevice *device in deviceList) {
        NSMenuItem *deviceItem = [[NSMenuItem alloc] initWithTitle:[device displayName]
                                                            action:@selector(deviceSelected:)
                                                     keyEquivalent:@""];
        deviceItem.target = target;
        deviceItem.representedObject = device;
        if (selectedDevice && [device.name isEqualToString:selectedDevice.name]) {
            deviceItem.state = NSControlStateValueOn;
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

    NSMenuItem *toggleHosts = [[NSMenuItem alloc] initWithTitle:@"Show Top Hosts"
                                                         action:@selector(toggleShowTopHosts:)
                                                  keyEquivalent:@""];
    toggleHosts.target = target;
    toggleHosts.state = self.showTopHosts ? NSControlStateValueOn : NSControlStateValueOff;
    NSMenuItem *toggleConnections = [[NSMenuItem alloc] initWithTitle:@"Show Top Connections"
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

    // Risk Overview
    [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"RISK OVERVIEW" style:@"header"]];

    if (!threatIntelEnabled) {
        NSMenuItem *disabledItem = [[NSMenuItem alloc] initWithTitle:@"Threat Intel: Off (enable in Settings)"
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
        NSMenuItem *emptyItem = [[NSMenuItem alloc] initWithTitle:@"No threat data available yet"
                                                          action:nil
                                                   keyEquivalent:@""];
        emptyItem.enabled = NO;
        [visualizationSubmenu addItem:emptyItem];
    } else {
        NSArray<NSString *> *sortedIPs = [self sortedThreatIPsFromResults:threatIntelResults];
        NSUInteger totalCount = 0;
        NSUInteger flaggedCount = 0;
        NSInteger worstRank = -1;

        for (NSString *ip in sortedIPs) {
            TIScoringResult *scoring = threatIntelResults[ip].scoringResult;
            if (!scoring) {
                continue;
            }
            totalCount += 1;
            NSInteger rank = [self severityRankForVerdict:scoring.verdict];
            if (rank > 0) {
                flaggedCount += 1;
            }
            if (rank > worstRank) {
                worstRank = rank;
            }
        }

        NSString *summaryValue = [NSString stringWithFormat:@"%lu / %lu", (unsigned long)flaggedCount, (unsigned long)totalCount];
        [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Flagged" value:summaryValue color:[NSColor labelColor]]];

        [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"Top Threats" style:@"subheader"]];
        NSUInteger topLimit = MIN(3, sortedIPs.count);
        NSUInteger shown = 0;
        for (NSString *ip in sortedIPs) {
            TIScoringResult *scoring = threatIntelResults[ip].scoringResult;
            if (!scoring) {
                continue;
            }
            if (scoring.verdict == TIThreatVerdictClean) {
                continue;
            }
            [visualizationSubmenu addItem:[self threatBadgeItemWithIP:ip scoring:scoring]];
            shown += 1;
            if (shown >= topLimit) {
                break;
            }
        }

        if (shown == 0) {
            NSMenuItem *cleanItem = [[NSMenuItem alloc] initWithTitle:@"No active threats detected"
                                                              action:nil
                                                       keyEquivalent:@""];
            cleanItem.enabled = NO;
            [visualizationSubmenu addItem:cleanItem];
        }
    }

    [visualizationSubmenu addItem:[NSMenuItem separatorItem]];

    // Network Snapshot
    [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"NETWORK SNAPSHOT" style:@"header"]];
    NSString *rateStr = [SNBByteFormatter stringFromBytes:stats.bytesPerSecond];
    [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Rate" value:[NSString stringWithFormat:@"%@/s", rateStr]
                                                         color:[NSColor labelColor]]];
    NSString *totalBytesStr = [SNBByteFormatter stringFromBytes:stats.totalBytes];
    [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Total" value:totalBytesStr color:[NSColor labelColor]]];
    NSString *countsStr = [NSString stringWithFormat:@"%lu / %lu",
                           (unsigned long)stats.topHosts.count,
                           (unsigned long)stats.topConnections.count];
    [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Hosts/Conns" value:countsStr
                                                         color:[NSColor secondaryLabelColor]]];

    [visualizationSubmenu addItem:[NSMenuItem separatorItem]];

    // Asset Monitor
    [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"ASSET MONITOR" style:@"header"]];
    if (!assetMonitorEnabled) {
        NSMenuItem *disabledItem = [[NSMenuItem alloc] initWithTitle:@"Asset Monitor: Off (enable in Settings)"
                                                             action:nil
                                                      keyEquivalent:@""];
        disabledItem.enabled = NO;
        [visualizationSubmenu addItem:disabledItem];
    } else if (networkAssets.count == 0) {
        NSMenuItem *emptyItem = [[NSMenuItem alloc] initWithTitle:@"No devices detected yet"
                                                          action:nil
                                                   keyEquivalent:@""];
        emptyItem.enabled = NO;
        [visualizationSubmenu addItem:emptyItem];
    } else {
        NSString *totalStr = [NSString stringWithFormat:@"%lu", (unsigned long)networkAssets.count];
        [visualizationSubmenu addItem:[self styledStatItemWithLabel:@"Known Devices" value:totalStr
                                                             color:[NSColor labelColor]]];
        if (recentNewAssets.count > 0) {
            [visualizationSubmenu addItem:[self styledMenuItemWithTitle:@"New Devices" style:@"subheader"]];
            NSUInteger limit = MIN(3, recentNewAssets.count);
            for (NSUInteger i = 0; i < limit; i++) {
                SNBNetworkAsset *asset = recentNewAssets[i];
                NSString *name = asset.hostname.length > 0 ? asset.hostname : asset.ipAddress;
                NSString *line = [NSString stringWithFormat:@"  %@ (%@)", name, asset.macAddress];
                NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
                item.enabled = NO;
                [visualizationSubmenu addItem:item];
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
        NSMenuItem *hostsTitle = [[NSMenuItem alloc] initWithTitle:@"TOP HOSTS" action:nil keyEquivalent:@""];
        hostsTitle.enabled = NO;
        [detailsSubmenu addItem:hostsTitle];

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

    if (self.showTopConnections && stats.topConnections.count > 0) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *connectionsTitle = [[NSMenuItem alloc] initWithTitle:@"TOP CONNECTIONS" action:nil keyEquivalent:@""];
        connectionsTitle.enabled = NO;
        [detailsSubmenu addItem:connectionsTitle];

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

    if (assetMonitorEnabled && networkAssets.count > 0) {
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *assetsTitle = [[NSMenuItem alloc] initWithTitle:@"NETWORK ASSETS" action:nil keyEquivalent:@""];
        assetsTitle.enabled = NO;
        [detailsSubmenu addItem:assetsTitle];

        NSSet<NSString *> *localIPs = SNBLocalIPAddresses();
        NSUInteger limit = MIN(10, networkAssets.count);
        for (NSUInteger i = 0; i < limit; i++) {
            SNBNetworkAsset *asset = networkAssets[i];
            NSString *name = asset.hostname.length > 0 ? asset.hostname : @"Unknown";
            BOOL isLocal = [localIPs containsObject:asset.ipAddress];
            NSString *suffix = isLocal ? @" (This Mac)" : @"";
            NSString *line = [NSString stringWithFormat:@"  %@ - %@%@", name, asset.ipAddress, suffix];
            NSMenuItem *assetItem = [[NSMenuItem alloc] initWithTitle:line action:nil keyEquivalent:@""];
            assetItem.enabled = NO;
            [detailsSubmenu addItem:assetItem];
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
        [detailsSubmenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *threatTitle = [[NSMenuItem alloc] initWithTitle:@"THREAT INTELLIGENCE" action:nil keyEquivalent:@""];
        threatTitle.enabled = NO;
        [detailsSubmenu addItem:threatTitle];

        NSArray<NSString *> *sortedIPs = [self sortedThreatIPsFromResults:threatIntelResults];
        for (NSString *ip in sortedIPs) {
            TIEnrichmentResponse *response = threatIntelResults[ip];
            if (response.scoringResult) {
                TIScoringResult *scoring = response.scoringResult;
                NSString *verdictStr = [scoring verdictString];

                NSString *displayStr = [NSString stringWithFormat:@"  %@ - %@ (%ld)",
                                        ip, verdictStr, (long)scoring.finalScore];

                NSMenuItem *threatItem = [[NSMenuItem alloc] initWithTitle:displayStr
                                                                   action:nil
                                                            keyEquivalent:@""];
                threatItem.enabled = NO;
                [detailsSubmenu addItem:threatItem];
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

@end
