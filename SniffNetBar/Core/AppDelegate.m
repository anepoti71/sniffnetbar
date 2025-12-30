//
//  AppDelegate.m
//  SniffNetBar
//
//  Created from Rust networking code refactoring
//

#import "AppDelegate.h"
#import "ConfigurationManager.h"
#import "PacketCaptureManager.h"
#import "TrafficStatistics.h"
#import "NetworkDevice.h"
#import "MapMenuView.h"
#import "ThreatIntelFacade.h"
#import "ThreatIntelProvider.h"
#import "ThreatIntelModels.h"

static NSString *const kSelectedDeviceKey = @"SelectedNetworkDevice";
static NSString *const kMapProviderKey = @"MapProvider";
static NSString *const kThreatIntelEnabledKey = @"ThreatIntelEnabled";

@interface AppDelegate ()
@property (nonatomic, strong) PacketCaptureManager *packetManager;
@property (nonatomic, strong) TrafficStatistics *statistics;
@property (nonatomic, strong) NSTimer *updateTimer;
@property (nonatomic, strong) NetworkDevice *selectedDevice;
@property (nonatomic, strong) NSArray<NetworkDevice *> *availableDevices;
@property (nonatomic, assign) BOOL showTopHosts;
@property (nonatomic, assign) BOOL showTopConnections;
@property (nonatomic, assign) BOOL showMap;
@property (nonatomic, copy) NSString *mapProviderName;
@property (nonatomic, strong) MapMenuView *mapMenuView;
@property (nonatomic, strong) NSMenuItem *mapMenuItem;
@property (nonatomic, assign) BOOL menuIsOpen;
@property (nonatomic, strong) NSTimer *deviceRefreshTimer;
@property (nonatomic, assign) NSUInteger reconnectAttempts;
@property (nonatomic, strong) NSMutableDictionary<NSString *, TIEnrichmentResponse *> *threatIntelResults;
@end

@implementation AppDelegate

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

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    // Create status item
    NSStatusBar *statusBar = [NSStatusBar systemStatusBar];
    self.statusItem = [statusBar statusItemWithLength:NSVariableStatusItemLength];
    NSImage *statusImage = [NSImage imageNamed:@"icon_macos"];
    if (!statusImage) {
        NSString *iconPath = [[NSBundle mainBundle] pathForResource:@"icon_macos" ofType:@"png"];
        statusImage = iconPath ? [[NSImage alloc] initWithContentsOfFile:iconPath] : nil;
    }
    if (statusImage) {
        CGFloat targetSize = statusBar.thickness - 2.0;
        statusImage.size = NSMakeSize(targetSize, targetSize);
        statusImage.template = NO;
        self.statusItem.button.image = statusImage;
        self.statusItem.button.imageScaling = NSImageScaleProportionallyDown;
        self.statusItem.button.title = @"";
    } else {
        SNBLog(@"Status icon not found in bundle resources.");
        self.statusItem.button.title = @"📊";
    }
    self.statusItem.button.target = self;
    self.statusItem.button.action = @selector(statusItemClicked:);
    [self.statusItem.button sendActionOn:NSEventMaskLeftMouseUp | NSEventMaskRightMouseUp];
    
    // Create menu
    self.statusMenu = [[NSMenu alloc] init];
    self.statusMenu.delegate = self;
    
    // Initialize packet capture manager
    self.packetManager = [[PacketCaptureManager alloc] init];
    self.statistics = [[TrafficStatistics alloc] init];
    self.showTopHosts = YES;
    self.showTopConnections = YES;
    self.showMap = NO;
    ConfigurationManager *config = [ConfigurationManager sharedManager];
    NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderKey];
    self.mapProviderName = savedProvider.length > 0 ? savedProvider : config.defaultMapProvider;

    // Initialize threat intelligence
    self.threatIntel = [ThreatIntelFacade sharedInstance];
    self.threatIntelResults = [NSMutableDictionary dictionary];

    // Restore threat intel enabled state
    BOOL threatIntelEnabled = [[NSUserDefaults standardUserDefaults] boolForKey:kThreatIntelEnabledKey];
    self.threatIntel.enabled = threatIntelEnabled;

    // Configure with a simple test provider
    TISimpleProvider *testProvider = [[TISimpleProvider alloc] initWithName:@"test"];
    [testProvider configureWithAPIKey:nil timeout:2.0 maxRequestsPerMin:60 completion:nil];
    // Add some test malicious IPs for demonstration
    [testProvider addMaliciousIndicator:@"1.2.3.4" type:TIIndicatorTypeIPv4 confidence:85 categories:@[@"malware", @"botnet"]];
    [testProvider addMaliciousIndicator:@"8.8.4.4" type:TIIndicatorTypeIPv4 confidence:60 categories:@[@"suspicious"]];
    [self.threatIntel addProvider:testProvider];

    SNBLog(@"Threat Intelligence initialized (enabled: %@)", threatIntelEnabled ? @"YES" : @"NO");

    // Set up callback for packet updates
    __weak typeof(self) weakSelf = self;
    self.packetManager.onPacketReceived = ^(PacketInfo *packetInfo) {
        [weakSelf.statistics processPacket:packetInfo];
    };

    // Load available devices and restore selected device
    [self loadAvailableDevices];
    [self restoreSelectedDevice];

    // Update menu after devices are loaded
    [self updateMenu];

    // Start packet capture
    [self startCaptureWithCurrentDevice];

    // Set up timer to update UI (use block-based timer to avoid retain cycle)
    // Note: weakSelf already declared above for packet callback
    self.updateTimer = [NSTimer timerWithTimeInterval:config.menuUpdateInterval
                                              repeats:YES
                                                block:^(NSTimer *timer) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf updateMenuIfNeeded];
        }
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.updateTimer forMode:NSRunLoopCommonModes];

    // Set up timer to periodically refresh device list
    self.deviceRefreshTimer = [NSTimer timerWithTimeInterval:config.deviceListRefreshInterval
                                                     repeats:YES
                                                       block:^(NSTimer *timer) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf refreshDeviceList];
        }
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.deviceRefreshTimer forMode:NSRunLoopCommonModes];
}

- (void)statusItemClicked:(id)sender {
    NSEvent *event = [NSApp currentEvent];
    if (event.type == NSEventTypeRightMouseUp) {
        [self.statusItem popUpStatusItemMenu:self.statusMenu];
    } else {
        [self updateMenu];
        [self.statusItem popUpStatusItemMenu:self.statusMenu];
    }
}

- (void)loadAvailableDevices {
    self.availableDevices = [NetworkDevice listAllDevices];
    if (self.availableDevices.count == 0) {
        SNBLog(@"Warning: No network devices found");
    }
}

- (void)restoreSelectedDevice {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *savedDeviceName = [defaults stringForKey:kSelectedDeviceKey];
    
    if (savedDeviceName) {
        for (NetworkDevice *device in self.availableDevices) {
            if ([device.name isEqualToString:savedDeviceName]) {
                self.selectedDevice = device;
                return;
            }
        }
    }
    
    // Use default device if saved device not found or not set
    self.selectedDevice = [NetworkDevice defaultDevice];
}

- (void)saveSelectedDevice {
    if (self.selectedDevice) {
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:self.selectedDevice.name forKey:kSelectedDeviceKey];
        [defaults synchronize];
    }
}

- (void)startCaptureWithCurrentDevice {
    if (!self.selectedDevice) {
        self.selectedDevice = [NetworkDevice defaultDevice];
    }

    // Double-check we have a valid device
    if (!self.selectedDevice || [self.selectedDevice.name isEqualToString:@"(no device)"]) {
        SNBLog(@"Error: No valid network device available for capture");
        self.statusItem.button.title = @"❌ No Device";
        return;
    }

    NSError *error;
    if (![self.packetManager startCaptureWithDeviceName:self.selectedDevice.name error:&error]) {
        SNBLog(@"Failed to start packet capture: %@", error.localizedDescription);
        self.statusItem.button.title = @"❌";

        // Attempt automatic reconnection
        ConfigurationManager *config = [ConfigurationManager sharedManager];
        if (self.reconnectAttempts < config.maxReconnectAttempts) {
            self.reconnectAttempts++;
            SNBLog(@"Scheduling reconnection attempt %lu of %lu in %.0f seconds",
                  (unsigned long)self.reconnectAttempts,
                  (unsigned long)config.maxReconnectAttempts,
                  config.reconnectDelay);
            __weak typeof(self) weakSelf = self;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(config.reconnectDelay * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [weakSelf attemptReconnection];
            });
        } else {
            SNBLog(@"Maximum reconnection attempts reached. Manual intervention required.");
        }
    } else {
        // Successfully started capture, reset reconnection counter
        self.reconnectAttempts = 0;
    }
}

- (void)attemptReconnection {
    SNBLog(@"Attempting to reconnect to device: %@", self.selectedDevice.name);

    // Refresh device list first in case device came back
    [self refreshDeviceList];

    // Try to reconnect
    [self startCaptureWithCurrentDevice];
}

- (void)refreshDeviceList {
    NSArray<NetworkDevice *> *previousDevices = self.availableDevices;
    [self loadAvailableDevices];

    // Log changes if any
    if (previousDevices.count != self.availableDevices.count) {
        SNBLog(@"Device list changed: %lu -> %lu devices",
              (unsigned long)previousDevices.count,
              (unsigned long)self.availableDevices.count);
    }

    // Check if currently selected device is still available
    BOOL deviceStillAvailable = NO;
    for (NetworkDevice *device in self.availableDevices) {
        if ([device.name isEqualToString:self.selectedDevice.name]) {
            deviceStillAvailable = YES;
            break;
        }
    }

    if (!deviceStillAvailable && self.selectedDevice) {
        SNBLog(@"Currently selected device '%@' is no longer available", self.selectedDevice.name);
    }
}

- (void)selectDevice:(NetworkDevice *)device {
    if (!device || [device.name isEqualToString:self.selectedDevice.name]) {
        return;
    }
    
    self.selectedDevice = device;
    [self saveSelectedDevice];
    
    // Restart capture with new device
    [self startCaptureWithCurrentDevice];
    
    // Reset statistics for new device
    [self.statistics reset];
}

- (void)updateMenuIfNeeded {
    // Always update status bar
    TrafficStats *stats = [self.statistics getCurrentStats];
    NSString *deviceDisplay = (self.selectedDevice && self.selectedDevice.name) ? [NSString stringWithFormat:@"[%@] ", self.selectedDevice.name] : @"";

    // Update status bar title (same regardless of icon presence)
    NSString *rateDisplay = [NSString stringWithFormat:@"%@%@/s", deviceDisplay, [self formatBytes:stats.bytesPerSecond]];
    self.statusItem.button.title = rateDisplay;

    // If menu is open, update it with live data
    if (self.menuIsOpen) {
        [self updateMenu];
    }
}

- (void)updateMenu {
    [self.statusMenu removeAllItems];
    
    // Display statistics
    TrafficStats *stats = [self.statistics getCurrentStats];
    ConfigurationManager *config = [ConfigurationManager sharedManager];
    
    NSMenuItem *titleItem = [self fixedWidthTitleItemWithTitle:@"Network Traffic" width:config.menuFixedWidth];
    [self.statusMenu addItem:titleItem];
    
    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    
    // Device selection submenu
    NSMenuItem *deviceMenu = [[NSMenuItem alloc] initWithTitle:@"Network Interface" action:nil keyEquivalent:@""];
    NSMenu *deviceSubmenu = [[NSMenu alloc] init];
    
    if (!self.availableDevices) {
        self.availableDevices = @[];
    }
    
    for (NetworkDevice *device in self.availableDevices) {
        NSMenuItem *deviceItem = [[NSMenuItem alloc] initWithTitle:[device displayName]
                                                            action:@selector(deviceSelected:)
                                                     keyEquivalent:@""];
        deviceItem.target = self;
        deviceItem.representedObject = device;
        if (self.selectedDevice && [device.name isEqualToString:self.selectedDevice.name]) {
            deviceItem.state = NSControlStateValueOn;
        }
        [deviceSubmenu addItem:deviceItem];
    }
    
    deviceMenu.submenu = deviceSubmenu;
    [self.statusMenu addItem:deviceMenu];
    
    [self.statusMenu addItem:[NSMenuItem separatorItem]];

    // View options
    NSMenuItem *viewItem = [[NSMenuItem alloc] initWithTitle:@"View" action:nil keyEquivalent:@""];
    viewItem.enabled = NO;
    [self.statusMenu addItem:viewItem];
    
    NSMenuItem *toggleHosts = [[NSMenuItem alloc] initWithTitle:@"Show Top Hosts"
                                                         action:@selector(toggleShowTopHosts:)
                                                  keyEquivalent:@""];
    toggleHosts.target = self;
    toggleHosts.state = self.showTopHosts ? NSControlStateValueOn : NSControlStateValueOff;
    [self.statusMenu addItem:toggleHosts];
    
    NSMenuItem *toggleConnections = [[NSMenuItem alloc] initWithTitle:@"Show Top Connections"
                                                               action:@selector(toggleShowTopConnections:)
                                                        keyEquivalent:@""];
    toggleConnections.target = self;
    toggleConnections.state = self.showTopConnections ? NSControlStateValueOn : NSControlStateValueOff;
    [self.statusMenu addItem:toggleConnections];
    
    [self.statusMenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *toggleMap = [[NSMenuItem alloc] initWithTitle:@"Show Map Visualization"
                                                       action:@selector(toggleShowMap:)
                                                keyEquivalent:@""];
    toggleMap.target = self;
    toggleMap.state = self.showMap ? NSControlStateValueOn : NSControlStateValueOff;
    [self.statusMenu addItem:toggleMap];

    // Threat Intelligence toggle
    NSMenuItem *toggleThreatIntel = [[NSMenuItem alloc] initWithTitle:@"Enable Threat Intelligence"
                                                               action:@selector(toggleThreatIntel:)
                                                        keyEquivalent:@""];
    toggleThreatIntel.target = self;
    toggleThreatIntel.state = self.threatIntel.isEnabled ? NSControlStateValueOn : NSControlStateValueOff;
    [self.statusMenu addItem:toggleThreatIntel];

    NSMenuItem *providerItem = [[NSMenuItem alloc] initWithTitle:@"Map Provider" action:nil keyEquivalent:@""];
    NSMenu *providerSubmenu = [[NSMenu alloc] init];
    NSArray<NSString *> *providers = @[@"ip-api.com", @"ipinfo.io", @"Custom (UserDefaults)"];
    for (NSString *provider in providers) {
        NSMenuItem *providerMenuItem = [[NSMenuItem alloc] initWithTitle:provider
                                                                  action:@selector(selectMapProvider:)
                                                           keyEquivalent:@""];
        providerMenuItem.target = self;
        providerMenuItem.representedObject = provider;
        NSString *providerValue = [provider isEqualToString:@"Custom (UserDefaults)"] ? @"custom" : provider;
        if ([self.mapProviderName isEqualToString:providerValue]) {
            providerMenuItem.state = NSControlStateValueOn;
        }
        [providerSubmenu addItem:providerMenuItem];
    }
    providerItem.submenu = providerSubmenu;
    [self.statusMenu addItem:providerItem];
    
    [self.statusMenu addItem:[NSMenuItem separatorItem]];

    if (self.showMap && self.menuIsOpen) {
        NSMenuItem *mapItem = [self mapMenuItemIfNeeded];
        if (mapItem) {
            [self.statusMenu addItem:mapItem];
            [self.statusMenu addItem:[NSMenuItem separatorItem]];
        }
    } else {
        [self tearDownMapMenuItem];
    }
    
    // Total bytes
    NSString *totalBytesStr = [self formatBytes:stats.totalBytes];
    NSMenuItem *bytesItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Total: %@", totalBytesStr]
                                                       action:nil
                                                keyEquivalent:@""];
    bytesItem.enabled = NO;
    [self.statusMenu addItem:bytesItem];
    
    // Incoming/Outgoing
    NSString *incomingStr = [self formatBytes:stats.incomingBytes];
    NSString *outgoingStr = [self formatBytes:stats.outgoingBytes];
    NSMenuItem *incomingItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"↓ In: %@", incomingStr]
                                                          action:nil
                                                   keyEquivalent:@""];
    incomingItem.enabled = NO;
    [self.statusMenu addItem:incomingItem];
    
    NSMenuItem *outgoingItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"↑ Out: %@", outgoingStr]
                                                          action:nil
                                                   keyEquivalent:@""];
    outgoingItem.enabled = NO;
    [self.statusMenu addItem:outgoingItem];
    
    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    
    // Packets count
    NSMenuItem *packetsItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Packets: %llu", stats.totalPackets]
                                                         action:nil
                                                  keyEquivalent:@""];
    packetsItem.enabled = NO;
    [self.statusMenu addItem:packetsItem];
    
    // Top hosts
    if (self.showTopHosts && stats.topHosts.count > 0) {
        [self.statusMenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *hostsTitle = [[NSMenuItem alloc] initWithTitle:@"Top Hosts" action:nil keyEquivalent:@""];
        hostsTitle.enabled = NO;
        [self.statusMenu addItem:hostsTitle];

        NSInteger count = MIN(config.maxTopHostsToShow, stats.topHosts.count);
        for (NSInteger i = 0; i < count; i++) {
            HostTraffic *host = stats.topHosts[i];
            NSString *hostName = host.hostname.length > 0 ? host.hostname : @"";
            NSString *hostDisplay = hostName.length > 0 ? [NSString stringWithFormat:@"%@ (%@)", hostName, host.address] : host.address;
            NSString *hostItemStr = [NSString stringWithFormat:@"  %@ - %@", hostDisplay, [self formatBytes:host.bytes]];
            NSMenuItem *hostItem = [[NSMenuItem alloc] initWithTitle:hostItemStr action:nil keyEquivalent:@""];
            hostItem.enabled = NO;
            [self.statusMenu addItem:hostItem];
        }
    }
    
    // Top connections
    if (self.showTopConnections && stats.topConnections.count > 0) {
        [self.statusMenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *connectionsTitle = [[NSMenuItem alloc] initWithTitle:@"Top Connections" action:nil keyEquivalent:@""];
        connectionsTitle.enabled = NO;
        [self.statusMenu addItem:connectionsTitle];

        NSInteger count = MIN(config.maxTopConnectionsToShow, stats.topConnections.count);
        for (NSInteger i = 0; i < count; i++) {
            ConnectionTraffic *connection = stats.topConnections[i];
            NSString *connectionItemStr = [NSString stringWithFormat:@"  %@ - %@  %@",
                                           connection.sourceAddress,
                                           connection.destinationAddress,
                                           [self formatBytes:connection.bytes]];
            NSMenuItem *connectionItem = [[NSMenuItem alloc] initWithTitle:connectionItemStr action:nil keyEquivalent:@""];
            connectionItem.enabled = NO;
            [self.statusMenu addItem:connectionItem];

            // Add threat intel result if enabled and available
            if (self.threatIntel.isEnabled) {
                [self enrichAndDisplayThreatIntelForIP:connection.destinationAddress];
            }
        }
    }

    // Threat Intelligence Results
    if (self.threatIntel.isEnabled && self.threatIntelResults.count > 0) {
        [self.statusMenu addItem:[NSMenuItem separatorItem]];
        NSMenuItem *threatTitle = [[NSMenuItem alloc] initWithTitle:@"Threat Intelligence" action:nil keyEquivalent:@""];
        threatTitle.enabled = NO;
        [self.statusMenu addItem:threatTitle];

        // Show cached threat intel results
        for (NSString *ip in [self.threatIntelResults allKeys]) {
            TIEnrichmentResponse *response = self.threatIntelResults[ip];
            if (response.scoringResult) {
                TIScoringResult *scoring = response.scoringResult;
                NSString *verdictStr = [scoring verdictString];
                NSColor *color = [scoring verdictColor];

                // Create attributed string for colored verdict
                NSString *displayStr = [NSString stringWithFormat:@"  %@: %@ (Score: %ld)",
                                       ip, verdictStr, (long)scoring.finalScore];

                NSMenuItem *threatItem = [[NSMenuItem alloc] initWithTitle:displayStr
                                                                   action:nil
                                                            keyEquivalent:@""];
                threatItem.enabled = NO;

                // Color the text based on verdict
                NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:displayStr];
                [attrString addAttribute:NSForegroundColorAttributeName
                                   value:color
                                   range:NSMakeRange(0, displayStr.length)];
                threatItem.attributedTitle = attrString;

                [self.statusMenu addItem:threatItem];
            }
        }

        // Show cache stats
        NSDictionary *cacheStats = [self.threatIntel cacheStats];
        NSString *statsStr = [NSString stringWithFormat:@"  Cache: %@ entries (%.1f%% hit rate)",
                             cacheStats[@"size"], [cacheStats[@"hitRate"] doubleValue] * 100];
        NSMenuItem *statsItem = [[NSMenuItem alloc] initWithTitle:statsStr action:nil keyEquivalent:@""];
        statsItem.enabled = NO;
        [self.statusMenu addItem:statsItem];
    }

    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    
    // Quit item
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"];
    [self.statusMenu addItem:quitItem];
    
    // Update status bar title
    NSString *deviceDisplay = (self.selectedDevice && self.selectedDevice.name) ? [NSString stringWithFormat:@"[%@] ", self.selectedDevice.name] : @"";
    self.statusItem.button.title = [NSString stringWithFormat:@"%@%@/s", deviceDisplay, [self formatBytes:stats.bytesPerSecond]];
    
    [self truncateMenuItemsInMenu:self.statusMenu maxWidth:config.menuFixedWidth];

    if (self.showMap && self.menuIsOpen && self.mapMenuView) {
        [self.mapMenuView updateWithConnections:[self connectionsForMapFromStats:stats]];
    }
}

- (NSString *)formatBytes:(uint64_t)bytes {
    if (bytes < 1024) {
        return [NSString stringWithFormat:@"%llu B", bytes];
    } else if (bytes < 1024 * 1024) {
        return [NSString stringWithFormat:@"%.2f KB", bytes / 1024.0];
    } else if (bytes < 1024 * 1024 * 1024) {
        return [NSString stringWithFormat:@"%.2f MB", bytes / (1024.0 * 1024.0)];
    } else {
        return [NSString stringWithFormat:@"%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0)];
    }
}

- (void)deviceSelected:(NSMenuItem *)sender {
    NetworkDevice *device = sender.representedObject;
    if (device) {
        [self selectDevice:device];
    }
}

- (void)toggleShowTopHosts:(NSMenuItem *)sender {
    self.showTopHosts = !self.showTopHosts;
    [self updateMenu];
}

- (void)toggleShowTopConnections:(NSMenuItem *)sender {
    self.showTopConnections = !self.showTopConnections;
    [self updateMenu];
}

- (void)toggleShowMap:(NSMenuItem *)sender {
    self.showMap = !self.showMap;
    SNBLog(@"Map visualization toggled: %@", self.showMap ? @"ON" : @"OFF");
    if (!self.showMap) {
        [self tearDownMapMenuItem];
    }
    [self updateMenu];
}

- (void)selectMapProvider:(NSMenuItem *)sender {
    NSString *provider = sender.representedObject;
    if (provider.length == 0) {
        return;
    }
    NSString *providerValue = [provider isEqualToString:@"Custom (UserDefaults)"] ? @"custom" : provider;
    self.mapProviderName = providerValue;
    [[NSUserDefaults standardUserDefaults] setObject:self.mapProviderName forKey:kMapProviderKey];
    SNBLog(@"Map provider selected: %@", self.mapProviderName);
    if (self.mapMenuView) {
        self.mapMenuView.providerName = self.mapProviderName;
        if (self.showMap) {
            [self.mapMenuView updateWithConnections:[self connectionsForMapFromStats:[self.statistics getCurrentStats]]];
        }
    }
    [self updateMenu];
}

- (void)toggleThreatIntel:(NSMenuItem *)sender {
    self.threatIntel.enabled = !self.threatIntel.isEnabled;
    [[NSUserDefaults standardUserDefaults] setBool:self.threatIntel.isEnabled forKey:kThreatIntelEnabledKey];
    [[NSUserDefaults standardUserDefaults] synchronize];

    SNBLog(@"Threat Intelligence %@", self.threatIntel.isEnabled ? @"ENABLED" : @"DISABLED");

    if (!self.threatIntel.isEnabled) {
        // Clear results when disabled
        [self.threatIntelResults removeAllObjects];
    }

    [self updateMenu];
}

- (void)enrichAndDisplayThreatIntelForIP:(NSString *)ipAddress {
    // Check if we already have a result
    if (self.threatIntelResults[ipAddress]) {
        return; // Already have it
    }

    // Enrich asynchronously
    [self.threatIntel enrichIP:ipAddress completion:^(TIEnrichmentResponse *response, NSError *error) {
        if (response && response.scoringResult) {
            // Store result
            self.threatIntelResults[ipAddress] = response;

            // Log result
            TIScoringResult *scoring = response.scoringResult;
            SNBLog(@"Threat Intel: %@ -> %@ (score: %ld, confidence: %.2f)",
                   ipAddress, [scoring verdictString], (long)scoring.finalScore, scoring.confidence);

            // Update menu on main thread
            dispatch_async(dispatch_get_main_queue(), ^{
                [self updateMenu];
            });
        } else if (error) {
            SNBLog(@"Threat Intel error for %@: %@", ipAddress, error.localizedDescription);
        }
    }];
}

- (void)menuWillOpen:(NSMenu *)menu {
    if (menu != self.statusMenu) {
        return;
    }
    self.menuIsOpen = YES;
    SNBLog(@"Status menu opened");
    [self updateMenu];
    if (self.showMap && self.mapMenuView) {
        [self.mapMenuView updateWithConnections:[self connectionsForMapFromStats:[self.statistics getCurrentStats]]];
    }
}

- (void)menuDidClose:(NSMenu *)menu {
    if (menu != self.statusMenu) {
        return;
    }
    self.menuIsOpen = NO;
    SNBLog(@"Status menu closed");
    [self tearDownMapMenuItem];
}

- (NSArray<ConnectionTraffic *> *)connectionsForMapFromStats:(TrafficStats *)stats {
    NSArray<ConnectionTraffic *> *connections = stats.topConnections ?: @[];
    if (connections.count > 10) {
        connections = [connections subarrayWithRange:NSMakeRange(0, 10)];
    }
    return connections;
}

- (NSMenuItem *)mapMenuItemIfNeeded {
    if (!self.menuIsOpen) {
        return nil;
    }
    if (!self.mapMenuItem) {
        ConfigurationManager *config = [ConfigurationManager sharedManager];
        self.mapMenuView = [[MapMenuView alloc] initWithFrame:NSMakeRect(0, 0, config.menuFixedWidth, config.mapMenuViewHeight)];
        self.mapMenuView.providerName = self.mapProviderName;

        // Use Auto Layout to enforce fixed size
        self.mapMenuView.translatesAutoresizingMaskIntoConstraints = NO;

        self.mapMenuItem = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
        self.mapMenuItem.view = self.mapMenuView;

        // Add width and height constraints to the view
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

        SNBLog(@"Map menu view created with constraints: width=%.0f, height=%.0f", config.menuFixedWidth, config.mapMenuViewHeight);
    }
    return self.mapMenuItem;
}

- (void)tearDownMapMenuItem {
    if (self.mapMenuItem) {
        self.mapMenuItem.view = nil;
        self.mapMenuItem = nil;
        self.mapMenuView = nil;
        SNBLog(@"Map menu view released");
    }
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self.updateTimer invalidate];
    [self.deviceRefreshTimer invalidate];
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(attemptReconnection) object:nil];
    [self.packetManager stopCapture];
}

@end
