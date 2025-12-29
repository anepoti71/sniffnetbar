//
//  AppDelegate.m
//  SniffNetBar
//
//  Created from Rust networking code refactoring
//

#import "AppDelegate.h"
#import "PacketCaptureManager.h"
#import "TrafficStatistics.h"
#import "NetworkDevice.h"
#import "MapWindowController.h"

static NSString *const kSelectedDeviceKey = @"SelectedNetworkDevice";
static NSString *const kMapProviderKey = @"MapProvider";

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
@property (nonatomic, strong) MapWindowController *mapWindowController;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    // Create status item
    NSStatusBar *statusBar = [NSStatusBar systemStatusBar];
    self.statusItem = [statusBar statusItemWithLength:NSVariableStatusItemLength];
    self.statusItem.button.title = @"📊";
    self.statusItem.button.target = self;
    self.statusItem.button.action = @selector(statusItemClicked:);
    [self.statusItem.button sendActionOn:NSEventMaskLeftMouseUp | NSEventMaskRightMouseUp];
    
    // Create menu
    self.statusMenu = [[NSMenu alloc] init];
    
    // Initialize packet capture manager
    self.packetManager = [[PacketCaptureManager alloc] init];
    self.statistics = [[TrafficStatistics alloc] init];
    self.showTopHosts = YES;
    self.showTopConnections = YES;
    self.showMap = NO;
    NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderKey];
    self.mapProviderName = savedProvider.length > 0 ? savedProvider : @"ip-api.com";
    
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
    
    // Set up timer to update UI every second
    self.updateTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                         target:self
                                                       selector:@selector(updateMenu)
                                                       userInfo:nil
                                                        repeats:YES];
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
        NSLog(@"Warning: No network devices found");
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
    
    NSError *error;
    if (![self.packetManager startCaptureWithDeviceName:self.selectedDevice.name error:&error]) {
        NSLog(@"Failed to start packet capture: %@", error.localizedDescription);
        self.statusItem.button.title = @"❌";
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

- (void)updateMenu {
    [self.statusMenu removeAllItems];
    
    // Display statistics
    TrafficStats *stats = [self.statistics getCurrentStats];
    
    NSMenuItem *titleItem = [[NSMenuItem alloc] initWithTitle:@"Network Traffic" action:nil keyEquivalent:@""];
    titleItem.enabled = NO;
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
        
        NSInteger count = MIN(5, stats.topHosts.count);
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
        
        NSInteger count = MIN(10, stats.topConnections.count);
        for (NSInteger i = 0; i < count; i++) {
            ConnectionTraffic *connection = stats.topConnections[i];
            NSString *connectionItemStr = [NSString stringWithFormat:@"  %@ - %@  %@",
                                           connection.sourceAddress,
                                           connection.destinationAddress,
                                           [self formatBytes:connection.bytes]];
            NSMenuItem *connectionItem = [[NSMenuItem alloc] initWithTitle:connectionItemStr action:nil keyEquivalent:@""];
            connectionItem.enabled = NO;
            [self.statusMenu addItem:connectionItem];
        }
    }
    
    [self.statusMenu addItem:[NSMenuItem separatorItem]];
    
    // Quit item
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"];
    [self.statusMenu addItem:quitItem];
    
    // Update status bar title
    NSString *deviceDisplay = (self.selectedDevice && self.selectedDevice.name) ? [NSString stringWithFormat:@"[%@] ", self.selectedDevice.name] : @"";
    self.statusItem.button.title = [NSString stringWithFormat:@"📊 %@%@/s", deviceDisplay, [self formatBytes:stats.bytesPerSecond]];
    
    if (self.showMap && self.mapWindowController) {
        [self.mapWindowController updateWithConnections:[self connectionsForMapFromStats:stats]];
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
    if (self.showMap) {
        if (!self.mapWindowController) {
            self.mapWindowController = [[MapWindowController alloc] init];
        }
        self.mapWindowController.providerName = self.mapProviderName;
        [self.mapWindowController showWindow:self];
        [self.mapWindowController updateWithConnections:[self connectionsForMapFromStats:[self.statistics getCurrentStats]]];
    } else if (self.mapWindowController) {
        [self.mapWindowController close];
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
    if (self.mapWindowController) {
        self.mapWindowController.providerName = self.mapProviderName;
        if (self.showMap) {
            [self.mapWindowController updateWithConnections:[self connectionsForMapFromStats:[self.statistics getCurrentStats]]];
        }
    }
    [self updateMenu];
}

- (NSArray<ConnectionTraffic *> *)connectionsForMapFromStats:(TrafficStats *)stats {
    NSArray<ConnectionTraffic *> *connections = stats.topConnections ?: @[];
    if (connections.count > 10) {
        connections = [connections subarrayWithRange:NSMakeRange(0, 10)];
    }
    return connections;
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self.updateTimer invalidate];
    [self.packetManager stopCapture];
    if (self.mapWindowController) {
        [self.mapWindowController close];
    }
}

@end
