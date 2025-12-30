//
//  AppDelegate.m
//  SniffNetBar
//
//  Created from Rust networking code refactoring
//

#import "AppDelegate.h"
#import "ConfigurationManager.h"
#import "DeviceManager.h"
#import "MenuBuilder.h"
#import "NetworkDevice.h"
#import "PacketCaptureManager.h"
#import "ThreatIntelCoordinator.h"
#import "TrafficStatistics.h"

@interface AppDelegate ()
@property (nonatomic, strong) TrafficStatistics *statistics;
@property (nonatomic, strong) NSTimer *updateTimer;
@property (nonatomic, strong) NSTimer *deviceRefreshTimer;
@property (nonatomic, strong) DeviceManager *deviceManager;
@property (nonatomic, strong) MenuBuilder *menuBuilder;
@property (nonatomic, strong) ThreatIntelCoordinator *threatIntelCoordinator;
@end

@implementation AppDelegate

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

    ConfigurationManager *config = [ConfigurationManager sharedManager];
    PacketCaptureManager *packetManager = [[PacketCaptureManager alloc] init];
    self.statistics = [[TrafficStatistics alloc] init];
    self.deviceManager = [[DeviceManager alloc] initWithPacketManager:packetManager
                                                        configuration:config];
    self.menuBuilder = [[MenuBuilder alloc] initWithMenu:self.statusMenu
                                              statusItem:self.statusItem
                                           configuration:config];
    self.threatIntelCoordinator = [[ThreatIntelCoordinator alloc] initWithConfiguration:config];

    // Set up callback for packet updates
    __weak typeof(self) weakSelf = self;
    self.deviceManager.packetManager.onPacketReceived = ^(PacketInfo *packetInfo) {
        [weakSelf.statistics processPacket:packetInfo];
    };

    // Load available devices and restore selected device
    [self.deviceManager loadAvailableDevices];
    [self.deviceManager restoreSelectedDevice];

    // Update menu after devices are loaded
    [self updateMenu];

    // Start packet capture
    [self startCaptureWithCurrentDevice];

    // Set up timer to update UI (use block-based timer to avoid retain cycle)
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
            [strongSelf.deviceManager refreshDeviceList];
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

- (void)startCaptureWithCurrentDevice {
    NSError *error = nil;
    BOOL started = [self.deviceManager startCaptureWithError:&error];
    if (!started) {
        if (!self.deviceManager.selectedDevice ||
            [self.deviceManager.selectedDevice.name isEqualToString:@"(no device)"]) {
            self.statusItem.button.title = @"❌ No Device";
        } else {
            self.statusItem.button.title = @"❌";
        }
    }
}

- (void)selectDevice:(NetworkDevice *)device {
    NSError *error = nil;
    BOOL changed = [self.deviceManager selectDevice:device error:&error];
    if (changed) {
        [self.statistics reset];
        if (error) {
            self.statusItem.button.title = @"❌";
        }
    }
}

- (void)updateMenuIfNeeded {
    TrafficStats *stats = [self.statistics getCurrentStats];
    [self.menuBuilder updateStatusWithStats:stats selectedDevice:self.deviceManager.selectedDevice];
    if (self.menuBuilder.menuIsOpen) {
        [self updateMenu];
    }
}

- (void)updateMenu {
    TrafficStats *stats = [self.statistics getCurrentStats];

    if (self.menuBuilder.showTopConnections && self.threatIntelCoordinator.isEnabled) {
        for (ConnectionTraffic *connection in stats.topConnections) {
            [self.threatIntelCoordinator enrichIPIfNeeded:connection.destinationAddress
                                               completion:^{
                if (self.menuBuilder.menuIsOpen) {
                    [self updateMenu];
                }
            }];
        }
    }

    [self.menuBuilder updateMenuWithStats:stats
                                  devices:self.deviceManager.availableDevices
                           selectedDevice:self.deviceManager.selectedDevice
                       threatIntelEnabled:self.threatIntelCoordinator.isEnabled
                      threatIntelResults:[self.threatIntelCoordinator resultsSnapshot]
                               cacheStats:[self.threatIntelCoordinator cacheStats]
                                   target:self];
}

- (void)deviceSelected:(NSMenuItem *)sender {
    NetworkDevice *device = sender.representedObject;
    if (device) {
        [self selectDevice:device];
        [self updateMenu];
    }
}

- (void)toggleShowTopHosts:(NSMenuItem *)sender {
    self.menuBuilder.showTopHosts = !self.menuBuilder.showTopHosts;
    [self updateMenu];
}

- (void)toggleShowTopConnections:(NSMenuItem *)sender {
    self.menuBuilder.showTopConnections = !self.menuBuilder.showTopConnections;
    [self updateMenu];
}

- (void)toggleShowMap:(NSMenuItem *)sender {
    self.menuBuilder.showMap = !self.menuBuilder.showMap;
    SNBLog(@"Map visualization toggled: %@", self.menuBuilder.showMap ? @"ON" : @"OFF");
    [self updateMenu];
}

- (void)selectMapProvider:(NSMenuItem *)sender {
    NSString *provider = sender.representedObject;
    [self.menuBuilder selectMapProviderWithName:provider stats:[self.statistics getCurrentStats]];
    [self updateMenu];
}

- (void)toggleThreatIntel:(NSMenuItem *)sender {
    [self.threatIntelCoordinator toggleEnabled];
    [self updateMenu];
}

- (void)menuWillOpen:(NSMenu *)menu {
    if (menu != self.statusMenu) {
        return;
    }
    [self.menuBuilder menuWillOpenWithStats:[self.statistics getCurrentStats]];
    [self updateMenu];
}

- (void)menuDidClose:(NSMenu *)menu {
    if (menu != self.statusMenu) {
        return;
    }
    [self.menuBuilder menuDidClose];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self.updateTimer invalidate];
    [self.deviceRefreshTimer invalidate];
    [self.deviceManager.packetManager stopCapture];
}

@end
