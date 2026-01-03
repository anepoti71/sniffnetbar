//
//  AppCoordinator.m
//  SniffNetBar
//
//  Main coordinator for orchestrating application subsystems
//

#import "AppCoordinator.h"
#import "ConfigurationManager.h"
#import "DeviceManager.h"
#import "MenuBuilder.h"
#import "NetworkDevice.h"
#import "PacketCaptureManager.h"
#import "PacketInfo.h"
#import "ThreatIntelCoordinator.h"
#import "Logger.h"
#import "TrafficStatistics.h"

@interface AppCoordinator ()
@property (nonatomic, strong, readwrite) TrafficStatistics *statistics;
@property (nonatomic, strong, readwrite) DeviceManager *deviceManager;
@property (nonatomic, strong, readwrite) MenuBuilder *menuBuilder;
@property (nonatomic, strong, readwrite) ThreatIntelCoordinator *threatIntelCoordinator;
@property (nonatomic, strong, readwrite) ConfigurationManager *configuration;
@property (nonatomic, strong) NSTimer *updateTimer;
@property (nonatomic, strong) NSTimer *deviceRefreshTimer;
@property (nonatomic, weak) NSStatusItem *statusItem;
@property (nonatomic, weak) NSMenu *statusMenu;
@end

@implementation AppCoordinator

- (instancetype)initWithStatusItem:(NSStatusItem *)statusItem
                         statusMenu:(NSMenu *)statusMenu {
    self = [super init];
    if (self) {
        _statusItem = statusItem;
        _statusMenu = statusMenu;
        _configuration = [ConfigurationManager sharedManager];

        // Initialize subsystems
        PacketCaptureManager *packetManager = [[PacketCaptureManager alloc] init];
        _statistics = [[TrafficStatistics alloc] init];
        _deviceManager = [[DeviceManager alloc] initWithPacketManager:packetManager
                                                        configuration:_configuration];
        _menuBuilder = [[MenuBuilder alloc] initWithMenu:statusMenu
                                              statusItem:statusItem
                                           configuration:_configuration];
        _threatIntelCoordinator = [[ThreatIntelCoordinator alloc] initWithConfiguration:_configuration];

        // Set up callback for packet updates
        __weak typeof(self) weakSelf = self;
        _deviceManager.packetManager.onPacketReceived = ^(PacketInfo *packetInfo) {
            [weakSelf.statistics processPacket:packetInfo];
        };
    }
    return self;
}

- (void)start {
    // Load available devices and restore selected device
    [self.deviceManager loadAvailableDevices];
    [self.deviceManager restoreSelectedDevice];

    // Update menu after devices are loaded
    [self updateMenu];

    // Start packet capture
    [self startCaptureWithCurrentDevice];

    // Set up timer to update UI
    __weak typeof(self) weakSelf = self;
    self.updateTimer = [NSTimer timerWithTimeInterval:self.configuration.menuUpdateInterval
                                              repeats:YES
                                                block:^(NSTimer *timer) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf updateMenuIfNeeded];
        }
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.updateTimer forMode:NSRunLoopCommonModes];

    // Set up timer to periodically refresh device list
    self.deviceRefreshTimer = [NSTimer timerWithTimeInterval:self.configuration.deviceListRefreshInterval
                                                     repeats:YES
                                                       block:^(NSTimer *timer) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf.deviceManager refreshDeviceList];
        }
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.deviceRefreshTimer forMode:NSRunLoopCommonModes];
}

- (void)stop {
    [self.updateTimer invalidate];
    self.updateTimer = nil;
    [self.deviceRefreshTimer invalidate];
    self.deviceRefreshTimer = nil;
    [self.deviceManager.packetManager stopCapture];
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
    SNBLogInfo("Map visualization toggled: %{public}@", self.menuBuilder.showMap ? @"ON" : @"OFF");
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

- (void)menuWillOpenWithStats {
    [self.menuBuilder menuWillOpenWithStats:[self.statistics getCurrentStats]];
    [self updateMenu];
}

- (void)menuDidClose {
    [self.menuBuilder menuDidClose];
}

@end
