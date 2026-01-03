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
#import "AnomalyDetector.h"
#import "AnomalyStore.h"

@interface AppCoordinator ()
@property (nonatomic, strong, readwrite) TrafficStatistics *statistics;
@property (nonatomic, strong, readwrite) DeviceManager *deviceManager;
@property (nonatomic, strong, readwrite) MenuBuilder *menuBuilder;
@property (nonatomic, strong, readwrite) ThreatIntelCoordinator *threatIntelCoordinator;
@property (nonatomic, strong, readwrite) ConfigurationManager *configuration;
@property (nonatomic, strong) SNBAnomalyDetector *anomalyDetector;
@property (nonatomic, strong) NSTimer *updateTimer;
@property (nonatomic, strong) NSTimer *deviceRefreshTimer;
@property (nonatomic, strong) NSTimer *anomalyRetrainTimer;
@property (nonatomic, assign) BOOL anomalyRetrainInProgress;
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
        _anomalyDetector = [[SNBAnomalyDetector alloc] initWithWindowSeconds:60.0];

        // Set up callback for packet updates
        __weak typeof(self) weakSelf = self;
        _deviceManager.packetManager.onPacketReceived = ^(PacketInfo *packetInfo) {
            [weakSelf.statistics processPacket:packetInfo];
            [weakSelf.anomalyDetector processPacket:packetInfo];
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
            [strongSelf.anomalyDetector flushIfNeeded];
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

    // Set up periodic anomaly retraining
    [self scheduleAnomalyRetrain];
}

- (void)stop {
    [self.updateTimer invalidate];
    self.updateTimer = nil;
    [self.deviceRefreshTimer invalidate];
    self.deviceRefreshTimer = nil;
    [self.anomalyRetrainTimer invalidate];
    self.anomalyRetrainTimer = nil;
    [self.deviceManager.packetManager stopCapture];
    [self.anomalyDetector flushIfNeeded];
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

#pragma mark - Anomaly retraining

- (void)scheduleAnomalyRetrain {
    NSTimeInterval retrainInterval = 6.0 * 60.0 * 60.0;
    __weak typeof(self) weakSelf = self;
    self.anomalyRetrainTimer = [NSTimer timerWithTimeInterval:retrainInterval
                                                      repeats:YES
                                                        block:^(NSTimer *timer) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf triggerAnomalyRetrain];
        }
    }];
    [[NSRunLoop mainRunLoop] addTimer:self.anomalyRetrainTimer forMode:NSRunLoopCommonModes];
}

- (void)triggerAnomalyRetrain {
    if (self.anomalyRetrainInProgress) {
        return;
    }
    self.anomalyRetrainInProgress = YES;

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        SNBLogInfo("Starting anomaly retrain");
        NSString *trainScript = [[NSBundle mainBundle] pathForResource:@"anomaly_train" ofType:@"py"];
        NSString *convertScript = [[NSBundle mainBundle] pathForResource:@"convert_iforest_to_coreml" ofType:@"py"];
        NSString *dbPath = [SNBAnomalyStore defaultDatabasePath];
        NSString *modelPath = [SNBAnomalyStore defaultModelPath];
        NSString *supportDir = [SNBAnomalyStore applicationSupportDirectoryPath];
        NSString *coreMLModelPath = [supportDir stringByAppendingPathComponent:@"anomaly_model.mlmodel"];

        BOOL trained = [self runPythonScript:trainScript
                                   arguments:@[@"--db", dbPath, @"--out", modelPath]];

        if (trained && convertScript.length > 0) {
            [self runPythonScript:convertScript
                        arguments:@[@"--db", dbPath, @"--out", coreMLModelPath, @"--compile"]];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            self.anomalyRetrainInProgress = NO;
            if (trained) {
                SNBLogInfo("Anomaly retrain completed");
                [self.anomalyDetector reloadModels];
            } else {
                SNBLogWarn("Anomaly retrain failed");
            }
        });
    });
}

- (BOOL)runPythonScript:(NSString *)scriptPath arguments:(NSArray<NSString *> *)arguments {
    if (scriptPath.length == 0) {
        return NO;
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:scriptPath]) {
        return NO;
    }

    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/python3";
    task.arguments = [@[scriptPath] arrayByAddingObjectsFromArray:arguments];
    task.standardOutput = [NSPipe pipe];
    task.standardError = [NSPipe pipe];

    @try {
        [task launch];
        [task waitUntilExit];
    } @catch (NSException *exception) {
        return NO;
    }

    return task.terminationStatus == 0;
}

@end
