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
#import "AnomalyExplainabilityCoordinator.h"
#import "KeychainManager.h"
#import "NetworkAssetMonitor.h"
#import "UserDefaultsKeys.h"
#import "StatisticsHistory.h"

@interface AppCoordinator () <MenuBuilderDelegate>
@property (nonatomic, strong, readwrite) TrafficStatistics *statistics;
@property (nonatomic, strong, readwrite) DeviceManager *deviceManager;
@property (nonatomic, strong, readwrite) MenuBuilder *menuBuilder;
@property (nonatomic, strong, readwrite) ThreatIntelCoordinator *threatIntelCoordinator;
@property (nonatomic, strong, readwrite) ConfigurationManager *configuration;
@property (nonatomic, strong) SNBAnomalyDetector *anomalyDetector;
@property (nonatomic, strong) SNBAnomalyExplainabilityCoordinator *anomalyExplainabilityCoordinator;
@property (nonatomic, strong) NSTimer *updateTimer;
@property (nonatomic, strong) NSTimer *deviceRefreshTimer;
@property (nonatomic, strong) NSTimer *anomalyRetrainTimer;
@property (nonatomic, assign) BOOL anomalyRetrainInProgress;
@property (nonatomic, weak) NSStatusItem *statusItem;
@property (nonatomic, weak) NSMenu *statusMenu;
@property (nonatomic, assign) BOOL menuRefreshPending;
@property (nonatomic, strong) SNBNetworkAssetMonitor *assetMonitor;
@property (nonatomic, strong) SNBStatisticsHistory *statisticsHistory;
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
        _menuBuilder.delegate = self;
        _threatIntelCoordinator = [[ThreatIntelCoordinator alloc] initWithConfiguration:_configuration];
        NSTimeInterval anomalyWindowSeconds = _configuration.anomalyWindowSeconds;
        _anomalyDetector = [[SNBAnomalyDetector alloc] initWithWindowSeconds:anomalyWindowSeconds];
        _anomalyExplainabilityCoordinator = [[SNBAnomalyExplainabilityCoordinator alloc]
                                             initWithConfiguration:_configuration
                                             threatIntelCoordinator:_threatIntelCoordinator];
        _assetMonitor = [[SNBNetworkAssetMonitor alloc] init];
        _statisticsHistory = [[SNBStatisticsHistory alloc] init];

        // Set up callback for packet updates
        __weak typeof(self) weakSelf = self;
        _deviceManager.packetManager.onPacketReceived = ^(PacketInfo *packetInfo) {
            [weakSelf.statistics processPacket:packetInfo];
            [weakSelf.anomalyDetector processPacket:packetInfo];
            [weakSelf.statisticsHistory processPacket:packetInfo];
        };
    }
    return self;
}

- (void)start {
    // Load available devices and restore selected device
    [self.deviceManager loadAvailableDevices];
    [self.deviceManager restoreSelectedDevice];

    // Keep the asset monitor aligned with the selected capture interface
    self.assetMonitor.interfaceName = self.deviceManager.selectedDevice.name;

    // Update menu after devices are loaded
    [self updateMenu];

    // Start packet capture
    [self startCaptureWithCurrentDevice];

    // Start asset monitor if enabled
    BOOL assetMonitorEnabled = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyAssetMonitorEnabled];
    self.assetMonitor.enabled = assetMonitorEnabled;
    NSNumber *dailyStatsValue = [[NSUserDefaults standardUserDefaults] objectForKey:SNBUserDefaultsKeyDailyStatisticsEnabled];
    BOOL dailyStatsEnabled = dailyStatsValue ? [dailyStatsValue boolValue] : YES;
    self.statisticsHistory.enabled = dailyStatsEnabled;
    __weak typeof(self) weakSelfAsset = self;
    self.assetMonitor.onAssetsUpdated = ^(NSArray<SNBNetworkAsset *> *assets, NSArray<SNBNetworkAsset *> *newAssets) {
        [weakSelfAsset scheduleMenuRefresh];
    };

    // Set up timer to update UI
    __weak typeof(self) weakSelf = self;
    self.updateTimer = [NSTimer timerWithTimeInterval:self.configuration.menuUpdateInterval
                                              repeats:YES
                                                block:^(NSTimer *timer) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (strongSelf) {
            [strongSelf updateMenuIfNeeded];
            [strongSelf.anomalyDetector flushIfNeeded];
            [strongSelf.anomalyExplainabilityCoordinator processPendingExplanations];
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
    [self.assetMonitor stop];
    [self.statisticsHistory flush];
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
    self.assetMonitor.interfaceName = device.name;
    BOOL changed = [self.deviceManager selectDevice:device error:&error];
    if (changed) {
        [self.statistics reset];
        if (error) {
            self.statusItem.button.title = @"❌";
        }
    }
}

- (void)updateMenuIfNeeded {
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        // Proactively enrich IPs for threat intel (regardless of menu state)
        [strongSelf enrichStatsForThreatIntel:stats];

        [strongSelf.menuBuilder updateStatusWithStats:stats selectedDevice:strongSelf.deviceManager.selectedDevice];
        if (strongSelf.menuBuilder.menuIsOpen) {
            [strongSelf.menuBuilder refreshVisualizationWithStats:stats
                                             threatIntelEnabled:strongSelf.threatIntelCoordinator.isEnabled
                                    threatIntelStatusMessage:[strongSelf.threatIntelCoordinator availabilityMessage]
                                            threatIntelResults:[strongSelf.threatIntelCoordinator resultsSnapshot]
                                                     cacheStats:[strongSelf.threatIntelCoordinator cacheStats]
                                           assetMonitorEnabled:strongSelf.assetMonitor.isEnabled
                                                networkAssets:[strongSelf.assetMonitor assetsSnapshot]
                                              recentNewAssets:[strongSelf.assetMonitor recentNewAssetsSnapshot]];
        } else {
            [strongSelf updateMenuWithStats:stats];
        }
    }];
}

- (void)enrichStatsForThreatIntel:(TrafficStats *)stats {
    if (!self.threatIntelCoordinator.isEnabled) {
        return;
    }

    // Get ALL unique destination IPs (not just top connections) for comprehensive threat detection
    __weak typeof(self) weakSelf = self;
    [self.statistics getAllDestinationIPsWithCompletion:^(NSSet<NSString *> *destinationIPs) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        // Enrich every destination IP for threat intelligence
        // enrichIPIfNeeded uses caching, so this won't overwhelm the API
        for (NSString *ip in destinationIPs) {
            [strongSelf.threatIntelCoordinator enrichIPIfNeeded:ip completion:^{
                [strongSelf scheduleMenuRefresh];
            }];
        }
    }];
}

- (void)updateMenu {
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        [strongSelf updateMenuWithStats:stats];
    }];
}

- (void)updateMenuWithStats:(TrafficStats *)stats {
    self.menuBuilder.dailyStatsEnabled = self.statisticsHistory.isEnabled;
    self.menuBuilder.statsReportAvailable = [self.statisticsHistory reportExists];

    [self.menuBuilder updateMenuWithStats:stats
                                  devices:self.deviceManager.availableDevices
                           selectedDevice:self.deviceManager.selectedDevice
                       threatIntelEnabled:self.threatIntelCoordinator.isEnabled
                   threatIntelStatusMessage:[self.threatIntelCoordinator availabilityMessage]
                      threatIntelResults:[self.threatIntelCoordinator resultsSnapshot]
                               cacheStats:[self.threatIntelCoordinator cacheStats]
                       assetMonitorEnabled:self.assetMonitor.isEnabled
                            networkAssets:[self.assetMonitor assetsSnapshot]
                          recentNewAssets:[self.assetMonitor recentNewAssetsSnapshot]
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
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        [strongSelf.menuBuilder selectMapProviderWithName:provider stats:stats];
        [strongSelf updateMenuWithStats:stats];
    }];
}

- (void)toggleThreatIntel:(NSMenuItem *)sender {
    [self.threatIntelCoordinator toggleEnabled];
    [self updateMenu];
}

- (void)toggleDailyStatistics:(NSMenuItem *)sender {
    BOOL enabled = !self.statisticsHistory.isEnabled;
    self.statisticsHistory.enabled = enabled;
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:SNBUserDefaultsKeyDailyStatisticsEnabled];
    [self updateMenu];
}

- (void)openStatisticsReport:(NSMenuItem *)sender {
    [self.statisticsHistory generateReport];
    NSString *path = [self.statisticsHistory reportPath];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        [[NSWorkspace sharedWorkspace] openFile:path];
    } else {
        SNBLogWarn("Statistics report not found at %{public}@", path);
    }
}

- (void)toggleAssetMonitor:(NSMenuItem *)sender {
    BOOL enabled = !self.assetMonitor.isEnabled;
    self.assetMonitor.enabled = enabled;
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:SNBUserDefaultsKeyAssetMonitorEnabled];
    [self updateMenu];
}

- (void)resetStatistics:(NSMenuItem *)sender {
    [self.statistics reset];
    [self updateMenu];
}

- (void)menuWillOpenWithStats {
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        [strongSelf.menuBuilder menuWillOpenWithStats:stats];
        [strongSelf updateMenuWithStats:stats];
    }];
}

- (void)menuDidClose {
    [self.menuBuilder menuDidClose];
}

#pragma mark - MenuBuilderDelegate

- (void)menuBuilderNeedsVisualizationRefresh:(id)sender {
    __weak typeof(self) weakSelf = self;
    [self.statistics getCurrentStatsWithCompletion:^(TrafficStats *stats) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf || !strongSelf.menuBuilder.menuIsOpen) {
            return;
        }
        [strongSelf.menuBuilder refreshVisualizationWithStats:stats
                                         threatIntelEnabled:strongSelf.threatIntelCoordinator.isEnabled
                                   threatIntelStatusMessage:[strongSelf.threatIntelCoordinator availabilityMessage]
                                       threatIntelResults:[strongSelf.threatIntelCoordinator resultsSnapshot]
                                                cacheStats:[strongSelf.threatIntelCoordinator cacheStats]
                                      assetMonitorEnabled:strongSelf.assetMonitor.isEnabled
                                           networkAssets:[strongSelf.assetMonitor assetsSnapshot]
                                         recentNewAssets:[strongSelf.assetMonitor recentNewAssetsSnapshot]];
    }];
}

#pragma mark - Menu refresh

- (void)scheduleMenuRefresh {
    if (self.menuRefreshPending) {
        return;
    }
    if (self.menuBuilder.menuIsOpen) {
        return;
    }

    self.menuRefreshPending = YES;
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        strongSelf.menuRefreshPending = NO;
        if (strongSelf.menuBuilder.menuIsOpen) {
            [strongSelf updateMenu];
        }
    });
}

#pragma mark - Anomaly retraining

- (void)scheduleAnomalyRetrain {
    NSTimeInterval retrainInterval = self.configuration.anomalyRetrainInterval;
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

    NSPipe *outputPipe = [NSPipe pipe];
    NSPipe *errorPipe = [NSPipe pipe];
    task.standardOutput = outputPipe;
    task.standardError = errorPipe;

    // Read pipes asynchronously to prevent deadlock if output exceeds buffer size
    NSMutableData *outputData = [NSMutableData data];
    NSMutableData *errorData = [NSMutableData data];

    outputPipe.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = [handle availableData];
        if (data.length > 0) {
            [outputData appendData:data];
        }
    };

    errorPipe.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = [handle availableData];
        if (data.length > 0) {
            [errorData appendData:data];
        }
    };

    @try {
        [task launch];
        [task waitUntilExit];

        // Clean up handlers after task completes
        outputPipe.fileHandleForReading.readabilityHandler = nil;
        errorPipe.fileHandleForReading.readabilityHandler = nil;

        // Log output if task failed
        if (task.terminationStatus != 0 && errorData.length > 0) {
            NSString *errorString = [[NSString alloc] initWithData:errorData encoding:NSUTF8StringEncoding];
            if (errorString) {
                SNBLogWarn("Python script failed with error: %{public}@", errorString);
            }
        }
    } @catch (NSException *exception) {
        outputPipe.fileHandleForReading.readabilityHandler = nil;
        errorPipe.fileHandleForReading.readabilityHandler = nil;
        return NO;
    }

    return task.terminationStatus == 0;
}

@end
