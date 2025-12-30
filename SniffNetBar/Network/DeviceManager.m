//
//  DeviceManager.m
//  SniffNetBar
//

#import "DeviceManager.h"
#import "ConfigurationManager.h"
#import "NetworkDevice.h"
#import "PacketCaptureManager.h"
#import "UserDefaultsKeys.h"

@interface DeviceManager ()
@property (nonatomic, strong) ConfigurationManager *configuration;
@property (nonatomic, strong, readwrite) PacketCaptureManager *packetManager;
@property (nonatomic, strong, readwrite) NSArray<NetworkDevice *> *availableDevices;
@property (nonatomic, assign) NSUInteger reconnectAttempts;
@end

@implementation DeviceManager

- (instancetype)initWithPacketManager:(PacketCaptureManager *)packetManager
                        configuration:(ConfigurationManager *)configuration {
    self = [super init];
    if (self) {
        _packetManager = packetManager;
        _configuration = configuration;
        _availableDevices = @[];
    }
    return self;
}

- (void)loadAvailableDevices {
    self.availableDevices = [NetworkDevice listAllDevices];
    if (self.availableDevices.count == 0) {
        SNBLog(@"Warning: No network devices found");
    }
}

- (void)restoreSelectedDevice {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *savedDeviceName = [defaults stringForKey:SNBUserDefaultsKeySelectedNetworkDevice];

    if (savedDeviceName) {
        for (NetworkDevice *device in self.availableDevices) {
            if ([device.name isEqualToString:savedDeviceName]) {
                self.selectedDevice = device;
                return;
            }
        }
    }

    self.selectedDevice = [NetworkDevice defaultDevice];
}

- (void)saveSelectedDevice {
    if (self.selectedDevice) {
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:self.selectedDevice.name forKey:SNBUserDefaultsKeySelectedNetworkDevice];
        [defaults synchronize];
    }
}

- (BOOL)startCaptureWithError:(NSError **)error {
    if (!self.selectedDevice) {
        self.selectedDevice = [NetworkDevice defaultDevice];
    }

    if (!self.selectedDevice || [self.selectedDevice.name isEqualToString:@"(no device)"]) {
        SNBLog(@"Error: No valid network device available for capture");
        if (error) {
            *error = [NSError errorWithDomain:@"DeviceManager"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"No valid network device available"}];
        }
        return NO;
    }

    NSError *startError = nil;
    if (![self.packetManager startCaptureWithDeviceName:self.selectedDevice.name error:&startError]) {
        SNBLog(@"Failed to start packet capture: %@", startError.localizedDescription);
        if (error) {
            *error = startError;
        }
        [self scheduleReconnection];
        return NO;
    }

    self.reconnectAttempts = 0;
    return YES;
}

- (void)attemptReconnection {
    SNBLog(@"Attempting to reconnect to device: %@", self.selectedDevice.name);
    [self refreshDeviceList];
    [self startCaptureWithError:nil];
}

- (void)scheduleReconnection {
    ConfigurationManager *config = self.configuration;
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
}

- (void)refreshDeviceList {
    NSArray<NetworkDevice *> *previousDevices = self.availableDevices;
    [self loadAvailableDevices];

    if (previousDevices.count != self.availableDevices.count) {
        SNBLog(@"Device list changed: %lu -> %lu devices",
               (unsigned long)previousDevices.count,
               (unsigned long)self.availableDevices.count);
    }

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

- (BOOL)selectDevice:(NetworkDevice *)device error:(NSError **)error {
    if (!device || [device.name isEqualToString:self.selectedDevice.name]) {
        return NO;
    }

    self.selectedDevice = device;
    [self saveSelectedDevice];
    [self startCaptureWithError:error];
    return YES;
}

@end
