//
//  PacketCaptureManager.m
//  SniffNetBar
//
//  Packet capture manager using privileged helper via XPC
//

#import "PacketCaptureManager.h"
#import "PacketInfo.h"
#import "NetworkDevice.h"
#import "SNBPrivilegedHelperClient.h"
#import "Logger.h"

@interface PacketCaptureManager ()
@property (nonatomic, assign) BOOL isCapturing;
@property (nonatomic, strong) dispatch_queue_t captureQueue;
@property (nonatomic, strong, readwrite) NSString *currentDeviceName;
@property (nonatomic, strong) NSString *sessionID;
@property (nonatomic, strong) NSTimer *pollingTimer;
@end

@implementation PacketCaptureManager

- (instancetype)init {
    self = [super init];
    if (self) {
        _captureQueue = dispatch_queue_create("com.sniffnetbar.capture", DISPATCH_QUEUE_SERIAL);
        _isCapturing = NO;
    }
    return self;
}

- (void)dealloc {
    [self stopCapture];
}

- (BOOL)startCaptureWithError:(NSError **)error {
    __block NSString *defaultDevice = nil;
    __block NSError *deviceError = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [[SNBPrivilegedHelperClient sharedClient] enumerateDevicesWithCompletion:^(NSArray<NetworkDevice *> *devices, NSError *err) {
        if (err || devices.count == 0) {
            deviceError = err ?: [NSError errorWithDomain:@"PacketCaptureError"
                                                     code:1
                                                 userInfo:@{NSLocalizedDescriptionKey: @"No devices available"}];
        } else {
            defaultDevice = devices.firstObject.name;
        }
        dispatch_semaphore_signal(semaphore);
    }];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (deviceError) {
        if (error) {
            *error = deviceError;
        }
        return NO;
    }

    return [self startCaptureWithDeviceName:defaultDevice error:error];
}

- (BOOL)startCaptureWithDeviceName:(NSString *)deviceName error:(NSError **)error {
    if (self.isCapturing) {
        [self stopCapture];
    }

    if (!deviceName || deviceName.length == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"PacketCaptureError"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Invalid device name"}];
        }
        return NO;
    }

    __block BOOL success = NO;
    __block NSError *startError = nil;
    __block NSString *newSessionID = nil;
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    [[SNBPrivilegedHelperClient sharedClient] startCaptureOnDevice:deviceName
                                                        completion:^(NSString *sessionID, NSError *err) {
        if (err) {
            startError = err;
        } else if (sessionID) {
            newSessionID = sessionID;
            success = YES;
        } else {
            startError = [NSError errorWithDomain:@"PacketCaptureError"
                                             code:2
                                         userInfo:@{NSLocalizedDescriptionKey: @"Failed to start capture"}];
        }
        dispatch_semaphore_signal(semaphore);
    }];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (!success) {
        if (error) {
            *error = startError;
        }
        return NO;
    }

    self.sessionID = newSessionID;
    self.currentDeviceName = deviceName;
    self.isCapturing = YES;

    SNBLogInfo("Capture started with session ID: %{public}@", self.sessionID);
    [self startPollingForPackets];
    return YES;
}

- (void)stopCapture {
    if (!self.isCapturing) {
        return;
    }

    self.isCapturing = NO;

    [self.pollingTimer invalidate];
    self.pollingTimer = nil;

    if (self.sessionID) {
        [[SNBPrivilegedHelperClient sharedClient] stopCaptureForSession:self.sessionID
                                                             completion:^(NSError *error) {
            if (error) {
                SNBLogWarn("Error stopping capture: %{public}@", error.localizedDescription);
            }
        }];
        self.sessionID = nil;
    }
}

- (void)startPollingForPackets {
    [self.pollingTimer invalidate];
    dispatch_async(dispatch_get_main_queue(), ^{
        self.pollingTimer = [NSTimer scheduledTimerWithTimeInterval:0.01
                                                            repeats:YES
                                                              block:^(NSTimer *timer) {
            [self pollNextPacket];
        }];
    });
}

- (void)pollNextPacket {
    if (!self.isCapturing || !self.sessionID) {
        return;
    }

    [[SNBPrivilegedHelperClient sharedClient] getNextPacketForSession:self.sessionID
                                                           completion:^(PacketInfo *packet, NSError *error) {
        if (error) {
            SNBLogWarn("Error getting packet: %{public}@", error.localizedDescription);
            if (self.onCaptureError) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.onCaptureError(error);
                });
            }
            return;
        }

        if (packet && self.onPacketReceived) {
            dispatch_async(self.captureQueue, ^{
                self.onPacketReceived(packet);
            });
        }
    }];
}

@end
