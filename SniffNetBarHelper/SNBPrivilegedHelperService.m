//
//  SNBPrivilegedHelperService.m
//  SniffNetBarHelper
//
//  XPC service listener for privileged helper tool
//

#import "SNBPrivilegedHelperService.h"
#import <Security/Security.h>
#import "SNBHelperPacketCapture.h"
#import "SNBHelperProcessLookup.h"
#import "SNBHelperDeviceEnumerator.h"

#import "../SniffNetBar/XPC/SNBPrivilegedHelperProtocol.h"

#define kSNBPrivilegedHelperVersion @"1.0"

@interface SNBPrivilegedHelperService () <NSXPCListenerDelegate, SNBPrivilegedHelperProtocol>

@property (nonatomic, strong) NSXPCListener *listener;
@property (nonatomic, strong) SNBHelperPacketCapture *packetCapture;
@property (nonatomic, strong) SNBHelperProcessLookup *processLookup;
@property (nonatomic, strong) SNBHelperDeviceEnumerator *deviceEnumerator;

@end

@implementation SNBPrivilegedHelperService

- (instancetype)init {
    self = [super init];
    if (self) {
        _listener = [[NSXPCListener alloc] initWithMachServiceName:kSNBPrivilegedHelperMachServiceName];
        _listener.delegate = self;
        _packetCapture = [[SNBHelperPacketCapture alloc] init];
        _processLookup = [[SNBHelperProcessLookup alloc] init];
        _deviceEnumerator = [[SNBHelperDeviceEnumerator alloc] init];
    }
    return self;
}

- (void)run {
    NSLog(@"SniffNetBarHelper starting (version %@)", kSNBPrivilegedHelperVersion);
    NSLog(@"Helper running as UID: %d", getuid());

    [self.listener resume];
    [[NSRunLoop currentRunLoop] run];
}

#pragma mark - NSXPCListenerDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    NSLog(@"Helper: Received new XPC connection from PID %d", newConnection.processIdentifier);

    if (![self validateConnection:newConnection]) {
        NSLog(@"Helper: Connection validation failed, rejecting");
        return NO;
    }

    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SNBPrivilegedHelperProtocol)];
    newConnection.exportedObject = self;

    newConnection.invalidationHandler = ^{
        NSLog(@"Helper: Connection invalidated");
    };

    newConnection.interruptionHandler = ^{
        NSLog(@"Helper: Connection interrupted");
    };

    [newConnection resume];
    NSLog(@"Helper: Connection accepted and resumed");
    return YES;
}

#pragma mark - Connection Validation

- (BOOL)validateConnection:(NSXPCConnection *)connection {
    pid_t pid = connection.processIdentifier;
    NSDictionary *attributes = @{(__bridge id)kSecGuestAttributePid: @(pid)};
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL,
                                                     (__bridge CFDictionaryRef)attributes,
                                                     kSecCSDefaultFlags,
                                                     &code);
    if (status != errSecSuccess) {
        NSLog(@"Helper: Failed to create SecCode from pid: %d", status);
        return NO;
    }

    status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
    if (status != errSecSuccess) {
        NSLog(@"Helper: Code signature validation failed: %d", status);
        CFRelease(code);
        return NO;
    }

    CFDictionaryRef signingInfo = NULL;
    status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signingInfo);
    if (status != errSecSuccess) {
        NSLog(@"Helper: Failed to get signing information: %d", status);
        CFRelease(code);
        return NO;
    }

    NSString *bundleID = [(__bridge NSDictionary *)signingInfo objectForKey:(__bridge id)kSecCodeInfoIdentifier];
    BOOL isValid = [bundleID isEqualToString:@"com.sniffnetbar.app"];
    if (!isValid) {
        NSLog(@"Helper: Invalid bundle identifier: %@", bundleID);
    }

    CFRelease(signingInfo);
    CFRelease(code);
    return isValid;
}

#pragma mark - SNBPrivilegedHelperProtocol

- (void)getVersionWithReply:(void (^)(NSString *version))reply {
    reply(kSNBPrivilegedHelperVersion);
}

- (void)enumerateNetworkDevicesWithReply:(void (^)(NSArray<NSDictionary *> *devices, NSError *error))reply {
    [self.deviceEnumerator enumerateDevicesWithReply:reply];
}

- (void)startCaptureOnDevice:(NSString *)deviceName
                   withReply:(void (^)(NSString *sessionID, NSError *error))reply {
    [self.packetCapture startCaptureOnDevice:deviceName withReply:reply];
}

- (void)stopCaptureForSession:(NSString *)sessionID
                     withReply:(void (^)(NSError *error))reply {
    [self.packetCapture stopCaptureForSession:sessionID withReply:reply];
}

- (void)getNextPacketForSession:(NSString *)sessionID
                      withReply:(void (^)(NSDictionary *packetInfo, NSError *error))reply {
    [self.packetCapture getNextPacketForSession:sessionID withReply:reply];
}

- (void)lookupProcessWithSourceAddress:(NSString *)sourceAddress
                            sourcePort:(NSInteger)sourcePort
                    destinationAddress:(NSString *)destinationAddress
                       destinationPort:(NSInteger)destinationPort
                             withReply:(void (^)(NSDictionary *processInfo, NSError *error))reply {
    [self.processLookup lookupProcessWithSourceAddress:sourceAddress
                                            sourcePort:sourcePort
                                    destinationAddress:destinationAddress
                                       destinationPort:destinationPort
                                             withReply:reply];
}

@end
