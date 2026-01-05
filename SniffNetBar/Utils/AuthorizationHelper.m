//
//  AuthorizationHelper.m
//  SniffNetBar
//
//  Authorization helper for requesting root privileges
//

#import "AuthorizationHelper.h"
#import "Logger.h"
#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import <unistd.h>

@implementation AuthorizationHelper

+ (BOOL)isRunningAsRoot {
    return geteuid() == 0;
}

+ (SNBAuthorizationStatus)requestAuthorizationWithMessage:(NSString *)message
                                            informativeText:(NSString *)informativeText {
    if ([self isRunningAsRoot]) {
        return SNBAuthorizationStatusAlreadyRoot;
    }

    __block SNBAuthorizationStatus status = SNBAuthorizationStatusDenied;
    __block BOOL dialogCompleted = NO;

    dispatch_async(dispatch_get_main_queue(), ^{
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = message;
        alert.informativeText = informativeText;
        alert.alertStyle = NSAlertStyleInformational;
        [alert addButtonWithTitle:@"Grant Access"];
        [alert addButtonWithTitle:@"Quit"];
        alert.icon = [NSImage imageNamed:NSImageNameCaution];

        NSModalResponse response = [alert runModal];

        if (response == NSAlertFirstButtonReturn) {
            status = SNBAuthorizationStatusAuthorized;
        } else {
            status = SNBAuthorizationStatusDenied;
        }

        dialogCompleted = YES;
    });

    while (!dialogCompleted) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }

    return status;
}

+ (BOOL)relaunchAsRoot {
    if ([self isRunningAsRoot]) {
        SNBLogInfo("Already running as root");
        return YES;
    }

    SNBLogInfo("Attempting to relaunch with root privileges");

    AuthorizationRef authRef;
    OSStatus status;

    status = AuthorizationCreate(NULL,
                                 kAuthorizationEmptyEnvironment,
                                 kAuthorizationFlagDefaults,
                                 &authRef);

    if (status != errAuthorizationSuccess) {
        SNBLogError("Failed to create authorization reference: %d", status);
        return NO;
    }

    AuthorizationItem authItems = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights authRights = {1, &authItems};

    AuthorizationFlags flags = kAuthorizationFlagDefaults |
                              kAuthorizationFlagInteractionAllowed |
                              kAuthorizationFlagPreAuthorize |
                              kAuthorizationFlagExtendRights;

    // Create custom prompt for authorization dialog
    NSString *promptMessage = @"SniffNetBar needs root privileges to capture network packets.\n\n"
                              @"This is required because packet capture requires low-level access to network interfaces.";
    AuthorizationItem envItems[] = {
        {kAuthorizationEnvironmentPrompt, [promptMessage length], (void *)[promptMessage UTF8String], 0}
    };
    AuthorizationEnvironment environment = {1, envItems};

    status = AuthorizationCopyRights(authRef,
                                    &authRights,
                                    &environment,
                                    flags,
                                    NULL);

    if (status != errAuthorizationSuccess) {
        SNBLogError("Failed to copy rights: %d", status);
        if (status == errAuthorizationCanceled) {
            SNBLogInfo("User canceled authorization");
        }
        AuthorizationFree(authRef, kAuthorizationFlagDestroyRights);
        return NO;
    }

    NSString *appPath = [[NSBundle mainBundle] executablePath];
    const char *path = [appPath UTF8String];

    char *args[] = {NULL};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    status = AuthorizationExecuteWithPrivileges(authRef,
                                               path,
                                               kAuthorizationFlagDefaults,
                                               args,
                                               NULL);
#pragma clang diagnostic pop

    AuthorizationFree(authRef, kAuthorizationFlagDestroyRights);

    if (status == errAuthorizationSuccess) {
        SNBLogInfo("Successfully relaunched with root privileges");
        [NSApp terminate:nil];
        return YES;
    } else {
        SNBLogError("Failed to relaunch with root privileges: %d", status);
        return NO;
    }
}

@end
