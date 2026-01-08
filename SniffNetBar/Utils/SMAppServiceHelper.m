//
//  SMAppServiceHelper.m
//  SniffNetBar
//

#import "SMAppServiceHelper.h"
#import <ServiceManagement/ServiceManagement.h>
#import "Logger.h"

@implementation SMAppServiceHelper

+ (NSString *)helperPlistPath {
    NSString *bundlePath = [NSBundle mainBundle].bundlePath;
    return [bundlePath stringByAppendingPathComponent:
            @"Contents/Library/LaunchDaemons/com.sniffnetbar.helper.plist"];
}

+ (NSString *)helperBinaryPath {
    NSString *bundlePath = [NSBundle mainBundle].bundlePath;
    return [bundlePath stringByAppendingPathComponent:
            @"Contents/Library/LaunchDaemons/com.sniffnetbar.helper.app/Contents/MacOS/com.sniffnetbar.helper"];
}

+ (BOOL)helperPlistProgramArgumentsMatch {
    NSString *plistPath = [self helperPlistPath];
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (!plist) {
        SNBLogWarn("Helper plist not found or unreadable at %{public}@", plistPath);
        return NO;
    }

    NSString *binaryPath = [self helperBinaryPath];
    NSArray *arguments = plist[@"ProgramArguments"];
    if (arguments.count == 0) {
        SNBLogWarn("Helper plist ProgramArguments missing at %{public}@", plistPath);
        return NO;
    }

    NSString *currentPath = arguments.firstObject;
    if (![currentPath isEqualToString:binaryPath]) {
        SNBLogWarn("Helper plist ProgramArguments mismatch. Expected %{public}@, found %{public}@",
                   binaryPath, currentPath);
        return NO;
    }

    return YES;
}

+ (BOOL)helperBinaryExists {
    NSString *binaryPath = [self helperBinaryPath];
    BOOL exists = [[NSFileManager defaultManager] fileExistsAtPath:binaryPath];
    if (!exists) {
        SNBLogWarn("Helper binary missing at %{public}@", binaryPath);
    }
    return exists;
}

+ (SMAppService *)helperService {
    return [SMAppService daemonServiceWithPlistName:@"com.sniffnetbar.helper.plist"];
}

+ (BOOL)isHelperInstalled {
    if (![self helperBinaryExists]) {
        return NO;
    }

    if (![self helperPlistProgramArgumentsMatch]) {
        return NO;
    }

    SMAppService *service = [self helperService];
    SMAppServiceStatus status = service.status;
    SNBLogInfo("Helper daemon status check: %ld", (long)status);
    if (status != SMAppServiceStatusEnabled) {
        return NO;
    }

    return YES;
}

+ (BOOL)installHelperWithError:(NSError **)error {
    if (![self helperBinaryExists]) {
        if (error && *error == nil) {
            *error = [NSError errorWithDomain:@"SMAppServiceHelper"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey:
                                                    @"Helper binary missing from app bundle. Rebuild and reinstall the app."}];
        }
        return NO;
    }

    if (![self helperPlistProgramArgumentsMatch]) {
        if (error && *error == nil) {
            *error = [NSError errorWithDomain:@"SMAppServiceHelper"
                                         code:3
                                     userInfo:@{NSLocalizedDescriptionKey:
                                                    @"Helper plist ProgramArguments do not match the current app location. Rebuild the app to update the helper path."}];
        }
        return NO;
    }

    SMAppService *service = [self helperService];
    SMAppServiceStatus status = service.status;

    SNBLogInfo("Helper daemon status before registration: %ld", (long)status);

    if (status == SMAppServiceStatusEnabled) {
        SNBLogInfo("Helper already enabled, skipping registration");
        return YES;
    }

    SNBLogInfo("Registering helper via SMAppService...");
    BOOL success = [service registerAndReturnError:error];

    if (!success) {
        SNBLogError("Helper registration failed: %s", error ? (*error).localizedDescription.UTF8String : "unknown error");
        return NO;
    }

    // Check status after registration
    SMAppServiceStatus newStatus = service.status;
    SNBLogInfo("Helper daemon status after registration: %ld", (long)newStatus);

    if (newStatus == SMAppServiceStatusNotFound || newStatus == SMAppServiceStatusNotRegistered) {
        if (error && *error == nil) {
            *error = [NSError errorWithDomain:@"SMAppServiceHelper"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey:
                                                    @"Helper registration failed. Verify helper plist and bundle are embedded in the app."}];
        }
        return NO;
    }

    return YES;
}

+ (BOOL)uninstallHelperWithError:(NSError **)error {
    SMAppService *service = [self helperService];
    return [service unregisterAndReturnError:error];
}

+ (NSString *)helperStatus {
    SMAppServiceStatus status = [self helperService].status;
    switch (status) {
        case SMAppServiceStatusNotRegistered:
            return @"Not Registered";
        case SMAppServiceStatusEnabled:
            return @"Enabled";
        case SMAppServiceStatusRequiresApproval:
            return @"Requires Approval";
        case SMAppServiceStatusNotFound:
            return @"Not Found";
        default:
            return @"Unknown";
    }
}

@end
