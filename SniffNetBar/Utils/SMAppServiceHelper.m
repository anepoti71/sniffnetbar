//
//  SMAppServiceHelper.m
//  SniffNetBar
//

#import "SMAppServiceHelper.h"
#import <ServiceManagement/ServiceManagement.h>
#import <Security/Security.h>
#import "Logger.h"

@implementation SMAppServiceHelper

static BOOL SNBSetError(NSError **error, NSInteger code, NSString *message) {
    if (error && *error == nil) {
        *error = [NSError errorWithDomain:@"SMAppServiceHelper"
                                     code:code
                                 userInfo:@{NSLocalizedDescriptionKey: message ?: @"Unknown error"}];
    }
    return NO;
}

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

+ (BOOL)isBundleCodeSigned {
    NSString *bundlePath = [NSBundle mainBundle].bundlePath;
    if (bundlePath.length == 0) {
        return NO;
    }

    SecStaticCodeRef codeRef = NULL;
    NSURL *bundleURL = [NSURL fileURLWithPath:bundlePath];
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)bundleURL,
                                                  kSecCSDefaultFlags,
                                                  &codeRef);
    if (status != errSecSuccess || !codeRef) {
        return NO;
    }

    status = SecStaticCodeCheckValidity(codeRef, kSecCSDefaultFlags, NULL);
    CFRelease(codeRef);
    return status == errSecSuccess;
}

+ (BOOL)ensureHelperPlistProgramArgumentsWithError:(NSError **)error {
    NSString *plistPath = [self helperPlistPath];
    NSMutableDictionary *plist = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (!plist) {
        return SNBSetError(error, 4, @"Helper plist not found or unreadable in app bundle.");
    }

    NSString *binaryPath = [self helperBinaryPath];
    NSArray *arguments = plist[@"ProgramArguments"];
    NSString *currentPath = arguments.firstObject;
    if ([currentPath isEqualToString:binaryPath]) {
        return YES;
    }

    if ([self isBundleCodeSigned]) {
        return SNBSetError(error, 5,
                           @"Helper plist ProgramArguments do not match the current app location. "
                           @"App bundle is code signed, so it cannot be modified. Rebuild and reinstall.");
    }

    plist[@"ProgramArguments"] = @[binaryPath];
    if (![plist writeToFile:plistPath atomically:YES]) {
        return SNBSetError(error, 6, @"Failed to update helper plist ProgramArguments.");
    }

    SNBLogInfo("Updated helper plist ProgramArguments to %{public}@", binaryPath);
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

    if (![self ensureHelperPlistProgramArgumentsWithError:error]) {
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
