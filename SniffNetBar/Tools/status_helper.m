//
//  status_helper.m
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "SMAppServiceHelper.h"

static const char *statusString(NSString *status) {
    return status.length > 0 ? status.UTF8String : "Unknown";
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        BOOL binaryExists = [SMAppServiceHelper helperBinaryExists];
        BOOL plistMatch = [SMAppServiceHelper helperPlistProgramArgumentsMatch];
        NSString *status = [SMAppServiceHelper helperStatus];

        printf("=== SniffNetBar Helper Status ===\n\n");
        printf("Helper binary exists: %s\n", binaryExists ? "YES" : "NO");
        printf("Plist ProgramArguments match: %s\n", plistMatch ? "YES" : "NO");
        printf("Service status: %s\n", statusString(status));

        if (!binaryExists) {
            printf("Hint: rebuild and reinstall the app bundle.\n");
        } else if (!plistMatch) {
            printf("Hint: run make install to fix ProgramArguments path.\n");
        } else if ([status isEqualToString:@"Requires Approval"]) {
            printf("Hint: enable SniffNetBar Helper in System Settings > Login Items.\n");
        }

        return 0;
    }
}
