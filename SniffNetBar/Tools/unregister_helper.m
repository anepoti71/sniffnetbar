//
//  unregister_helper.m
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "SMAppServiceHelper.h"

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSError *error = nil;
        BOOL success = [SMAppServiceHelper uninstallHelperWithError:&error];
        if (!success) {
            const char *message = error.localizedDescription.UTF8String ?: "Unknown error";
            fprintf(stderr, "Failed to unregister helper: %s\n", message);
            return 1;
        }

        printf("Helper unregistered.\n");
        return 0;
    }
}
