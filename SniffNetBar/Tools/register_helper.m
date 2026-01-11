//
//  register_helper.m
//  SniffNetBar
//

#import <Foundation/Foundation.h>
#import "SMAppServiceHelper.h"

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSError *error = nil;
        BOOL success = [SMAppServiceHelper installHelperWithError:&error];
        if (!success) {
            const char *message = error.localizedDescription.UTF8String ?: "Unknown error";
            fprintf(stderr, "Failed to register helper: %s\n", message);
            return 1;
        }

        printf("Helper registered. Status: %s\n", [[SMAppServiceHelper helperStatus] UTF8String]);
        return 0;
    }
}
