//
//  remove_apikey.m
//  SniffNetBar
//
//  Command-line tool to remove API keys from keychain
//

#import <Foundation/Foundation.h>
#import "KeychainManager.h"
#import "ConfigurationManager.h"

extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;

void printUsage(const char *progName) {
    printf("Usage: %s <provider>\n", progName);
    printf("\nProviders:\n");
    printf("  virustotal    Remove VirusTotal API key\n");
    printf("  abuseipdb     Remove AbuseIPDB API key\n");
    printf("  all           Remove all API keys\n");
    printf("\nExamples:\n");
    printf("  %s virustotal\n", progName);
    printf("  %s abuseipdb\n", progName);
    printf("  %s all\n", progName);
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            printUsage(argv[0]);
            return 1;
        }

        NSString *provider = [NSString stringWithUTF8String:argv[1]];
        NSArray<NSString *> *identifiers = nil;

        // Determine which identifiers to remove
        if ([provider isEqualToString:@"virustotal"]) {
            identifiers = @[kVirusTotalAPIKeyIdentifier];
        } else if ([provider isEqualToString:@"abuseipdb"]) {
            identifiers = @[kAbuseIPDBAPIKeyIdentifier];
        } else if ([provider isEqualToString:@"all"]) {
            identifiers = @[kVirusTotalAPIKeyIdentifier, kAbuseIPDBAPIKeyIdentifier];
        } else {
            printf("Error: Unknown provider '%s'\n", [provider UTF8String]);
            printf("Valid providers: virustotal, abuseipdb, all\n");
            return 1;
        }

        // Remove from keychain
        BOOL allSuccess = YES;
        for (NSString *identifier in identifiers) {
            NSError *error = nil;
            BOOL success = [KeychainManager deleteAPIKeyForIdentifier:identifier
                                                                 error:&error];

            if (success) {
                printf("✓ API key for %s removed from keychain\n", [identifier UTF8String]);
            } else {
                printf("✗ Failed to remove API key for %s: %s\n",
                       [identifier UTF8String],
                       [error.localizedDescription UTF8String]);
                allSuccess = NO;
            }
        }

        return allSuccess ? 0 : 1;
    }
}
