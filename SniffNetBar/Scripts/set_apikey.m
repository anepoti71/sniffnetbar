//
//  set_apikey.m
//  SniffNetBar
//
//  Command-line tool to set API keys in keychain
//

#import <Foundation/Foundation.h>
#import "KeychainManager.h"
#import "ConfigurationManager.h"

extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;

void printUsage(const char *progName) {
    printf("Usage: %s <provider> <api_key>\n", progName);
    printf("\nProviders:\n");
    printf("  virustotal    Set VirusTotal API key\n");
    printf("  abuseipdb     Set AbuseIPDB API key\n");
    printf("\nExamples:\n");
    printf("  %s virustotal abc123def456\n", progName);
    printf("  %s abuseipdb xyz789uvw012\n", progName);
    printf("\nTo remove a key, use remove_apikey command\n");
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc != 3) {
            printUsage(argv[0]);
            return 1;
        }

        NSString *provider = [NSString stringWithUTF8String:argv[1]];
        NSString *apiKey = [NSString stringWithUTF8String:argv[2]];
        NSString *identifier = nil;

        // Determine identifier based on provider
        if ([provider isEqualToString:@"virustotal"]) {
            identifier = kVirusTotalAPIKeyIdentifier;
        } else if ([provider isEqualToString:@"abuseipdb"]) {
            identifier = kAbuseIPDBAPIKeyIdentifier;
        } else {
            printf("Error: Unknown provider '%s'\n", [provider UTF8String]);
            printf("Valid providers: virustotal, abuseipdb\n");
            return 1;
        }

        // Save to keychain
        NSError *error = nil;
        BOOL success = [KeychainManager saveAPIKey:apiKey
                                     forIdentifier:identifier
                                             error:&error];

        if (success) {
            printf("✓ API key for %s saved successfully to keychain\n", [provider UTF8String]);
            printf("  Identifier: %s\n", [identifier UTF8String]);
            printf("  Key: %s (first 8 chars)\n", [[apiKey substringToIndex:MIN(8, apiKey.length)] UTF8String]);
            return 0;
        } else {
            printf("✗ Failed to save API key: %s\n", [error.localizedDescription UTF8String]);
            return 1;
        }
    }
}
