//
//  test_persistence.m
//  SniffNetBar
//
//  Test program to verify keychain persistence
//

#import <Foundation/Foundation.h>
#import "KeychainManager.h"

extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"=== Testing Keychain Persistence ===\n");

        // Store test keys
        NSString *persistVTKey = @"persistent_virustotal_key_abc123";
        NSString *persistAbuseKey = @"persistent_abuseipdb_key_xyz789";

        NSLog(@"Saving keys to keychain...");
        NSError *error = nil;
        [KeychainManager saveAPIKey:persistVTKey
                      forIdentifier:kVirusTotalAPIKeyIdentifier
                              error:&error];
        [KeychainManager saveAPIKey:persistAbuseKey
                      forIdentifier:kAbuseIPDBAPIKeyIdentifier
                              error:&error];

        NSLog(@"✓ Keys saved");
        NSLog(@"\nTo test persistence:");
        NSLog(@"1. Run this program again to verify keys are still there");
        NSLog(@"2. Use terminal commands to inspect keychain:");
        NSLog(@"   security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'VirusTotalAPIKey' -w");
        NSLog(@"   security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'AbuseIPDBAPIKey' -w");
        NSLog(@"\n3. To clean up:");
        NSLog(@"   security delete-generic-password -s 'com.sniffnetbar.api-keys' -a 'VirusTotalAPIKey'");
        NSLog(@"   security delete-generic-password -s 'com.sniffnetbar.api-keys' -a 'AbuseIPDBAPIKey'");

        return 0;
    }
}
