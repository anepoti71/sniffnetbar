//
//  test_keychain.m
//  SniffNetBar
//
//  Test program for KeychainManager functionality
//

#import <Foundation/Foundation.h>
#import "KeychainManager.h"
#import "ConfigurationManager.h"

extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSLog(@"=== Testing KeychainManager ===\n");

        // Test 1: Save API keys
        NSLog(@"Test 1: Saving API keys to keychain...");
        NSString *testVTKey = @"test_virustotal_key_12345";
        NSString *testAbuseKey = @"test_abuseipdb_key_67890";

        NSError *error = nil;
        BOOL saveVTSuccess = [KeychainManager saveAPIKey:testVTKey
                                          forIdentifier:kVirusTotalAPIKeyIdentifier
                                                  error:&error];
        if (saveVTSuccess) {
            NSLog(@"✓ VirusTotal API key saved successfully");
        } else {
            NSLog(@"✗ Failed to save VirusTotal API key: %@", error.localizedDescription);
            return 1;
        }

        error = nil;
        BOOL saveAbuseSuccess = [KeychainManager saveAPIKey:testAbuseKey
                                             forIdentifier:kAbuseIPDBAPIKeyIdentifier
                                                     error:&error];
        if (saveAbuseSuccess) {
            NSLog(@"✓ AbuseIPDB API key saved successfully");
        } else {
            NSLog(@"✗ Failed to save AbuseIPDB API key: %@", error.localizedDescription);
            return 1;
        }

        // Test 2: Retrieve API keys
        NSLog(@"\nTest 2: Retrieving API keys from keychain...");
        error = nil;
        NSString *retrievedVTKey = [KeychainManager getAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier
                                                                     error:&error];
        if (retrievedVTKey && [retrievedVTKey isEqualToString:testVTKey]) {
            NSLog(@"✓ VirusTotal API key retrieved successfully: %@", retrievedVTKey);
        } else {
            NSLog(@"✗ Failed to retrieve VirusTotal API key or mismatch. Got: %@, Expected: %@", retrievedVTKey, testVTKey);
            return 1;
        }

        error = nil;
        NSString *retrievedAbuseKey = [KeychainManager getAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier
                                                                        error:&error];
        if (retrievedAbuseKey && [retrievedAbuseKey isEqualToString:testAbuseKey]) {
            NSLog(@"✓ AbuseIPDB API key retrieved successfully: %@", retrievedAbuseKey);
        } else {
            NSLog(@"✗ Failed to retrieve AbuseIPDB API key or mismatch. Got: %@, Expected: %@", retrievedAbuseKey, testAbuseKey);
            return 1;
        }

        // Test 3: Check existence
        NSLog(@"\nTest 3: Checking key existence...");
        BOOL vtExists = [KeychainManager hasAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier];
        BOOL abuseExists = [KeychainManager hasAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier];

        if (vtExists) {
            NSLog(@"✓ VirusTotal API key exists in keychain");
        } else {
            NSLog(@"✗ VirusTotal API key not found in keychain");
            return 1;
        }

        if (abuseExists) {
            NSLog(@"✓ AbuseIPDB API key exists in keychain");
        } else {
            NSLog(@"✗ AbuseIPDB API key not found in keychain");
            return 1;
        }

        // Test 4: Update API key
        NSLog(@"\nTest 4: Updating API key...");
        NSString *updatedVTKey = @"updated_virustotal_key_99999";
        error = nil;
        BOOL updateSuccess = [KeychainManager saveAPIKey:updatedVTKey
                                           forIdentifier:kVirusTotalAPIKeyIdentifier
                                                   error:&error];
        if (updateSuccess) {
            NSLog(@"✓ VirusTotal API key updated successfully");

            error = nil;
            NSString *verifyUpdated = [KeychainManager getAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier
                                                                        error:&error];
            if (verifyUpdated && [verifyUpdated isEqualToString:updatedVTKey]) {
                NSLog(@"✓ Updated key verified: %@", verifyUpdated);
            } else {
                NSLog(@"✗ Updated key mismatch. Got: %@, Expected: %@", verifyUpdated, updatedVTKey);
                return 1;
            }
        } else {
            NSLog(@"✗ Failed to update VirusTotal API key: %@", error.localizedDescription);
            return 1;
        }

        // Test 5: ConfigurationManager integration
        NSLog(@"\nTest 5: Testing ConfigurationManager integration...");
        ConfigurationManager *config = [ConfigurationManager sharedManager];

        NSString *configVTKey = config.virusTotalAPIKey;
        NSString *configAbuseKey = config.abuseIPDBAPIKey;

        if ([configVTKey isEqualToString:updatedVTKey]) {
            NSLog(@"✓ ConfigurationManager returns correct VirusTotal key: %@", configVTKey);
        } else {
            NSLog(@"✗ ConfigurationManager VirusTotal key mismatch. Got: %@, Expected: %@", configVTKey, updatedVTKey);
            return 1;
        }

        if ([configAbuseKey isEqualToString:testAbuseKey]) {
            NSLog(@"✓ ConfigurationManager returns correct AbuseIPDB key: %@", configAbuseKey);
        } else {
            NSLog(@"✗ ConfigurationManager AbuseIPDB key mismatch. Got: %@, Expected: %@", configAbuseKey, testAbuseKey);
            return 1;
        }

        // Test 6: Delete API keys
        NSLog(@"\nTest 6: Deleting API keys from keychain...");
        error = nil;
        BOOL deleteVTSuccess = [KeychainManager deleteAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier
                                                                     error:&error];
        if (deleteVTSuccess) {
            NSLog(@"✓ VirusTotal API key deleted successfully");

            BOOL stillExists = [KeychainManager hasAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier];
            if (!stillExists) {
                NSLog(@"✓ Verified VirusTotal key no longer exists");
            } else {
                NSLog(@"✗ VirusTotal key still exists after deletion");
                return 1;
            }
        } else {
            NSLog(@"✗ Failed to delete VirusTotal API key: %@", error.localizedDescription);
            return 1;
        }

        error = nil;
        BOOL deleteAbuseSuccess = [KeychainManager deleteAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier
                                                                        error:&error];
        if (deleteAbuseSuccess) {
            NSLog(@"✓ AbuseIPDB API key deleted successfully");

            BOOL stillExists = [KeychainManager hasAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier];
            if (!stillExists) {
                NSLog(@"✓ Verified AbuseIPDB key no longer exists");
            } else {
                NSLog(@"✗ AbuseIPDB key still exists after deletion");
                return 1;
            }
        } else {
            NSLog(@"✗ Failed to delete AbuseIPDB API key: %@", error.localizedDescription);
            return 1;
        }

        // Test 7: Verify ConfigurationManager returns empty after deletion
        NSLog(@"\nTest 7: Verifying ConfigurationManager returns empty after deletion...");
        NSString *emptyVTKey = config.virusTotalAPIKey;
        NSString *emptyAbuseKey = config.abuseIPDBAPIKey;

        if (emptyVTKey.length == 0) {
            NSLog(@"✓ ConfigurationManager returns empty for VirusTotal key");
        } else {
            NSLog(@"✗ ConfigurationManager still returns key after deletion: %@", emptyVTKey);
            return 1;
        }

        if (emptyAbuseKey.length == 0) {
            NSLog(@"✓ ConfigurationManager returns empty for AbuseIPDB key");
        } else {
            NSLog(@"✗ ConfigurationManager still returns key after deletion: %@", emptyAbuseKey);
            return 1;
        }

        NSLog(@"\n=== All tests passed! ✓ ===");
        return 0;
    }
}
