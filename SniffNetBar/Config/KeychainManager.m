//
//  KeychainManager.m
//  SniffNetBar
//
//  Secure keychain management for API keys
//

#import "KeychainManager.h"
#import <Security/Security.h>

// Service identifier for keychain items
static NSString * const kKeychainServiceName = @"com.sniffnetbar.api-keys";

// Error domain for KeychainManager errors
static NSString * const kKeychainManagerErrorDomain = @"com.sniffnetbar.keychain";

// Error codes
typedef NS_ENUM(NSInteger, KeychainManagerErrorCode) {
    KeychainManagerErrorItemNotFound = 1001,
    KeychainManagerErrorAccessDenied = 1002,
    KeychainManagerErrorInvalidParameter = 1003,
    KeychainManagerErrorUnknown = 1004
};

@implementation KeychainManager

#pragma mark - Public Methods

+ (BOOL)saveAPIKey:(nullable NSString *)apiKey
     forIdentifier:(NSString *)identifier
             error:(NSError *_Nullable *_Nullable)error {

    if (!identifier || identifier.length == 0) {
        if (error) {
            *error = [self errorWithCode:KeychainManagerErrorInvalidParameter
                             description:@"Identifier cannot be nil or empty"];
        }
        return NO;
    }

    // If apiKey is nil or empty, delete the item
    if (!apiKey || apiKey.length == 0) {
        return [self deleteAPIKeyForIdentifier:identifier error:error];
    }

    // Check if item already exists
    BOOL exists = [self hasAPIKeyForIdentifier:identifier];

    NSData *passwordData = [apiKey dataUsingEncoding:NSUTF8StringEncoding];

    if (exists) {
        // Update existing item
        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: kKeychainServiceName,
            (__bridge id)kSecAttrAccount: identifier
        };

        NSDictionary *attributesToUpdate = @{
            (__bridge id)kSecValueData: passwordData
        };

        OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query,
                                       (__bridge CFDictionaryRef)attributesToUpdate);

        if (status != errSecSuccess) {
            if (error) {
                *error = [self errorFromOSStatus:status];
            }
            return NO;
        }
    } else {
        // Add new item
        NSDictionary *attributes = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: kKeychainServiceName,
            (__bridge id)kSecAttrAccount: identifier,
            (__bridge id)kSecValueData: passwordData,
            (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleWhenUnlocked
        };

        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);

        if (status != errSecSuccess) {
            if (error) {
                *error = [self errorFromOSStatus:status];
            }
            return NO;
        }
    }

    return YES;
}

+ (nullable NSString *)getAPIKeyForIdentifier:(NSString *)identifier
                                        error:(NSError *_Nullable *_Nullable)error {

    if (!identifier || identifier.length == 0) {
        if (error) {
            *error = [self errorWithCode:KeychainManagerErrorInvalidParameter
                             description:@"Identifier cannot be nil or empty"];
        }
        return nil;
    }

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainServiceName,
        (__bridge id)kSecAttrAccount: identifier,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

    if (status == errSecSuccess && result) {
        NSData *passwordData = (__bridge_transfer NSData *)result;
        NSString *password = [[NSString alloc] initWithData:passwordData
                                                   encoding:NSUTF8StringEncoding];
        return password;
    }

    if (status != errSecItemNotFound && error) {
        *error = [self errorFromOSStatus:status];
    }

    return nil;
}

+ (BOOL)deleteAPIKeyForIdentifier:(NSString *)identifier
                            error:(NSError *_Nullable *_Nullable)error {

    if (!identifier || identifier.length == 0) {
        if (error) {
            *error = [self errorWithCode:KeychainManagerErrorInvalidParameter
                             description:@"Identifier cannot be nil or empty"];
        }
        return NO;
    }

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainServiceName,
        (__bridge id)kSecAttrAccount: identifier
    };

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

    // Consider errSecItemNotFound as success (item doesn't exist = successfully deleted)
    if (status == errSecSuccess || status == errSecItemNotFound) {
        return YES;
    }

    if (error) {
        *error = [self errorFromOSStatus:status];
    }

    return NO;
}

+ (BOOL)hasAPIKeyForIdentifier:(NSString *)identifier {
    if (!identifier || identifier.length == 0) {
        return NO;
    }

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainServiceName,
        (__bridge id)kSecAttrAccount: identifier,
        (__bridge id)kSecReturnData: @NO,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };

    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, NULL);

    return status == errSecSuccess;
}

#pragma mark - Error Handling

+ (NSError *)errorFromOSStatus:(OSStatus)status {
    KeychainManagerErrorCode code;
    NSString *description;

    switch (status) {
        case errSecItemNotFound:
            code = KeychainManagerErrorItemNotFound;
            description = @"Keychain item not found";
            break;

        case errSecAuthFailed:
        case errSecInteractionNotAllowed:
            code = KeychainManagerErrorAccessDenied;
            description = @"Access to keychain denied";
            break;

        case errSecParam:
            code = KeychainManagerErrorInvalidParameter;
            description = @"Invalid parameter";
            break;

        default:
            code = KeychainManagerErrorUnknown;
            description = [NSString stringWithFormat:@"Keychain error: %d", (int)status];
            break;
    }

    return [self errorWithCode:code description:description];
}

+ (NSError *)errorWithCode:(KeychainManagerErrorCode)code description:(NSString *)description {
    NSDictionary *userInfo = @{NSLocalizedDescriptionKey: description};
    return [NSError errorWithDomain:kKeychainManagerErrorDomain
                               code:code
                           userInfo:userInfo];
}

@end
