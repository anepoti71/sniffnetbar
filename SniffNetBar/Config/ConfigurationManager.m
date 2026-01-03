//
//  ConfigurationManager.m
//  SniffNetBar
//
//  Centralized configuration management
//

#import "ConfigurationManager.h"
#import "KeychainManager.h"
#import "Logger.h"

// Define keychain identifier constants
NSString * const kVirusTotalAPIKeyIdentifier = @"VirusTotalAPIKey";
NSString * const kAbuseIPDBAPIKeyIdentifier = @"AbuseIPDBAPIKey";

@interface ConfigurationManager ()
@property (nonatomic, strong) NSDictionary *configuration;
@end

@implementation ConfigurationManager

static BOOL sConfigurationManagerInitializing = NO;

BOOL SNBConfigurationManagerIsInitializing(void) {
    return sConfigurationManagerInitializing;
}

+ (instancetype)sharedManager {
    static ConfigurationManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[self alloc] init];
    });
    return sharedInstance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        sConfigurationManagerInitializing = YES;
        [self loadConfiguration];
        sConfigurationManagerInitializing = NO;
    }
    return self;
}

- (void)loadConfiguration {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"Configuration" ofType:@"plist"];
    if (!path) {
        SNBLogConfigError("Configuration.plist not found in bundle!");
        [self loadDefaultConfiguration];
        return;
    }

    NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!config) {
        SNBLogConfigError("Failed to load Configuration.plist!");
        [self loadDefaultConfiguration];
        return;
    }

    self.configuration = config;
    SNBLogConfigInfo("Configuration loaded successfully from %{public}@", path);
    NSError *validationError = nil;
    if (![self validateConfiguration:&validationError]) {
        SNBLogConfigError("Configuration validation failed: %{public}@",
                          validationError.localizedDescription);
    }
}

- (void)loadDefaultConfiguration {
    // Fallback to hardcoded defaults if plist is missing
    self.configuration = @{
        @"DebugLogging": @YES,
        @"MenuUpdateInterval": @1.0,
        @"DeviceListRefreshInterval": @30.0,
        @"MaxTopHostsToShow": @5,
        @"MaxTopConnectionsToShow": @10,
        @"MapMenuViewHeight": @220.0,
        @"MenuFixedWidth": @420.0,
        @"ReconnectDelay": @5.0,
        @"MaxReconnectAttempts": @3,
        @"MaxLocationCacheSize": @500,
        @"LocationCacheExpirationTime": @7200.0,
        @"DefaultMapProvider": @"ipinfo.io",
        @"MaxConnectionLinesToShow": @10,
        @"ConnectionLineColor": @"#ff7a18",
        @"ConnectionLineWeight": @3,
        @"ConnectionLineOpacity": @0.9
    };
    SNBLogConfigInfo("Using default configuration");
    NSError *validationError = nil;
    if (![self validateConfiguration:&validationError]) {
        SNBLogConfigError("Default configuration validation failed: %{public}@",
                          validationError.localizedDescription);
    }
}

- (void)reloadConfiguration {
    [self loadConfiguration];
}

- (BOOL)validateConfiguration:(NSError **)error {
    NSMutableArray<NSString *> *issues = [NSMutableArray array];

    if (self.menuUpdateInterval <= 0) {
        [issues addObject:@"MenuUpdateInterval must be greater than 0."];
    }
    if (self.deviceListRefreshInterval <= 0) {
        [issues addObject:@"DeviceListRefreshInterval must be greater than 0."];
    }
    if (self.menuFixedWidth <= 0 || self.mapMenuViewHeight <= 0) {
        [issues addObject:@"MenuFixedWidth and MapMenuViewHeight must be greater than 0."];
    }
    if (self.maxTopHostsToShow == 0 || self.maxTopConnectionsToShow == 0) {
        [issues addObject:@"MaxTopHostsToShow and MaxTopConnectionsToShow must be greater than 0."];
    }
    if (self.maxReconnectAttempts == 0) {
        [issues addObject:@"MaxReconnectAttempts must be greater than 0."];
    }
    if (self.reconnectDelay < 0) {
        [issues addObject:@"ReconnectDelay must be 0 or greater."];
    }
    if (self.maxLocationCacheSize == 0 || self.locationCacheExpirationTime <= 0) {
        [issues addObject:@"Location cache size and expiration time must be greater than 0."];
    }
    if (self.threatIntelCacheSize == 0 || self.threatIntelCacheTTL <= 0) {
        [issues addObject:@"Threat intel cache size and TTL must be greater than 0."];
    }
    if (self.defaultMapProvider.length == 0) {
        [issues addObject:@"DefaultMapProvider must be a non-empty string."];
    }

    if (self.virusTotalEnabled) {
        if (self.virusTotalAPIURL.length == 0) {
            [issues addObject:@"VirusTotalAPIURL must be set when VirusTotal is enabled."];
        }
        if (self.virusTotalAPIKey.length == 0) {
            [issues addObject:@"VirusTotalAPIKey must be set when VirusTotal is enabled."];
        }
        if (self.virusTotalMaxRequestsPerMin <= 0) {
            [issues addObject:@"VirusTotalMaxRequestsPerMin must be greater than 0."];
        }
        if (self.virusTotalTimeout <= 0) {
            [issues addObject:@"VirusTotalTimeout must be greater than 0."];
        }
    }

    if (self.abuseIPDBEnabled) {
        if (self.abuseIPDBAPIURL.length == 0) {
            [issues addObject:@"AbuseIPDBAPIURL must be set when AbuseIPDB is enabled."];
        }
        if (self.abuseIPDBAPIKey.length == 0) {
            [issues addObject:@"AbuseIPDBAPIKey must be set when AbuseIPDB is enabled."];
        }
        if (self.abuseIPDBMaxRequestsPerMin <= 0) {
            [issues addObject:@"AbuseIPDBMaxRequestsPerMin must be greater than 0."];
        }
        if (self.abuseIPDBTimeout <= 0) {
            [issues addObject:@"AbuseIPDBTimeout must be greater than 0."];
        }
    }

    if (issues.count == 0) {
        return YES;
    }

    if (error) {
        NSString *description = [issues componentsJoinedByString:@" "];
        *error = [NSError errorWithDomain:@"ConfigurationManager"
                                     code:1001
                                 userInfo:@{NSLocalizedDescriptionKey: description}];
    }
    return NO;
}

#pragma mark - Logging Configuration

- (BOOL)debugLogging {
    return [self.configuration[@"DebugLogging"] boolValue];
}

#pragma mark - UI Update Configuration

- (NSTimeInterval)menuUpdateInterval {
    NSNumber *value = self.configuration[@"MenuUpdateInterval"];
    return value ? [value doubleValue] : 1.0;
}

- (NSTimeInterval)deviceListRefreshInterval {
    NSNumber *value = self.configuration[@"DeviceListRefreshInterval"];
    return value ? [value doubleValue] : 30.0;
}

- (NSUInteger)maxTopHostsToShow {
    NSNumber *value = self.configuration[@"MaxTopHostsToShow"];
    return value ? [value unsignedIntegerValue] : 5;
}

- (NSUInteger)maxTopConnectionsToShow {
    NSNumber *value = self.configuration[@"MaxTopConnectionsToShow"];
    return value ? [value unsignedIntegerValue] : 10;
}

- (CGFloat)mapMenuViewHeight {
    NSNumber *value = self.configuration[@"MapMenuViewHeight"];
    return value ? [value doubleValue] : 220.0;
}

- (CGFloat)menuFixedWidth {
    NSNumber *value = self.configuration[@"MenuFixedWidth"];
    if (!value) {
        value = self.configuration[@"MenuMaxWidth"];
    }
    return value ? [value doubleValue] : 420.0;
}

#pragma mark - Reconnection Configuration

- (NSTimeInterval)reconnectDelay {
    NSNumber *value = self.configuration[@"ReconnectDelay"];
    return value ? [value doubleValue] : 5.0;
}

- (NSUInteger)maxReconnectAttempts {
    NSNumber *value = self.configuration[@"MaxReconnectAttempts"];
    return value ? [value unsignedIntegerValue] : 3;
}

#pragma mark - Location Cache Configuration

- (NSUInteger)maxLocationCacheSize {
    NSNumber *value = self.configuration[@"MaxLocationCacheSize"];
    return value ? [value unsignedIntegerValue] : 500;
}

- (NSTimeInterval)locationCacheExpirationTime {
    NSNumber *value = self.configuration[@"LocationCacheExpirationTime"];
    return value ? [value doubleValue] : 7200.0;
}

#pragma mark - Map Configuration

- (NSString *)defaultMapProvider {
    NSString *value = self.configuration[@"DefaultMapProvider"];
    return value.length > 0 ? value : @"ipinfo.io";
}

- (NSUInteger)maxConnectionLinesToShow {
    NSNumber *value = self.configuration[@"MaxConnectionLinesToShow"];
    return value ? [value unsignedIntegerValue] : 10;
}

- (NSString *)connectionLineColor {
    NSString *value = self.configuration[@"ConnectionLineColor"];
    return value.length > 0 ? value : @"#ff7a18";
}

- (NSInteger)connectionLineWeight {
    NSNumber *value = self.configuration[@"ConnectionLineWeight"];
    return value ? [value integerValue] : 3;
}

- (CGFloat)connectionLineOpacity {
    NSNumber *value = self.configuration[@"ConnectionLineOpacity"];
    return value ? [value doubleValue] : 0.9;
}

#pragma mark - Threat Intelligence Configuration

- (NSUInteger)threatIntelCacheSize {
    NSNumber *value = self.configuration[@"ThreatIntelCacheSize"];
    return value ? [value unsignedIntegerValue] : 1000;
}

- (NSTimeInterval)threatIntelCacheTTL {
    NSNumber *value = self.configuration[@"ThreatIntelCacheTTL"];
    return value ? [value doubleValue] : 3600.0;
}

#pragma mark - VirusTotal Provider Configuration

- (BOOL)virusTotalEnabled {
    NSNumber *value = self.configuration[@"VirusTotalEnabled"];
    return value ? [value boolValue] : NO;
}

- (NSString *)virusTotalAPIURL {
    NSString *value = self.configuration[@"VirusTotalAPIURL"];
    return value.length > 0 ? value : @"https://www.virustotal.com/api/v3";
}

- (NSString *)virusTotalAPIKey {
    // Try keychain first
    NSError *error = nil;
    NSString *keychainKey = [KeychainManager getAPIKeyForIdentifier:kVirusTotalAPIKeyIdentifier
                                                              error:&error];
    if (keychainKey.length > 0) {
        return keychainKey;
    }

    // Fall back to plist for backward compatibility (migration scenario)
    NSString *plistKey = self.configuration[@"VirusTotalAPIKey"];
    if (plistKey.length > 0 && ![plistKey isEqualToString:@"YOUR_API_KEY_HERE"]) {
        // Migrate to keychain
        [KeychainManager saveAPIKey:plistKey
                      forIdentifier:kVirusTotalAPIKeyIdentifier
                              error:nil];
        SNBLogConfigInfo("Migrated VirusTotal API key to keychain");
        return plistKey;
    }

    return @"";
}

- (NSTimeInterval)virusTotalTimeout {
    NSNumber *value = self.configuration[@"VirusTotalTimeout"];
    return value ? [value doubleValue] : 10.0;
}

- (NSInteger)virusTotalMaxRequestsPerMin {
    NSNumber *value = self.configuration[@"VirusTotalMaxRequestsPerMin"];
    return value ? [value integerValue] : 4;
}

- (NSTimeInterval)virusTotalTTL {
    NSNumber *value = self.configuration[@"VirusTotalTTL"];
    return value ? [value doubleValue] : 86400.0;
}

#pragma mark - AbuseIPDB Provider Configuration

- (BOOL)abuseIPDBEnabled {
    NSNumber *value = self.configuration[@"AbuseIPDBEnabled"];
    return value ? [value boolValue] : NO;
}

- (NSString *)abuseIPDBAPIURL {
    NSString *value = self.configuration[@"AbuseIPDBAPIURL"];
    return value.length > 0 ? value : @"https://api.abuseipdb.com/api/v2";
}

- (NSString *)abuseIPDBAPIKey {
    // Try keychain first
    NSError *error = nil;
    NSString *keychainKey = [KeychainManager getAPIKeyForIdentifier:kAbuseIPDBAPIKeyIdentifier
                                                              error:&error];
    if (keychainKey.length > 0) {
        return keychainKey;
    }

    // Fall back to plist for backward compatibility (migration scenario)
    NSString *plistKey = self.configuration[@"AbuseIPDBAPIKey"];
    if (plistKey.length > 0 && ![plistKey isEqualToString:@"YOUR_API_KEY_HERE"]) {
        // Migrate to keychain
        [KeychainManager saveAPIKey:plistKey
                      forIdentifier:kAbuseIPDBAPIKeyIdentifier
                              error:nil];
        SNBLogConfigInfo("Migrated AbuseIPDB API key to keychain");
        return plistKey;
    }

    return @"";
}

- (NSTimeInterval)abuseIPDBTimeout {
    NSNumber *value = self.configuration[@"AbuseIPDBTimeout"];
    return value ? [value doubleValue] : 10.0;
}

- (NSInteger)abuseIPDBMaxRequestsPerMin {
    NSNumber *value = self.configuration[@"AbuseIPDBMaxRequestsPerMin"];
    return value ? [value integerValue] : 60;
}

- (NSTimeInterval)abuseIPDBTTL {
    NSNumber *value = self.configuration[@"AbuseIPDBTTL"];
    return value ? [value doubleValue] : 86400.0;
}

- (NSInteger)abuseIPDBMaxAgeInDays {
    NSNumber *value = self.configuration[@"AbuseIPDBMaxAgeInDays"];
    return value ? [value integerValue] : 90;
}

#pragma mark - API Key Management

- (void)setAPIKey:(nullable NSString *)apiKey forIdentifier:(NSString *)identifier {
    NSError *error = nil;
    if ([KeychainManager saveAPIKey:apiKey forIdentifier:identifier error:&error]) {
        SNBLogConfigInfo("API key saved to keychain: %{public}@", identifier);
    } else {
        SNBLogConfigError("Failed to save API key to keychain: %{public}@, error: %{public}@",
                          identifier, error.localizedDescription);
    }
}

@end
