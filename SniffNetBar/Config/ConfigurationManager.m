//
//  ConfigurationManager.m
//  SniffNetBar
//
//  Centralized configuration management
//

#import "ConfigurationManager.h"

@interface ConfigurationManager ()
@property (nonatomic, strong) NSDictionary *configuration;
@end

@implementation ConfigurationManager

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
        [self loadConfiguration];
    }
    return self;
}

- (void)loadConfiguration {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"Configuration" ofType:@"plist"];
    if (!path) {
        NSLog(@"[ConfigurationManager] ERROR: Configuration.plist not found in bundle!");
        [self loadDefaultConfiguration];
        return;
    }

    NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!config) {
        NSLog(@"[ConfigurationManager] ERROR: Failed to load Configuration.plist!");
        [self loadDefaultConfiguration];
        return;
    }

    self.configuration = config;
    NSLog(@"[ConfigurationManager] Configuration loaded successfully from %@", path);
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
    NSLog(@"[ConfigurationManager] Using default configuration");
}

- (void)reloadConfiguration {
    [self loadConfiguration];
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
    NSString *value = self.configuration[@"VirusTotalAPIKey"];
    return value.length > 0 ? value : @"";
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
    NSString *value = self.configuration[@"AbuseIPDBAPIKey"];
    return value.length > 0 ? value : @"";
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

@end
