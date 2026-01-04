//
//  ConfigurationManager.h
//  SniffNetBar
//
//  Centralized configuration management
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Keychain identifier constants for API keys
extern NSString * const kVirusTotalAPIKeyIdentifier;
extern NSString * const kAbuseIPDBAPIKeyIdentifier;
extern NSString * const kGreyNoiseAPIKeyIdentifier;

/**
 * Centralized configuration manager that loads settings from Configuration.plist
 * and provides a singleton interface for accessing configuration values throughout the app.
 */
@interface ConfigurationManager : NSObject

// Singleton instance
+ (instancetype)sharedManager;

// Logging Configuration
@property (nonatomic, readonly) BOOL debugLogging;

// UI Update Configuration
@property (nonatomic, readonly) NSTimeInterval menuUpdateInterval;
@property (nonatomic, readonly) NSTimeInterval deviceListRefreshInterval;
@property (nonatomic, readonly) NSUInteger maxTopHostsToShow;
@property (nonatomic, readonly) NSUInteger maxTopConnectionsToShow;
@property (nonatomic, readonly) CGFloat mapMenuViewHeight;
@property (nonatomic, readonly) CGFloat menuFixedWidth;

// Reconnection Configuration
@property (nonatomic, readonly) NSTimeInterval reconnectDelay;
@property (nonatomic, readonly) NSUInteger maxReconnectAttempts;

// Location Cache Configuration
@property (nonatomic, readonly) NSUInteger maxLocationCacheSize;
@property (nonatomic, readonly) NSTimeInterval locationCacheExpirationTime;

// Map Configuration
@property (nonatomic, readonly) NSString *defaultMapProvider;
@property (nonatomic, readonly) NSUInteger maxConnectionLinesToShow;
@property (nonatomic, readonly) NSString *connectionLineColor;
@property (nonatomic, readonly) NSInteger connectionLineWeight;
@property (nonatomic, readonly) CGFloat connectionLineOpacity;

// Threat Intelligence Configuration
@property (nonatomic, readonly) NSUInteger threatIntelCacheSize;
@property (nonatomic, readonly) NSTimeInterval threatIntelCacheTTL;

// Explainability Configuration
@property (nonatomic, readonly) BOOL explainabilityEnabled;
@property (nonatomic, readonly) NSString *explainabilityOllamaBaseURL;
@property (nonatomic, readonly) NSString *explainabilityOllamaModel;
@property (nonatomic, readonly) NSTimeInterval explainabilityOllamaTimeout;
@property (nonatomic, readonly) double explainabilityMinScore;

// VirusTotal Provider Configuration
@property (nonatomic, readonly) BOOL virusTotalEnabled;
@property (nonatomic, readonly) NSString *virusTotalAPIURL;
@property (nonatomic, readonly) NSString *virusTotalAPIKey;
@property (nonatomic, readonly) NSTimeInterval virusTotalTimeout;
@property (nonatomic, readonly) NSInteger virusTotalMaxRequestsPerMin;
@property (nonatomic, readonly) NSTimeInterval virusTotalTTL;

// AbuseIPDB Provider Configuration
@property (nonatomic, readonly) BOOL abuseIPDBEnabled;
@property (nonatomic, readonly) NSString *abuseIPDBAPIURL;
@property (nonatomic, readonly) NSString *abuseIPDBAPIKey;
@property (nonatomic, readonly) NSTimeInterval abuseIPDBTimeout;
@property (nonatomic, readonly) NSInteger abuseIPDBMaxRequestsPerMin;
@property (nonatomic, readonly) NSTimeInterval abuseIPDBTTL;
@property (nonatomic, readonly) NSInteger abuseIPDBMaxAgeInDays;

// GreyNoise Provider Configuration
@property (nonatomic, readonly) BOOL greyNoiseEnabled;
@property (nonatomic, readonly) NSString *greyNoiseAPIURL;
@property (nonatomic, readonly) NSString *greyNoiseAPIKey;
@property (nonatomic, readonly) NSTimeInterval greyNoiseTimeout;
@property (nonatomic, readonly) NSInteger greyNoiseMaxRequestsPerMin;
@property (nonatomic, readonly) NSTimeInterval greyNoiseTTL;

/**
 * Reload configuration from the plist file
 * Useful if the configuration file is modified at runtime
 */
- (void)reloadConfiguration;
/**
 * Validate configuration values and required dependencies.
 * @param error Optional error describing validation failures.
 */
- (BOOL)validateConfiguration:(NSError **)error;

/**
 * Set an API key in the keychain
 * @param apiKey The API key to store (if nil or empty, removes the keychain item)
 * @param identifier The keychain identifier (use kVirusTotalAPIKeyIdentifier, kAbuseIPDBAPIKeyIdentifier, or kGreyNoiseAPIKeyIdentifier)
 */
- (void)setAPIKey:(nullable NSString *)apiKey forIdentifier:(NSString *)identifier;

@end

NS_ASSUME_NONNULL_END

// C helper for early startup logging to avoid recursive sharedManager access.
BOOL SNBConfigurationManagerIsInitializing(void);
