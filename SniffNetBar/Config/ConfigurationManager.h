//
//  ConfigurationManager.h
//  SniffNetBar
//
//  Centralized configuration management
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

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

/**
 * Reload configuration from the plist file
 * Useful if the configuration file is modified at runtime
 */
- (void)reloadConfiguration;

@end

// Convenience logging macro that respects the debugLogging configuration
#define SNBLog(fmt, ...) \
    do { \
        if ([ConfigurationManager sharedManager].debugLogging) { \
            NSLog((@"[SniffNetBar] " fmt), ##__VA_ARGS__); \
        } \
    } while(0)

NS_ASSUME_NONNULL_END
