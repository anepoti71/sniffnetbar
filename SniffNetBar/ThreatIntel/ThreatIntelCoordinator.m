//
//  ThreatIntelCoordinator.m
//  SniffNetBar
//

#import "ThreatIntelCoordinator.h"
#import "ConfigurationManager.h"
#import "ThreatIntelFacade.h"
#import "ThreatIntelModels.h"
#import "UserDefaultsKeys.h"
#import "VirusTotalProvider.h"
#import "AbuseIPDBProvider.h"
#import "GreyNoiseProvider.h"
#import "IPAddressUtilities.h"
#import "Logger.h"

@interface ThreatIntelCoordinator ()
@property (nonatomic, strong) ConfigurationManager *configuration;
@property (nonatomic, strong) NSMutableDictionary<NSString *, TIEnrichmentResponse *> *results;
@end

@implementation ThreatIntelCoordinator

- (instancetype)initWithConfiguration:(ConfigurationManager *)configuration {
    self = [super init];
    if (self) {
        _configuration = configuration;
        _facade = [ThreatIntelFacade sharedInstance];
        _results = [NSMutableDictionary dictionary];
        [self loadEnabledState];
        [self configureProviders];
    }
    return self;
}

- (void)loadEnabledState {
    BOOL enabled = [[NSUserDefaults standardUserDefaults] boolForKey:SNBUserDefaultsKeyThreatIntelEnabled];
    self.facade.enabled = enabled;
    _enabled = enabled;
}

- (void)configureProviders {
    ConfigurationManager *config = self.configuration;

    if (config.virusTotalEnabled && config.virusTotalAPIKey.length > 0) {
        VirusTotalProvider *vtProvider = [[VirusTotalProvider alloc] initWithTTL:config.virusTotalTTL
                                                                      negativeTTL:3600.0];
        [vtProvider configureWithBaseURL:config.virusTotalAPIURL
                                  APIKey:config.virusTotalAPIKey
                                 timeout:config.virusTotalTimeout
                       maxRequestsPerMin:config.virusTotalMaxRequestsPerMin
                              completion:^(NSError *error) {
            if (error) {
                SNBLogThreatIntelError("Failed to configure VirusTotal: %{public}@", error.localizedDescription);
            } else {
                SNBLogThreatIntelInfo("VirusTotal provider configured successfully");
            }
        }];
        [self.facade addProvider:vtProvider];
        SNBLogThreatIntelDebug("VirusTotal provider added");
    } else {
        SNBLogThreatIntelDebug("VirusTotal provider disabled (enabled: %{public}@, has key: %{public}@)",
                               config.virusTotalEnabled ? @"YES" : @"NO",
                               config.virusTotalAPIKey.length > 0 ? @"YES" : @"NO");
    }

    if (config.abuseIPDBEnabled && config.abuseIPDBAPIKey.length > 0) {
        AbuseIPDBProvider *abuseProvider = [[AbuseIPDBProvider alloc] initWithTTL:config.abuseIPDBTTL
                                                                       negativeTTL:3600.0
                                                                     maxAgeInDays:config.abuseIPDBMaxAgeInDays];
        [abuseProvider configureWithBaseURL:config.abuseIPDBAPIURL
                                     APIKey:config.abuseIPDBAPIKey
                                    timeout:config.abuseIPDBTimeout
                          maxRequestsPerMin:config.abuseIPDBMaxRequestsPerMin
                                 completion:^(NSError *error) {
            if (error) {
                SNBLogThreatIntelError("Failed to configure AbuseIPDB: %{public}@", error.localizedDescription);
            } else {
                SNBLogThreatIntelInfo("AbuseIPDB provider configured successfully");
            }
        }];
        [self.facade addProvider:abuseProvider];
        SNBLogThreatIntelDebug("AbuseIPDB provider added");
    } else {
        SNBLogThreatIntelDebug("AbuseIPDB provider disabled (enabled: %{public}@, has key: %{public}@)",
                               config.abuseIPDBEnabled ? @"YES" : @"NO",
                               config.abuseIPDBAPIKey.length > 0 ? @"YES" : @"NO");
    }

    if (config.greyNoiseEnabled && config.greyNoiseAPIKey.length > 0) {
        GreyNoiseProvider *greyNoiseProvider = [[GreyNoiseProvider alloc] initWithTTL:config.greyNoiseTTL
                                                                           negativeTTL:3600.0];
        [greyNoiseProvider configureWithBaseURL:config.greyNoiseAPIURL
                                         APIKey:config.greyNoiseAPIKey
                                        timeout:config.greyNoiseTimeout
                              maxRequestsPerMin:config.greyNoiseMaxRequestsPerMin
                                     completion:^(NSError *error) {
            if (error) {
                SNBLogThreatIntelError("Failed to configure GreyNoise: %{public}@", error.localizedDescription);
            } else {
                SNBLogThreatIntelInfo("GreyNoise provider configured successfully");
            }
        }];
        [self.facade addProvider:greyNoiseProvider];
        SNBLogThreatIntelDebug("GreyNoise provider added");
    } else {
        SNBLogThreatIntelDebug("GreyNoise provider disabled (enabled: %{public}@, has key: %{public}@)",
                               config.greyNoiseEnabled ? @"YES" : @"NO",
                               config.greyNoiseAPIKey.length > 0 ? @"YES" : @"NO");
    }

    SNBLogThreatIntelInfo("Threat Intelligence initialized (enabled: %{public}@)", self.isEnabled ? @"YES" : @"NO");
}

- (void)toggleEnabled {
    [self setEnabled:!self.isEnabled];
}

- (void)setEnabled:(BOOL)enabled {
    _enabled = enabled;
    self.facade.enabled = enabled;
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:SNBUserDefaultsKeyThreatIntelEnabled];
    [[NSUserDefaults standardUserDefaults] synchronize];

    SNBLogThreatIntelInfo("Threat Intelligence %{public}@", enabled ? @"ENABLED" : @"DISABLED");

    if (!enabled) {
        [self.results removeAllObjects];
    }
}

- (NSDictionary<NSString *, TIEnrichmentResponse *> *)resultsSnapshot {
    return [self.results copy];
}

- (NSDictionary *)cacheStats {
    return [self.facade cacheStats];
}

- (void)enrichIPIfNeeded:(NSString *)ipAddress completion:(dispatch_block_t)completion {
    if (!self.isEnabled) {
        return;
    }
    if (![IPAddressUtilities isPublicIPAddress:ipAddress]) {
        SNBLogThreatIntelDebug("Skipping threat intel for private/local IP: %{" SNB_IP_PRIVACY "}@", ipAddress);
        return;
    }
    if (self.results[ipAddress]) {
        return;
    }

    [self.facade enrichIP:ipAddress completion:^(TIEnrichmentResponse *response, NSError *error) {
        if (response && response.scoringResult) {
            self.results[ipAddress] = response;

            TIScoringResult *scoring = response.scoringResult;
            SNBLogThreatIntelInfo("Threat Intel: %{" SNB_IP_PRIVACY "}@ -> %{public}@ (score: %ld, confidence: %.2f)",
                                  ipAddress, [scoring verdictString], (long)scoring.finalScore, scoring.confidence);

            if (completion) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion();
                });
            }
        } else if (error) {
            SNBLogThreatIntelWarn("Threat Intel error for %{" SNB_IP_PRIVACY "}@: %{public}@", ipAddress, error.localizedDescription);
        }
    }];
}

@end
