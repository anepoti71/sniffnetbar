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

- (NSString *)availabilityMessage {
    if (!self.isEnabled) {
        return nil;
    }
    return [self.facade availabilityMessage];
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
            // Validate scoring result before logging
            if (scoring && scoring.indicator) {
                NSInteger score = scoring.finalScore;
                double confidence = scoring.confidence;
                NSString *verdict = [scoring verdictString];

                // Sanity check the values
                if (score < 0 || score > 10000) {
                    SNBLogThreatIntelError("Invalid threat intel score for %{" SNB_IP_PRIVACY "}@: %ld (corrupted data)",
                                          ipAddress, (long)score);
                } else {
                    SNBLogThreatIntelInfo("Threat Intel: %{" SNB_IP_PRIVACY "}@ -> %{public}@ (score: %ld, confidence: %.2f)",
                                          ipAddress, verdict ?: @"Unknown", (long)score, confidence);
                }
            } else {
                SNBLogThreatIntelWarn("Threat Intel: %{" SNB_IP_PRIVACY "}@ -> incomplete scoring result", ipAddress);
            }

            if (completion) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion();
                });
            }
        } else if (error) {
            NSString *provider = [self providerNameFromError:error];
            if (provider.length > 0) {
                SNBLogThreatIntelWarn("Threat Intel error for %{" SNB_IP_PRIVACY "}@ (%{public}@): %{public}@",
                                      ipAddress, provider, error.localizedDescription);
            } else {
                SNBLogThreatIntelWarn("Threat Intel error for %{" SNB_IP_PRIVACY "}@: %{public}@", ipAddress, error.localizedDescription);
            }
        }
    }];
}

- (NSString *)providerNameFromError:(NSError *)error {
    if (!error.domain || error.domain.length == 0) {
        return nil;
    }
    if ([error.domain isEqualToString:@"AbuseIPDBProvider"]) {
        return @"AbuseIPDB";
    }
    if ([error.domain isEqualToString:@"VirusTotalProvider"]) {
        return @"VirusTotal";
    }
    if ([error.domain isEqualToString:@"GreyNoiseProvider"]) {
        return @"GreyNoise";
    }
    NSArray<NSError *> *providerErrors = error.userInfo[@"providerErrors"];
    if ([providerErrors isKindOfClass:[NSArray class]] && providerErrors.count > 0) {
        NSMutableSet<NSString *> *names = [NSMutableSet set];
        for (NSError *providerError in providerErrors) {
            NSString *name = [self providerNameFromError:providerError];
            if (name.length > 0) {
                [names addObject:name];
            }
        }
        if (names.count == 1) {
            return names.anyObject;
        }
        if (names.count > 1) {
            NSArray<NSString *> *sorted = [[names allObjects] sortedArrayUsingSelector:@selector(compare:)];
            return [sorted componentsJoinedByString:@", "];
        }
    }
    return nil;
}

@end
