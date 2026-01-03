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
#import "IPAddressUtilities.h"

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
                NSLog(@"[ThreatIntelCoordinator] Failed to configure VirusTotal: %@", error.localizedDescription);
            } else {
                SNBLog(@"VirusTotal provider configured successfully");
            }
        }];
        [self.facade addProvider:vtProvider];
        SNBLog(@"VirusTotal provider added");
    } else {
        SNBLog(@"VirusTotal provider disabled (enabled: %@, has key: %@)",
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
                NSLog(@"[ThreatIntelCoordinator] Failed to configure AbuseIPDB: %@", error.localizedDescription);
            } else {
                SNBLog(@"AbuseIPDB provider configured successfully");
            }
        }];
        [self.facade addProvider:abuseProvider];
        SNBLog(@"AbuseIPDB provider added");
    } else {
        SNBLog(@"AbuseIPDB provider disabled (enabled: %@, has key: %@)",
               config.abuseIPDBEnabled ? @"YES" : @"NO",
               config.abuseIPDBAPIKey.length > 0 ? @"YES" : @"NO");
    }

    SNBLog(@"Threat Intelligence initialized (enabled: %@)", self.isEnabled ? @"YES" : @"NO");
}

- (void)toggleEnabled {
    [self setEnabled:!self.isEnabled];
}

- (void)setEnabled:(BOOL)enabled {
    _enabled = enabled;
    self.facade.enabled = enabled;
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:SNBUserDefaultsKeyThreatIntelEnabled];
    [[NSUserDefaults standardUserDefaults] synchronize];

    SNBLog(@"Threat Intelligence %@", enabled ? @"ENABLED" : @"DISABLED");

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
        SNBLog(@"Skipping threat intel for private/local IP: %@", ipAddress);
        return;
    }
    if (self.results[ipAddress]) {
        return;
    }

    [self.facade enrichIP:ipAddress completion:^(TIEnrichmentResponse *response, NSError *error) {
        if (response && response.scoringResult) {
            self.results[ipAddress] = response;

            TIScoringResult *scoring = response.scoringResult;
            SNBLog(@"Threat Intel: %@ -> %@ (score: %ld, confidence: %.2f)",
                   ipAddress, [scoring verdictString], (long)scoring.finalScore, scoring.confidence);

            if (completion) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    completion();
                });
            }
        } else if (error) {
            SNBLog(@"Threat Intel error for %@: %@", ipAddress, error.localizedDescription);
        }
    }];
}

@end
