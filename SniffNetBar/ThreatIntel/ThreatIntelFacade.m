//
//  ThreatIntelFacade.m
//  SniffNetBar
//

#import "ThreatIntelFacade.h"
#import "ThreatIntelCache.h"
#import "ConfigurationManager.h"

@interface ThreatIntelFacade ()
@property (nonatomic, strong) NSMutableArray<id<ThreatIntelProvider>> *providers;
@property (nonatomic, strong) ThreatIntelCache *cache;
@property (nonatomic, strong) dispatch_queue_t enrichmentQueue;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSMutableArray *> *inFlightRequests;
@end

@implementation ThreatIntelFacade

+ (instancetype)sharedInstance {
    static ThreatIntelFacade *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _providers = [NSMutableArray array];
        _cache = [[ThreatIntelCache alloc] initWithMaxSize:5000];
        _enrichmentQueue = dispatch_queue_create("com.sniffnetbar.threatintel.enrichment", DISPATCH_QUEUE_CONCURRENT);
        _inFlightRequests = [NSMutableDictionary dictionary];
        _enabled = NO;
    }
    return self;
}

- (void)configureWithProviders:(NSArray<id<ThreatIntelProvider>> *)providers {
    [self.providers removeAllObjects];
    [self.providers addObjectsFromArray:providers];
    SNBLog(@"ThreatIntelFacade: Configured with %lu providers", (unsigned long)providers.count);
}

- (void)addProvider:(id<ThreatIntelProvider>)provider {
    [self.providers addObject:provider];
    SNBLog(@"ThreatIntelFacade: Added provider %@", provider.name);
}

- (void)enrichIP:(NSString *)ipAddress completion:(TIEnrichmentCompletion)completion {
    TIIndicator *indicator = [TIIndicator indicatorWithIP:ipAddress];
    [self enrichIndicator:indicator completion:completion];
}

- (void)enrichIndicator:(TIIndicator *)indicator completion:(TIEnrichmentCompletion)completion {
    if (!self.enabled) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:TIErrorDomain
                                                 code:TIErrorCodeProviderUnavailable
                                             userInfo:@{NSLocalizedDescriptionKey: @"Threat intelligence is disabled"}];
            completion(nil, error);
        }
        return;
    }

    // Check for in-flight requests (single-flight pattern)
    NSString *key = [self keyForIndicator:indicator];

    @synchronized(self.inFlightRequests) {
        NSMutableArray *callbacks = self.inFlightRequests[key];
        if (callbacks) {
            // Already in flight, add callback
            [callbacks addObject:[completion copy]];
            SNBLog(@"ThreatIntelFacade: Coalescing request for %@", indicator.value);
            return;
        }

        // Start new request
        self.inFlightRequests[key] = [NSMutableArray arrayWithObject:[completion copy]];
    }

    // Execute enrichment
    dispatch_async(self.enrichmentQueue, ^{
        [self performEnrichmentForIndicator:indicator];
    });
}

- (void)performEnrichmentForIndicator:(TIIndicator *)indicator {
    NSDate *startTime = [NSDate date];
    NSString *key = [self keyForIndicator:indicator];

    // Get applicable providers
    NSArray<id<ThreatIntelProvider>> *applicableProviders = [self getApplicableProvidersForIndicator:indicator];

    if (applicableProviders.count == 0) {
        [self completeEnrichmentForKey:key response:nil error:[self errorNoProviders]];
        return;
    }

    // Create dispatch group for concurrent provider queries
    dispatch_group_t group = dispatch_group_create();
    NSMutableArray<TIResult *> *results = [NSMutableArray array];
    NSMutableArray<NSError *> *errors = [NSMutableArray array];
    __block NSInteger cacheHits = 0;

    for (id<ThreatIntelProvider> provider in applicableProviders) {
        dispatch_group_enter(group);

        // Check cache first
        TIResult *cachedResult = [self.cache getResultForProvider:provider.name indicator:indicator];

        if (cachedResult) {
            @synchronized(results) {
                [results addObject:cachedResult];
                cacheHits++;
            }
            dispatch_group_leave(group);
            continue;
        }

        // Query provider
        [provider enrichIndicator:indicator completion:^(TIResult *result, NSError *error) {
            if (result) {
                @synchronized(results) {
                    [results addObject:result];
                }
                // Cache result
                [self.cache setResult:result];
            } else if (error) {
                @synchronized(errors) {
                    [errors addObject:error];
                }
            }
            dispatch_group_leave(group);
        }];
    }

    // Wait for all providers (with timeout)
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC));
    dispatch_group_wait(group, timeout);

    // Calculate scoring
    TIScoringResult *scoringResult = [self calculateScoringForResults:results indicator:indicator];

    // Build response
    TIEnrichmentResponse *response = [[TIEnrichmentResponse alloc] init];
    response.indicator = indicator;
    response.providerResults = [results copy];
    response.scoringResult = scoringResult;
    response.duration = [[NSDate date] timeIntervalSinceDate:startTime];
    response.cacheHits = cacheHits;

    SNBLog(@"ThreatIntelFacade: Enrichment completed for %@ - %lu providers, %ld hits, score=%ld, verdict=%@",
           indicator.value, (unsigned long)results.count, (long)cacheHits,
           (long)scoringResult.finalScore, [scoringResult verdictString]);

    [self completeEnrichmentForKey:key response:response error:nil];
}

- (void)completeEnrichmentForKey:(NSString *)key
                        response:(TIEnrichmentResponse *)response
                           error:(NSError *)error {
    NSArray *callbacks = nil;

    @synchronized(self.inFlightRequests) {
        callbacks = [self.inFlightRequests[key] copy];
        [self.inFlightRequests removeObjectForKey:key];
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        for (TIEnrichmentCompletion completion in callbacks) {
            completion(response, error);
        }
    });
}

- (NSArray<id<ThreatIntelProvider>> *)getApplicableProvidersForIndicator:(TIIndicator *)indicator {
    NSMutableArray *applicable = [NSMutableArray array];
    for (id<ThreatIntelProvider> provider in self.providers) {
        if ([provider supportsIndicatorType:indicator.type]) {
            [applicable addObject:provider];
        }
    }
    return applicable;
}

// MARK: - Simple Scoring Engine

- (TIScoringResult *)calculateScoringForResults:(NSArray<TIResult *> *)results
                                      indicator:(TIIndicator *)indicator {
    TIScoringResult *scoring = [[TIScoringResult alloc] init];
    scoring.indicator = indicator;
    scoring.evaluatedAt = [NSDate date];

    NSMutableArray<TIScoreBreakdown *> *breakdown = [NSMutableArray array];
    NSInteger totalScore = 0;
    NSMutableArray<NSNumber *> *confidences = [NSMutableArray array];

    // Simple scoring rules
    for (TIResult *result in results) {
        if (!result.verdict.hit) continue;

        NSInteger score = 0;
        NSString *ruleDesc = @"";

        // Score based on confidence
        if (result.verdict.confidence >= 75) {
            score = 40;
            ruleDesc = @"High confidence threat detected";
        } else if (result.verdict.confidence >= 50) {
            score = 25;
            ruleDesc = @"Medium confidence threat detected";
        } else if (result.verdict.confidence >= 25) {
            score = 10;
            ruleDesc = @"Low confidence threat detected";
        }

        // Category bonuses
        for (NSString *category in result.verdict.categories) {
            if ([category containsString:@"malware"] || [category containsString:@"trojan"]) {
                score += 15;
            } else if ([category containsString:@"phishing"] || [category containsString:@"scam"]) {
                score += 10;
            } else if ([category containsString:@"botnet"] || [category containsString:@"c2"]) {
                score += 15;
            }
        }

        if (score > 0) {
            TIScoreBreakdown *item = [[TIScoreBreakdown alloc] init];
            item.ruleName = [NSString stringWithFormat:@"%@_detection", result.providerName];
            item.ruleDescription = ruleDesc;
            item.provider = result.providerName;
            item.scoreContribution = score;
            item.confidence = result.verdict.confidence;
            item.evidence = @{
                @"categories": [result.verdict.categories componentsJoinedByString:@", "],
                @"confidence": [NSString stringWithFormat:@"%ld", (long)result.verdict.confidence]
            };

            [breakdown addObject:item];
            totalScore += score;
            [confidences addObject:@(result.verdict.confidence / 100.0)];
        }
    }

    // Consensus bonus: if multiple providers agree
    NSInteger hitsCount = 0;
    for (TIResult *result in results) {
        if (result.verdict.hit) hitsCount++;
    }

    if (hitsCount >= 2) {
        NSInteger bonus = 5 * hitsCount;
        TIScoreBreakdown *item = [[TIScoreBreakdown alloc] init];
        item.ruleName = @"consensus_bonus";
        item.ruleDescription = [NSString stringWithFormat:@"%ld providers agree on threat", (long)hitsCount];
        item.provider = @"system";
        item.scoreContribution = bonus;
        item.confidence = 90;
        item.evidence = @{@"agreeing_providers": @(hitsCount).stringValue};
        [breakdown addObject:item];
        totalScore += bonus;
    }

    scoring.breakdown = breakdown;
    scoring.finalScore = totalScore;

    // Calculate confidence
    double avgConfidence = 0.0;
    if (confidences.count > 0) {
        double sum = 0.0;
        for (NSNumber *c in confidences) {
            sum += [c doubleValue];
        }
        avgConfidence = sum / confidences.count;
    }
    scoring.confidence = avgConfidence;

    // Determine verdict
    if (totalScore >= 60) {
        scoring.verdict = TIThreatVerdictMalicious;
    } else if (totalScore >= 30) {
        scoring.verdict = TIThreatVerdictSuspicious;
    } else if (results.count > 0) {
        scoring.verdict = TIThreatVerdictClean;
    } else {
        scoring.verdict = TIThreatVerdictUnknown;
    }

    // Generate explanation
    scoring.explanation = [self generateExplanationForScoring:scoring];

    return scoring;
}

- (NSString *)generateExplanationForScoring:(TIScoringResult *)scoring {
    if (scoring.breakdown.count == 0) {
        return @"No threat intelligence matches found.";
    }

    NSMutableString *explanation = [NSMutableString stringWithFormat:
                                   @"Score: %ld → %@\n\n",
                                   (long)scoring.finalScore,
                                   [scoring verdictString]];

    [explanation appendString:@"Contributing Factors:\n"];
    for (NSInteger i = 0; i < scoring.breakdown.count; i++) {
        TIScoreBreakdown *item = scoring.breakdown[i];
        [explanation appendFormat:@"%ld. [%@] %@ → +%ld pts\n",
         (long)(i + 1), item.provider, item.ruleDescription, (long)item.scoreContribution];
    }

    return explanation;
}

// MARK: - Batch Enrichment

- (void)enrichIndicators:(NSArray<TIIndicator *> *)indicators
              completion:(void (^)(NSArray<TIEnrichmentResponse *> *))completion {
    if (!self.enabled) {
        if (completion) {
            completion(@[]);
        }
        return;
    }

    dispatch_group_t group = dispatch_group_create();
    NSMutableArray<TIEnrichmentResponse *> *responses = [NSMutableArray arrayWithCapacity:indicators.count];

    for (TIIndicator *indicator in indicators) {
        dispatch_group_enter(group);
        [responses addObject:[NSNull null]]; // Placeholder

        [self enrichIndicator:indicator completion:^(TIEnrichmentResponse *response, NSError *error) {
            NSUInteger index = [indicators indexOfObject:indicator];
            if (index != NSNotFound && response) {
                @synchronized(responses) {
                    responses[index] = response;
                }
            }
            dispatch_group_leave(group);
        }];
    }

    dispatch_group_notify(group, dispatch_get_main_queue(), ^{
        // Remove nulls
        NSMutableArray *validResponses = [NSMutableArray array];
        for (id obj in responses) {
            if (![obj isKindOfClass:[NSNull class]]) {
                [validResponses addObject:obj];
            }
        }
        if (completion) {
            completion(validResponses);
        }
    });
}

// MARK: - Cache Management

- (NSDictionary *)cacheStats {
    return @{
        @"size": @([self.cache size]),
        @"hitRate": @([self.cache hitRate])
    };
}

- (void)clearCache {
    [self.cache clear];
}

// MARK: - Helpers

- (NSString *)keyForIndicator:(TIIndicator *)indicator {
    return [NSString stringWithFormat:@"%ld:%@", (long)indicator.type, indicator.value];
}

- (NSError *)errorNoProviders {
    return [NSError errorWithDomain:TIErrorDomain
                               code:TIErrorCodeProviderUnavailable
                           userInfo:@{NSLocalizedDescriptionKey: @"No providers available for indicator type"}];
}

- (void)shutdown {
    for (id<ThreatIntelProvider> provider in self.providers) {
        if ([provider respondsToSelector:@selector(shutdown)]) {
            [provider shutdown];
        }
    }
    [self.providers removeAllObjects];
    [self.cache clear];
}

@end
