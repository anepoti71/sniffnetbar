//
//  ThreatIntelStore.m
//  SniffNetBar
//
//  SQLite persistence for threat intelligence results
//

#import "ThreatIntelStore.h"
#import "Logger.h"
#import <sqlite3.h>

@interface ThreatIntelStore ()
@property (nonatomic, assign) sqlite3 *db;
@property (nonatomic, assign) NSTimeInterval ttlSeconds;
@property (nonatomic, strong) dispatch_queue_t dbQueue;
@end

@implementation ThreatIntelStore

- (instancetype)initWithTTLSeconds:(NSTimeInterval)ttlSeconds {
    self = [super init];
    if (self) {
        _ttlSeconds = ttlSeconds;
        _dbQueue = dispatch_queue_create("com.sniffnetbar.threatintel.store", DISPATCH_QUEUE_SERIAL);
        [self openDatabase];
        [self ensureSchema];
    }
    return self;
}

- (void)dealloc {
    if (self.db) {
        sqlite3_close(self.db);
        self.db = NULL;
    }
}

- (TIEnrichmentResponse *)responseForIndicator:(TIIndicator *)indicator {
    if (!indicator || !self.db) {
        return nil;
    }

    __block TIEnrichmentResponse *response = nil;
    dispatch_sync(self.dbQueue, ^{
        const char *sql = "SELECT response_json, expires_at FROM threat_intel_cache "
                          "WHERE indicator_type = ? AND ip = ? LIMIT 1;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            SNBLogThreatIntelWarn("ThreatIntelStore query prepare failed: %s", sqlite3_errmsg(self.db));
            return;
        }

        sqlite3_bind_int(stmt, 1, (int)indicator.type);
        sqlite3_bind_text(stmt, 2, indicator.value.UTF8String, -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *jsonText = sqlite3_column_text(stmt, 0);
            sqlite3_int64 expiresAt = sqlite3_column_int64(stmt, 1);
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            if (expiresAt > 0 && now > (NSTimeInterval)expiresAt) {
                sqlite3_finalize(stmt);
                [self deleteIndicatorLocked:indicator];
                return;
            }

            if (jsonText) {
                NSString *jsonString = [NSString stringWithUTF8String:(const char *)jsonText];
                response = [self responseFromJSONString:jsonString];
            }
        }

        sqlite3_finalize(stmt);
    });

    return response;
}

- (void)storeResponse:(TIEnrichmentResponse *)response {
    if (!response || !response.indicator || !self.db) {
        return;
    }

    NSString *jsonString = [self jsonStringFromResponse:response];
    if (jsonString.length == 0) {
        return;
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval expiresAt = now + self.ttlSeconds;

    dispatch_async(self.dbQueue, ^{
        const char *sql =
            "INSERT OR REPLACE INTO threat_intel_cache "
            "(ip, indicator_type, evaluated_at, expires_at, response_json) "
            "VALUES (?, ?, ?, ?, ?);";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            SNBLogThreatIntelWarn("ThreatIntelStore insert prepare failed: %s", sqlite3_errmsg(self.db));
            return;
        }

        sqlite3_bind_text(stmt, 1, response.indicator.value.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, (int)response.indicator.type);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)expiresAt);
        sqlite3_bind_text(stmt, 5, jsonString.UTF8String, -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            SNBLogThreatIntelWarn("ThreatIntelStore insert failed: %s", sqlite3_errmsg(self.db));
        }
        sqlite3_finalize(stmt);
    });
}

- (void)purgeExpired {
    if (!self.db) {
        return;
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    dispatch_async(self.dbQueue, ^{
        const char *sql = "DELETE FROM threat_intel_cache WHERE expires_at <= ?;";
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    });
}

#pragma mark - Database Setup

- (void)openDatabase {
    NSString *path = [[self class] defaultDatabasePath];

    NSString *directory = [path stringByDeletingLastPathComponent];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:directory]) {
        [fm createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    int result = sqlite3_open_v2([path fileSystemRepresentation], &_db, flags, NULL);
    if (result != SQLITE_OK) {
        SNBLogThreatIntelWarn("Failed to open threat intel db at %{public}@: %s",
                              path, sqlite3_errmsg(self.db));
        if (self.db) {
            sqlite3_close(self.db);
            self.db = NULL;
        }
        return;
    }

    sqlite3_exec(self.db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(self.db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
    sqlite3_busy_timeout(self.db, 2000);
}

- (void)ensureSchema {
    if (!self.db) {
        return;
    }

    const char *createTable =
        "CREATE TABLE IF NOT EXISTS threat_intel_cache ("
        "ip TEXT NOT NULL, "
        "indicator_type INTEGER NOT NULL, "
        "evaluated_at INTEGER NOT NULL, "
        "expires_at INTEGER NOT NULL, "
        "response_json TEXT NOT NULL, "
        "PRIMARY KEY (ip, indicator_type)"
        ");";
    sqlite3_exec(self.db, createTable, NULL, NULL, NULL);
    sqlite3_exec(self.db, "CREATE INDEX IF NOT EXISTS idx_threat_intel_expires ON threat_intel_cache (expires_at);",
                 NULL, NULL, NULL);
}

+ (NSString *)defaultDatabasePath {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                     NSUserDomainMask,
                                                                     YES);
    NSString *baseDir = paths.firstObject ?: NSTemporaryDirectory();
    NSString *appDir = [baseDir stringByAppendingPathComponent:@"SniffNetBar"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:appDir]) {
        [fm createDirectoryAtPath:appDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return [appDir stringByAppendingPathComponent:@"threat_intel.sqlite"];
}

- (void)deleteIndicatorLocked:(TIIndicator *)indicator {
    const char *sql = "DELETE FROM threat_intel_cache WHERE indicator_type = ? AND ip = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, (int)indicator.type);
        sqlite3_bind_text(stmt, 2, indicator.value.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
}

#pragma mark - Serialization

- (NSString *)jsonStringFromResponse:(TIEnrichmentResponse *)response {
    NSDictionary *dict = [self dictionaryFromResponse:response];
    if (!dict) {
        return nil;
    }
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:&error];
    if (!data || error) {
        SNBLogThreatIntelWarn("ThreatIntelStore JSON encode failed: %{public}@", error.localizedDescription);
        return nil;
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSDictionary *)dictionaryFromResponse:(TIEnrichmentResponse *)response {
    NSMutableArray *providerResults = [NSMutableArray array];
    for (TIResult *result in response.providerResults) {
        NSDictionary *resultDict = @{
            @"provider_name": result.providerName ?: @"",
            @"verdict": [self dictionaryFromVerdict:result.verdict],
            @"metadata": [self dictionaryFromMetadata:result.metadata]
        };
        [providerResults addObject:resultDict];
    }

    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"indicator"] = @{
        @"type": @(response.indicator.type),
        @"value": response.indicator.value ?: @""
    };
    dict[@"provider_results"] = providerResults;
    if (response.scoringResult) {
        dict[@"scoring_result"] = [self dictionaryFromScoring:response.scoringResult];
    }
    dict[@"duration"] = @(response.duration);
    dict[@"cache_hits"] = @(response.cacheHits);
    return dict;
}

- (NSDictionary *)dictionaryFromVerdict:(TIVerdict *)verdict {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"hit"] = @(verdict.hit);
    dict[@"confidence"] = @(verdict.confidence);
    dict[@"categories"] = verdict.categories ?: @[];
    dict[@"tags"] = verdict.tags ?: @[];
    dict[@"last_seen"] = verdict.lastSeen ? @([verdict.lastSeen timeIntervalSince1970]) : [NSNull null];
    dict[@"evidence"] = verdict.evidence ?: @{};
    return dict;
}

- (NSDictionary *)dictionaryFromMetadata:(TIMetadata *)metadata {
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    dict[@"source_url"] = metadata.sourceURL ?: @"";
    dict[@"fetched_at"] = @([metadata.fetchedAt timeIntervalSince1970]);
    dict[@"expires_at"] = @([metadata.expiresAt timeIntervalSince1970]);
    dict[@"ttl_seconds"] = @(metadata.ttlSeconds);
    dict[@"rate_limit_remaining"] = @(metadata.rateLimitRemaining);
    return dict;
}

- (NSDictionary *)dictionaryFromScoring:(TIScoringResult *)scoring {
    NSMutableArray *breakdown = [NSMutableArray array];
    for (TIScoreBreakdown *item in scoring.breakdown) {
        NSDictionary *itemDict = @{
            @"rule_name": item.ruleName ?: @"",
            @"rule_description": item.ruleDescription ?: @"",
            @"provider": item.provider ?: @"",
            @"score": @(item.scoreContribution),
            @"evidence": item.evidence ?: @{},
            @"confidence": @(item.confidence)
        };
        [breakdown addObject:itemDict];
    }

    return @{
        @"final_score": @(scoring.finalScore),
        @"verdict": @(scoring.verdict),
        @"breakdown": breakdown,
        @"confidence": @(scoring.confidence),
        @"evaluated_at": @([scoring.evaluatedAt timeIntervalSince1970]),
        @"explanation": scoring.explanation ?: @""
    };
}

- (TIEnrichmentResponse *)responseFromJSONString:(NSString *)jsonString {
    if (jsonString.length == 0) {
        return nil;
    }
    NSData *data = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) {
        return nil;
    }
    NSError *error = nil;
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (![dict isKindOfClass:[NSDictionary class]] || error) {
        SNBLogThreatIntelWarn("ThreatIntelStore JSON decode failed: %{public}@", error.localizedDescription);
        return nil;
    }
    return [self responseFromDictionary:dict];
}

- (TIEnrichmentResponse *)responseFromDictionary:(NSDictionary *)dict {
    NSDictionary *indicatorDict = dict[@"indicator"];
    NSNumber *typeNumber = indicatorDict[@"type"];
    NSString *value = indicatorDict[@"value"];
    if (![typeNumber isKindOfClass:[NSNumber class]] || ![value isKindOfClass:[NSString class]]) {
        return nil;
    }

    TIIndicator *indicator = [[TIIndicator alloc] initWithType:(TIIndicatorType)typeNumber.integerValue value:value];
    TIEnrichmentResponse *response = [[TIEnrichmentResponse alloc] init];
    response.indicator = indicator;

    NSArray *resultsArray = dict[@"provider_results"];
    NSMutableArray<TIResult *> *results = [NSMutableArray array];
    if ([resultsArray isKindOfClass:[NSArray class]]) {
        for (NSDictionary *resultDict in resultsArray) {
            TIResult *result = [self resultFromDictionary:resultDict indicator:indicator];
            if (result) {
                [results addObject:result];
            }
        }
    }
    response.providerResults = results;

    NSDictionary *scoringDict = dict[@"scoring_result"];
    if ([scoringDict isKindOfClass:[NSDictionary class]]) {
        response.scoringResult = [self scoringFromDictionary:scoringDict indicator:indicator];
    }
    NSNumber *duration = dict[@"duration"];
    NSNumber *cacheHits = dict[@"cache_hits"];
    response.duration = [duration isKindOfClass:[NSNumber class]] ? duration.doubleValue : 0.0;
    response.cacheHits = [cacheHits isKindOfClass:[NSNumber class]] ? cacheHits.integerValue : 0;
    return response;
}

- (TIResult *)resultFromDictionary:(NSDictionary *)dict indicator:(TIIndicator *)indicator {
    NSString *providerName = dict[@"provider_name"];
    NSDictionary *verdictDict = dict[@"verdict"];
    NSDictionary *metadataDict = dict[@"metadata"];
    if (![providerName isKindOfClass:[NSString class]] ||
        ![verdictDict isKindOfClass:[NSDictionary class]] ||
        ![metadataDict isKindOfClass:[NSDictionary class]]) {
        return nil;
    }

    TIVerdict *verdict = [self verdictFromDictionary:verdictDict];
    TIMetadata *metadata = [self metadataFromDictionary:metadataDict];
    if (!verdict || !metadata) {
        return nil;
    }

    TIResult *result = [[TIResult alloc] init];
    result.indicator = indicator;
    result.providerName = providerName;
    result.verdict = verdict;
    result.metadata = metadata;
    result.error = nil;
    return result;
}

- (TIVerdict *)verdictFromDictionary:(NSDictionary *)dict {
    TIVerdict *verdict = [[TIVerdict alloc] init];
    NSNumber *hit = dict[@"hit"];
    NSNumber *confidence = dict[@"confidence"];
    NSArray *categories = dict[@"categories"];
    NSArray *tags = dict[@"tags"];
    id lastSeen = dict[@"last_seen"];
    NSDictionary *evidence = dict[@"evidence"];

    verdict.hit = [hit isKindOfClass:[NSNumber class]] ? hit.boolValue : NO;
    verdict.confidence = [confidence isKindOfClass:[NSNumber class]] ? confidence.integerValue : 0;
    verdict.categories = [categories isKindOfClass:[NSArray class]] ? categories : @[];
    verdict.tags = [tags isKindOfClass:[NSArray class]] ? tags : @[];
    verdict.evidence = [evidence isKindOfClass:[NSDictionary class]] ? evidence : @{};
    if ([lastSeen isKindOfClass:[NSNumber class]]) {
        verdict.lastSeen = [NSDate dateWithTimeIntervalSince1970:[lastSeen doubleValue]];
    }
    return verdict;
}

- (TIMetadata *)metadataFromDictionary:(NSDictionary *)dict {
    TIMetadata *metadata = [[TIMetadata alloc] init];
    NSString *sourceURL = dict[@"source_url"];
    NSNumber *fetchedAt = dict[@"fetched_at"];
    NSNumber *expiresAt = dict[@"expires_at"];
    NSNumber *ttlSeconds = dict[@"ttl_seconds"];
    NSNumber *rateLimit = dict[@"rate_limit_remaining"];

    if ([sourceURL isKindOfClass:[NSString class]]) {
        metadata.sourceURL = sourceURL;
    }
    if ([fetchedAt isKindOfClass:[NSNumber class]]) {
        metadata.fetchedAt = [NSDate dateWithTimeIntervalSince1970:fetchedAt.doubleValue];
    }
    if ([expiresAt isKindOfClass:[NSNumber class]]) {
        metadata.expiresAt = [NSDate dateWithTimeIntervalSince1970:expiresAt.doubleValue];
    }
    metadata.ttlSeconds = [ttlSeconds isKindOfClass:[NSNumber class]] ? ttlSeconds.doubleValue : metadata.ttlSeconds;
    metadata.rateLimitRemaining = [rateLimit isKindOfClass:[NSNumber class]] ? rateLimit.integerValue : -1;
    return metadata;
}

- (TIScoringResult *)scoringFromDictionary:(NSDictionary *)dict indicator:(TIIndicator *)indicator {
    TIScoringResult *scoring = [[TIScoringResult alloc] init];
    scoring.indicator = indicator;
    NSNumber *finalScore = dict[@"final_score"];
    NSNumber *verdict = dict[@"verdict"];
    NSNumber *confidence = dict[@"confidence"];
    NSNumber *evaluatedAt = dict[@"evaluated_at"];
    NSString *explanation = dict[@"explanation"];

    scoring.finalScore = [finalScore isKindOfClass:[NSNumber class]] ? finalScore.integerValue : 0;
    scoring.verdict = [verdict isKindOfClass:[NSNumber class]] ? (TIThreatVerdict)verdict.integerValue : TIThreatVerdictUnknown;
    scoring.confidence = [confidence isKindOfClass:[NSNumber class]] ? confidence.doubleValue : 0.0;
    scoring.evaluatedAt = [evaluatedAt isKindOfClass:[NSNumber class]]
        ? [NSDate dateWithTimeIntervalSince1970:evaluatedAt.doubleValue]
        : [NSDate date];
    scoring.explanation = [explanation isKindOfClass:[NSString class]] ? explanation : @"";

    NSArray *breakdownArray = dict[@"breakdown"];
    NSMutableArray<TIScoreBreakdown *> *breakdown = [NSMutableArray array];
    if ([breakdownArray isKindOfClass:[NSArray class]]) {
        for (NSDictionary *itemDict in breakdownArray) {
            TIScoreBreakdown *item = [self breakdownFromDictionary:itemDict];
            if (item) {
                [breakdown addObject:item];
            }
        }
    }
    scoring.breakdown = breakdown;
    return scoring;
}

- (TIScoreBreakdown *)breakdownFromDictionary:(NSDictionary *)dict {
    if (![dict isKindOfClass:[NSDictionary class]]) {
        return nil;
    }
    TIScoreBreakdown *item = [[TIScoreBreakdown alloc] init];
    NSString *ruleName = dict[@"rule_name"];
    NSString *ruleDescription = dict[@"rule_description"];
    NSString *provider = dict[@"provider"];
    NSNumber *score = dict[@"score"];
    NSDictionary *evidence = dict[@"evidence"];
    NSNumber *confidence = dict[@"confidence"];

    item.ruleName = [ruleName isKindOfClass:[NSString class]] ? ruleName : @"";
    item.ruleDescription = [ruleDescription isKindOfClass:[NSString class]] ? ruleDescription : @"";
    item.provider = [provider isKindOfClass:[NSString class]] ? provider : @"";
    item.scoreContribution = [score isKindOfClass:[NSNumber class]] ? score.integerValue : 0;
    item.evidence = [evidence isKindOfClass:[NSDictionary class]] ? evidence : @{};
    item.confidence = [confidence isKindOfClass:[NSNumber class]] ? confidence.integerValue : 0;
    return item;
}

@end
