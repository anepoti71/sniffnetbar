//
//  StatisticsHistory.m
//  SniffNetBar
//
//  Daily/weekly statistics persistence and reporting
//

#import "StatisticsHistory.h"
#import "PacketInfo.h"
#import "ByteFormatter.h"
#import "Logger.h"
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <netinet/in.h>

static NSString * const kStatsFilename = @"traffic_stats.json";
static NSString * const kReportFilename = @"traffic_report.html";
static const NSTimeInterval kStatsFlushInterval = 300.0;
static const NSUInteger kStatsMaxStoredDays = 90;
static const NSUInteger kStatsTopHostsLimit = 10;
static const NSUInteger kStatsMaxHostMapSize = 2000;
static const NSUInteger kStatsMaxHostSetSize = 5000;

static NSString * const kStatsKeyDays = @"days";
static NSString * const kStatsKeyDate = @"date";
static NSString * const kStatsKeyTotalBytes = @"totalBytes";
static NSString * const kStatsKeyTotalPackets = @"totalPackets";
static NSString * const kStatsKeyMaxRate = @"maxRateBytesPerSecond";
static NSString * const kStatsKeyMaxConnections = @"maxConnectionsPerSecond";
static NSString * const kStatsKeyUniqueHosts = @"uniqueHosts";
static NSString * const kStatsKeyTopHosts = @"topHosts";
static NSString * const kStatsKeyHostBytes = @"hostBytes";
static NSString * const kStatsKeyHostSet = @"hostSet";
static NSString * const kStatsKeyFirstSeen = @"firstSeen";
static NSString * const kStatsKeyLastSeen = @"lastSeen";
static NSString * const kStatsKeyActiveSeconds = @"activeSeconds";

static NSString * const kStatsKeyHostAddress = @"address";
static NSString * const kStatsKeyHostBytesValue = @"bytes";

@interface SNBStatisticsHistory ()
@property (nonatomic, strong) dispatch_queue_t statsQueue;
@property (nonatomic, strong) dispatch_source_t flushTimer;
@property (nonatomic, strong) NSMutableArray<NSMutableDictionary *> *dailyRecords;
@property (nonatomic, strong) NSMutableDictionary *currentDayRecord;
@property (nonatomic, copy) NSString *currentDayString;
@property (nonatomic, assign) NSTimeInterval currentSecond;
@property (nonatomic, assign) uint64_t bytesThisSecond;
@property (nonatomic, strong) NSMutableSet<NSString *> *connectionsThisSecond;
@property (nonatomic, strong) NSMutableSet<NSString *> *uniqueHosts;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *hostBytes;
@property (nonatomic, strong) NSSet<NSString *> *localAddresses;
@end

@implementation SNBStatisticsHistory

- (instancetype)init {
    self = [super init];
    if (self) {
        _statsQueue = dispatch_queue_create("com.sniffnetbar.stats.history", DISPATCH_QUEUE_SERIAL);
        _dailyRecords = [NSMutableArray array];
        _connectionsThisSecond = [NSMutableSet set];
        _uniqueHosts = [NSMutableSet set];
        _hostBytes = [NSMutableDictionary dictionary];
        _localAddresses = [self loadLocalAddresses];
        _enabled = YES;

        [self loadFromDisk];
        [self generateReportLocked];
        [self startFlushTimer];
    }
    return self;
}

- (void)dealloc {
    if (_flushTimer) {
        dispatch_source_cancel(_flushTimer);
    }
}

- (void)setEnabled:(BOOL)enabled {
    _enabled = enabled;
    dispatch_async(self.statsQueue, ^{
        if (!enabled) {
            [self finalizeCurrentSecondBucketWithTimestamp:[NSDate date].timeIntervalSince1970];
            [self finalizeCurrentDayIfNeeded];
            [self persistToDisk];
            [self generateReportLocked];
        }
    });
}

- (void)processPacket:(PacketInfo *)packetInfo {
    if (!packetInfo || packetInfo.totalBytes == 0) {
        return;
    }
    if (!self.enabled) {
        return;
    }

    dispatch_async(self.statsQueue, ^{
        NSDate *now = [NSDate date];
        [self ensureCurrentDayForDate:now];
        if (!self.currentDayRecord) {
            [self startNewDayWithDate:now];
        }

        [self updateSecondBucketsWithDate:now packet:packetInfo];

        uint64_t totalBytes = [self.currentDayRecord[kStatsKeyTotalBytes] unsignedLongLongValue];
        totalBytes += packetInfo.totalBytes;
        self.currentDayRecord[kStatsKeyTotalBytes] = @(totalBytes);

        uint64_t totalPackets = [self.currentDayRecord[kStatsKeyTotalPackets] unsignedLongLongValue];
        totalPackets += 1;
        self.currentDayRecord[kStatsKeyTotalPackets] = @(totalPackets);

        self.currentDayRecord[kStatsKeyLastSeen] = @([now timeIntervalSince1970]);
        [self updateHostStatsForPacket:packetInfo];
    });
}

- (void)flush {
    dispatch_async(self.statsQueue, ^{
        [self finalizeCurrentSecondBucketWithTimestamp:[NSDate date].timeIntervalSince1970];
        [self finalizeCurrentDayIfNeeded];
        [self persistToDisk];
        [self generateReportLocked];
    });
}

- (void)generateReport {
    dispatch_async(self.statsQueue, ^{
        [self generateReportLocked];
    });
}

- (NSString *)reportPath {
    return [[self applicationSupportDirectory] stringByAppendingPathComponent:kReportFilename];
}

- (BOOL)reportExists {
    return [[NSFileManager defaultManager] fileExistsAtPath:[self reportPath]];
}

#pragma mark - Day and Second Tracking

- (void)ensureCurrentDayForDate:(NSDate *)date {
    NSString *dayString = [self dayStringFromDate:date];
    if (!self.currentDayString) {
        self.currentDayString = dayString;
        return;
    }
    if (![self.currentDayString isEqualToString:dayString]) {
        NSMutableDictionary *recordToFinalize = self.currentDayRecord;
        [self finalizeCurrentSecondBucketWithTimestamp:date.timeIntervalSince1970];
        [self finalizeCurrentDayIfNeeded];
        if (recordToFinalize) {
            [self stripVolatileStatsFromRecord:recordToFinalize];
        }
        self.currentDayString = dayString;
        self.currentDayRecord = nil;
        [self.uniqueHosts removeAllObjects];
        [self.hostBytes removeAllObjects];
        [self.connectionsThisSecond removeAllObjects];
        self.bytesThisSecond = 0;
        self.currentSecond = 0;
    }
}

- (void)startNewDayWithDate:(NSDate *)date {
    NSString *dayString = [self dayStringFromDate:date];
    self.currentDayString = dayString;
    NSMutableDictionary *record = [NSMutableDictionary dictionary];
    record[kStatsKeyDate] = dayString;
    record[kStatsKeyTotalBytes] = @(0);
    record[kStatsKeyTotalPackets] = @(0);
    record[kStatsKeyMaxRate] = @(0);
    record[kStatsKeyMaxConnections] = @(0);
    record[kStatsKeyUniqueHosts] = @(0);
    record[kStatsKeyFirstSeen] = @([date timeIntervalSince1970]);
    record[kStatsKeyLastSeen] = @([date timeIntervalSince1970]);
    self.currentDayRecord = record;

    NSUInteger existingIndex = [self indexOfRecordForDay:dayString];
    if (existingIndex != NSNotFound) {
        self.dailyRecords[existingIndex] = record;
    } else {
        [self.dailyRecords addObject:record];
    }
}

- (void)finalizeCurrentSecondBucketWithTimestamp:(NSTimeInterval)timestamp {
    if (!self.currentDayRecord || self.currentSecond == 0) {
        return;
    }
    if (self.bytesThisSecond > 0) {
        uint64_t maxRate = [self.currentDayRecord[kStatsKeyMaxRate] unsignedLongLongValue];
        if (self.bytesThisSecond > maxRate) {
            self.currentDayRecord[kStatsKeyMaxRate] = @(self.bytesThisSecond);
        }
    }

    NSUInteger connectionsCount = self.connectionsThisSecond.count;
    if (connectionsCount > 0) {
        NSUInteger maxConnections = [self.currentDayRecord[kStatsKeyMaxConnections] unsignedIntegerValue];
        if (connectionsCount > maxConnections) {
            self.currentDayRecord[kStatsKeyMaxConnections] = @(connectionsCount);
        }
    }

    [self.connectionsThisSecond removeAllObjects];
    self.bytesThisSecond = 0;
    self.currentSecond = floor(timestamp);
}

- (void)updateSecondBucketsWithDate:(NSDate *)date packet:(PacketInfo *)packet {
    NSTimeInterval now = [date timeIntervalSince1970];
    NSTimeInterval second = floor(now);
    if (self.currentSecond == 0) {
        self.currentSecond = second;
    }
    if (second != self.currentSecond) {
        [self finalizeCurrentSecondBucketWithTimestamp:second];
    }
    self.bytesThisSecond += packet.totalBytes;
    NSString *connectionKey = [self connectionKeyForPacket:packet];
    if (connectionKey.length > 0) {
        [self.connectionsThisSecond addObject:connectionKey];
    }
}

- (void)finalizeCurrentDayIfNeeded {
    if (!self.currentDayRecord) {
        return;
    }

    NSTimeInterval firstSeen = [self.currentDayRecord[kStatsKeyFirstSeen] doubleValue];
    NSTimeInterval lastSeen = [self.currentDayRecord[kStatsKeyLastSeen] doubleValue];
    NSTimeInterval activeSeconds = MAX(1.0, lastSeen - firstSeen);
    self.currentDayRecord[kStatsKeyActiveSeconds] = @(activeSeconds);

    self.currentDayRecord[kStatsKeyUniqueHosts] = @(self.uniqueHosts.count);
    self.currentDayRecord[kStatsKeyHostBytes] = [self.hostBytes copy];
    self.currentDayRecord[kStatsKeyHostSet] = [self.uniqueHosts allObjects];
    self.currentDayRecord[kStatsKeyTopHosts] = [self topHostsFromMap:self.hostBytes limit:kStatsTopHostsLimit];

    [self trimOldRecords];
}

- (void)updateHostStatsForPacket:(PacketInfo *)packet {
    NSString *remoteAddress = [self remoteAddressForPacket:packet];
    if (remoteAddress.length == 0) {
        return;
    }

    [self.uniqueHosts addObject:remoteAddress];
    if (self.uniqueHosts.count > kStatsMaxHostSetSize) {
        NSString *toRemove = self.uniqueHosts.anyObject;
        if (toRemove) {
            [self.uniqueHosts removeObject:toRemove];
        }
    }

    NSNumber *existing = self.hostBytes[remoteAddress];
    uint64_t bytes = existing ? existing.unsignedLongLongValue : 0;
    bytes += packet.totalBytes;
    self.hostBytes[remoteAddress] = @(bytes);

    if (self.hostBytes.count > kStatsMaxHostMapSize) {
        [self trimHostBytesToLimit:kStatsMaxHostMapSize];
    }
}

- (NSString *)remoteAddressForPacket:(PacketInfo *)packet {
    NSString *source = packet.sourceAddress ?: @"";
    NSString *destination = packet.destinationAddress ?: @"";
    if (source.length == 0 && destination.length == 0) {
        return nil;
    }

    BOOL isIncoming = [self isLocalAddress:destination];
    BOOL isOutgoing = [self isLocalAddress:source];
    if (isIncoming && isOutgoing) {
        if (packet.sourcePort > 0 && packet.destinationPort > 0) {
            isIncoming = packet.sourcePort < packet.destinationPort;
            isOutgoing = !isIncoming;
        }
    } else if (!isIncoming && !isOutgoing) {
        isIncoming = YES;
        isOutgoing = NO;
    }

    NSString *remote = isIncoming ? source : destination;
    if (remote.length == 0) {
        return nil;
    }
    if ([self isLocalAddress:remote]) {
        return nil;
    }
    return remote;
}

- (NSString *)connectionKeyForPacket:(PacketInfo *)packet {
    if (packet.sourceAddress.length == 0 || packet.destinationAddress.length == 0) {
        return nil;
    }
    return [NSString stringWithFormat:@"%@:%ld->%@:%ld",
            packet.sourceAddress, (long)packet.sourcePort,
            packet.destinationAddress, (long)packet.destinationPort];
}

#pragma mark - Persistence

- (void)loadFromDisk {
    NSString *path = [self statsFilePath];
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) {
        return;
    }
    NSError *error = nil;
    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (error || ![json isKindOfClass:[NSDictionary class]]) {
        SNBLogWarn("Failed to load stats history: %{public}@", error.localizedDescription);
        return;
    }
    NSArray *days = json[kStatsKeyDays];
    if (![days isKindOfClass:[NSArray class]]) {
        return;
    }

    [self.dailyRecords removeAllObjects];
    for (NSDictionary *record in days) {
        if (![record isKindOfClass:[NSDictionary class]]) {
            continue;
        }
        [self.dailyRecords addObject:[record mutableCopy]];
    }

    NSString *today = [self dayStringFromDate:[NSDate date]];
    NSUInteger index = [self indexOfRecordForDay:today];
    if (index != NSNotFound) {
        self.currentDayRecord = self.dailyRecords[index];
        self.currentDayString = today;
        NSDictionary *hostBytes = self.currentDayRecord[kStatsKeyHostBytes];
        if ([hostBytes isKindOfClass:[NSDictionary class]]) {
            [self.hostBytes addEntriesFromDictionary:hostBytes];
        }
        NSArray *hostSet = self.currentDayRecord[kStatsKeyHostSet];
        if ([hostSet isKindOfClass:[NSArray class]]) {
            for (NSString *host in hostSet) {
                if ([host isKindOfClass:[NSString class]]) {
                    [self.uniqueHosts addObject:host];
                }
            }
        }
    }

}

- (void)persistToDisk {
    NSMutableDictionary *payload = [NSMutableDictionary dictionary];
    payload[kStatsKeyDays] = self.dailyRecords;
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:NSJSONWritingPrettyPrinted error:&error];
    if (!data) {
        SNBLogWarn("Failed to serialize stats history: %{public}@", error.localizedDescription);
        return;
    }
    [data writeToFile:[self statsFilePath] atomically:YES];
}

- (NSString *)statsFilePath {
    return [[self applicationSupportDirectory] stringByAppendingPathComponent:kStatsFilename];
}

- (void)trimOldRecords {
    if (self.dailyRecords.count <= kStatsMaxStoredDays) {
        return;
    }
    [self.dailyRecords sortUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
        NSString *date1 = obj1[kStatsKeyDate];
        NSString *date2 = obj2[kStatsKeyDate];
        return [date1 compare:date2];
    }];
    while (self.dailyRecords.count > kStatsMaxStoredDays) {
        [self.dailyRecords removeObjectAtIndex:0];
    }
}

- (NSUInteger)indexOfRecordForDay:(NSString *)dayString {
    __block NSUInteger index = NSNotFound;
    [self.dailyRecords enumerateObjectsUsingBlock:^(NSDictionary *obj, NSUInteger idx, BOOL *stop) {
        NSString *date = obj[kStatsKeyDate];
        if ([date isKindOfClass:[NSString class]] && [date isEqualToString:dayString]) {
            index = idx;
            *stop = YES;
        }
    }];
    return index;
}

#pragma mark - Report

- (void)generateReportLocked {
    [self refreshCurrentDaySnapshot];
    NSMutableString *html = [NSMutableString string];
    [html appendString:@"<!DOCTYPE html>\n"];
    [html appendString:@"<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"];
    [html appendString:@"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"];
    [html appendString:@"<title>SniffNetBar Statistics</title>\n"];
    [html appendString:@"<style>\n"];
    [html appendString:@"body{font-family:Menlo,Monaco,Consolas,\"Courier New\",monospace;background:#f4f1ea;color:#1c1c1c;margin:0;padding:24px;}\n"];
    [html appendString:@"h1,h2{margin:0 0 12px 0;}\n"];
    [html appendString:@".card{background:#fff;border:1px solid #d9d2c3;border-radius:8px;padding:16px;margin-bottom:20px;box-shadow:0 2px 6px rgba(0,0,0,0.04);}"];
    [html appendString:@"table{width:100%;border-collapse:collapse;font-size:14px;}\n"];
    [html appendString:@"th,td{padding:8px 6px;border-bottom:1px solid #e6e0d4;text-align:left;vertical-align:top;}\n"];
    [html appendString:@"th{background:#f0e9db;font-weight:600;}\n"];
    [html appendString:@".muted{color:#6b6b6b;font-size:12px;}\n"];
    [html appendString:@"ul{padding-left:18px;margin:6px 0;}\n"];
    [html appendString:@"</style>\n</head>\n<body>\n"];
    [html appendFormat:@"<h1>SniffNetBar Statistics</h1>\n<p class=\"muted\">Generated %@</p>\n",
     [self formattedDateTime:[NSDate date]]];

    NSArray<NSDictionary *> *sorted = [self sortedRecords];
    NSDictionary *weekly = [self weeklySummaryFromRecords:sorted];

    [html appendString:@"<div class=\"card\">\n<h2>Weekly Summary</h2>\n"];
    if (weekly.count == 0) {
        [html appendString:@"<p class=\"muted\">No weekly data available yet.</p>\n"];
    } else {
        [html appendString:@"<table>\n"];
        [html appendString:@"<tr><th>Range</th><th>Total Bytes</th><th>Avg Rate</th><th>Max Rate</th><th>Max Hosts</th><th>Max Connections/s</th><th>Most Active Day</th></tr>\n"];
        [html appendFormat:@"<tr><td>%@</td><td>%@</td><td>%@</td><td>%@</td><td>%@</td><td>%@</td><td>%@</td></tr>\n",
         weekly[@"range"],
         weekly[@"totalBytes"],
         weekly[@"avgRate"],
         weekly[@"maxRate"],
         weekly[@"maxHosts"],
         weekly[@"maxConnections"],
         weekly[@"mostActiveDay"]];
        [html appendString:@"</table>\n"];
    }
    [html appendString:@"</div>\n"];

    [html appendString:@"<div class=\"card\">\n<h2>Daily Statistics</h2>\n"];
    if (sorted.count == 0) {
        [html appendString:@"<p class=\"muted\">No daily data available yet.</p>\n"];
    } else {
        [html appendString:@"<table>\n"];
        [html appendString:@"<tr><th>Date</th><th>Avg Rate</th><th>Max Rate</th><th>Hosts</th><th>Max Connections/s</th><th>Total Bytes</th><th>Top Hosts</th></tr>\n"];
        for (NSDictionary *record in sorted) {
            NSString *date = record[kStatsKeyDate] ?: @"";
            uint64_t totalBytes = [record[kStatsKeyTotalBytes] unsignedLongLongValue];
            uint64_t maxRate = [record[kStatsKeyMaxRate] unsignedLongLongValue];
            NSUInteger maxConnections = [record[kStatsKeyMaxConnections] unsignedIntegerValue];
            NSUInteger hostCount = [record[kStatsKeyUniqueHosts] unsignedIntegerValue];
            NSTimeInterval activeSeconds = [self activeSecondsForRecord:record];
            uint64_t avgRate = activeSeconds > 0 ? (uint64_t)(totalBytes / activeSeconds) : 0;

            NSString *topHostsHtml = [self topHostsHTMLForRecord:record];
            [html appendFormat:@"<tr><td>%@</td><td>%@</td><td>%@</td><td>%lu</td><td>%lu</td><td>%@</td><td>%@</td></tr>\n",
             date,
             [self formattedRate:avgRate],
             [self formattedRate:maxRate],
             (unsigned long)hostCount,
             (unsigned long)maxConnections,
             [SNBByteFormatter stringFromBytes:totalBytes],
             topHostsHtml];
        }
        [html appendString:@"</table>\n"];
    }
    [html appendString:@"</div>\n"];

    [html appendString:@"</body>\n</html>\n"];

    NSError *error = nil;
    [html writeToFile:[self reportPath] atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        SNBLogWarn("Failed to write report: %{public}@", error.localizedDescription);
    }
}

- (NSArray<NSDictionary *> *)sortedRecords {
    NSArray<NSDictionary *> *records = [self.dailyRecords copy];
    return [records sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *obj1, NSDictionary *obj2) {
        NSString *date1 = obj1[kStatsKeyDate];
        NSString *date2 = obj2[kStatsKeyDate];
        return [date2 compare:date1];
    }];
}

- (NSDictionary *)weeklySummaryFromRecords:(NSArray<NSDictionary *> *)records {
    if (records.count == 0) {
        return @{};
    }

    NSArray<NSDictionary *> *recent = records.count > 7 ? [records subarrayWithRange:NSMakeRange(0, 7)] : records;
    uint64_t totalBytes = 0;
    uint64_t maxRate = 0;
    NSUInteger maxHosts = 0;
    NSUInteger maxConnections = 0;
    NSTimeInterval totalSeconds = 0;
    NSString *mostActiveDay = @"";
    uint64_t mostActiveBytes = 0;
    NSString *range = @"";

    NSString *startDate = recent.lastObject[kStatsKeyDate];
    NSString *endDate = recent.firstObject[kStatsKeyDate];
    if (startDate.length > 0 && endDate.length > 0) {
        range = [NSString stringWithFormat:@"%@ to %@", startDate, endDate];
    }

    for (NSDictionary *record in recent) {
        uint64_t dayBytes = [record[kStatsKeyTotalBytes] unsignedLongLongValue];
        uint64_t dayMaxRate = [record[kStatsKeyMaxRate] unsignedLongLongValue];
        NSUInteger dayHosts = [record[kStatsKeyUniqueHosts] unsignedIntegerValue];
        NSUInteger dayConnections = [record[kStatsKeyMaxConnections] unsignedIntegerValue];
        NSTimeInterval activeSeconds = [self activeSecondsForRecord:record];
        totalBytes += dayBytes;
        totalSeconds += activeSeconds;
        if (dayMaxRate > maxRate) {
            maxRate = dayMaxRate;
        }
        if (dayHosts > maxHosts) {
            maxHosts = dayHosts;
        }
        if (dayConnections > maxConnections) {
            maxConnections = dayConnections;
        }
        if (dayBytes > mostActiveBytes) {
            mostActiveBytes = dayBytes;
            mostActiveDay = record[kStatsKeyDate] ?: @"";
        }
    }

    uint64_t avgRate = totalSeconds > 0 ? (uint64_t)(totalBytes / totalSeconds) : 0;

    return @{
        @"range": range.length > 0 ? range : @"-",
        @"totalBytes": [SNBByteFormatter stringFromBytes:totalBytes],
        @"avgRate": [self formattedRate:avgRate],
        @"maxRate": [self formattedRate:maxRate],
        @"maxHosts": [NSString stringWithFormat:@"%lu", (unsigned long)maxHosts],
        @"maxConnections": [NSString stringWithFormat:@"%lu", (unsigned long)maxConnections],
        @"mostActiveDay": mostActiveDay.length > 0 ? mostActiveDay : @"-"
    };
}

- (NSTimeInterval)activeSecondsForRecord:(NSDictionary *)record {
    NSNumber *active = record[kStatsKeyActiveSeconds];
    if (active) {
        return MAX(1.0, active.doubleValue);
    }
    NSTimeInterval first = [record[kStatsKeyFirstSeen] doubleValue];
    NSTimeInterval last = [record[kStatsKeyLastSeen] doubleValue];
    if (first > 0 && last > 0) {
        return MAX(1.0, last - first);
    }
    return 1.0;
}

- (NSArray<NSDictionary *> *)topHostsFromMap:(NSDictionary<NSString *, NSNumber *> *)map
                                      limit:(NSUInteger)limit {
    if (map.count == 0 || limit == 0) {
        return @[];
    }
    NSArray<NSString *> *sortedKeys = [map keysSortedByValueUsingComparator:^NSComparisonResult(NSNumber *obj1, NSNumber *obj2) {
        return [obj2 compare:obj1];
    }];
    NSUInteger count = MIN(limit, sortedKeys.count);
    NSMutableArray<NSDictionary *> *top = [NSMutableArray arrayWithCapacity:count];
    for (NSUInteger i = 0; i < count; i++) {
        NSString *host = sortedKeys[i];
        NSNumber *bytes = map[host] ?: @(0);
        [top addObject:@{kStatsKeyHostAddress: host, kStatsKeyHostBytesValue: bytes}];
    }
    return top;
}

- (NSString *)topHostsHTMLForRecord:(NSDictionary *)record {
    NSArray *hosts = record[kStatsKeyTopHosts];
    if (![hosts isKindOfClass:[NSArray class]] || hosts.count == 0) {
        return @"<span class=\"muted\">None</span>";
    }
    NSMutableString *html = [NSMutableString stringWithString:@"<ul>"];
    for (NSDictionary *host in hosts) {
        NSString *address = host[kStatsKeyHostAddress] ?: @"";
        uint64_t bytes = [host[kStatsKeyHostBytesValue] unsignedLongLongValue];
        [html appendFormat:@"<li>%@ (%@)</li>", address, [SNBByteFormatter stringFromBytes:bytes]];
    }
    [html appendString:@"</ul>"];
    return html;
}

#pragma mark - Helpers

- (void)refreshCurrentDaySnapshot {
    if (!self.currentDayRecord) {
        return;
    }
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    NSTimeInterval firstSeen = [self.currentDayRecord[kStatsKeyFirstSeen] doubleValue];
    NSTimeInterval activeSeconds = MAX(1.0, now - firstSeen);
    self.currentDayRecord[kStatsKeyLastSeen] = @(now);
    self.currentDayRecord[kStatsKeyActiveSeconds] = @(activeSeconds);
    self.currentDayRecord[kStatsKeyUniqueHosts] = @(self.uniqueHosts.count);
    self.currentDayRecord[kStatsKeyTopHosts] = [self topHostsFromMap:self.hostBytes limit:kStatsTopHostsLimit];
}

- (void)stripVolatileStatsFromRecord:(NSMutableDictionary *)record {
    [record removeObjectForKey:kStatsKeyHostBytes];
    [record removeObjectForKey:kStatsKeyHostSet];
}

- (void)trimHostBytesToLimit:(NSUInteger)limit {
    if (self.hostBytes.count <= limit) {
        return;
    }
    NSArray *sortedKeys = [self.hostBytes keysSortedByValueUsingComparator:^NSComparisonResult(NSNumber *obj1, NSNumber *obj2) {
        return [obj1 compare:obj2];
    }];
    NSUInteger toRemove = self.hostBytes.count - limit;
    for (NSUInteger i = 0; i < toRemove && i < sortedKeys.count; i++) {
        [self.hostBytes removeObjectForKey:sortedKeys[i]];
    }
}

- (BOOL)isLocalAddress:(NSString *)address {
    return [self.localAddresses containsObject:address];
}

- (NSSet<NSString *> *)loadLocalAddresses {
    NSMutableSet<NSString *> *addresses = [NSMutableSet set];
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) == 0) {
        struct ifaddrs *interface;
        for (interface = interfaces; interface != NULL; interface = interface->ifa_next) {
            if (interface->ifa_addr == NULL) {
                continue;
            }
            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)interface->ifa_addr;
                char addr[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &sin->sin_addr, addr, INET_ADDRSTRLEN)) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            } else if (interface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)interface->ifa_addr;
                char addr[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, addr, INET6_ADDRSTRLEN)) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            }
        }
        freeifaddrs(interfaces);
    }
    [addresses addObject:@"127.0.0.1"];
    [addresses addObject:@"::1"];
    return [addresses copy];
}

- (NSString *)applicationSupportDirectory {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                                     NSUserDomainMask,
                                                                     YES);
    NSString *baseDir = paths.firstObject ?: NSTemporaryDirectory();
    NSString *appDir = [baseDir stringByAppendingPathComponent:@"SniffNetBar"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:appDir]) {
        [fm createDirectoryAtPath:appDir withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return appDir;
}

- (NSString *)dayStringFromDate:(NSDate *)date {
    static NSDateFormatter *formatter = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.timeZone = [NSTimeZone localTimeZone];
        formatter.dateFormat = @"yyyy-MM-dd";
    });
    return [formatter stringFromDate:date];
}

- (NSString *)formattedDateTime:(NSDate *)date {
    static NSDateFormatter *formatter = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSDateFormatter alloc] init];
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.timeZone = [NSTimeZone localTimeZone];
        formatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    });
    return [formatter stringFromDate:date];
}

- (NSString *)formattedRate:(uint64_t)bytesPerSecond {
    if (bytesPerSecond == 0) {
        return @"0 B/s";
    }
    return [NSString stringWithFormat:@"%@/s", [SNBByteFormatter stringFromBytes:bytesPerSecond]];
}

- (void)startFlushTimer {
    self.flushTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.statsQueue);
    dispatch_source_set_timer(self.flushTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kStatsFlushInterval * NSEC_PER_SEC)),
                              (uint64_t)(kStatsFlushInterval * NSEC_PER_SEC),
                              (uint64_t)(5 * NSEC_PER_SEC));
    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(self.flushTimer, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf || !strongSelf.enabled) {
            return;
        }
        [strongSelf finalizeCurrentSecondBucketWithTimestamp:[NSDate date].timeIntervalSince1970];
        [strongSelf finalizeCurrentDayIfNeeded];
        [strongSelf persistToDisk];
        [strongSelf generateReportLocked];
    });
    dispatch_resume(self.flushTimer);
}

@end
