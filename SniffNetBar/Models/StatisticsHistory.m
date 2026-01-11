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
#import <sqlite3.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <netinet/in.h>

static NSString * const kStatsDatabaseFilename = @"traffic_stats.sqlite";
static NSString * const kReportFilename = @"traffic_report.html";
static const NSTimeInterval kStatsFlushInterval = 300.0;
static const NSUInteger kStatsMaxStoredDays = 90;

static NSString * const kStatsKeyDate = @"date";
static NSString * const kStatsKeyTotalBytes = @"totalBytes";
static NSString * const kStatsKeyTotalPackets = @"totalPackets";
static NSString * const kStatsKeyMaxRate = @"maxRateBytesPerSecond";
static NSString * const kStatsKeyMaxConnections = @"maxConnectionsPerSecond";
static NSString * const kStatsKeyUniqueHosts = @"uniqueHosts";
static NSString * const kStatsKeyFirstSeen = @"firstSeen";
static NSString * const kStatsKeyLastSeen = @"lastSeen";
static NSString * const kStatsKeyActiveSeconds = @"activeSeconds";

static NSString * const kHostKeyAddress = @"host";
static NSString * const kHostKeyBytes = @"bytes";
static NSString * const kHostKeyPackets = @"packets";
static NSString * const kConnectionKeySource = @"source";
static NSString * const kConnectionKeyDestination = @"destination";
static NSString * const kConnectionKeyBytes = @"bytes";
static NSString * const kConnectionKeyPackets = @"packets";
static NSString * const kConnectionKeySourcePort = @"sourcePort";
static NSString * const kConnectionKeyDestinationPort = @"destinationPort";

@interface SNBConnectionStats : NSObject
@property (nonatomic, copy) NSString *sourceAddress;
@property (nonatomic, copy) NSString *destinationAddress;
@property (nonatomic, assign) NSInteger sourcePort;
@property (nonatomic, assign) NSInteger destinationPort;
@property (nonatomic, assign) uint64_t bytes;
@property (nonatomic, assign) uint64_t packets;
@end

@implementation SNBConnectionStats
@end

@interface SNBStatisticsHistory ()
@property (nonatomic, strong) dispatch_queue_t statsQueue;
@property (nonatomic, strong) dispatch_source_t flushTimer;
@property (nonatomic, strong) NSMutableDictionary *currentDayRecord;
@property (nonatomic, copy) NSString *currentDayString;
@property (nonatomic, assign) NSTimeInterval currentSecond;
@property (nonatomic, assign) uint64_t bytesThisSecond;
@property (nonatomic, strong) NSMutableSet<NSString *> *connectionsThisSecond;
@property (nonatomic, strong) NSMutableSet<NSString *> *uniqueHosts;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *hostBytes;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *hostPackets;
@property (nonatomic, strong) NSMutableDictionary<NSString *, SNBConnectionStats *> *connectionStats;
@property (nonatomic, strong) NSSet<NSString *> *localAddresses;
@property (nonatomic, assign) sqlite3 *db;
@end

@implementation SNBStatisticsHistory

- (instancetype)init {
    self = [super init];
    if (self) {
        _statsQueue = dispatch_queue_create("com.sniffnetbar.stats.history", DISPATCH_QUEUE_SERIAL);
        _connectionsThisSecond = [NSMutableSet set];
        _uniqueHosts = [NSMutableSet set];
        _hostBytes = [NSMutableDictionary dictionary];
        _hostPackets = [NSMutableDictionary dictionary];
        _connectionStats = [NSMutableDictionary dictionary];
        _localAddresses = [self loadLocalAddresses];
        _enabled = YES;

        [self openDatabase];
        [self ensureSchema];
        [self loadFromDatabase];
        [self generateReportLocked];
        [self startFlushTimer];
    }
    return self;
}

- (void)dealloc {
    if (_flushTimer) {
        dispatch_source_cancel(_flushTimer);
    }
    if (_db) {
        sqlite3_close(_db);
        _db = NULL;
    }
}

- (void)setEnabled:(BOOL)enabled {
    _enabled = enabled;
    dispatch_async(self.statsQueue, ^{
        if (!enabled) {
            [self finalizeCurrentSecondBucketWithTimestamp:[NSDate date].timeIntervalSince1970];
            [self finalizeCurrentDayIfNeeded];
            [self persistToDatabase];
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
        [self updateConnectionStatsForPacket:packetInfo];
    });
}

- (void)flush {
    dispatch_async(self.statsQueue, ^{
        [self finalizeCurrentSecondBucketWithTimestamp:[NSDate date].timeIntervalSince1970];
        [self finalizeCurrentDayIfNeeded];
        [self persistToDatabase];
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
        [self finalizeCurrentSecondBucketWithTimestamp:date.timeIntervalSince1970];
        [self finalizeCurrentDayIfNeeded];
        [self persistToDatabase];
        self.currentDayString = dayString;
        self.currentDayRecord = nil;
        [self.uniqueHosts removeAllObjects];
        [self.hostBytes removeAllObjects];
        [self.hostPackets removeAllObjects];
        [self.connectionStats removeAllObjects];
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
}

- (void)updateHostStatsForPacket:(PacketInfo *)packet {
    NSString *remoteAddress = [self remoteAddressForPacket:packet];
    if (remoteAddress.length == 0) {
        return;
    }

    [self.uniqueHosts addObject:remoteAddress];

    NSNumber *existing = self.hostBytes[remoteAddress];
    uint64_t bytes = existing ? existing.unsignedLongLongValue : 0;
    bytes += packet.totalBytes;
    self.hostBytes[remoteAddress] = @(bytes);
    NSNumber *packetExisting = self.hostPackets[remoteAddress];
    uint64_t packets = packetExisting ? packetExisting.unsignedLongLongValue : 0;
    packets += 1;
    self.hostPackets[remoteAddress] = @(packets);
}

- (void)updateConnectionStatsForPacket:(PacketInfo *)packet {
    NSString *connectionKey = [self connectionKeyForPacket:packet];
    if (connectionKey.length == 0) {
        return;
    }

    SNBConnectionStats *stats = self.connectionStats[connectionKey];
    if (!stats) {
        stats = [[SNBConnectionStats alloc] init];
        stats.sourceAddress = packet.sourceAddress ?: @"";
        stats.destinationAddress = packet.destinationAddress ?: @"";
        stats.sourcePort = packet.sourcePort;
        stats.destinationPort = packet.destinationPort;
        self.connectionStats[connectionKey] = stats;
    }

    stats.bytes += packet.totalBytes;
    stats.packets += 1;
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

- (void)openDatabase {
    NSString *path = [self statsDatabasePath];
    NSString *directory = [path stringByDeletingLastPathComponent];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:directory]) {
        NSError *error = nil;
        if (![fm createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:&error]) {
            SNBLogWarn("Failed to create stats database directory at %{public}@ (%{public}@)", directory, error.localizedDescription);
            return;
        }
    }

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    int result = sqlite3_open_v2([path fileSystemRepresentation], &_db, flags, NULL);
    if (result != SQLITE_OK) {
        SNBLogWarn("Failed to open stats database at %{public}@ (%s)", path, sqlite3_errmsg(self.db));
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

    const char *createDays =
        "CREATE TABLE IF NOT EXISTS stats_days ("
        "day TEXT PRIMARY KEY, "
        "total_bytes INTEGER NOT NULL, "
        "total_packets INTEGER NOT NULL, "
        "max_rate INTEGER NOT NULL, "
        "max_connections INTEGER NOT NULL, "
        "unique_hosts INTEGER NOT NULL, "
        "first_seen REAL NOT NULL, "
        "last_seen REAL NOT NULL, "
        "active_seconds REAL NOT NULL"
        ");";
    const char *createHosts =
        "CREATE TABLE IF NOT EXISTS stats_hosts ("
        "day TEXT NOT NULL, "
        "host TEXT NOT NULL, "
        "bytes INTEGER NOT NULL, "
        "packets INTEGER NOT NULL, "
        "PRIMARY KEY (day, host)"
        ");";
    const char *createConnections =
        "CREATE TABLE IF NOT EXISTS stats_connections ("
        "day TEXT NOT NULL, "
        "src_addr TEXT NOT NULL, "
        "src_port INTEGER NOT NULL, "
        "dst_addr TEXT NOT NULL, "
        "dst_port INTEGER NOT NULL, "
        "bytes INTEGER NOT NULL, "
        "packets INTEGER NOT NULL, "
        "PRIMARY KEY (day, src_addr, src_port, dst_addr, dst_port)"
        ");";
    sqlite3_exec(self.db, createDays, NULL, NULL, NULL);
    sqlite3_exec(self.db, createHosts, NULL, NULL, NULL);
    sqlite3_exec(self.db, createConnections, NULL, NULL, NULL);
    sqlite3_exec(self.db, "CREATE INDEX IF NOT EXISTS stats_hosts_day_idx ON stats_hosts(day);", NULL, NULL, NULL);
    sqlite3_exec(self.db, "CREATE INDEX IF NOT EXISTS stats_connections_day_idx ON stats_connections(day);", NULL, NULL, NULL);
}

- (void)loadFromDatabase {
    if (!self.db) {
        return;
    }

    NSString *today = [self dayStringFromDate:[NSDate date]];
    const char *selectDay =
        "SELECT total_bytes, total_packets, max_rate, max_connections, unique_hosts, first_seen, last_seen, active_seconds "
        "FROM stats_days WHERE day = ? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(self.db, selectDay, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, today.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            NSMutableDictionary *record = [NSMutableDictionary dictionary];
            record[kStatsKeyDate] = today;
            record[kStatsKeyTotalBytes] = @((uint64_t)sqlite3_column_int64(stmt, 0));
            record[kStatsKeyTotalPackets] = @((uint64_t)sqlite3_column_int64(stmt, 1));
            record[kStatsKeyMaxRate] = @((uint64_t)sqlite3_column_int64(stmt, 2));
            record[kStatsKeyMaxConnections] = @((uint64_t)sqlite3_column_int64(stmt, 3));
            record[kStatsKeyUniqueHosts] = @((NSUInteger)sqlite3_column_int64(stmt, 4));
            record[kStatsKeyFirstSeen] = @((double)sqlite3_column_double(stmt, 5));
            record[kStatsKeyLastSeen] = @((double)sqlite3_column_double(stmt, 6));
            record[kStatsKeyActiveSeconds] = @((double)sqlite3_column_double(stmt, 7));
            self.currentDayRecord = record;
            self.currentDayString = today;
        }
        sqlite3_finalize(stmt);
    }

    if (!self.currentDayRecord) {
        return;
    }

    const char *selectHosts =
        "SELECT host, bytes, packets FROM stats_hosts WHERE day = ?;";
    stmt = NULL;
    if (sqlite3_prepare_v2(self.db, selectHosts, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, today.UTF8String, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *host = (const char *)sqlite3_column_text(stmt, 0);
            uint64_t bytes = (uint64_t)sqlite3_column_int64(stmt, 1);
            uint64_t packets = (uint64_t)sqlite3_column_int64(stmt, 2);
            if (host) {
                NSString *hostString = [NSString stringWithUTF8String:host];
                self.hostBytes[hostString] = @(bytes);
                self.hostPackets[hostString] = @(packets);
                [self.uniqueHosts addObject:hostString];
            }
        }
        sqlite3_finalize(stmt);
    }

    const char *selectConnections =
        "SELECT src_addr, src_port, dst_addr, dst_port, bytes, packets FROM stats_connections WHERE day = ?;";
    stmt = NULL;
    if (sqlite3_prepare_v2(self.db, selectConnections, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, today.UTF8String, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *src = (const char *)sqlite3_column_text(stmt, 0);
            const char *dst = (const char *)sqlite3_column_text(stmt, 2);
            if (!src || !dst) {
                continue;
            }
            SNBConnectionStats *stats = [[SNBConnectionStats alloc] init];
            stats.sourceAddress = [NSString stringWithUTF8String:src];
            stats.destinationAddress = [NSString stringWithUTF8String:dst];
            stats.sourcePort = sqlite3_column_int(stmt, 1);
            stats.destinationPort = sqlite3_column_int(stmt, 3);
            stats.bytes = (uint64_t)sqlite3_column_int64(stmt, 4);
            stats.packets = (uint64_t)sqlite3_column_int64(stmt, 5);
            NSString *key = [NSString stringWithFormat:@"%@:%ld->%@:%ld",
                             stats.sourceAddress, (long)stats.sourcePort,
                             stats.destinationAddress, (long)stats.destinationPort];
            self.connectionStats[key] = stats;
        }
        sqlite3_finalize(stmt);
    }
}

- (void)persistToDatabase {
    if (!self.db || !self.currentDayRecord) {
        return;
    }

    [self refreshCurrentDaySnapshot];
    NSString *day = self.currentDayRecord[kStatsKeyDate];
    if (day.length == 0) {
        return;
    }

    sqlite3_exec(self.db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);

    const char *upsertDay =
        "INSERT INTO stats_days "
        "(day, total_bytes, total_packets, max_rate, max_connections, unique_hosts, first_seen, last_seen, active_seconds) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(day) DO UPDATE SET "
        "total_bytes=excluded.total_bytes, "
        "total_packets=excluded.total_packets, "
        "max_rate=excluded.max_rate, "
        "max_connections=excluded.max_connections, "
        "unique_hosts=excluded.unique_hosts, "
        "first_seen=excluded.first_seen, "
        "last_seen=excluded.last_seen, "
        "active_seconds=excluded.active_seconds;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(self.db, upsertDay, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, day.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, [self.currentDayRecord[kStatsKeyTotalBytes] longLongValue]);
        sqlite3_bind_int64(stmt, 3, [self.currentDayRecord[kStatsKeyTotalPackets] longLongValue]);
        sqlite3_bind_int64(stmt, 4, [self.currentDayRecord[kStatsKeyMaxRate] longLongValue]);
        sqlite3_bind_int64(stmt, 5, [self.currentDayRecord[kStatsKeyMaxConnections] longLongValue]);
        sqlite3_bind_int64(stmt, 6, [self.currentDayRecord[kStatsKeyUniqueHosts] longLongValue]);
        sqlite3_bind_double(stmt, 7, [self.currentDayRecord[kStatsKeyFirstSeen] doubleValue]);
        sqlite3_bind_double(stmt, 8, [self.currentDayRecord[kStatsKeyLastSeen] doubleValue]);
        sqlite3_bind_double(stmt, 9, [self.currentDayRecord[kStatsKeyActiveSeconds] doubleValue]);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    const char *upsertHost =
        "INSERT INTO stats_hosts (day, host, bytes, packets) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(day, host) DO UPDATE SET bytes=excluded.bytes, packets=excluded.packets;";
    stmt = NULL;
    if (sqlite3_prepare_v2(self.db, upsertHost, -1, &stmt, NULL) == SQLITE_OK) {
        [self.hostBytes enumerateKeysAndObjectsUsingBlock:^(NSString *host, NSNumber *bytes, BOOL *stop) {
            NSNumber *packets = self.hostPackets[host] ?: @(0);
            sqlite3_bind_text(stmt, 1, day.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, host.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 3, bytes.longLongValue);
            sqlite3_bind_int64(stmt, 4, packets.longLongValue);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
        }];
        sqlite3_finalize(stmt);
    }

    const char *upsertConnection =
        "INSERT INTO stats_connections (day, src_addr, src_port, dst_addr, dst_port, bytes, packets) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(day, src_addr, src_port, dst_addr, dst_port) DO UPDATE SET "
        "bytes=excluded.bytes, packets=excluded.packets;";
    stmt = NULL;
    if (sqlite3_prepare_v2(self.db, upsertConnection, -1, &stmt, NULL) == SQLITE_OK) {
        [self.connectionStats enumerateKeysAndObjectsUsingBlock:^(NSString *key, SNBConnectionStats *stats, BOOL *stop) {
            sqlite3_bind_text(stmt, 1, day.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, stats.sourceAddress.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 3, (int)stats.sourcePort);
            sqlite3_bind_text(stmt, 4, stats.destinationAddress.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(stmt, 5, (int)stats.destinationPort);
            sqlite3_bind_int64(stmt, 6, (sqlite3_int64)stats.bytes);
            sqlite3_bind_int64(stmt, 7, (sqlite3_int64)stats.packets);
            sqlite3_step(stmt);
            sqlite3_reset(stmt);
        }];
        sqlite3_finalize(stmt);
    }

    sqlite3_exec(self.db, "COMMIT;", NULL, NULL, NULL);
    [self trimOldRecordsFromDatabase];
}

- (NSString *)statsDatabasePath {
    return [[self applicationSupportDirectory] stringByAppendingPathComponent:kStatsDatabaseFilename];
}

- (void)trimOldRecordsFromDatabase {
    if (!self.db) {
        return;
    }
    NSString *deleteDays =
        [NSString stringWithFormat:
         @"DELETE FROM stats_days WHERE day NOT IN "
         "(SELECT day FROM stats_days ORDER BY day DESC LIMIT %lu);",
         (unsigned long)kStatsMaxStoredDays];
    sqlite3_exec(self.db, deleteDays.UTF8String, NULL, NULL, NULL);
    sqlite3_exec(self.db, "DELETE FROM stats_hosts WHERE day NOT IN (SELECT day FROM stats_days);", NULL, NULL, NULL);
    sqlite3_exec(self.db, "DELETE FROM stats_connections WHERE day NOT IN (SELECT day FROM stats_days);", NULL, NULL, NULL);
}

#pragma mark - Report

- (void)generateReportLocked {
    [self refreshCurrentDaySnapshot];
    [self persistToDatabase];
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
    [html appendString:@".controls{display:flex;flex-wrap:wrap;gap:12px;margin:10px 0 16px 0;font-size:12px;}\n"];
    [html appendString:@".controls label{display:flex;align-items:center;gap:6px;}\n"];
    [html appendString:@"details{margin:12px 0;border:1px solid #eee3cf;border-radius:8px;padding:10px;background:#fffaf1;}\n"];
    [html appendString:@"summary{cursor:pointer;font-weight:600;}\n"];
    [html appendString:@".section-title{margin:16px 0 8px 0;}\n"];
    [html appendString:@"</style>\n</head>\n<body>\n"];
    [html appendFormat:@"<h1>SniffNetBar Statistics</h1>\n<p class=\"muted\">Generated %@</p>\n",
     [self formattedDateTime:[NSDate date]]];

    NSArray<NSDictionary *> *records = [self dailyRecordsFromDatabase];
    NSDictionary *weekly = [self weeklySummaryFromRecords:records];

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
    if (records.count == 0) {
        [html appendString:@"<p class=\"muted\">No daily data available yet.</p>\n"];
    } else {
        [html appendString:@"<div class=\"controls\">\n"];
        [html appendString:@"<label>Sort daily by\n"];
        [html appendString:@"<select id=\"dailySort\">\n"];
        [html appendString:@"<option value=\"date_desc\" selected>Date (newest)</option>\n"];
        [html appendString:@"<option value=\"date_asc\">Date (oldest)</option>\n"];
        [html appendString:@"<option value=\"hosts_desc\">Hosts</option>\n"];
        [html appendString:@"<option value=\"connections_desc\">Connections/s</option>\n"];
        [html appendString:@"<option value=\"rate_desc\">Avg rate</option>\n"];
        [html appendString:@"</select></label>\n"];
        [html appendString:@"</div>\n"];

        [html appendString:@"<table id=\"dailyTable\">\n"];
        [html appendString:@"<thead><tr><th>Date</th><th>Avg Rate</th><th>Max Rate</th><th>Hosts</th><th>Max Connections/s</th><th>Total Bytes</th></tr></thead>\n"];
        [html appendString:@"<tbody>\n"];
        for (NSDictionary *record in records) {
            NSString *date = record[kStatsKeyDate] ?: @"";
            uint64_t totalBytes = [record[kStatsKeyTotalBytes] unsignedLongLongValue];
            uint64_t maxRate = [record[kStatsKeyMaxRate] unsignedLongLongValue];
            NSUInteger maxConnections = [record[kStatsKeyMaxConnections] unsignedIntegerValue];
            NSUInteger hostCount = [record[kStatsKeyUniqueHosts] unsignedIntegerValue];
            NSTimeInterval activeSeconds = [self activeSecondsForRecord:record];
            uint64_t avgRate = activeSeconds > 0 ? (uint64_t)(totalBytes / activeSeconds) : 0;

            [html appendFormat:@"<tr data-date=\"%@\" data-hosts=\"%lu\" data-connections=\"%lu\" data-rate=\"%llu\">"
             "<td>%@</td><td>%@</td><td>%@</td><td>%lu</td><td>%lu</td><td>%@</td></tr>\n",
             date,
             (unsigned long)hostCount,
             (unsigned long)maxConnections,
             (unsigned long long)avgRate,
             date,
             [self formattedRate:avgRate],
             [self formattedRate:maxRate],
             (unsigned long)hostCount,
             (unsigned long)maxConnections,
             [SNBByteFormatter stringFromBytes:totalBytes]];
        }
        [html appendString:@"</tbody></table>\n"];
    }
    [html appendString:@"</div>\n"];

    [html appendString:@"<div class=\"card\">\n<h2>Daily Details</h2>\n"];
    if (records.count == 0) {
        [html appendString:@"<p class=\"muted\">No daily details available yet.</p>\n"];
    } else {
        [records enumerateObjectsUsingBlock:^(NSDictionary *record, NSUInteger idx, BOOL *stop) {
            NSString *date = record[kStatsKeyDate] ?: @"";
            uint64_t totalBytes = [record[kStatsKeyTotalBytes] unsignedLongLongValue];
            NSTimeInterval activeSeconds = [self activeSecondsForRecord:record];
            uint64_t avgRate = activeSeconds > 0 ? (uint64_t)(totalBytes / activeSeconds) : 0;
            NSString *detailsId = [NSString stringWithFormat:@"day-%lu", (unsigned long)idx];
            NSString *hostsTableId = [NSString stringWithFormat:@"hosts-%lu", (unsigned long)idx];
            NSString *connectionsTableId = [NSString stringWithFormat:@"connections-%lu", (unsigned long)idx];
            NSArray<NSDictionary *> *hosts = [self hostsForDay:date];
            NSArray<NSDictionary *> *connections = [self connectionsForDay:date];

            [html appendFormat:@"<details id=\"%@\" open>\n", detailsId];
            [html appendFormat:@"<summary>%@ - %@ total, %@ avg rate</summary>\n",
             date,
             [SNBByteFormatter stringFromBytes:totalBytes],
             [self formattedRate:avgRate]];

            [html appendString:@"<div class=\"controls\">"];
            [html appendFormat:@"<label>Hosts sort <select data-target=\"%@\">", hostsTableId];
            [html appendString:@"<option value=\"bytes_desc\" selected>Bytes</option>"];
            [html appendString:@"<option value=\"packets_desc\">Packets</option>"];
            [html appendString:@"<option value=\"host_asc\">Host</option>"];
            [html appendString:@"</select></label>"];
            [html appendFormat:@"<label>Connections sort <select data-target=\"%@\">", connectionsTableId];
            [html appendString:@"<option value=\"bytes_desc\" selected>Bytes</option>"];
            [html appendString:@"<option value=\"packets_desc\">Packets</option>"];
            [html appendString:@"<option value=\"connection_asc\">Connection</option>"];
            [html appendString:@"</select></label>"];
            [html appendString:@"</div>"];

            [html appendString:@"<h3 class=\"section-title\">Hosts</h3>\n"];
            if (hosts.count == 0) {
                [html appendString:@"<p class=\"muted\">No host activity recorded.</p>\n"];
            } else {
                [html appendFormat:@"<table id=\"%@\"><thead><tr><th>Host</th><th>Bytes</th><th>Packets</th></tr></thead><tbody>\n", hostsTableId];
                for (NSDictionary *host in hosts) {
                    NSString *address = host[kHostKeyAddress] ?: @"";
                    uint64_t bytes = [host[kHostKeyBytes] unsignedLongLongValue];
                    uint64_t packets = [host[kHostKeyPackets] unsignedLongLongValue];
                    [html appendFormat:@"<tr data-host=\"%@\" data-bytes=\"%llu\" data-packets=\"%llu\"><td>%@</td><td>%@</td><td>%llu</td></tr>\n",
                     address,
                     (unsigned long long)bytes,
                     (unsigned long long)packets,
                     address,
                     [SNBByteFormatter stringFromBytes:bytes],
                     (unsigned long long)packets];
                }
                [html appendString:@"</tbody></table>\n"];
            }

            [html appendString:@"<h3 class=\"section-title\">Connections</h3>\n"];
            if (connections.count == 0) {
                [html appendString:@"<p class=\"muted\">No connection activity recorded.</p>\n"];
            } else {
                [html appendFormat:@"<table id=\"%@\"><thead><tr><th>Connection</th><th>Bytes</th><th>Packets</th></tr></thead><tbody>\n", connectionsTableId];
                for (NSDictionary *connection in connections) {
                    NSString *source = connection[kConnectionKeySource] ?: @"";
                    NSString *destination = connection[kConnectionKeyDestination] ?: @"";
                    NSNumber *sourcePort = connection[kConnectionKeySourcePort] ?: @(0);
                    NSNumber *destinationPort = connection[kConnectionKeyDestinationPort] ?: @(0);
                    uint64_t bytes = [connection[kConnectionKeyBytes] unsignedLongLongValue];
                    uint64_t packets = [connection[kConnectionKeyPackets] unsignedLongLongValue];
                    NSString *connectionLabel = [NSString stringWithFormat:@"%@:%ld -> %@:%ld",
                                                 source, (long)sourcePort.integerValue,
                                                 destination, (long)destinationPort.integerValue];
                    [html appendFormat:@"<tr data-connection=\"%@\" data-bytes=\"%llu\" data-packets=\"%llu\"><td>%@</td><td>%@</td><td>%llu</td></tr>\n",
                     connectionLabel,
                     (unsigned long long)bytes,
                     (unsigned long long)packets,
                     connectionLabel,
                     [SNBByteFormatter stringFromBytes:bytes],
                     (unsigned long long)packets];
                }
                [html appendString:@"</tbody></table>\n"];
            }

            [html appendString:@"</details>\n"];
        }];
    }
    [html appendString:@"</div>\n"];

    [html appendString:@"<script>\n"];
    [html appendString:@"(function(){\n"];
    [html appendString:@"function sortRows(tbody, compare){\n"];
    [html appendString:@"  var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));\n"];
    [html appendString:@"  rows.sort(compare);\n"];
    [html appendString:@"  rows.forEach(function(row){ tbody.appendChild(row); });\n"];
    [html appendString:@"}\n"];
    [html appendString:@"var dailySelect = document.getElementById('dailySort');\n"];
    [html appendString:@"var dailyBody = document.querySelector('#dailyTable tbody');\n"];
    [html appendString:@"if (dailySelect && dailyBody) {\n"];
    [html appendString:@"  var sortDaily = function(){\n"];
    [html appendString:@"    var mode = dailySelect.value;\n"];
    [html appendString:@"    sortRows(dailyBody, function(a, b){\n"];
    [html appendString:@"      var ad = a.dataset.date || '';\n"];
    [html appendString:@"      var bd = b.dataset.date || '';\n"];
    [html appendString:@"      var ah = parseInt(a.dataset.hosts || '0', 10);\n"];
    [html appendString:@"      var bh = parseInt(b.dataset.hosts || '0', 10);\n"];
    [html appendString:@"      var ac = parseInt(a.dataset.connections || '0', 10);\n"];
    [html appendString:@"      var bc = parseInt(b.dataset.connections || '0', 10);\n"];
    [html appendString:@"      var ar = parseInt(a.dataset.rate || '0', 10);\n"];
    [html appendString:@"      var br = parseInt(b.dataset.rate || '0', 10);\n"];
    [html appendString:@"      if (mode === 'date_asc') { return ad.localeCompare(bd); }\n"];
    [html appendString:@"      if (mode === 'date_desc') { return bd.localeCompare(ad); }\n"];
    [html appendString:@"      if (mode === 'hosts_desc') { return bh - ah; }\n"];
    [html appendString:@"      if (mode === 'connections_desc') { return bc - ac; }\n"];
    [html appendString:@"      return br - ar;\n"];
    [html appendString:@"    });\n"];
    [html appendString:@"  };\n"];
    [html appendString:@"  dailySelect.addEventListener('change', sortDaily);\n"];
    [html appendString:@"  sortDaily();\n"];
    [html appendString:@"}\n"];
    [html appendString:@"document.querySelectorAll('select[data-target]').forEach(function(select){\n"];
    [html appendString:@"  select.addEventListener('change', function(){\n"];
    [html appendString:@"    var target = select.getAttribute('data-target');\n"];
    [html appendString:@"    var table = document.getElementById(target);\n"];
    [html appendString:@"    if (!table) { return; }\n"];
    [html appendString:@"    var tbody = table.querySelector('tbody');\n"];
    [html appendString:@"    if (!tbody) { return; }\n"];
    [html appendString:@"    var mode = select.value;\n"];
    [html appendString:@"    sortRows(tbody, function(a, b){\n"];
    [html appendString:@"      var ab = parseInt(a.dataset.bytes || '0', 10);\n"];
    [html appendString:@"      var bb = parseInt(b.dataset.bytes || '0', 10);\n"];
    [html appendString:@"      var ap = parseInt(a.dataset.packets || '0', 10);\n"];
    [html appendString:@"      var bp = parseInt(b.dataset.packets || '0', 10);\n"];
    [html appendString:@"      var ah = a.dataset.host || '';\n"];
    [html appendString:@"      var bh = b.dataset.host || '';\n"];
    [html appendString:@"      var ac = a.dataset.connection || '';\n"];
    [html appendString:@"      var bc = b.dataset.connection || '';\n"];
    [html appendString:@"      if (mode === 'bytes_desc') { return bb - ab; }\n"];
    [html appendString:@"      if (mode === 'packets_desc') { return bp - ap; }\n"];
    [html appendString:@"      if (mode === 'host_asc') { return ah.localeCompare(bh); }\n"];
    [html appendString:@"      return ac.localeCompare(bc);\n"];
    [html appendString:@"    });\n"];
    [html appendString:@"  });\n"];
    [html appendString:@"});\n"];
    [html appendString:@"})();\n"];
    [html appendString:@"</script>\n"];

    [html appendString:@"</body>\n</html>\n"];

    NSError *error = nil;
    [html writeToFile:[self reportPath] atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        SNBLogWarn("Failed to write report: %{public}@", error.localizedDescription);
    }
}

- (NSArray<NSDictionary *> *)dailyRecordsFromDatabase {
    if (!self.db) {
        return @[];
    }

    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    const char *sql =
        "SELECT day, total_bytes, total_packets, max_rate, max_connections, unique_hosts, first_seen, last_seen, active_seconds "
        "FROM stats_days ORDER BY day DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *day = (const char *)sqlite3_column_text(stmt, 0);
            if (!day) {
                continue;
            }
            NSMutableDictionary *record = [NSMutableDictionary dictionary];
            record[kStatsKeyDate] = [NSString stringWithUTF8String:day];
            record[kStatsKeyTotalBytes] = @((uint64_t)sqlite3_column_int64(stmt, 1));
            record[kStatsKeyTotalPackets] = @((uint64_t)sqlite3_column_int64(stmt, 2));
            record[kStatsKeyMaxRate] = @((uint64_t)sqlite3_column_int64(stmt, 3));
            record[kStatsKeyMaxConnections] = @((uint64_t)sqlite3_column_int64(stmt, 4));
            record[kStatsKeyUniqueHosts] = @((NSUInteger)sqlite3_column_int64(stmt, 5));
            record[kStatsKeyFirstSeen] = @((double)sqlite3_column_double(stmt, 6));
            record[kStatsKeyLastSeen] = @((double)sqlite3_column_double(stmt, 7));
            record[kStatsKeyActiveSeconds] = @((double)sqlite3_column_double(stmt, 8));
            [records addObject:record];
        }
        sqlite3_finalize(stmt);
    }
    return records;
}

- (NSArray<NSDictionary *> *)hostsForDay:(NSString *)day {
    if (!self.db || day.length == 0) {
        return @[];
    }
    NSMutableArray<NSDictionary *> *hosts = [NSMutableArray array];
    const char *sql = "SELECT host, bytes, packets FROM stats_hosts WHERE day = ? ORDER BY bytes DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, day.UTF8String, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *host = (const char *)sqlite3_column_text(stmt, 0);
            if (!host) {
                continue;
            }
            uint64_t bytes = (uint64_t)sqlite3_column_int64(stmt, 1);
            uint64_t packets = (uint64_t)sqlite3_column_int64(stmt, 2);
            [hosts addObject:@{
                kHostKeyAddress: [NSString stringWithUTF8String:host],
                kHostKeyBytes: @(bytes),
                kHostKeyPackets: @(packets)
            }];
        }
        sqlite3_finalize(stmt);
    }
    return hosts;
}

- (NSArray<NSDictionary *> *)connectionsForDay:(NSString *)day {
    if (!self.db || day.length == 0) {
        return @[];
    }
    NSMutableArray<NSDictionary *> *connections = [NSMutableArray array];
    const char *sql =
        "SELECT src_addr, src_port, dst_addr, dst_port, bytes, packets "
        "FROM stats_connections WHERE day = ? ORDER BY bytes DESC;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, day.UTF8String, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *src = (const char *)sqlite3_column_text(stmt, 0);
            const char *dst = (const char *)sqlite3_column_text(stmt, 2);
            if (!src || !dst) {
                continue;
            }
            uint64_t bytes = (uint64_t)sqlite3_column_int64(stmt, 4);
            uint64_t packets = (uint64_t)sqlite3_column_int64(stmt, 5);
            [connections addObject:@{
                kConnectionKeySource: [NSString stringWithUTF8String:src],
                kConnectionKeySourcePort: @(sqlite3_column_int(stmt, 1)),
                kConnectionKeyDestination: [NSString stringWithUTF8String:dst],
                kConnectionKeyDestinationPort: @(sqlite3_column_int(stmt, 3)),
                kConnectionKeyBytes: @(bytes),
                kConnectionKeyPackets: @(packets)
            }];
        }
        sqlite3_finalize(stmt);
    }
    return connections;
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
        [strongSelf persistToDatabase];
        [strongSelf generateReportLocked];
    });
    dispatch_resume(self.flushTimer);
}

@end
