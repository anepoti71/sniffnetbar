//
//  AnomalyStore.m
//  SniffNetBar
//
//  SQLite persistence for anomaly detection data
//

#import "AnomalyStore.h"
#import <sqlite3.h>

@interface SNBAnomalyStore ()
@property (nonatomic, assign) sqlite3 *db;
@end

@implementation SNBAnomalyStore

+ (NSString *)applicationSupportDirectory {
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

+ (NSString *)applicationSupportDirectoryPath {
    return [self applicationSupportDirectory];
}

+ (NSString *)defaultDatabasePath {
    return [[self applicationSupportDirectory] stringByAppendingPathComponent:@"anomaly.sqlite"];
}

+ (NSString *)defaultModelPath {
    return [[self applicationSupportDirectory] stringByAppendingPathComponent:@"anomaly_model.joblib"];
}

+ (NSString *)defaultCoreMLModelPath {
    NSString *supportPath = [[self applicationSupportDirectory] stringByAppendingPathComponent:@"anomaly_model.mlmodelc"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:supportPath]) {
        return supportPath;
    }
    NSString *bundled = [[NSBundle mainBundle] pathForResource:@"anomaly_model" ofType:@"mlmodelc"];
    if (bundled.length > 0) {
        return bundled;
    }
    return supportPath;
}

- (instancetype)init {
    self = [super init];
    if (self) {
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

- (void)openDatabase {
    NSString *path = [SNBAnomalyStore defaultDatabasePath];
    if (sqlite3_open([path fileSystemRepresentation], &_db) != SQLITE_OK) {
        sqlite3_close(self.db);
        self.db = NULL;
    }
}

- (void)ensureSchema {
    if (!self.db) {
        return;
    }

    const char *createWindows =
        "CREATE TABLE IF NOT EXISTS anomaly_windows ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "window_start INTEGER NOT NULL, "
        "dst_ip TEXT NOT NULL, "
        "dst_port INTEGER NOT NULL, "
        "proto INTEGER NOT NULL, "
        "total_bytes REAL NOT NULL, "
        "total_packets REAL NOT NULL, "
        "unique_src_ports REAL NOT NULL, "
        "flow_count REAL NOT NULL, "
        "avg_pkt_size REAL NOT NULL, "
        "bytes_per_flow REAL NOT NULL, "
        "pkts_per_flow REAL NOT NULL, "
        "burstiness REAL NOT NULL, "
        "is_new_dst INTEGER NOT NULL, "
        "is_rare_dst INTEGER NOT NULL, "
        "score REAL NOT NULL, "
        "created_at INTEGER NOT NULL"
        ");";

    const char *createIpStats =
        "CREATE TABLE IF NOT EXISTS anomaly_ip_stats ("
        "dst_ip TEXT PRIMARY KEY, "
        "seen_count INTEGER NOT NULL, "
        "last_seen INTEGER NOT NULL, "
        "avg_score REAL NOT NULL"
        ");";

    const char *createIndex =
        "CREATE INDEX IF NOT EXISTS idx_anomaly_windows_time "
        "ON anomaly_windows(window_start);";

    sqlite3_exec(self.db, createWindows, NULL, NULL, NULL);
    sqlite3_exec(self.db, createIpStats, NULL, NULL, NULL);
    sqlite3_exec(self.db, createIndex, NULL, NULL, NULL);
}

- (NSInteger)seenCountForIP:(NSString *)ipAddress {
    if (!self.db) {
        return 0;
    }
    sqlite3_stmt *stmt = NULL;
    NSInteger seenCount = 0;
    const char *sql = "SELECT seen_count FROM anomaly_ip_stats WHERE dst_ip = ?;";
    if (sqlite3_prepare_v2(self.db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            seenCount = sqlite3_column_int(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    return seenCount;
}

- (void)recordWindowForIP:(NSString *)ipAddress
              windowStart:(NSTimeInterval)windowStart
                  dstPort:(NSInteger)dstPort
                    proto:(NSInteger)proto
               totalBytes:(double)totalBytes
             totalPackets:(double)totalPackets
          uniqueSrcPorts:(double)uniqueSrcPorts
                flowCount:(double)flowCount
             avgPktSize:(double)avgPktSize
          bytesPerFlow:(double)bytesPerFlow
            pktsPerFlow:(double)pktsPerFlow
              burstiness:(double)burstiness
                 isNewDst:(BOOL)isNewDst
                isRareDst:(BOOL)isRareDst
                   score:(double)score {
    if (!self.db) {
        return;
    }

    sqlite3_exec(self.db, "BEGIN;", NULL, NULL, NULL);

    sqlite3_stmt *stmt = NULL;
    const char *insertWindow =
        "INSERT INTO anomaly_windows ("
        "window_start, dst_ip, dst_port, proto, total_bytes, total_packets, "
        "unique_src_ports, flow_count, avg_pkt_size, bytes_per_flow, pkts_per_flow, "
        "burstiness, is_new_dst, is_rare_dst, score, created_at"
        ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

    if (sqlite3_prepare_v2(self.db, insertWindow, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)windowStart);
        sqlite3_bind_text(stmt, 2, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, (int)dstPort);
        sqlite3_bind_int(stmt, 4, (int)proto);
        sqlite3_bind_double(stmt, 5, totalBytes);
        sqlite3_bind_double(stmt, 6, totalPackets);
        sqlite3_bind_double(stmt, 7, uniqueSrcPorts);
        sqlite3_bind_double(stmt, 8, flowCount);
        sqlite3_bind_double(stmt, 9, avgPktSize);
        sqlite3_bind_double(stmt, 10, bytesPerFlow);
        sqlite3_bind_double(stmt, 11, pktsPerFlow);
        sqlite3_bind_double(stmt, 12, burstiness);
        sqlite3_bind_int(stmt, 13, isNewDst ? 1 : 0);
        sqlite3_bind_int(stmt, 14, isRareDst ? 1 : 0);
        sqlite3_bind_double(stmt, 15, score);
        sqlite3_bind_int64(stmt, 16, (sqlite3_int64)[[NSDate date] timeIntervalSince1970]);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    const char *upsertIp =
        "INSERT INTO anomaly_ip_stats (dst_ip, seen_count, last_seen, avg_score) "
        "VALUES (?, 1, ?, ?) "
        "ON CONFLICT(dst_ip) DO UPDATE SET "
        "seen_count = seen_count + 1, "
        "last_seen = excluded.last_seen, "
        "avg_score = (avg_score * (seen_count) + excluded.avg_score) / (seen_count + 1);";

    if (sqlite3_prepare_v2(self.db, upsertIp, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, ipAddress.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)[[NSDate date] timeIntervalSince1970]);
        sqlite3_bind_double(stmt, 3, score);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    sqlite3_exec(self.db, "COMMIT;", NULL, NULL, NULL);
}

@end
