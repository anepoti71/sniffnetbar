//
//  MenuBuilder+ThreatDisplay.m
//  SniffNetBar
//
//  Threat display helpers for Phase 1 & 2 improvements
//

#import "MenuBuilder+ThreatDisplay.h"
#import "TrafficStatistics.h"
#import "ThreatIntelModels.h"
#import "ByteFormatter.h"

@implementation ThreatInfo
@end

@implementation MenuBuilder (ThreatDisplay)

#pragma mark - Severity Helpers

- (ThreatSeverityLevel)severityLevelForScore:(NSInteger)score {
    if (score >= 70) {
        return ThreatSeverityHigh;
    } else if (score >= 40) {
        return ThreatSeverityMedium;
    } else if (score > 0) {
        return ThreatSeverityLow;
    }
    return ThreatSeverityNone;
}

- (NSColor *)colorForSeverityLevel:(ThreatSeverityLevel)level {
    switch (level) {
        case ThreatSeverityHigh:
            return [NSColor systemRedColor];
        case ThreatSeverityMedium:
            return [NSColor systemOrangeColor];
        case ThreatSeverityLow:
            return [NSColor systemYellowColor];
        case ThreatSeverityNone:
            return [NSColor systemGreenColor];
    }
}

- (NSString *)iconForSeverityLevel:(ThreatSeverityLevel)level {
    switch (level) {
        case ThreatSeverityHigh:
            return @"🔴";
        case ThreatSeverityMedium:
            return @"🟡";
        case ThreatSeverityLow:
            return @"🟢";
        case ThreatSeverityNone:
            return @"✓";
    }
}

- (NSString *)labelForSeverityLevel:(ThreatSeverityLevel)level {
    switch (level) {
        case ThreatSeverityHigh:
            return @"HIGH SEVERITY";
        case ThreatSeverityMedium:
            return @"MEDIUM SEVERITY";
        case ThreatSeverityLow:
            return @"LOW SEVERITY";
        case ThreatSeverityNone:
            return @"CLEAN";
    }
}

#pragma mark - Connection Analysis

- (NSArray<ConnectionTraffic *> *)connectionsForIP:(NSString *)ip inStats:(TrafficStats *)stats {
    NSMutableArray<ConnectionTraffic *> *connections = [NSMutableArray array];
    for (ConnectionTraffic *conn in stats.topConnections) {
        if ([conn.sourceAddress isEqualToString:ip] || [conn.destinationAddress isEqualToString:ip]) {
            [connections addObject:conn];
        }
    }
    return connections;
}

- (uint64_t)totalBytesForIP:(NSString *)ip inStats:(TrafficStats *)stats {
    uint64_t totalBytes = 0;

    // Check hosts
    for (HostTraffic *host in stats.topHosts) {
        if ([host.address isEqualToString:ip]) {
            totalBytes += host.bytes;
            break;
        }
    }

    // If not found in hosts, sum from connections
    if (totalBytes == 0) {
        for (ConnectionTraffic *conn in stats.topConnections) {
            if ([conn.sourceAddress isEqualToString:ip] || [conn.destinationAddress isEqualToString:ip]) {
                totalBytes += conn.bytes;
            }
        }
    }

    return totalBytes;
}

#pragma mark - Threat Categorization

- (NSDictionary<NSNumber *, NSArray<ThreatInfo *> *> *)categorizeThreats:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                                                               activeIPs:(NSSet<NSString *> *)activeIPs
                                                                   stats:(TrafficStats *)stats {

    NSMutableDictionary<NSNumber *, NSMutableArray<ThreatInfo *> *> *categorized = [NSMutableDictionary dictionary];
    categorized[@(ThreatSeverityHigh)] = [NSMutableArray array];
    categorized[@(ThreatSeverityMedium)] = [NSMutableArray array];
    categorized[@(ThreatSeverityLow)] = [NSMutableArray array];

    for (NSString *ip in threatIntelResults) {
        TIEnrichmentResponse *response = threatIntelResults[ip];
        TIScoringResult *scoring = response.scoringResult;

        if (!scoring || scoring.verdict == TIThreatVerdictClean) {
            continue;
        }

        NSInteger score = scoring.finalScore;
        ThreatSeverityLevel level = [self severityLevelForScore:score];

        if (level == ThreatSeverityNone) {
            continue;
        }

        ThreatInfo *threat = [[ThreatInfo alloc] init];
        threat.ipAddress = ip;
        threat.response = response;
        threat.severityLevel = level;
        threat.score = score;
        threat.isActive = [activeIPs containsObject:ip];
        threat.totalBytes = [self totalBytesForIP:ip inStats:stats];

        // Find primary connection (highest bytes)
        NSArray<ConnectionTraffic *> *connections = [self connectionsForIP:ip inStats:stats];
        threat.connectionCount = connections.count;
        if (connections.count > 0) {
            threat.primaryConnection = connections[0]; // Already sorted by bytes
        }

        [categorized[@(level)] addObject:threat];
    }

    // Sort each category by score (highest first)
    for (NSNumber *levelKey in categorized) {
        [categorized[levelKey] sortUsingComparator:^NSComparisonResult(ThreatInfo *t1, ThreatInfo *t2) {
            if (t1.score != t2.score) {
                return t1.score > t2.score ? NSOrderedAscending : NSOrderedDescending;
            }
            return [t1.ipAddress compare:t2.ipAddress];
        }];
    }

    return categorized;
}

#pragma mark - Menu Item Creation

- (NSMenuItem *)severityHeaderForLevel:(ThreatSeverityLevel)level count:(NSUInteger)count {
    NSString *icon = [self iconForSeverityLevel:level];
    NSString *label = [self labelForSeverityLevel:level];
    NSString *title = [NSString stringWithFormat:@"%@ %@ (%lu)", icon, label, (unsigned long)count];

    NSMenuItem *item = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
    item.enabled = NO;

    NSMutableAttributedString *attrString = [[NSMutableAttributedString alloc] initWithString:title];
    NSFont *font = [NSFont boldSystemFontOfSize:12.0];
    NSColor *color = [self colorForSeverityLevel:level];

    [attrString addAttribute:NSFontAttributeName value:font range:NSMakeRange(0, title.length)];
    [attrString addAttribute:NSForegroundColorAttributeName value:color range:NSMakeRange(0, title.length)];

    item.attributedTitle = attrString;
    return item;
}

- (NSMenuItem *)enhancedThreatItemForThreat:(ThreatInfo *)threat {
    TIScoringResult *scoring = threat.response.scoringResult;
    NSString *verdict = [scoring verdictString];
    ConnectionTraffic *conn = threat.primaryConnection;

    // Line 1: IP + Port + Process
    NSMutableString *line1 = [NSMutableString string];
    if (conn) {
        [line1 appendFormat:@"  %@:%ld", threat.ipAddress, (long)conn.destinationPort];
        if (conn.processName.length > 0) {
            [line1 appendFormat:@" ← %@ [%d]", conn.processName, conn.processPID];
        }
    } else {
        [line1 appendFormat:@"  %@", threat.ipAddress];
    }
    if (!threat.isActive) {
        [line1 appendString:@" [CLOSED]"];
    }

    NSMenuItem *item1 = [[NSMenuItem alloc] initWithTitle:line1 action:nil keyEquivalent:@""];
    item1.enabled = NO;

    // Style line 1
    NSMutableAttributedString *attr1 = [[NSMutableAttributedString alloc] initWithString:line1];
    NSFont *font1 = threat.isActive ? [NSFont systemFontOfSize:12.0 weight:NSFontWeightSemibold] : [NSFont systemFontOfSize:12.0];
    NSColor *color1 = threat.isActive ? [NSColor labelColor] : [NSColor secondaryLabelColor];

    [attr1 addAttribute:NSFontAttributeName value:font1 range:NSMakeRange(0, line1.length)];
    [attr1 addAttribute:NSForegroundColorAttributeName value:color1 range:NSMakeRange(0, line1.length)];

    item1.attributedTitle = attr1;

    return item1;
}

- (NSMenuItem *)threatDetailItemForThreat:(ThreatInfo *)threat {
    TIScoringResult *scoring = threat.response.scoringResult;
    NSString *verdict = [scoring verdictString];

    // Line 2: Verdict + Score + Traffic + Providers
    NSMutableString *line2 = [NSMutableString stringWithFormat:@"    %@ (score %ld)", verdict, (long)threat.score];

    if (threat.totalBytes > 0) {
        NSString *bytesStr = [SNBByteFormatter stringFromBytes:threat.totalBytes];
        [line2 appendFormat:@" • %@", bytesStr];
    }

    if (threat.connectionCount > 0) {
        [line2 appendFormat:@" • %ld conn%@", (long)threat.connectionCount, threat.connectionCount == 1 ? @"" : @"s"];
    }

    // Add provider info
    NSString *providers = [self providerSummaryForResponse:threat.response];
    if (providers.length > 0 && ![providers isEqualToString:@"Unknown"]) {
        [line2 appendFormat:@" • %@", providers];
    }

    NSMenuItem *item2 = [[NSMenuItem alloc] initWithTitle:line2 action:nil keyEquivalent:@""];
    item2.enabled = NO;

    // Style line 2
    NSMutableAttributedString *attr2 = [[NSMutableAttributedString alloc] initWithString:line2];
    NSFont *font2 = [NSFont systemFontOfSize:11.0];
    NSColor *color2 = [NSColor secondaryLabelColor];

    [attr2 addAttribute:NSFontAttributeName value:font2 range:NSMakeRange(0, line2.length)];
    [attr2 addAttribute:NSForegroundColorAttributeName value:color2 range:NSMakeRange(0, line2.length)];

    item2.attributedTitle = attr2;

    return item2;
}

- (NSMenuItem *)threatConnectionItemForThreat:(ThreatInfo *)threat {
    ConnectionTraffic *conn = threat.primaryConnection;
    if (!conn) {
        return nil;
    }

    // Line 3: Connection details
    NSString *line3 = [NSString stringWithFormat:@"    %@:%ld → %@:%ld",
                      conn.sourceAddress, (long)conn.sourcePort,
                      conn.destinationAddress, (long)conn.destinationPort];

    NSMenuItem *item3 = [[NSMenuItem alloc] initWithTitle:line3 action:nil keyEquivalent:@""];
    item3.enabled = NO;

    // Style line 3
    NSMutableAttributedString *attr3 = [[NSMutableAttributedString alloc] initWithString:line3];
    NSFont *font3 = [NSFont monospacedSystemFontOfSize:10.0 weight:NSFontWeightRegular];
    NSColor *color3 = [NSColor tertiaryLabelColor];

    [attr3 addAttribute:NSFontAttributeName value:font3 range:NSMakeRange(0, line3.length)];
    [attr3 addAttribute:NSForegroundColorAttributeName value:color3 range:NSMakeRange(0, line3.length)];

    item3.attributedTitle = attr3;

    return item3;
}

@end
