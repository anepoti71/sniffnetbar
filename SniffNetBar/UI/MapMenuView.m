//
//  MapMenuView.m
//  SniffNetBar
//
//  Map visualization embedded in the menu (Leaflet via WebKit)
//

#import "MapMenuView.h"
#import "ByteFormatter.h"
#import "ConfigurationManager.h"
#import "ExpiringCache.h"
#import "IPAddressUtilities.h"
#import "UserDefaultsKeys.h"
#import "SNBLocationStore.h"
#import "SNBBadgeRegistry.h"
#import "Logger.h"
#import <WebKit/WebKit.h>
#import <CoreLocation/CoreLocation.h>

@interface MapMenuView () <WKNavigationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, strong) NSButton *zoomInButton;
@property (nonatomic, strong) NSButton *zoomOutButton;
@property (nonatomic, strong) SNBExpiringCache<NSString *, NSDictionary *> *locationCache;
@property (nonatomic, strong) SNBLocationStore *locationStore;
@property (nonatomic, strong) NSMutableSet<NSString *> *inFlightLookups;
@property (nonatomic, strong) NSMutableSet<NSString *> *failedLookups;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, copy) NSArray<ConnectionTraffic *> *lastConnections;
@property (nonatomic, copy) NSString *publicIPAddress;
@property (nonatomic, strong) NSValue *publicIPCoordinate;
@property (nonatomic, assign) BOOL publicIPLookupInFlight;
@property (nonatomic, assign) BOOL mapReady;
@property (nonatomic, copy) NSArray<NSString *> *lastTargetIPs;
@property (nonatomic, strong) dispatch_queue_t renderQueue;
@property (nonatomic, assign) NSUInteger renderGeneration;
@property (nonatomic, strong) NSDate *lastCacheCleanupTime;
@property (nonatomic, strong) dispatch_semaphore_t geoLocationSemaphore;
@property (nonatomic, assign, readwrite) NSUInteger drawnConnectionCount;
@end

@implementation MapMenuView

static NSString *SNBLocationStoreDirectory(void) {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    if (paths.count == 0) {
        return NSTemporaryDirectory();
    }
    NSString *dir = [paths.firstObject stringByAppendingPathComponent:@"SniffNetBar"];
    NSError *error = nil;
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:&error];
    if (error) {
        SNBLogUIDebug("Unable to create App Support dir: %{public}@", error.localizedDescription);
        return NSTemporaryDirectory();
    }
    return dir;
}

- (instancetype)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        // Enable layer backing for proper z-ordering
        self.wantsLayer = YES;

        WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
        _webView = [[WKWebView alloc] initWithFrame:self.bounds configuration:config];
        _webView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        _webView.navigationDelegate = self;
        _webView.wantsLayer = YES;
        [self addSubview:_webView];

        _zoomInButton = [self zoomButtonWithTitle:@"+" action:@selector(zoomIn:)];
        _zoomOutButton = [self zoomButtonWithTitle:@"−" action:@selector(zoomOut:)];
        _zoomInButton.wantsLayer = YES;
        _zoomOutButton.wantsLayer = YES;
        [self addSubview:_zoomInButton];
        [self addSubview:_zoomOutButton];

        // Ensure buttons are on top
        [_zoomInButton setNeedsDisplay:YES];
        [_zoomOutButton setNeedsDisplay:YES];

        _locationCache = [[SNBExpiringCache alloc] initWithMaxSize:[ConfigurationManager sharedManager].maxLocationCacheSize
                                                expirationInterval:[ConfigurationManager sharedManager].locationCacheExpirationTime];
        _inFlightLookups = [NSMutableSet set];
        _failedLookups = [NSMutableSet set];
        NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        sessionConfig.URLCache = nil;
        sessionConfig.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        _session = [NSURLSession sessionWithConfiguration:sessionConfig];
        _renderQueue = dispatch_queue_create("com.sniffnetbar.map.render", DISPATCH_QUEUE_SERIAL);
        NSUInteger semaphoreLimit = [ConfigurationManager sharedManager].geoLocationSemaphoreLimit;
        _geoLocationSemaphore = dispatch_semaphore_create((long)semaphoreLimit);

        NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProvider];
        NSString *defaultProvider = [ConfigurationManager sharedManager].defaultMapProvider;
        _providerName = savedProvider.length > 0 ? savedProvider : defaultProvider;

        NSString *supportDir = SNBLocationStoreDirectory();
        NSString *dbPath = [supportDir stringByAppendingPathComponent:@"location_cache.sqlite"];
        _locationStore = [[SNBLocationStore alloc] initWithPath:dbPath
                                            expirationInterval:[ConfigurationManager sharedManager].locationCacheExpirationTime];

        [self loadMapHTML];
        [self updateLayout];
    }
    return self;
}

- (NSSize)intrinsicContentSize {
    // Return the size we want the view to be
    return self.frame.size;
}

- (void)dealloc {
    [_session invalidateAndCancel];
}

- (void)setProviderName:(NSString *)providerName {
    if ([_providerName isEqualToString:providerName]) {
        return;
    }
    _providerName = [providerName copy];
    [self.failedLookups removeAllObjects];
    [self.inFlightLookups removeAllObjects];
}

- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    if (self.window && self.lastConnections.count > 0) {
        [self updateWithConnections:self.lastConnections];
    }
}

- (void)viewDidMoveToSuperview {
    [super viewDidMoveToSuperview];
}

- (void)setFrameSize:(NSSize)newSize {
    [super setFrameSize:newSize];
    [self updateLayout];
}

- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self updateWithConnections:connections];
        });
        return;
    }

    self.lastConnections = connections;
    if (!self.window) {
        return;
    }

    NSDate *now = [NSDate date];
    if (!self.lastCacheCleanupTime || [now timeIntervalSinceDate:self.lastCacheCleanupTime] > 5.0) {
        self.lastCacheCleanupTime = now;
        NSUInteger expiredCount = [self.locationCache cleanupAndReturnExpiredCount];
        [self.locationStore cleanupExpiredEntries];
        if (expiredCount > 0) {
            SNBLogUIDebug(": cleaned up %lu expired location cache entries",
                   (unsigned long)expiredCount);
        }
    }
    SNBLogUIDebug(" update: %lu connections", (unsigned long)connections.count);
    [self updatePublicIPLocationIfNeeded];
    if (connections.count == 0) {
        [self refreshMarkers];
        return;
    }
    
    NSMutableSet<NSString *> *ips = [NSMutableSet set];
    for (ConnectionTraffic *connection in connections) {
        if (connection.sourceAddress.length > 0) {
            [ips addObject:connection.sourceAddress];
        }
        if (connection.destinationAddress.length > 0) {
            [ips addObject:connection.destinationAddress];
        }
    }
    
    NSMutableSet<NSString *> *targetIps = [NSMutableSet set];
    for (NSString *ip in ips) {
        if ([self shouldGeolocateIPAddress:ip]) {
            [targetIps addObject:ip];
        } else {
            SNBLogUIDebug(" skip local IP: %{public}@", ip);
        }
    }
    self.lastTargetIPs = [targetIps.allObjects sortedArrayUsingSelector:@selector(compare:)];
    
    SNBLogUIDebug(" target IPs: %{public}@", targetIps);
    
    BOOL canLookup = YES;
    if ([self.providerName isEqualToString:@"custom"]) {
        NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderURLTemplate];
        if (template.length == 0) {
            canLookup = NO;
        }
    }
    
    for (NSString *ip in targetIps) {
        NSDictionary *cached = [self.locationCache objectForKey:ip];
        if (!cached) {
            cached = [self.locationStore locationForIP:ip];
            if (cached) {
                [self.locationCache setObject:cached forKey:ip];
            }
        }
        if (cached) {
            continue;
        }
        if (!canLookup || [self.inFlightLookups containsObject:ip] || [self.failedLookups containsObject:ip]) {
            continue;
        }
        
        [self.inFlightLookups addObject:ip];
        [self fetchLocationForIP:ip completion:^(CLLocationCoordinate2D coord, BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.inFlightLookups removeObject:ip];
                if (!success) {
                    [self.failedLookups addObject:ip];
                    return;
                }
                SNBLogUIDebug(" pin ready for %{public}@ (%f, %f)", ip, coord.latitude, coord.longitude);
                [self refreshMarkers];
            });
        }];
    }
    
    [self refreshMarkers];
}

- (void)updatePublicIPLocationIfNeeded {
    if (self.publicIPLookupInFlight || self.publicIPAddress.length > 0) {
        return;
    }
    
    self.publicIPLookupInFlight = YES;
    NSURL *url = [NSURL URLWithString:@"https://api.ipify.org?format=json"];
    if (!url) {
        self.publicIPLookupInFlight = NO;
        return;
    }
    
    SNBLogUIDebug(" public IP lookup via %{public}@", url.absoluteString);
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) {
            SNBLogUIDebug(" public IP lookup failed: %{public}@", error.localizedDescription);
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        NSError *jsonError;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError || ![json isKindOfClass:[NSDictionary class]]) {
            SNBLogUIDebug(" public IP JSON error: %{public}@", jsonError.localizedDescription);
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        NSString *ip = json[@"ip"];
        if (ip.length == 0) {
            SNBLogUIDebug(" public IP missing in response");
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        SNBLogUIDebug(" public IP: %{public}@", ip);
        self.publicIPAddress = ip;
        [self fetchLocationForIP:ip completion:^(CLLocationCoordinate2D coord, BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.publicIPLookupInFlight = NO;
                if (!success) {
                    SNBLogUIDebug(" public IP geolocation failed: %{public}@", ip);
                    return;
                }
                self.publicIPCoordinate = [NSValue valueWithBytes:&coord objCType:@encode(CLLocationCoordinate2D)];
                SNBLogUIDebug(" public IP located: %{public}@ => (%f, %f)", ip, coord.latitude, coord.longitude);
                [self refreshMarkers];
            });
        }];
    }];
    [task resume];
}

- (void)refreshMarkers {
    if (!self.mapReady) {
        return;
    }

    self.renderGeneration += 1;
    NSUInteger generation = self.renderGeneration;
    NSArray<NSString *> *targetIPs = [self.lastTargetIPs copy] ?: @[];
    NSArray<ConnectionTraffic *> *connections = [self.lastConnections copy] ?: @[];
    NSString *publicIP = [self.publicIPAddress copy];
    NSValue *publicCoordValue = self.publicIPCoordinate;
    ConfigurationManager *config = [ConfigurationManager sharedManager];

    NSMutableDictionary<NSString *, NSDictionary *> *locationByIP = [NSMutableDictionary dictionary];
    for (NSString *ip in targetIPs) {
        NSDictionary *value = [self.locationCache objectForKey:ip];
        if (value) {
            locationByIP[ip] = value;
        }
    }

    NSMutableDictionary<NSString *, NSDictionary *> *badgeInfoByIP = [NSMutableDictionary dictionary];
    for (ConnectionTraffic *connection in connections) {
        [self addBadgeInfoForIPAddress:connection.sourceAddress connection:connection map:badgeInfoByIP];
        [self addBadgeInfoForIPAddress:connection.destinationAddress connection:connection map:badgeInfoByIP];
    }

    NSInteger maxLines = MIN(config.maxConnectionLinesToShow, connections.count);
    for (NSInteger i = 0; i < maxLines; i++) {
        ConnectionTraffic *connection = connections[i];
        if (connection.sourceAddress.length > 0 && !locationByIP[connection.sourceAddress]) {
            NSDictionary *value = [self.locationCache objectForKey:connection.sourceAddress];
            if (value) {
                locationByIP[connection.sourceAddress] = value;
            }
        }
        if (connection.destinationAddress.length > 0 && !locationByIP[connection.destinationAddress]) {
            NSDictionary *value = [self.locationCache objectForKey:connection.destinationAddress];
            if (value) {
                locationByIP[connection.destinationAddress] = value;
            }
        }
    }

    __weak typeof(self) weakSelf = self;
    dispatch_async(self.renderQueue, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NSMutableDictionary<NSString *, NSMutableArray<NSDictionary *> *> *pointsByCoord = [NSMutableDictionary dictionary];
        for (NSString *ip in targetIPs) {
            NSDictionary *value = locationByIP[ip];
            if (!value) {
                continue;
            }
            CLLocationCoordinate2D coord;
            coord.latitude = [value[@"lat"] doubleValue];
            coord.longitude = [value[@"lon"] doubleValue];
            if (!CLLocationCoordinate2DIsValid(coord)) {
                continue;
            }
            NSString *name = value[@"name"];
            NSString *isp = value[@"isp"];
            NSString *locationPart = name.length > 0 ? [NSString stringWithFormat:@"%@ — %@", ip, name] : ip;
            NSMutableDictionary *payload = [NSMutableDictionary dictionary];
            payload[@"lat"] = @(coord.latitude);
            payload[@"lon"] = @(coord.longitude);
            payload[@"ip"] = ip;
            payload[@"title"] = isp.length > 0 ? [NSString stringWithFormat:@"%@\nISP: %@", locationPart, isp] : locationPart;
            payload[@"name"] = name ?: @"";
            payload[@"isp"] = isp ?: @"";

            // Group by 3 decimal places (~111m precision) to cluster nearby IPs
            NSString *coordKey = [NSString stringWithFormat:@"%.3f,%.3f", coord.latitude, coord.longitude];
            NSMutableArray<NSDictionary *> *group = pointsByCoord[coordKey];
            if (!group) {
                group = [NSMutableArray array];
                pointsByCoord[coordKey] = group;
            }
            [group addObject:payload];
        }

        NSMutableArray<NSDictionary *> *points = [NSMutableArray array];
        [pointsByCoord enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSArray<NSDictionary *> *group, BOOL *stop) {
            NSDictionary *firstPoint = group.firstObject;
            NSMutableDictionary *pointData = [NSMutableDictionary dictionary];
            pointData[@"lat"] = firstPoint[@"lat"];
            pointData[@"lon"] = firstPoint[@"lon"];
            pointData[@"ips"] = [group valueForKey:@"ip"];
            pointData[@"names"] = [group valueForKey:@"name"];
            pointData[@"isps"] = [group valueForKey:@"isp"];
            pointData[@"locationName"] = firstPoint[@"name"] ?: @"";
            NSMutableArray<NSDictionary *> *badges = [NSMutableArray array];
            for (NSDictionary *payload in group) {
                NSString *ip = payload[@"ip"];
                NSDictionary *badge = badgeInfoByIP[ip];
                if (!badge) {
                    NSString *label = payload[@"name"] ?: ip;
                    NSString *icon = [[SNBBadgeRegistry sharedRegistry] badgeIconForLabel:label fallback:ip];
                    NSColor *badgeColor = [[SNBBadgeRegistry sharedRegistry] colorForLabel:label
                                                                 createIfMissing:YES];
                    NSString *colorHex = [self hexStringForColor:badgeColor];
                    badge = @{@"icon": icon ?: @"", @"color": colorHex};
                }
                [badges addObject:badge];
            }
            pointData[@"badgeInfos"] = badges;
            if (group.count > 1) {
                pointData[@"isDuplicate"] = @YES;
                pointData[@"color"] = @"#ffad60";
            } else {
                pointData[@"isDuplicate"] = @NO;
            }
            [points addObject:pointData];
            SNBLogUIDebug("Map marker: %@ @ (%f, %f) duplicates=%@", pointData[@"ips"], [pointData[@"lat"] doubleValue], [pointData[@"lon"] doubleValue], pointData[@"isDuplicate"]);
        }];

        CLLocationCoordinate2D publicCoord = kCLLocationCoordinate2DInvalid;
        if (publicCoordValue) {
            [publicCoordValue getValue:&publicCoord];
        }
        if (publicIP.length > 0 && CLLocationCoordinate2DIsValid(publicCoord)) {
            [points addObject:@{@"lat": @(publicCoord.latitude),
                                @"lon": @(publicCoord.longitude),
                                @"title": [NSString stringWithFormat:@"Public IP: %@", publicIP]}];
        }

        NSError *jsonError;
        NSData *data = [NSJSONSerialization dataWithJSONObject:points options:0 error:&jsonError];
        if (!data) {
            SNBLogUIDebug(" JSON encode error: %{public}@", jsonError.localizedDescription);
            return;
        }
        NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

        NSMutableArray<NSDictionary *> *lines = [NSMutableArray array];
        for (NSInteger i = 0; i < maxLines; i++) {
            ConnectionTraffic *connection = connections[i];

            NSDictionary *src = locationByIP[connection.sourceAddress];
            BOOL srcIsLocal = ![strongSelf shouldGeolocateIPAddress:connection.sourceAddress];
            if (!src && srcIsLocal && CLLocationCoordinate2DIsValid(publicCoord)) {
                src = @{@"lat": @(publicCoord.latitude), @"lon": @(publicCoord.longitude)};
            }

            NSDictionary *dst = locationByIP[connection.destinationAddress];
            BOOL dstIsLocal = ![strongSelf shouldGeolocateIPAddress:connection.destinationAddress];
            if (!dst && dstIsLocal && CLLocationCoordinate2DIsValid(publicCoord)) {
                dst = @{@"lat": @(publicCoord.latitude), @"lon": @(publicCoord.longitude)};
            }

            if (!src || !dst) {
                continue;
            }

            CLLocationCoordinate2D srcCoord = CLLocationCoordinate2DMake([src[@"lat"] doubleValue], [src[@"lon"] doubleValue]);
            CLLocationCoordinate2D dstCoord = CLLocationCoordinate2DMake([dst[@"lat"] doubleValue], [dst[@"lon"] doubleValue]);
            if (!CLLocationCoordinate2DIsValid(srcCoord) || !CLLocationCoordinate2DIsValid(dstCoord)) {
                continue;
            }

            NSString *lineTitle = [NSString stringWithFormat:@"%@ → %@ (%@)",
                                   connection.sourceAddress,
                                   connection.destinationAddress,
                                   [SNBByteFormatter stringFromBytes:connection.bytes]];
            [lines addObject:@{@"srcLat": @(srcCoord.latitude),
                               @"srcLon": @(srcCoord.longitude),
                               @"dstLat": @(dstCoord.latitude),
                               @"dstLon": @(dstCoord.longitude),
                               @"title": lineTitle}];
            SNBLogUIDebug("Map line: %@.%ld (%@) -> %@.%ld (%@)",
                          connection.sourceAddress,
                          connection.sourcePort,
                          [SNBByteFormatter stringFromBytes:connection.bytes],
                          connection.destinationAddress,
                          connection.destinationPort,
                          [NSString stringWithFormat:@"src(%f,%f) dst(%f,%f)",
                             srcCoord.latitude, srcCoord.longitude, dstCoord.latitude, dstCoord.longitude]);
        }
        SNBLogUIDebug(": created %lu connection lines from %lu connections", (unsigned long)lines.count, (unsigned long)connections.count);

        // Update the count of actually drawn connections for display synchronization
        strongSelf.drawnConnectionCount = lines.count;
        SNBLogUIDebug("Map draw count=%lu (capped at %ld lines)", (unsigned long)lines.count, (long)maxLines);

        if (lines.count > 0) {
            SNBLogUIDebug(": First line example: %{public}@", lines[0]);
        }

        NSData *lineData = [NSJSONSerialization dataWithJSONObject:lines options:0 error:&jsonError];
        if (!lineData) {
            SNBLogUIDebug(" JSON encode error (lines): %{public}@", jsonError.localizedDescription);
            return;
        }
        NSString *lineJson = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];
        NSString *script = [NSString stringWithFormat:@"window.SniffNetBar && window.SniffNetBar.setMarkers(%@, %@);", json, lineJson];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (generation != strongSelf.renderGeneration || !strongSelf.mapReady) {
                return;
            }
            [strongSelf.webView evaluateJavaScript:script completionHandler:^(id result, NSError *error) {
                if (error) {
                    SNBLogUIDebug(" JS error: %{public}@", error.localizedDescription);
                }
            }];
        });
    });
}

- (void)loadMapHTML {
    ConfigurationManager *config = [ConfigurationManager sharedManager];
    NSString *lineColor = config.connectionLineColor;
    NSInteger lineWeight = config.connectionLineWeight;
    CGFloat lineOpacity = config.connectionLineOpacity;

    NSString *html = [NSString stringWithFormat:
    @"<!doctype html>"
    "<html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    "<link rel='stylesheet' href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'>"
    "<style>"
    "html,body,#map{height:100%%;margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}"
    "#map{background:#f8fafc;}"
    ".leaflet-popup-content-wrapper{background:#ffffff;color:#1e293b;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.15),"
    "0 0 0 1px rgba(0,0,0,0.05);max-width:300px;min-width:200px;}"
    ".leaflet-popup-content{margin:14px 16px;font-size:13px;line-height:1.6;}"
    ".leaflet-popup-tip{background:#ffffff;}"
    ".leaflet-popup-content .location-header{color:#0f172a;font-weight:600;font-size:14px;margin-bottom:8px;display:flex;align-items:center;gap:6px;}"
    ".leaflet-popup-content .location-name{color:#64748b;font-size:12px;margin-bottom:10px;}"
    ".leaflet-popup-content .ip-list{list-style:none;padding:0;margin:0;}"
    ".leaflet-popup-content .ip-list li{padding:8px 0;border-bottom:1px solid rgba(0,0,0,0.06);}"
    ".leaflet-popup-content .ip-list li:last-child{border-bottom:none;padding-bottom:0;}"
    ".leaflet-popup-content .ip-address{color:#0f172a;font-weight:500;font-size:13px;display:block;margin-bottom:2px;font-family:Monaco,Consolas,monospace;}"
    ".leaflet-popup-content .ip-company{color:#64748b;font-size:12px;display:block;}"
    ".leaflet-popup-content .ip-item{display:flex;align-items:flex-start;gap:8px;font-size:13px;}"
    ".leaflet-popup-content .ip-badge{display:flex;align-items:center;gap:4px;padding:3px 6px;border:1px solid currentColor;border-radius:999px;font-size:11px;font-weight:600;text-transform:uppercase;box-shadow:0 1px 3px rgba(15,23,42,0.1);}"
    ".leaflet-popup-content .ip-badge-dot{width:6px;height:6px;border-radius:50%;display:inline-block;}"
    ".leaflet-popup-content .ip-badge-icon{line-height:1;}"
    ".leaflet-popup-content .ip-text{flex:1;display:flex;flex-direction:column;gap:2px;}"
    ".cluster-marker{background:linear-gradient(135deg,#ef4444 0%%,#dc2626 100%%);"
    "border:3px solid #ffffff;border-radius:50%%;box-shadow:0 3px 12px rgba(239,68,68,0.4),"
    "0 0 0 4px rgba(239,68,68,0.15);display:flex;align-items:center;justify-content:center;"
    "color:white;font-weight:bold;font-size:13px;transition:all 0.2s ease;text-align:center;"
    "line-height:1;}"
    ".cluster-marker>div{display:flex;align-items:center;justify-content:center;width:100%%;height:100%%;}"
    ".cluster-marker:hover{transform:scale(1.15);box-shadow:0 5px 16px rgba(239,68,68,0.5),"
    "0 0 0 6px rgba(239,68,68,0.25);}"
    ".single-marker{width:28px;height:36px;position:relative;}"
    ".single-marker::before{content:'';position:absolute;bottom:0;left:50%%;transform:translateX(-50%%);"
    "width:0;height:0;border-left:14px solid transparent;border-right:14px solid transparent;"
    "border-top:20px solid #2563eb;filter:drop-shadow(0 2px 4px rgba(0,0,0,0.2));}"
    ".single-marker::after{content:'';position:absolute;top:4px;left:50%%;transform:translateX(-50%%);"
    "width:18px;height:18px;border-radius:50%%;background:#3b82f6;"
    "box-shadow:0 0 0 3px rgba(255,255,255,0.9),0 2px 8px rgba(37,99,235,0.4),"
    "inset 0 1px 3px rgba(255,255,255,0.5);}"
    ".connection-line{filter:drop-shadow(0 1px 2px rgba(0,0,0,0.15));}"
    "@keyframes pulse{0%%,100%%{opacity:0.7;transform:scale(1);}50%%{opacity:1;transform:scale(1.08);}}"
    "@keyframes dash{0%%{stroke-dashoffset:20;}100%%{stroke-dashoffset:0;}}"
    ".leaflet-interactive.connection-line{animation:dash 1.5s linear infinite;}"
    "</style>"
    "</head><body>"
    "<div id='map'></div>"
    "<script src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'></script>"
    "<script>"
    "var map=L.map('map',{zoomControl:false,attributionControl:false}).setView([20,0],2);"
    "L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png',{maxZoom:19,attribution:'&copy; OpenStreetMap &copy; CARTO'}).addTo(map);"
    "var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');"
    "svg.setAttribute('width','0');svg.setAttribute('height','0');"
    "svg.innerHTML='<defs><marker id=\"arrowhead\" markerWidth=\"6\" markerHeight=\"6\" refX=\"5\" refY=\"2\" orient=\"auto\"><polygon points=\"0 0, 6 2, 0 4\" fill=\"%@\" opacity=\"0.7\"/></marker></defs>';"
    "document.body.appendChild(svg);"
    "var markers=[];var lines=[];var hasAutoFitted=false;"
    "var popupOpen=false;"
    "var pendingUpdate=null;"
    "function applyPendingUpdate(){"
    "  if(pendingUpdate){"
    "    var update=pendingUpdate;"
    "    pendingUpdate=null;"
    "    setTimeout(function(){"
    "      setMarkers(update.points,update.connections);"
    "    },0);"
    "  }"
    "}"
    "function clearMarkers(){markers.forEach(function(m){map.removeLayer(m);});markers=[];}"
    "function clearLines(){lines.forEach(function(l){map.removeLayer(l);});lines=[];}"
    "function arcPoints(a,b){var lat1=a.lat,lon1=a.lon,lat2=b.lat,lon2=b.lon;"
    "var dx=lon2-lon1;var dy=lat2-lat1;var dist=Math.sqrt(dx*dx+dy*dy)||1;"
    "var curve=Math.min(10,Math.max(2,dist*0.3));var mx=(lat1+lat2)/2;var my=(lon1+lon2)/2;"
    "var cx=mx+(-dx/dist)*curve;var cy=my+(dy/dist)*curve;var pts=[];for(var t=0;t<=1.001;t+=0.1){"
    "var lat=(1-t)*(1-t)*lat1+2*(1-t)*t*cx+t*t*lat2;"
    "var lon=(1-t)*(1-t)*lon1+2*(1-t)*t*cy+t*t*lon2;pts.push([lat,lon]);}return pts;}"
    "function setMarkers(points,connections){"
    "  if(popupOpen){"
    "    pendingUpdate={points:points,connections:connections};"
    "    return;"
    "  }"
    "  pendingUpdate=null;"
    "  clearMarkers();clearLines();var bounds=[];"
    "console.log('setMarkers called with',points?points.length:0,'points and',connections?connections.length:0,'connections');"
    "if(points){points.forEach(function(p){if(typeof p.lat!=='number'||typeof p.lon!=='number'){return;}"
    "var popupContent='';"
    "if(Array.isArray(p.ips)&&p.ips.length>0){"
    "  var count=p.ips.length;"
    "  popupContent='<div class=\"location-header\">📍 '+count+' Connection'+(count>1?'s':'')+'</div>';"
    "  if(p.locationName&&p.locationName.length>0){"
    "    popupContent+='<div class=\"location-name\">'+p.locationName+'</div>';"
    "  }"
    "  popupContent+='<ul class=\"ip-list\">';"
    "  p.ips.forEach(function(ip,idx){"
    "    var isp=p.isps&&p.isps[idx]?p.isps[idx]:'';"
    "    var badge=p.badgeInfos&&p.badgeInfos[idx]?p.badgeInfos[idx]:null;"
    "    var badgeMarkup='';"
    "    if(badge){"
    "      var color=badge.color||'#94a3b8';"
    "      var icon=badge.icon||'';"
    "      badgeMarkup='<span class=\"ip-badge\" style=\"border-color:'+color+';color:'+color+';\">';"
    "      badgeMarkup+='<span class=\"ip-badge-dot\" style=\"background:'+color+'\"></span>';"
    "      badgeMarkup+='<span class=\"ip-badge-icon\">'+icon+'</span>';"
    "      badgeMarkup+='</span>';"
    "    }"
    "    popupContent+='<li class=\"ip-item\">';"
    "    popupContent+=badgeMarkup;"
    "    popupContent+='<span class=\"ip-text\">';"
    "    popupContent+='<span class=\"ip-address\">'+ip+'</span>';"
    "    if(isp&&isp.length>0){"
    "      popupContent+='<span class=\"ip-company\">'+isp+'</span>';"
    "    }"
    "    popupContent+='</span></li>';"
    "  });"
    "  popupContent+='</ul>';"
    "}else if(p.title){"
    "  popupContent='<div class=\"location-header\">📍 Location</div>'+p.title.replace(/\\n/g,'<br>');"
    "}"
    "var marker;"
    "if(p.isDuplicate){"
    "  var count=p.ips?p.ips.length:0;"
    "  var size=Math.min(44,Math.max(28,count*3+20));"
    "  var icon=L.divIcon({"
    "    className:'cluster-marker',"
    "    html:'<div>'+count+'</div>',"
    "    iconSize:[size,size],"
    "    iconAnchor:[size/2,size/2]"
    "  });"
    "  marker=L.marker([p.lat,p.lon],{icon:icon});"
    "}else{"
    "  var icon=L.divIcon({"
    "    className:'single-marker',"
    "    html:'<div class=\"single-marker\"></div>',"
    "    iconSize:[24,32],"
    "    iconAnchor:[12,32]"
    "  });"
    "  marker=L.marker([p.lat,p.lon],{icon:icon});"
    "}"
    "if(popupContent){"
     " marker.bindPopup(popupContent);"
    "}"
    "marker.on('popupopen',function(){popupOpen=true;});"
    "marker.on('popupclose',function(){"
     " popupOpen=false;"
     " applyPendingUpdate();"
    "});"
    "marker.addTo(map);markers.push(marker);bounds.push([p.lat,p.lon]);});}"
    "if(connections){console.log('Processing connections:',connections);connections.forEach(function(c,idx){"
    "console.log('Connection:',c);if(typeof c.srcLat!=='number'||typeof c.srcLon!=='number'||typeof c.dstLat!=='number'||typeof c.dstLon!=='number'){console.log('Invalid coords, skipping');return;}"
    "var arcPts=arcPoints({lat:c.srcLat,lon:c.srcLon},{lat:c.dstLat,lon:c.dstLon});console.log('Arc points:',arcPts.length);"
    "var opacity=Math.max(0.3,1-(idx*0.08));"
    "var lineWeight=Math.max(1,%ld-(idx*0.3));"
    "var line=L.polyline(arcPts,{color:'%@',weight:lineWeight,opacity:opacity*%f,dashArray:'8,12',className:'connection-line'});"
    "line.on('add',function(){var path=line.getElement();if(path){path.setAttribute('marker-end','url(#arrowhead)');}});"
    "if(c.title){var popupContent='<strong>🔄 Connection</strong><br>'+c.title.replace(/→/g,'<br>→ ');line.bindPopup(popupContent);}"
    "line.addTo(map);lines.push(line);console.log('Line added to map');bounds.push([c.srcLat,c.srcLon]);bounds.push([c.dstLat,c.dstLon]);});}"
    "if(bounds.length>0&&!hasAutoFitted){map.fitBounds(bounds,{padding:[20,20],maxZoom:6});hasAutoFitted=true;}}"
    "function zoomIn(){map.zoomIn();}"
    "function zoomOut(){map.zoomOut();}"
    "function resetView(){hasAutoFitted=false;}"
    "window.SniffNetBar={setMarkers:setMarkers,zoomIn:zoomIn,zoomOut:zoomOut,resetView:resetView};"
    "</script></body></html>", lineColor, (long)lineWeight, lineColor, lineOpacity];
    [self.webView loadHTMLString:html baseURL:nil];
}

// Helper badge generation
- (void)addBadgeInfoForIPAddress:(NSString *)address
                    connection:(ConnectionTraffic *)connection
                          map:(NSMutableDictionary<NSString *, NSDictionary *> *)map {
    if (!address.length || !map) {
        return;
    }
    if (map[address]) {
        return;
    }
    BOOL hasProcessInfo = connection.processName.length > 0 || connection.processPID != 0;
    NSColor *color;
    if (hasProcessInfo) {
        color = [[SNBBadgeRegistry sharedRegistry] colorForProcessName:connection.processName
                                                                   pid:connection.processPID
                                                  createIfMissing:YES];
    } else {
        color = [[SNBBadgeRegistry sharedRegistry] colorForLabel:address
                                                 createIfMissing:YES];
    }
    NSString *icon = [[SNBBadgeRegistry sharedRegistry] badgeIconForProcessName:connection.processName
                                                                             pid:connection.processPID
                                                                  fallbackLabel:address];
    NSString *colorHex = [self hexStringForColor:color];
    map[address] = @{@"icon": icon ?: @"", @"color": colorHex};
}

- (NSString *)hexStringForColor:(NSColor *)color {
    NSColor *rgbColor = (color ?: [NSColor labelColor]);
    rgbColor = [rgbColor colorUsingColorSpace:[NSColorSpace sRGBColorSpace]] ?: [NSColor labelColor];
    CGFloat red = 0, green = 0, blue = 0, alpha = 0;
    [rgbColor getRed:&red green:&green blue:&blue alpha:&alpha];
    return [NSString stringWithFormat:@"#%02lX%02lX%02lX",
            (long)(red * 255.0),
            (long)(green * 255.0),
            (long)(blue * 255.0)];
}

- (NSButton *)zoomButtonWithTitle:(NSString *)title action:(SEL)action {
    NSButton *button = [[NSButton alloc] initWithFrame:NSMakeRect(0, 0, 32, 32)];
    button.title = title;
    button.bezelStyle = NSBezelStyleShadowlessSquare;
    button.target = self;
    button.action = action;
    button.font = [NSFont boldSystemFontOfSize:18.0];
    button.bordered = YES;
    button.wantsLayer = YES;
    button.layer.backgroundColor = [[NSColor colorWithWhite:1.0 alpha:0.95] CGColor];
    button.layer.cornerRadius = 8.0;
    button.layer.borderWidth = 1.0;
    button.layer.borderColor = [[NSColor colorWithRed:0 green:0 blue:0 alpha:0.1] CGColor];
    button.layer.shadowColor = [[NSColor blackColor] CGColor];
    button.layer.shadowOpacity = 0.15;
    button.layer.shadowOffset = NSMakeSize(0, 2);
    button.layer.shadowRadius = 4.0;

    NSMutableParagraphStyle *style = [[NSMutableParagraphStyle alloc] init];
    style.alignment = NSTextAlignmentCenter;
    NSDictionary *attributes = @{
        NSForegroundColorAttributeName: [NSColor colorWithRed:0.09 green:0.09 blue:0.11 alpha:1.0],
        NSFontAttributeName: [NSFont boldSystemFontOfSize:18.0],
        NSParagraphStyleAttributeName: style
    };
    button.attributedTitle = [[NSAttributedString alloc] initWithString:title attributes:attributes];

    return button;
}

- (void)updateLayout {
    self.webView.frame = self.bounds;
    CGFloat padding = 10.0;
    CGFloat buttonSize = 32.0;
    CGFloat right = NSMaxX(self.bounds) - padding - buttonSize;
    CGFloat top = NSMaxY(self.bounds) - padding - buttonSize;
    self.zoomInButton.frame = NSMakeRect(right, top, buttonSize, buttonSize);
    self.zoomOutButton.frame = NSMakeRect(right, top - buttonSize - 8.0, buttonSize, buttonSize);

    // Ensure buttons stay on top of webview
    [self.zoomInButton removeFromSuperview];
    [self.zoomOutButton removeFromSuperview];
    [self addSubview:self.zoomInButton];
    [self addSubview:self.zoomOutButton];
}

- (void)zoomIn:(id)sender {
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.zoomIn();" completionHandler:nil];
}

- (void)zoomOut:(id)sender {
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.zoomOut();" completionHandler:nil];
}

- (BOOL)shouldGeolocateIPAddress:(NSString *)ip {
    // Use centralized validation - only geolocate public IPs
    return [IPAddressUtilities isPublicIPAddress:ip];
}

- (void)fetchLocationForIP:(NSString *)ip completion:(void (^)(CLLocationCoordinate2D, BOOL))completion {
    // Acquire semaphore to limit concurrent requests (prevents rate limiting)
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        dispatch_semaphore_wait(self.geoLocationSemaphore, DISPATCH_TIME_FOREVER);

        NSString *provider = self.providerName.length > 0 ? self.providerName : @"ipinfo.io";
        NSString *encodedIP = [ip stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLPathAllowedCharacterSet]];
        NSString *urlString = nil;

        if ([provider isEqualToString:@"ip-api.com"]) {
            urlString = [NSString stringWithFormat:@"https://ip-api.com/json/%@?fields=status,message,lat,lon,query", encodedIP];
        } else if ([provider isEqualToString:@"ipinfo.io"]) {
            NSString *token = [ConfigurationManager sharedManager].ipInfoAPIToken;
            NSString *encodedToken = token.length > 0 ? [token stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]] : @"";
            if (encodedToken.length > 0) {
                urlString = [NSString stringWithFormat:@"https://ipinfo.io/%@/json?token=%@", encodedIP, encodedToken];
            } else {
                urlString = [NSString stringWithFormat:@"https://ipinfo.io/%@/json", encodedIP];
            }
        } else {
            NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderURLTemplate];
            if (template.length == 0) {
                dispatch_semaphore_signal(self.geoLocationSemaphore);
                completion(kCLLocationCoordinate2DInvalid, NO);
                return;
            }
            urlString = [NSString stringWithFormat:template, encodedIP];
        }

        NSURL *url = [NSURL URLWithString:urlString];
        if (!url) {
            dispatch_semaphore_signal(self.geoLocationSemaphore);
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }

        SNBLogUIDebug(" lookup %{public}@ via %{public}@", ip, urlString);

        NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            // Release semaphore when request completes
            dispatch_semaphore_signal(self.geoLocationSemaphore);
        NSHTTPURLResponse *httpResponse = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        if (error || !data) {
            SNBLogUIDebug(" lookup failed for %{public}@: %{public}@", ip, error.localizedDescription);
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }
        if (httpResponse) {
            SNBLogUIDebug(" response %{public}@ status %ld", ip, (long)httpResponse.statusCode);
        }
        
        if ([provider isEqualToString:@"ip-api.com"] && httpResponse.statusCode == 403) {
            SNBLogUIDebug(" fallback to ipinfo.io for %{public}@", ip);
            dispatch_async(dispatch_get_main_queue(), ^{
                NSString *savedProvider = self.providerName;
                self.providerName = @"ipinfo.io";
                [self fetchLocationForIP:ip completion:completion];
                self.providerName = savedProvider;
            });
            return;
        }
        
        NSError *jsonError;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError || ![json isKindOfClass:[NSDictionary class]]) {
            SNBLogUIDebug(" JSON error for %{public}@: %{public}@", ip, jsonError.localizedDescription);
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }
        
        NSDictionary *dict = (NSDictionary *)json;
        CLLocationDegrees lat = 0;
        CLLocationDegrees lon = 0;
        BOOL success = NO;
        NSString *name = nil;
        NSString *isp = nil;
        
        if ([provider isEqualToString:@"ip-api.com"]) {
            NSString *status = dict[@"status"];
            if ([status isEqualToString:@"success"]) {
                lat = [dict[@"lat"] doubleValue];
                lon = [dict[@"lon"] doubleValue];
                NSString *city = dict[@"city"];
                NSString *region = dict[@"regionName"];
                NSString *country = dict[@"country"];
                isp = dict[@"isp"];
                NSMutableArray<NSString *> *parts = [NSMutableArray array];
                if (city.length > 0) [parts addObject:city];
                if (region.length > 0) [parts addObject:region];
                if (country.length > 0) [parts addObject:country];
                name = parts.count > 0 ? [parts componentsJoinedByString:@", "] : nil;
                success = YES;
            }
        } else if ([provider isEqualToString:@"ipinfo.io"]) {
            NSString *loc = dict[@"loc"];
            NSArray<NSString *> *parts = [loc componentsSeparatedByString:@","];
            if (parts.count == 2) {
                lat = [parts[0] doubleValue];
                lon = [parts[1] doubleValue];
                NSString *city = dict[@"city"];
                NSString *region = dict[@"region"];
                NSString *country = dict[@"country"];
                NSString *org = dict[@"org"];
                NSString *company = dict[@"company"];
                if (org.length > 0) {
                    isp = org;
                } else if (company.length > 0) {
                    isp = company;
                }
                NSMutableArray<NSString *> *nameParts = [NSMutableArray array];
                if (city.length > 0) [nameParts addObject:city];
                if (region.length > 0) [nameParts addObject:region];
                if (country.length > 0) [nameParts addObject:country];
                name = nameParts.count > 0 ? [nameParts componentsJoinedByString:@", "] : nil;
                success = YES;
            }
        } else {
            NSString *latKey = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderLatKey] ?: @"lat";
            NSString *lonKey = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderLonKey] ?: @"lon";
            id latValue = [dict valueForKeyPath:latKey];
            id lonValue = [dict valueForKeyPath:lonKey];
            if ([latValue respondsToSelector:@selector(doubleValue)] &&
                [lonValue respondsToSelector:@selector(doubleValue)]) {
                lat = [latValue doubleValue];
                lon = [lonValue doubleValue];
                success = YES;
            }
        }
        
        if (success) {
            SNBLogUIDebug(" location %{public}@ => (%f, %f)", ip, lat, lon);
            NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithDictionary:@{@"lat": @(lat), @"lon": @(lon)}];
            if (name.length > 0) {
                payload[@"name"] = name;
            }
            if (isp.length > 0) {
                payload[@"isp"] = isp;
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.locationCache setObject:payload forKey:ip];
                [self.locationStore storeLocation:payload forIP:ip];
                completion(CLLocationCoordinate2DMake(lat, lon), YES);
            });
        } else {
            SNBLogUIDebug(" location missing for %{public}@ (%{public}@)", ip, provider);
            completion(kCLLocationCoordinate2DInvalid, NO);
        }
        }];
        [task resume];
    });
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    self.mapReady = YES;
    [self refreshMarkers];
}

@end
