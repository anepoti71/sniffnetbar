//
//  MapMenuView.m
//  SniffNetBar
//
//  Map visualization embedded in the menu (Leaflet via WebKit)
//

#import "MapMenuView.h"
#import <WebKit/WebKit.h>
#import <CoreLocation/CoreLocation.h>

static NSString *const kMapProviderKey = @"MapProvider";
static NSString *const kMapProviderURLTemplateKey = @"MapProviderURLTemplate";
static NSString *const kMapProviderLatKey = @"MapProviderLatKey";
static NSString *const kMapProviderLonKey = @"MapProviderLonKey";

// Cache limits
static const NSUInteger kMaxLocationCacheSize = 500;
static const NSTimeInterval kLocationCacheExpirationTime = 7200; // 2 hours

@interface MapMenuView () <WKNavigationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, strong) NSButton *zoomInButton;
@property (nonatomic, strong) NSButton *zoomOutButton;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary *> *locationCache;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDate *> *locationCacheTimestamps;
@property (nonatomic, strong) NSMutableSet<NSString *> *inFlightLookups;
@property (nonatomic, strong) NSMutableSet<NSString *> *failedLookups;
@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, copy) NSArray<ConnectionTraffic *> *lastConnections;
@property (nonatomic, copy) NSString *publicIPAddress;
@property (nonatomic, strong) NSValue *publicIPCoordinate;
@property (nonatomic, assign) BOOL publicIPLookupInFlight;
@property (nonatomic, assign) BOOL mapReady;
@property (nonatomic, copy) NSArray<NSString *> *lastTargetIPs;
@end

@implementation MapMenuView

- (instancetype)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
        _webView = [[WKWebView alloc] initWithFrame:self.bounds configuration:config];
        _webView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        _webView.navigationDelegate = self;
        [self addSubview:_webView];
        
        _zoomInButton = [self zoomButtonWithTitle:@"+" action:@selector(zoomIn:)];
        _zoomOutButton = [self zoomButtonWithTitle:@"−" action:@selector(zoomOut:)];
        [self addSubview:_zoomInButton];
        [self addSubview:_zoomOutButton];
        
        _locationCache = [NSMutableDictionary dictionary];
        _locationCacheTimestamps = [NSMutableDictionary dictionary];
        _inFlightLookups = [NSMutableSet set];
        _failedLookups = [NSMutableSet set];
        _session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];

        NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderKey];
        _providerName = savedProvider.length > 0 ? savedProvider : @"ipinfo.io";

        [self loadMapHTML];
        [self updateLayout];
    }
    return self;
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

- (void)cleanupLocationCache {
    NSDate *now = [NSDate date];
    NSMutableArray<NSString *> *expiredKeys = [NSMutableArray array];

    // Find expired entries
    for (NSString *key in self.locationCacheTimestamps) {
        NSDate *timestamp = self.locationCacheTimestamps[key];
        if ([now timeIntervalSinceDate:timestamp] > kLocationCacheExpirationTime) {
            [expiredKeys addObject:key];
        }
    }

    // Remove expired entries
    for (NSString *key in expiredKeys) {
        [self.locationCache removeObjectForKey:key];
        [self.locationCacheTimestamps removeObjectForKey:key];
    }

    // If still over limit, remove oldest entries
    if (self.locationCache.count > kMaxLocationCacheSize) {
        NSArray<NSString *> *sortedKeys = [self.locationCacheTimestamps keysSortedByValueUsingComparator:^NSComparisonResult(NSDate *obj1, NSDate *obj2) {
            return [obj1 compare:obj2];
        }];
        NSUInteger toRemove = self.locationCache.count - kMaxLocationCacheSize;
        for (NSUInteger i = 0; i < toRemove && i < sortedKeys.count; i++) {
            NSString *key = sortedKeys[i];
            [self.locationCache removeObjectForKey:key];
            [self.locationCacheTimestamps removeObjectForKey:key];
        }
    }

    if (expiredKeys.count > 0) {
        NSLog(@"MapMenuView: cleaned up %lu expired location cache entries", (unsigned long)expiredKeys.count);
    }
}

- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    [self adjustToMenuWidthIfNeeded];
    if (self.window && self.lastConnections.count > 0) {
        [self updateWithConnections:self.lastConnections];
    }
}

- (void)viewDidMoveToSuperview {
    [super viewDidMoveToSuperview];
    [self adjustToMenuWidthIfNeeded];
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

    [self adjustToMenuWidthIfNeeded];
    [self cleanupLocationCache];  // Periodic cache cleanup
    NSLog(@"MapMenuView update: %lu connections", (unsigned long)connections.count);
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
            NSLog(@"MapMenuView skip local IP: %@", ip);
        }
    }
    self.lastTargetIPs = [targetIps.allObjects sortedArrayUsingSelector:@selector(compare:)];
    
    NSLog(@"MapMenuView target IPs: %@", targetIps);
    
    BOOL canLookup = YES;
    if ([self.providerName isEqualToString:@"custom"]) {
        NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderURLTemplateKey];
        if (template.length == 0) {
            canLookup = NO;
        }
    }
    
    for (NSString *ip in targetIps) {
        if (self.locationCache[ip]) {
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
                NSLog(@"MapMenuView pin ready for %@ (%f, %f)", ip, coord.latitude, coord.longitude);
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
    
    NSLog(@"MapMenuView public IP lookup via %@", url.absoluteString);
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) {
            NSLog(@"MapMenuView public IP lookup failed: %@", error.localizedDescription);
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        NSError *jsonError;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError || ![json isKindOfClass:[NSDictionary class]]) {
            NSLog(@"MapMenuView public IP JSON error: %@", jsonError.localizedDescription);
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        NSString *ip = json[@"ip"];
        if (ip.length == 0) {
            NSLog(@"MapMenuView public IP missing in response");
            self.publicIPLookupInFlight = NO;
            return;
        }
        
        NSLog(@"MapMenuView public IP: %@", ip);
        self.publicIPAddress = ip;
        [self fetchLocationForIP:ip completion:^(CLLocationCoordinate2D coord, BOOL success) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.publicIPLookupInFlight = NO;
                if (!success) {
                    NSLog(@"MapMenuView public IP geolocation failed: %@", ip);
                    return;
                }
                self.publicIPCoordinate = [NSValue valueWithBytes:&coord objCType:@encode(CLLocationCoordinate2D)];
                NSLog(@"MapMenuView public IP located: %@ => (%f, %f)", ip, coord.latitude, coord.longitude);
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
    
    NSMutableArray<NSDictionary *> *points = [NSMutableArray array];
    for (NSString *ip in self.lastTargetIPs) {
        NSDictionary *value = self.locationCache[ip];
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
        NSString *title = isp.length > 0 ? [NSString stringWithFormat:@"%@\nISP: %@", locationPart, isp] : locationPart;
        [points addObject:@{@"lat": @(coord.latitude), @"lon": @(coord.longitude), @"title": title}];
    }
    
    if (self.publicIPAddress.length > 0 && self.publicIPCoordinate) {
        CLLocationCoordinate2D coord;
        [self.publicIPCoordinate getValue:&coord];
        if (CLLocationCoordinate2DIsValid(coord)) {
            [points addObject:@{@"lat": @(coord.latitude),
                                @"lon": @(coord.longitude),
                                @"title": [NSString stringWithFormat:@"Public IP: %@", self.publicIPAddress]}];
        }
    }
    
    NSError *jsonError;
    NSData *data = [NSJSONSerialization dataWithJSONObject:points options:0 error:&jsonError];
    if (!data) {
        NSLog(@"MapMenuView JSON encode error: %@", jsonError.localizedDescription);
        return;
    }
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSMutableArray<NSDictionary *> *lines = [NSMutableArray array];
    NSInteger maxLines = MIN(10, self.lastConnections.count);
    for (NSInteger i = 0; i < maxLines; i++) {
        ConnectionTraffic *connection = self.lastConnections[i];
        NSDictionary *src = self.locationCache[connection.sourceAddress];
        NSDictionary *dst = self.locationCache[connection.destinationAddress];
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
                               [self formatBytes:connection.bytes]];
        [lines addObject:@{@"srcLat": @(srcCoord.latitude),
                           @"srcLon": @(srcCoord.longitude),
                           @"dstLat": @(dstCoord.latitude),
                           @"dstLon": @(dstCoord.longitude),
                           @"title": lineTitle}];
    }
    NSData *lineData = [NSJSONSerialization dataWithJSONObject:lines options:0 error:&jsonError];
    if (!lineData) {
        NSLog(@"MapMenuView JSON encode error (lines): %@", jsonError.localizedDescription);
        return;
    }
    NSString *lineJson = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];
    NSString *script = [NSString stringWithFormat:@"window.SniffNetBar && window.SniffNetBar.setMarkers(%@, %@);", json, lineJson];
    [self.webView evaluateJavaScript:script completionHandler:^(id result, NSError *error) {
        if (error) {
            NSLog(@"MapMenuView JS error: %@", error.localizedDescription);
        }
    }];
}

- (void)loadMapHTML {
    NSString *html = @"<!doctype html>"
    "<html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    "<link rel='stylesheet' href='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'>"
    "<style>html,body,#map{height:100%;margin:0;}#map{background:#1b2b3a;}</style>"
    "</head><body>"
    "<div id='map'></div>"
    "<script src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'></script>"
    "<script>"
    "var map=L.map('map',{zoomControl:false,attributionControl:false}).setView([20,0],2);"
    "L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19}).addTo(map);"
    "var markers=[];var lines=[];"
    "function clearMarkers(){markers.forEach(function(m){map.removeLayer(m);});markers=[];}"
    "function clearLines(){lines.forEach(function(l){map.removeLayer(l);});lines=[];}"
    "function arcPoints(a,b){var lat1=a.lat,lon1=a.lon,lat2=b.lat,lon2=b.lon;"
    "var dx=lon2-lon1;var dy=lat2-lat1;var dist=Math.sqrt(dx*dx+dy*dy)||1;"
    "var curve=Math.min(10,Math.max(2,dist*0.3));var mx=(lat1+lat2)/2;var my=(lon1+lon2)/2;"
    "var cx=mx+(-dx/dist)*curve;var cy=my+(dy/dist)*curve;var pts=[];for(var t=0;t<=1.001;t+=0.1){"
    "var lat=(1-t)*(1-t)*lat1+2*(1-t)*t*cx+t*t*lat2;"
    "var lon=(1-t)*(1-t)*lon1+2*(1-t)*t*cy+t*t*lon2;pts.push([lat,lon]);}return pts;}"
    "function setMarkers(points,connections){clearMarkers();clearLines();var bounds=[];"
    "if(points){points.forEach(function(p){if(typeof p.lat!=='number'||typeof p.lon!=='number'){return;}"
    "var m=L.marker([p.lat,p.lon]);if(p.title){m.bindPopup(p.title);}m.addTo(map);markers.push(m);bounds.push([p.lat,p.lon]);});}"
    "if(connections){connections.forEach(function(c){if(typeof c.srcLat!=='number'||typeof c.srcLon!=='number'||typeof c.dstLat!=='number'||typeof c.dstLon!=='number'){return;}"
    "var line=L.polyline(arcPoints({lat:c.srcLat,lon:c.srcLon},{lat:c.dstLat,lon:c.dstLon}),{color:'#ff7a18',weight:2,opacity:0.8});"
    "if(c.title){line.bindPopup(c.title);}line.addTo(map);lines.push(line);bounds.push([c.srcLat,c.srcLon]);bounds.push([c.dstLat,c.dstLon]);});}"
    "if(bounds.length>0){map.fitBounds(bounds,{padding:[20,20],maxZoom:6});}}"
    "function zoomIn(){map.zoomIn();}"
    "function zoomOut(){map.zoomOut();}"
    "window.SniffNetBar={setMarkers:setMarkers,zoomIn:zoomIn,zoomOut:zoomOut};"
    "</script></body></html>";
    [self.webView loadHTMLString:html baseURL:nil];
}

- (NSButton *)zoomButtonWithTitle:(NSString *)title action:(SEL)action {
    NSButton *button = [[NSButton alloc] initWithFrame:NSMakeRect(0, 0, 22, 22)];
    button.title = title;
    button.bezelStyle = NSBezelStyleTexturedRounded;
    button.target = self;
    button.action = action;
    button.font = [NSFont boldSystemFontOfSize:14.0];
    return button;
}

- (void)updateLayout {
    self.webView.frame = self.bounds;
    CGFloat padding = 6.0;
    CGFloat buttonSize = 22.0;
    CGFloat right = NSMaxX(self.bounds) - padding - buttonSize;
    CGFloat top = NSMaxY(self.bounds) - padding - buttonSize;
    self.zoomInButton.frame = NSMakeRect(right, top, buttonSize, buttonSize);
    self.zoomOutButton.frame = NSMakeRect(right, top - buttonSize - 4.0, buttonSize, buttonSize);
}

- (void)adjustToMenuWidthIfNeeded {
    if (!self.superview) {
        return;
    }
    CGFloat menuWidth = NSWidth(self.superview.bounds);
    if (menuWidth <= 0) {
        return;
    }
    if (fabs(NSWidth(self.frame) - menuWidth) > 0.5) {
        NSRect frame = self.frame;
        frame.size.width = menuWidth;
        self.frame = frame;
    }
}

- (void)zoomIn:(id)sender {
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.zoomIn();" completionHandler:nil];
}

- (void)zoomOut:(id)sender {
    [self.webView evaluateJavaScript:@"window.SniffNetBar && window.SniffNetBar.zoomOut();" completionHandler:nil];
}

- (BOOL)shouldGeolocateIPAddress:(NSString *)ip {
    if (ip.length == 0) {
        return NO;
    }
    
    if ([ip hasPrefix:@"127."] || [ip hasPrefix:@"10."] || [ip hasPrefix:@"192.168."] || [ip hasPrefix:@"169.254."]) {
        return NO;
    }
    
    if ([ip hasPrefix:@"172."]) {
        NSArray<NSString *> *parts = [ip componentsSeparatedByString:@"."];
        if (parts.count > 1) {
            NSInteger second = [parts[1] integerValue];
            if (second >= 16 && second <= 31) {
                return NO;
            }
        }
    }
    
    if ([ip isEqualToString:@"::1"] || [ip hasPrefix:@"fe80:"] || [ip hasPrefix:@"fc"] || [ip hasPrefix:@"fd"]) {
        return NO;
    }
    
    return YES;
}

- (void)fetchLocationForIP:(NSString *)ip completion:(void (^)(CLLocationCoordinate2D, BOOL))completion {
    NSString *provider = self.providerName.length > 0 ? self.providerName : @"ipinfo.io";
    NSString *encodedIP = [ip stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLPathAllowedCharacterSet]];
    NSString *urlString = nil;
    
    if ([provider isEqualToString:@"ip-api.com"]) {
        urlString = [NSString stringWithFormat:@"https://ip-api.com/json/%@?fields=status,message,lat,lon,query", encodedIP];
    } else if ([provider isEqualToString:@"ipinfo.io"]) {
        urlString = [NSString stringWithFormat:@"https://ipinfo.io/%@/json", encodedIP];
    } else {
        NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderURLTemplateKey];
        if (template.length == 0) {
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }
        urlString = [NSString stringWithFormat:template, encodedIP];
    }
    
    NSURL *url = [NSURL URLWithString:urlString];
    if (!url) {
        completion(kCLLocationCoordinate2DInvalid, NO);
        return;
    }
    
    NSLog(@"MapMenuView lookup %@ via %@", ip, urlString);
    
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSHTTPURLResponse *httpResponse = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        if (error || !data) {
            NSLog(@"MapMenuView lookup failed for %@: %@", ip, error.localizedDescription);
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }
        if (httpResponse) {
            NSLog(@"MapMenuView response %@ status %ld", ip, (long)httpResponse.statusCode);
        }
        
        if ([provider isEqualToString:@"ip-api.com"] && httpResponse.statusCode == 403) {
            NSLog(@"MapMenuView fallback to ipinfo.io for %@", ip);
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
            NSLog(@"MapMenuView JSON error for %@: %@", ip, jsonError.localizedDescription);
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
            NSString *latKey = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderLatKey] ?: @"lat";
            NSString *lonKey = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderLonKey] ?: @"lon";
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
            NSLog(@"MapMenuView location %@ => (%f, %f)", ip, lat, lon);
            NSMutableDictionary *payload = [NSMutableDictionary dictionaryWithDictionary:@{@"lat": @(lat), @"lon": @(lon)}];
            if (name.length > 0) {
                payload[@"name"] = name;
            }
            if (isp.length > 0) {
                payload[@"isp"] = isp;
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                self.locationCache[ip] = payload;
                self.locationCacheTimestamps[ip] = [NSDate date];
                completion(CLLocationCoordinate2DMake(lat, lon), YES);
            });
        } else {
            NSLog(@"MapMenuView location missing for %@ (%@)", ip, provider);
            completion(kCLLocationCoordinate2DInvalid, NO);
        }
    }];
    [task resume];
}

- (NSString *)formatBytes:(uint64_t)bytes {
    if (bytes < 1024) {
        return [NSString stringWithFormat:@"%llu B", bytes];
    } else if (bytes < 1024 * 1024) {
        return [NSString stringWithFormat:@"%.2f KB", bytes / 1024.0];
    } else if (bytes < 1024 * 1024 * 1024) {
        return [NSString stringWithFormat:@"%.2f MB", bytes / (1024.0 * 1024.0)];
    } else {
        return [NSString stringWithFormat:@"%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0)];
    }
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    self.mapReady = YES;
    [self refreshMarkers];
}

@end
