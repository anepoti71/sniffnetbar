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
#import "Logger.h"
#import <WebKit/WebKit.h>
#import <CoreLocation/CoreLocation.h>

@interface MapMenuView () <WKNavigationDelegate>
@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, strong) NSButton *zoomInButton;
@property (nonatomic, strong) NSButton *zoomOutButton;
@property (nonatomic, strong) SNBExpiringCache<NSString *, NSDictionary *> *locationCache;
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
@end

@implementation MapMenuView

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
        _session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
        _renderQueue = dispatch_queue_create("com.sniffnetbar.map.render", DISPATCH_QUEUE_SERIAL);

        NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProvider];
        NSString *defaultProvider = [ConfigurationManager sharedManager].defaultMapProvider;
        _providerName = savedProvider.length > 0 ? savedProvider : defaultProvider;

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

    NSUInteger expiredCount = [self.locationCache cleanupAndReturnExpiredCount];
    if (expiredCount > 0) {
        SNBLogUIDebug(": cleaned up %lu expired location cache entries",
               (unsigned long)expiredCount);
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
        if ([self.locationCache objectForKey:ip]) {
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

        NSMutableArray<NSDictionary *> *points = [NSMutableArray array];
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
            NSString *title = isp.length > 0 ? [NSString stringWithFormat:@"%@\nISP: %@", locationPart, isp] : locationPart;
            [points addObject:@{@"lat": @(coord.latitude), @"lon": @(coord.longitude), @"title": title}];
        }

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
        }
        SNBLogUIDebug(": created %lu connection lines from %lu connections", (unsigned long)lines.count, (unsigned long)connections.count);
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
    "<style>html,body,#map{height:100%%;margin:0;}#map{background:#1b2b3a;}</style>"
    "</head><body>"
    "<div id='map'></div>"
    "<script src='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js'></script>"
    "<script>"
    "var map=L.map('map',{zoomControl:false,attributionControl:false}).setView([20,0],2);"
    "L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19}).addTo(map);"
    "var markers=[];var lines=[];var hasAutoFitted=false;"
    "function clearMarkers(){markers.forEach(function(m){map.removeLayer(m);});markers=[];}"
    "function clearLines(){lines.forEach(function(l){map.removeLayer(l);});lines=[];}"
    "function arcPoints(a,b){var lat1=a.lat,lon1=a.lon,lat2=b.lat,lon2=b.lon;"
    "var dx=lon2-lon1;var dy=lat2-lat1;var dist=Math.sqrt(dx*dx+dy*dy)||1;"
    "var curve=Math.min(10,Math.max(2,dist*0.3));var mx=(lat1+lat2)/2;var my=(lon1+lon2)/2;"
    "var cx=mx+(-dx/dist)*curve;var cy=my+(dy/dist)*curve;var pts=[];for(var t=0;t<=1.001;t+=0.1){"
    "var lat=(1-t)*(1-t)*lat1+2*(1-t)*t*cx+t*t*lat2;"
    "var lon=(1-t)*(1-t)*lon1+2*(1-t)*t*cy+t*t*lon2;pts.push([lat,lon]);}return pts;}"
    "function setMarkers(points,connections){clearMarkers();clearLines();var bounds=[];"
    "console.log('setMarkers called with',points?points.length:0,'points and',connections?connections.length:0,'connections');"
    "if(points){points.forEach(function(p){if(typeof p.lat!=='number'||typeof p.lon!=='number'){return;}"
    "var m=L.marker([p.lat,p.lon]);if(p.title){m.bindPopup(p.title);}m.addTo(map);markers.push(m);bounds.push([p.lat,p.lon]);});}"
    "if(connections){console.log('Processing connections:',connections);connections.forEach(function(c){"
    "console.log('Connection:',c);if(typeof c.srcLat!=='number'||typeof c.srcLon!=='number'||typeof c.dstLat!=='number'||typeof c.dstLon!=='number'){console.log('Invalid coords, skipping');return;}"
    "var arcPts=arcPoints({lat:c.srcLat,lon:c.srcLon},{lat:c.dstLat,lon:c.dstLon});console.log('Arc points:',arcPts.length);"
    "var line=L.polyline(arcPts,{color:'%@',weight:%ld,opacity:%f});"
    "if(c.title){line.bindPopup(c.title);}line.addTo(map);lines.push(line);console.log('Line added to map');bounds.push([c.srcLat,c.srcLon]);bounds.push([c.dstLat,c.dstLon]);});}"
    "if(bounds.length>0&&!hasAutoFitted){map.fitBounds(bounds,{padding:[20,20],maxZoom:6});hasAutoFitted=true;}}"
    "function zoomIn(){map.zoomIn();}"
    "function zoomOut(){map.zoomOut();}"
    "function resetView(){hasAutoFitted=false;}"
    "window.SniffNetBar={setMarkers:setMarkers,zoomIn:zoomIn,zoomOut:zoomOut,resetView:resetView};"
    "</script></body></html>", lineColor, (long)lineWeight, lineOpacity];
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
    NSString *provider = self.providerName.length > 0 ? self.providerName : @"ipinfo.io";
    NSString *encodedIP = [ip stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLPathAllowedCharacterSet]];
    NSString *urlString = nil;
    
    if ([provider isEqualToString:@"ip-api.com"]) {
        urlString = [NSString stringWithFormat:@"https://ip-api.com/json/%@?fields=status,message,lat,lon,query", encodedIP];
    } else if ([provider isEqualToString:@"ipinfo.io"]) {
        urlString = [NSString stringWithFormat:@"https://ipinfo.io/%@/json", encodedIP];
    } else {
        NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:SNBUserDefaultsKeyMapProviderURLTemplate];
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
    
    SNBLogUIDebug(" lookup %{public}@ via %{public}@", ip, urlString);
    
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
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
                completion(CLLocationCoordinate2DMake(lat, lon), YES);
            });
        } else {
            SNBLogUIDebug(" location missing for %{public}@ (%{public}@)", ip, provider);
            completion(kCLLocationCoordinate2DInvalid, NO);
        }
    }];
    [task resume];
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    self.mapReady = YES;
    [self refreshMarkers];
}

@end
