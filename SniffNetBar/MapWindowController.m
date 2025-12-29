//
//  MapWindowController.m
//  SniffNetBar
//
//  Map visualization for geolocated connections
//

#import "MapWindowController.h"
#import <MapKit/MapKit.h>

static NSString *const kMapProviderKey = @"MapProvider";
static NSString *const kMapProviderURLTemplateKey = @"MapProviderURLTemplate";
static NSString *const kMapProviderLatKey = @"MapProviderLatKey";
static NSString *const kMapProviderLonKey = @"MapProviderLonKey";

@interface MapWindowController ()
@property (nonatomic, strong) MKMapView *mapView;
@property (nonatomic, strong) NSMutableDictionary<NSString *, MKPointAnnotation *> *annotations;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSValue *> *locationCache;
@property (nonatomic, strong) NSMutableSet<NSString *> *inFlightLookups;
@property (nonatomic, strong) NSMutableSet<NSString *> *failedLookups;
@property (nonatomic, strong) NSURLSession *session;
@end

@implementation MapWindowController

- (instancetype)init {
    NSRect frame = NSMakeRect(0, 0, 900, 600);
    NSWindow *window = [[NSWindow alloc] initWithContentRect:frame
                                                   styleMask:(NSWindowStyleMaskTitled |
                                                              NSWindowStyleMaskClosable |
                                                              NSWindowStyleMaskResizable)
                                                     backing:NSBackingStoreBuffered
                                                       defer:NO];
    self = [super initWithWindow:window];
    if (self) {
        _mapView = [[MKMapView alloc] initWithFrame:window.contentView.bounds];
        _mapView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        [window.contentView addSubview:_mapView];
        window.title = @"Network Map";
        
        _annotations = [NSMutableDictionary dictionary];
        _locationCache = [NSMutableDictionary dictionary];
        _inFlightLookups = [NSMutableSet set];
        _failedLookups = [NSMutableSet set];
        _session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]];
        
        NSString *savedProvider = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderKey];
        _providerName = savedProvider.length > 0 ? savedProvider : @"ip-api.com";
    }
    return self;
}

- (void)setProviderName:(NSString *)providerName {
    if ([_providerName isEqualToString:providerName]) {
        return;
    }
    _providerName = [providerName copy];
    [self.failedLookups removeAllObjects];
    [self.inFlightLookups removeAllObjects];
}

- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections {
    if (connections.count == 0) {
        [self.mapView removeAnnotations:self.mapView.annotations];
        [self.annotations removeAllObjects];
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
        }
    }

    BOOL canLookup = YES;
    if ([self.providerName isEqualToString:@"custom"]) {
        NSString *template = [[NSUserDefaults standardUserDefaults] stringForKey:kMapProviderURLTemplateKey];
        if (template.length == 0) {
            canLookup = NO;
        }
    }
    
    NSMutableArray<NSString *> *removeKeys = [NSMutableArray array];
    [self.annotations enumerateKeysAndObjectsUsingBlock:^(NSString *key, MKPointAnnotation *obj, BOOL *stop) {
        if (![targetIps containsObject:key]) {
            [removeKeys addObject:key];
        }
    }];
    for (NSString *key in removeKeys) {
        MKPointAnnotation *annotation = self.annotations[key];
        if (annotation) {
            [self.mapView removeAnnotation:annotation];
            [self.annotations removeObjectForKey:key];
        }
    }
    
    for (NSString *ip in targetIps) {
        if (self.annotations[ip]) {
            continue;
        }
        
        NSValue *cachedValue = self.locationCache[ip];
        if (cachedValue) {
            CLLocationCoordinate2D coord = [cachedValue MKCoordinateValue];
            [self addAnnotationForIP:ip coordinate:coord];
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
                self.locationCache[ip] = [NSValue valueWithMKCoordinate:coord];
                [self addAnnotationForIP:ip coordinate:coord];
                [self mapToFitAnnotations];
            });
        }];
    }
    
    [self mapToFitAnnotations];
}

- (void)addAnnotationForIP:(NSString *)ip coordinate:(CLLocationCoordinate2D)coord {
    if (self.annotations[ip]) {
        return;
    }
    
    MKPointAnnotation *annotation = [[MKPointAnnotation alloc] init];
    annotation.title = ip;
    annotation.coordinate = coord;
    [self.mapView addAnnotation:annotation];
    self.annotations[ip] = annotation;
}

- (void)mapToFitAnnotations {
    NSArray<id<MKAnnotation>> *annotations = self.mapView.annotations;
    if (annotations.count == 0) {
        return;
    }
    [self.mapView showAnnotations:annotations animated:YES];
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
    NSString *provider = self.providerName.length > 0 ? self.providerName : @"ip-api.com";
    NSString *encodedIP = [ip stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLPathAllowedCharacterSet]];
    NSString *urlString = nil;
    
    if ([provider isEqualToString:@"ip-api.com"]) {
        urlString = [NSString stringWithFormat:@"http://ip-api.com/json/%@?fields=status,message,lat,lon,query", encodedIP];
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
    
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) {
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }
        
        NSError *jsonError;
        id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        if (jsonError || ![json isKindOfClass:[NSDictionary class]]) {
            completion(kCLLocationCoordinate2DInvalid, NO);
            return;
        }
        
        NSDictionary *dict = (NSDictionary *)json;
        CLLocationDegrees lat = 0;
        CLLocationDegrees lon = 0;
        BOOL success = NO;
        
        if ([provider isEqualToString:@"ip-api.com"]) {
            NSString *status = dict[@"status"];
            if ([status isEqualToString:@"success"]) {
                lat = [dict[@"lat"] doubleValue];
                lon = [dict[@"lon"] doubleValue];
                success = YES;
            }
        } else if ([provider isEqualToString:@"ipinfo.io"]) {
            NSString *loc = dict[@"loc"];
            NSArray<NSString *> *parts = [loc componentsSeparatedByString:@","];
            if (parts.count == 2) {
                lat = [parts[0] doubleValue];
                lon = [parts[1] doubleValue];
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
            completion(CLLocationCoordinate2DMake(lat, lon), YES);
        } else {
            completion(kCLLocationCoordinate2DInvalid, NO);
        }
    }];
    [task resume];
}

@end
