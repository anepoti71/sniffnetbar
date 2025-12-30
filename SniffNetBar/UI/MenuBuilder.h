//
//  MenuBuilder.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>

@class ConfigurationManager;
@class NetworkDevice;
@class TrafficStats;
@class TIEnrichmentResponse;

@interface MenuBuilder : NSObject

@property (nonatomic, assign) BOOL showTopHosts;
@property (nonatomic, assign) BOOL showTopConnections;
@property (nonatomic, assign) BOOL showMap;
@property (nonatomic, copy, readonly) NSString *mapProviderName;
@property (nonatomic, assign, readonly) BOOL menuIsOpen;

- (instancetype)initWithMenu:(NSMenu *)menu
                  statusItem:(NSStatusItem *)statusItem
               configuration:(ConfigurationManager *)configuration;
- (void)updateStatusWithStats:(TrafficStats *)stats selectedDevice:(NetworkDevice *)selectedDevice;
- (void)updateMenuWithStats:(TrafficStats *)stats
                    devices:(NSArray<NetworkDevice *> *)devices
             selectedDevice:(NetworkDevice *)selectedDevice
         threatIntelEnabled:(BOOL)threatIntelEnabled
        threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                 cacheStats:(NSDictionary *)cacheStats
                     target:(id)target;
- (void)menuWillOpenWithStats:(TrafficStats *)stats;
- (void)menuDidClose;
- (void)selectMapProviderWithName:(NSString *)providerName stats:(TrafficStats *)stats;

@end
