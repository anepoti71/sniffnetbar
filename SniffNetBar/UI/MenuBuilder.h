//
//  MenuBuilder.h
//  SniffNetBar
//

#import <Cocoa/Cocoa.h>

@class ConfigurationManager;
@class NetworkDevice;
@class TrafficStats;
@class TIEnrichmentResponse;
@class SNBNetworkAsset;

@protocol MenuBuilderDelegate <NSObject>
- (void)menuBuilderNeedsVisualizationRefresh:(id)sender;
@end

@interface MenuBuilder : NSObject

@property (nonatomic, weak) id<MenuBuilderDelegate> delegate;

@property (nonatomic, assign) BOOL showTopHosts;
@property (nonatomic, assign) BOOL showTopConnections;
@property (nonatomic, assign) BOOL showMap;
@property (nonatomic, copy, readonly) NSString *mapProviderName;
@property (nonatomic, assign, readonly) BOOL menuIsOpen;

// Expandable sections state
@property (nonatomic, assign) BOOL showCleanConnections;
@property (nonatomic, assign) BOOL showAllAssets;
@property (nonatomic, assign) BOOL showProviderDetails;

- (instancetype)initWithMenu:(NSMenu *)menu
                  statusItem:(NSStatusItem *)statusItem
               configuration:(ConfigurationManager *)configuration;
- (void)updateStatusWithStats:(TrafficStats *)stats selectedDevice:(NetworkDevice *)selectedDevice;
- (void)updateMenuWithStats:(TrafficStats *)stats
                    devices:(NSArray<NetworkDevice *> *)devices
             selectedDevice:(NetworkDevice *)selectedDevice
         threatIntelEnabled:(BOOL)threatIntelEnabled
     threatIntelStatusMessage:(NSString * _Nullable)threatIntelStatusMessage
        threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                 cacheStats:(NSDictionary *)cacheStats
        assetMonitorEnabled:(BOOL)assetMonitorEnabled
             networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
           recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets
                     target:(id)target;
- (void)refreshVisualizationWithStats:(TrafficStats *)stats
                  threatIntelEnabled:(BOOL)threatIntelEnabled
              threatIntelStatusMessage:(NSString * _Nullable)threatIntelStatusMessage
                 threatIntelResults:(NSDictionary<NSString *, TIEnrichmentResponse *> *)threatIntelResults
                          cacheStats:(NSDictionary *)cacheStats
                assetMonitorEnabled:(BOOL)assetMonitorEnabled
                     networkAssets:(NSArray<SNBNetworkAsset *> *)networkAssets
                   recentNewAssets:(NSArray<SNBNetworkAsset *> *)recentNewAssets;
- (void)menuWillOpenWithStats:(TrafficStats *)stats;
- (void)menuDidClose;
- (void)selectMapProviderWithName:(NSString *)providerName stats:(TrafficStats *)stats;

// Expandable section toggles
- (void)toggleShowCleanConnections;
- (void)toggleShowAllAssets;
- (void)toggleShowProviderDetails;

@end
