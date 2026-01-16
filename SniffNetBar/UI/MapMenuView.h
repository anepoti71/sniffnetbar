//
//  MapMenuView.h
//  SniffNetBar
//
//  Map visualization embedded in the menu
//

#import <Cocoa/Cocoa.h>
#import "TrafficStatistics.h"

@class MapMenuView;

@protocol MapMenuViewDelegate <NSObject>
@optional
- (void)mapMenuView:(MapMenuView *)mapView didSelectConnectionWithSource:(NSString *)sourceIP destination:(NSString *)destinationIP;
- (void)mapMenuViewDidClearSelection:(MapMenuView *)mapView;
@end

@interface MapMenuView : NSView

@property (nonatomic, weak) id<MapMenuViewDelegate> delegate;

@property (nonatomic, copy) NSString *providerName;
@property (nonatomic, assign, readonly) NSUInteger drawnConnectionCount;

- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections;

@end
