//
//  MapMenuView.h
//  SniffNetBar
//
//  Map visualization embedded in the menu
//

#import <Cocoa/Cocoa.h>
#import "TrafficStatistics.h"

@interface MapMenuView : NSView

@property (nonatomic, copy) NSString *providerName;

- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections;

@end
