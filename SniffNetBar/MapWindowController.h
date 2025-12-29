//
//  MapWindowController.h
//  SniffNetBar
//
//  Map visualization for geolocated connections
//

#import <Cocoa/Cocoa.h>
#import "TrafficStatistics.h"

@interface MapWindowController : NSWindowController

@property (nonatomic, copy) NSString *providerName;

- (void)updateWithConnections:(NSArray<ConnectionTraffic *> *)connections;

@end
