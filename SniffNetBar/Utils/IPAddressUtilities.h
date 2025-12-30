//
//  IPAddressUtilities.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

@interface IPAddressUtilities : NSObject

+ (BOOL)isValidIPv4:(NSString *)ipAddress;
+ (BOOL)isPrivateIPv4Address:(NSString *)ipAddress;

@end
