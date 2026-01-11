//
//  SMAppServiceHelper.h
//  SniffNetBar
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SMAppServiceHelper : NSObject

+ (BOOL)isHelperInstalled;
+ (BOOL)installHelperWithError:(NSError **)error;
+ (BOOL)uninstallHelperWithError:(NSError **)error;
+ (NSString *)helperStatus;
+ (BOOL)helperBinaryExists;
+ (BOOL)helperPlistProgramArgumentsMatch;

@end

NS_ASSUME_NONNULL_END
