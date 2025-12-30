//
//  IPAddressUtilities.m
//  SniffNetBar
//

#import "IPAddressUtilities.h"

@implementation IPAddressUtilities

+ (BOOL)isValidIPv4:(NSString *)ipAddress {
    if (ipAddress.length == 0) {
        return NO;
    }

    NSArray<NSString *> *octets = [ipAddress componentsSeparatedByString:@"."];
    if (octets.count != 4) {
        return NO;
    }

    NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    for (NSString *octet in octets) {
        if (octet.length == 0 || [octet rangeOfCharacterFromSet:nonDigits].location != NSNotFound) {
            return NO;
        }
        NSInteger value = [octet integerValue];
        if (value < 0 || value > 255) {
            return NO;
        }
    }

    return YES;
}

+ (BOOL)isPrivateIPv4Address:(NSString *)ipAddress {
    if (![self isValidIPv4:ipAddress]) {
        return NO;
    }

    NSArray<NSString *> *octets = [ipAddress componentsSeparatedByString:@"."];
    NSInteger first = [octets[0] integerValue];
    NSInteger second = [octets[1] integerValue];

    if (first == 10) {
        return YES;
    }
    if (first == 172 && second >= 16 && second <= 31) {
        return YES;
    }
    if (first == 192 && second == 168) {
        return YES;
    }
    if (first == 127) {
        return YES;
    }
    if (first == 169 && second == 254) {
        return YES;
    }

    return NO;
}

@end
