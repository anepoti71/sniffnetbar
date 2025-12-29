//
//  NetworkDevice.m
//  SniffNetBar
//
//  Represents a network interface/device
//

#import "NetworkDevice.h"
#import <pcap/pcap.h>
#import <sys/socket.h>
#import <net/if.h>
#import <ifaddrs.h>
#import <netinet/in.h>
#import <arpa/inet.h>

@implementation NetworkDevice

- (instancetype)initWithName:(NSString *)name description:(NSString *)description addresses:(NSArray<NSString *> *)addresses {
    self = [super init];
    if (self) {
        _name = [name copy];
        _deviceDescription = description ? [description copy] : @"";
        _addresses = addresses ? [addresses copy] : @[];
    }
    return self;
}

+ (NSArray<NetworkDevice *> *)listAllDevices {
    NSMutableArray<NetworkDevice *> *devices = [NSMutableArray array];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Use pcap to find all capturable devices (only active/UP interfaces)
    pcap_if_t *allDevs;
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        NSLog(@"Error finding devices: %s", errbuf);
        return devices;
    }

    // Get interface addresses using getifaddrs
    NSMutableDictionary<NSString *, NSMutableArray<NSString *> *> *interfaceAddresses = [NSMutableDictionary dictionary];
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) == 0) {
        struct ifaddrs *interface;
        for (interface = interfaces; interface != NULL; interface = interface->ifa_next) {
            if (interface->ifa_addr == NULL) continue;

            NSString *ifName = [NSString stringWithUTF8String:interface->ifa_name];
            if (!ifName) continue;

            NSMutableArray<NSString *> *addresses = interfaceAddresses[ifName];
            if (!addresses) {
                addresses = [NSMutableArray array];
                interfaceAddresses[ifName] = addresses;
            }

            if (interface->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)interface->ifa_addr;
                char addr[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &sin->sin_addr, addr, INET_ADDRSTRLEN)) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            } else if (interface->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)interface->ifa_addr;
                char addr[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, addr, INET6_ADDRSTRLEN)) {
                    [addresses addObject:[NSString stringWithUTF8String:addr]];
                }
            }
        }
        freeifaddrs(interfaces);
    }

    // Iterate through pcap devices (only capturable interfaces)
    for (pcap_if_t *dev = allDevs; dev != NULL; dev = dev->next) {
        NSString *devName = [NSString stringWithUTF8String:dev->name];
        if (!devName) continue;

        NSString *devDesc = dev->description ? [NSString stringWithUTF8String:dev->description] : @"";
        NSArray<NSString *> *addresses = interfaceAddresses[devName] ?: @[];

        NetworkDevice *device = [[NetworkDevice alloc] initWithName:devName
                                                         description:devDesc
                                                            addresses:addresses];
        [devices addObject:device];
    }

    pcap_freealldevs(allDevs);
    return devices;
}

+ (NetworkDevice *)defaultDevice {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *defaultDev = pcap_lookupdev(errbuf);
    
    if (defaultDev) {
        NSString *devName = [NSString stringWithUTF8String:defaultDev];
        NSArray<NetworkDevice *> *allDevices = [self listAllDevices];
        for (NetworkDevice *device in allDevices) {
            if ([device.name isEqualToString:devName]) {
                return device;
            }
        }
    }
    
    // Fallback: return first available device
    NSArray<NetworkDevice *> *allDevices = [self listAllDevices];
    return allDevices.firstObject;
}

- (NSString *)displayName {
    if (self.deviceDescription.length > 0) {
        return [NSString stringWithFormat:@"%@ (%@)", self.deviceDescription, self.name];
    }
    return self.name;
}

@end

