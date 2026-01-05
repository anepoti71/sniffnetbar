//
//  PacketCaptureManager.m
//  SniffNetBar
//
//  Packet capture manager using libpcap
//

#import "PacketCaptureManager.h"
#import "PacketInfo.h"
#import "Logger.h"
#import <pcap/pcap.h>
#import <net/ethernet.h>
#import <netinet/ip.h>
#import <netinet/tcp.h>
#import <netinet/udp.h>
#import <arpa/inet.h>
#import <string.h>

// Packet capture configuration constants
static const int kPcapSnaplen = 65536;        // Maximum bytes to capture per packet
static const int kPcapPromiscuousMode = 0;   // 0 = non-promiscuous, 1 = promiscuous
static const int kPcapTimeoutMs = 500;        // Read timeout in milliseconds (increased for efficiency)
static void *kCaptureQueueKey = &kCaptureQueueKey;

@interface PacketCaptureManager ()
@property (nonatomic, assign) pcap_t *pcapHandle;
@property (nonatomic, assign) BOOL isCapturing;
@property (nonatomic, strong) dispatch_queue_t captureQueue;
@property (nonatomic, strong, readwrite) NSString *currentDeviceName;
@property (nonatomic, strong) NSCache<NSString *, NSString *> *ipStringCache;
@end

@implementation PacketCaptureManager

- (instancetype)init {
    self = [super init];
    if (self) {
        _captureQueue = dispatch_queue_create("com.sniffnetbar.capture", DISPATCH_QUEUE_SERIAL);
        dispatch_queue_set_specific(_captureQueue, kCaptureQueueKey, kCaptureQueueKey, NULL);
        _ipStringCache = [[NSCache alloc] init];
        _ipStringCache.countLimit = 512; // Automatic LRU eviction when limit exceeded
        _ipStringCache.name = @"com.sniffnetbar.ipcache";
        _pcapHandle = NULL;
        _isCapturing = NO;
    }
    return self;
}

- (void)dealloc {
    [self stopCapture];
}

- (BOOL)startCaptureWithError:(NSError **)error {
    NSString *deviceName = [self defaultDeviceNameWithError:error];
    return [self startCaptureWithDeviceName:deviceName error:error];
}

- (BOOL)startCaptureWithDeviceName:(NSString *)deviceName error:(NSError **)error {
    if (self.isCapturing) {
        [self stopCapture];
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Use provided device name or find default
    const char *device = NULL;
    if (deviceName && deviceName.length > 0) {
        device = [deviceName UTF8String];
    } else {
        NSString *fallbackName = [self defaultDeviceNameWithError:error];
        if (!fallbackName) {
            return NO;
        }
        device = [fallbackName UTF8String];
    }
    
    // Open device for capture
    self.pcapHandle = pcap_open_live(device, kPcapSnaplen, kPcapPromiscuousMode, kPcapTimeoutMs, errbuf);
    if (self.pcapHandle == NULL) {
        if (error) {
            *error = [NSError errorWithDomain:@"PacketCaptureError"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:errbuf]}];
        }
        return NO;
    }
    
    // Set non-blocking mode
    if (pcap_setnonblock(self.pcapHandle, 1, errbuf) == -1) {
        SNBLogNetworkWarn("Failed to set non-blocking mode: %{public}s", errbuf);
    }
    
    self.currentDeviceName = deviceName ?: [NSString stringWithUTF8String:device];
    self.isCapturing = YES;
    
    // Start capture in background
    __weak typeof(self) weakSelf = self;
    dispatch_async(self.captureQueue, ^{
        [weakSelf captureLoop];
    });
    
    return YES;
}

- (void)stopCapture {
    if (!self.isCapturing) {
        return;
    }

    self.isCapturing = NO;

    if (self.pcapHandle) {
        pcap_breakloop(self.pcapHandle);
        void (^closeHandle)(void) = ^{
            if (self.pcapHandle) {
                pcap_close(self.pcapHandle);
                self.pcapHandle = NULL;
            }
        };
        if (dispatch_get_specific(kCaptureQueueKey)) {
            closeHandle();
        } else {
            dispatch_sync(self.captureQueue, closeHandle);
        }
    }

    // Clear IP string cache when stopping capture
    [self.ipStringCache removeAllObjects];
}

// String interning for IP addresses to reduce memory allocations
// Performance optimization: Check cache first before creating NSString
- (NSString *)internIPString:(const char *)ipCString {
    if (!ipCString) {
        return nil;
    }

    // Create a temporary CFString to use as lookup key (zero-copy)
    CFStringRef cfKey = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault,
                                                         ipCString,
                                                         kCFStringEncodingUTF8,
                                                         kCFAllocatorNull);
    if (!cfKey) {
        return nil;
    }

    // NSCache is thread-safe, no need for explicit synchronization
    NSString *internedString = [self.ipStringCache objectForKey:(__bridge NSString *)cfKey];

    if (!internedString) {
        // Cache miss - create owned string and store it
        // NSCache automatically handles LRU eviction when countLimit is exceeded
        internedString = (__bridge_transfer NSString *)CFStringCreateCopy(kCFAllocatorDefault, cfKey);
        [self.ipStringCache setObject:internedString forKey:internedString];
    }

    CFRelease(cfKey);
    return internedString;
}

- (void)captureLoop {
    struct pcap_pkthdr *header;
    const u_char *packet;
    int result;
    
    while (self.isCapturing) {
        result = pcap_next_ex(self.pcapHandle, &header, &packet);
        
        if (result == 1) {
            // Packet captured successfully
            PacketInfo *packetInfo = [self parsePacket:packet
                                        capturedLength:header->caplen
                                          actualLength:header->len];
            if (packetInfo && self.onPacketReceived) {
                // Call callback directly on background thread
                // TrafficStatistics handles thread safety with its own queue
                self.onPacketReceived(packetInfo);
            }
        } else if (result == 0) {
            // Timeout - sleep briefly to avoid busy-waiting at 100% CPU
            usleep(10000); // 10ms sleep
            continue;
        } else if (result == -1) {
            // Error
            const char *errorMsg = pcap_geterr(self.pcapHandle);
            SNBLogNetworkWarn("Error reading packet: %{public}s", errorMsg);

            // Notify error callback
            if (self.onCaptureError) {
                NSError *error = [NSError errorWithDomain:@"PacketCaptureError"
                                                     code:3
                                                 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:errorMsg]}];
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.onCaptureError(error);
                });
            }
            break;
        } else if (result == -2) {
            // Break loop
            break;
        }
    }
}

- (PacketInfo *)parsePacket:(const u_char *)packet capturedLength:(int)capturedLength actualLength:(int)actualLength {
    if (capturedLength < sizeof(struct ether_header)) {
        return nil;
    }
    
    PacketInfo *info = [[PacketInfo alloc] init];
    info.totalBytes = actualLength;
    
    // Parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);
    
    const u_char *ip_packet = packet + sizeof(struct ether_header);
    int ip_length = capturedLength - sizeof(struct ether_header);
    
    if (ip_length <= 0) {
        return nil;
    }
    
    // Parse IP header
    if (ether_type == ETHERTYPE_IP) {
        // IPv4
        if (ip_length < sizeof(struct ip)) {
            return nil;
        }
        
        struct ip *ip_header = (struct ip *)ip_packet;
        int ip_header_len = ip_header->ip_hl * 4;
        
        if (ip_length < ip_header_len) {
            return nil;
        }
        
        // Get source and destination addresses
        struct in_addr src_addr = ip_header->ip_src;
        struct in_addr dst_addr = ip_header->ip_dst;
        
        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr, dst_str, INET_ADDRSTRLEN);

        // Use string interning to reduce memory allocations
        info.sourceAddress = [self internIPString:src_str];
        info.destinationAddress = [self internIPString:dst_str];
        
        // Parse transport layer
        const u_char *transport_packet = ip_packet + ip_header_len;
        int transport_length = ip_length - ip_header_len;
        
        if (transport_length <= 0) {
            return nil;
        }
        
        uint8_t protocol = ip_header->ip_p;
        if (protocol == IPPROTO_TCP) {
            if (transport_length >= sizeof(struct tcphdr)) {
                struct tcphdr *tcp_header = (struct tcphdr *)transport_packet;
                info.protocol = PacketProtocolTCP;
                info.sourcePort = ntohs(tcp_header->th_sport);
                info.destinationPort = ntohs(tcp_header->th_dport);
            }
        } else if (protocol == IPPROTO_UDP) {
            if (transport_length >= sizeof(struct udphdr)) {
                struct udphdr *udp_header = (struct udphdr *)transport_packet;
                info.protocol = PacketProtocolUDP;
                info.sourcePort = ntohs(udp_header->uh_sport);
                info.destinationPort = ntohs(udp_header->uh_dport);
            }
        } else if (protocol == IPPROTO_ICMP) {
            info.protocol = PacketProtocolICMP;
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        // IPv6 - header is always 40 bytes
        if (ip_length < 40) {
            return nil;
        }
        
        // Parse IPv6 header manually since structure names vary by platform
        struct in6_addr src_addr, dst_addr;
        memcpy(&src_addr, ip_packet + 8, sizeof(struct in6_addr));
        memcpy(&dst_addr, ip_packet + 24, sizeof(struct in6_addr));
        
        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &src_addr, src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &dst_addr, dst_str, INET6_ADDRSTRLEN);

        // Use string interning to reduce memory allocations
        info.sourceAddress = [self internIPString:src_str];
        info.destinationAddress = [self internIPString:dst_str];
        
        // IPv6 next header is at byte offset 6
        uint8_t next_header = ip_packet[6];
        const u_char *transport_packet = ip_packet + 40;  // IPv6 header is always 40 bytes
        int transport_length = ip_length - 40;
        
        if (next_header == IPPROTO_TCP && transport_length >= sizeof(struct tcphdr)) {
            struct tcphdr *tcp_header = (struct tcphdr *)transport_packet;
            info.protocol = PacketProtocolTCP;
            info.sourcePort = ntohs(tcp_header->th_sport);
            info.destinationPort = ntohs(tcp_header->th_dport);
        } else if (next_header == IPPROTO_UDP && transport_length >= sizeof(struct udphdr)) {
            struct udphdr *udp_header = (struct udphdr *)transport_packet;
            info.protocol = PacketProtocolUDP;
            info.sourcePort = ntohs(udp_header->uh_sport);
            info.destinationPort = ntohs(udp_header->uh_dport);
        } else if (next_header == IPPROTO_ICMPV6) {
            info.protocol = PacketProtocolICMP;
        } else {
            info.protocol = PacketProtocolUnknown;
        }
    } else {
        // Other protocols (ARP, etc.)
        return nil;
    }
    
    return info;
}

- (NSString *)defaultDeviceNameWithError:(NSError **)error {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDevs = NULL;
    if (pcap_findalldevs(&allDevs, errbuf) == -1 || !allDevs) {
        if (error) {
            *error = [NSError errorWithDomain:@"PacketCaptureError"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:errbuf]}];
        }
        return nil;
    }
    NSString *deviceName = nil;
    if (allDevs->name) {
        deviceName = [NSString stringWithUTF8String:allDevs->name];
    }
    pcap_freealldevs(allDevs);
    return deviceName;
}

@end
