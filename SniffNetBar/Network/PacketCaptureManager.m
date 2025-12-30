//
//  PacketCaptureManager.m
//  SniffNetBar
//
//  Packet capture manager using libpcap
//

#import "PacketCaptureManager.h"
#import "PacketInfo.h"
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
static const int kPcapTimeoutMs = 150;        // Read timeout in milliseconds

@interface PacketCaptureManager ()
@property (nonatomic, assign) pcap_t *pcapHandle;
@property (nonatomic, assign) BOOL isCapturing;
@property (nonatomic, strong) dispatch_queue_t captureQueue;
@property (nonatomic, strong, readwrite) NSString *currentDeviceName;
@end

@implementation PacketCaptureManager

- (instancetype)init {
    self = [super init];
    if (self) {
        _captureQueue = dispatch_queue_create("com.sniffnetbar.capture", DISPATCH_QUEUE_SERIAL);
        _pcapHandle = NULL;
        _isCapturing = NO;
    }
    return self;
}

- (void)dealloc {
    [self stopCapture];
}

- (BOOL)startCaptureWithError:(NSError **)error {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *defaultDevice = pcap_lookupdev(errbuf);
    NSString *deviceName = defaultDevice ? [NSString stringWithUTF8String:defaultDevice] : nil;
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
        // Find default network interface
        device = pcap_lookupdev(errbuf);
        if (device == NULL) {
            if (error) {
                *error = [NSError errorWithDomain:@"PacketCaptureError"
                                             code:1
                                         userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithUTF8String:errbuf]}];
            }
            return NO;
        }
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
        NSLog(@"Warning: Failed to set non-blocking mode: %s", errbuf);
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
        pcap_close(self.pcapHandle);
        self.pcapHandle = NULL;
    }
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
            // Timeout
            continue;
        } else if (result == -1) {
            // Error
            NSLog(@"Error reading packet: %s", pcap_geterr(self.pcapHandle));
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
        
        info.sourceAddress = [NSString stringWithUTF8String:src_str];
        info.destinationAddress = [NSString stringWithUTF8String:dst_str];
        
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
        
        info.sourceAddress = [NSString stringWithUTF8String:src_str];
        info.destinationAddress = [NSString stringWithUTF8String:dst_str];
        
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

@end
