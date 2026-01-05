//
//  ProcessLookup_lsof.m
//  SniffNetBar
//
//  Alternative process lookup using lsof (more reliable but slightly slower)
//

#import "ProcessLookup.h"
#import "Logger.h"

// Alternative implementation using lsof
@implementation ProcessLookup (Lsof)

+ (nullable ProcessInfo *)lookupUsingLsofForSource:(NSString *)sourceAddress
                                        sourcePort:(NSInteger)sourcePort
                                       destination:(NSString *)destinationAddress
                                   destinationPort:(NSInteger)destinationPort {

    SNBLogInfo("ProcessLookup(lsof): Looking for connection %@:%ld -> %@:%ld",
          sourceAddress, (long)sourcePort, destinationAddress, (long)destinationPort);

    // Use lsof to find the process
    // lsof -i TCP:port -n -P lists all processes using that port
    NSString *lsofCmd = [NSString stringWithFormat:@"/usr/sbin/lsof -i TCP:%ld -n -P 2>/dev/null", (long)sourcePort];

    FILE *pipe = popen([lsofCmd UTF8String], "r");
    if (!pipe) {
        SNBLogInfo("ProcessLookup(lsof): Failed to run lsof");
        return nil;
    }

    char buffer[1024];
    ProcessInfo *result = nil;

    // Skip header line
    if (fgets(buffer, sizeof(buffer), pipe) == NULL) {
        pclose(pipe);
        return nil;
    }

    // Parse output lines
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // Example: curl 12345 user 3u IPv4 0x123456 0t0 TCP 192.168.1.10:54321->93.184.216.34:80 (ESTABLISHED)

        char command[256] = {0};
        pid_t pid = 0;
        char name[512] = {0};

        // Parse the line
        if (sscanf(buffer, "%255s %d %*s %*s %*s %*s %*s %*s %511[^\n]", command, &pid, name) >= 2) {
            // Check if this connection matches our criteria
            NSString *nameStr = [NSString stringWithUTF8String:name];

            // Look for the connection pattern: localIP:localPort->remoteIP:remotePort
            NSString *expectedPattern = [NSString stringWithFormat:@"%@:%ld->%@:%ld",
                                        sourceAddress, (long)sourcePort,
                                        destinationAddress, (long)destinationPort];

            // Also check for IPv6 format or other variations
            if ([nameStr rangeOfString:expectedPattern].location != NSNotFound ||
                [nameStr rangeOfString:[NSString stringWithFormat:@":%ld->", (long)sourcePort]].location != NSNotFound) {

                result = [[ProcessInfo alloc] init];
                result.pid = pid;
                result.processName = [NSString stringWithUTF8String:command];

                SNBLogInfo("ProcessLookup(lsof): ✓ Found %@ (PID %d)", result.processName, result.pid);
                break;
            }
        }
    }

    pclose(pipe);

    if (!result) {
        SNBLogInfo("ProcessLookup(lsof): ✗ No matching process found");
    }

    return result;
}

@end
