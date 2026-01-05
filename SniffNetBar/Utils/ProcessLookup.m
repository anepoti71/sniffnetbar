//
//  ProcessLookup.m
//  SniffNetBar
//
//  Utility for looking up process information for network connections
//

#import "ProcessLookup.h"
#import "Logger.h"
#import <libproc.h>
#import <sys/sysctl.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <arpa/inet.h>

@implementation ProcessInfo
@end

@implementation ProcessLookup

+ (void)lookupProcessForConnectionWithSource:(NSString *)sourceAddress
                                  sourcePort:(NSInteger)sourcePort
                                 destination:(NSString *)destinationAddress
                             destinationPort:(NSInteger)destinationPort
                                  completion:(void (^)(ProcessInfo * _Nullable))completion {
    if (!completion) {
        return;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        ProcessInfo *info = [self lookupProcessForConnectionWithSource:sourceAddress
                                                            sourcePort:sourcePort
                                                           destination:destinationAddress
                                                       destinationPort:destinationPort];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(info);
        });
    });
}

+ (nullable ProcessInfo *)lookupProcessForConnectionWithSource:(NSString *)sourceAddress
                                                    sourcePort:(NSInteger)sourcePort
                                                   destination:(NSString *)destinationAddress
                                               destinationPort:(NSInteger)destinationPort {
    SNBLogInfo("ProcessLookup: Looking for %{public}@:%ld -> %{public}@:%ld",
          sourceAddress, (long)sourcePort, destinationAddress, (long)destinationPort);

    // Use lsof to find the process - more reliable than libproc for active connections
    // lsof -i TCP:port -n -P lists all processes using that TCP port
    NSString *lsofCmd = [NSString stringWithFormat:@"/usr/sbin/lsof -i TCP:%ld -n -P 2>/dev/null", (long)sourcePort];

    FILE *pipe = popen([lsofCmd UTF8String], "r");
    if (!pipe) {
        SNBLogInfo("ProcessLookup: Failed to run lsof");
        return nil;
    }

    char buffer[2048];
    ProcessInfo *result = nil;
    int linesChecked = 0;

    // Skip header line
    if (fgets(buffer, sizeof(buffer), pipe) == NULL) {
        pclose(pipe);
        return nil;
    }

    // Parse output lines
    // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    // Example: curl 12345 user 3u IPv4 0x123456 0t0 TCP 192.168.1.10:54321->93.184.216.34:80 (ESTABLISHED)
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        linesChecked++;

        char command[256] = {0};
        pid_t pid = 0;
        char user[256] = {0};
        char type[32] = {0};
        char name[512] = {0};

        // Parse the line - we need at least command, PID, and the connection name
        int fieldsRead = sscanf(buffer, "%255s %d %255s %*s %31s %*s %*s %*s %511[^\n]",
                               command, &pid, user, type, name);

        if (fieldsRead >= 5) {
            NSString *nameStr = [NSString stringWithUTF8String:name];

            // Check if this is a TCP connection and matches our ports
            if (strstr(type, "IPv4") || strstr(type, "IPv6")) {
                // Look for the source port in the connection string
                // Connection format: IP:PORT->IP:PORT or *:PORT (LISTEN)
                NSString *srcPattern = [NSString stringWithFormat:@":%ld->", (long)sourcePort];
                NSString *dstPattern = [NSString stringWithFormat:@"->%@:%ld",
                                       destinationAddress, (long)destinationPort];

                // Match if we find our source port and optionally the destination
                if ([nameStr rangeOfString:srcPattern].location != NSNotFound) {
                    // Found a connection with our source port
                    // If destination is specified, check it too
                    if (destinationPort > 0 && destinationAddress.length > 0) {
                        // Check destination
                        if ([nameStr rangeOfString:dstPattern].location == NSNotFound) {
                            // Destination doesn't match, skip
                            continue;
                        }
                    }

                    result = [[ProcessInfo alloc] init];
                    result.pid = pid;
                    result.processName = [NSString stringWithUTF8String:command];

                    SNBLogInfo("ProcessLookup: ✓ Found %@ (PID %d) - connection: %{public}@",
                          result.processName, result.pid, nameStr);
                    break;
                }
            }
        }
    }

    pclose(pipe);

    if (!result) {
        SNBLogInfo("ProcessLookup: ✗ No matching process found (checked %d connections for port %ld)",
              linesChecked, (long)sourcePort);
    }

    return result;
}

+ (nullable ProcessInfo *)processInfoForPID:(pid_t)pid {
    ProcessInfo *info = [[ProcessInfo alloc] init];
    info.pid = pid;

    // Get process path
    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
    int ret = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));
    if (ret > 0) {
        info.executablePath = [NSString stringWithUTF8String:pathBuffer];
        info.processName = [info.executablePath lastPathComponent];
    } else {
        // Fallback: get process name from proc_pidinfo
        struct proc_bsdinfo procInfo;
        ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo));
        if (ret > 0) {
            info.processName = [NSString stringWithUTF8String:procInfo.pbi_name];
        } else {
            info.processName = [NSString stringWithFormat:@"PID %d", pid];
        }
    }

    return info;
}

@end
