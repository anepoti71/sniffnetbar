//
//  ProcessLookup_Native.m
//  SniffNetBar
//
//  Native macOS API-based process lookup using libproc
//  More reliable than lsof, doesn't require parsing text output
//

#import "ProcessLookup.h"
#import "Logger.h"
#import <libproc.h>
#import <sys/proc_info.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>

// Category for native API-based lookups
@implementation ProcessLookup (Native)

+ (nullable ProcessInfo *)lookupUsingNativeAPIForSource:(NSString *)sourceAddress
                                             sourcePort:(NSInteger)sourcePort
                                            destination:(NSString *)destinationAddress
                                        destinationPort:(NSInteger)destinationPort {

    SNBLogInfo("ProcessLookup(native): Looking for connection %{public}@:%ld -> %{public}@:%ld",
               sourceAddress, (long)sourcePort, destinationAddress, (long)destinationPort);

    // Convert IP addresses to binary format for comparison
    struct in_addr srcAddr4, dstAddr4;
    struct in6_addr srcAddr6, dstAddr6;
    BOOL isIPv4 = NO;
    BOOL isIPv6 = NO;

    // Try parsing as IPv4
    if (inet_pton(AF_INET, sourceAddress.UTF8String, &srcAddr4) == 1 &&
        inet_pton(AF_INET, destinationAddress.UTF8String, &dstAddr4) == 1) {
        isIPv4 = YES;
    }
    // Try parsing as IPv6
    else if (inet_pton(AF_INET6, sourceAddress.UTF8String, &srcAddr6) == 1 &&
             inet_pton(AF_INET6, destinationAddress.UTF8String, &dstAddr6) == 1) {
        isIPv6 = YES;
    } else {
        SNBLogWarn("ProcessLookup(native): Invalid IP address format");
        return nil;
    }

    // Get list of all PIDs
    int numberOfPids = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (numberOfPids <= 0) {
        SNBLogWarn("ProcessLookup(native): Failed to get PID count");
        return nil;
    }

    pid_t *pids = malloc(sizeof(pid_t) * numberOfPids);
    if (!pids) {
        SNBLogError("ProcessLookup(native): Failed to allocate memory for PIDs");
        return nil;
    }

    numberOfPids = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pid_t) * numberOfPids);
    if (numberOfPids <= 0) {
        free(pids);
        SNBLogWarn("ProcessLookup(native): Failed to list PIDs");
        return nil;
    }

    ProcessInfo *result = nil;

    // Iterate through all PIDs
    for (int i = 0; i < numberOfPids; i++) {
        pid_t pid = pids[i];
        if (pid == 0) {
            continue;
        }

        // Get list of file descriptors for this process
        int fdBufferSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fdBufferSize <= 0) {
            continue;
        }

        struct proc_fdinfo *fdInfo = malloc(fdBufferSize);
        if (!fdInfo) {
            continue;
        }

        int fdCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdInfo, fdBufferSize);
        if (fdCount <= 0) {
            free(fdInfo);
            continue;
        }

        int numFds = fdCount / sizeof(struct proc_fdinfo);

        // Check each file descriptor
        for (int j = 0; j < numFds; j++) {
            if (fdInfo[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            // Get socket information
            struct socket_fdinfo socketInfo;
            int socketInfoSize = proc_pidfdinfo(pid, fdInfo[j].proc_fd, PROC_PIDFDSOCKETINFO,
                                               &socketInfo, sizeof(socketInfo));
            if (socketInfoSize <= 0) {
                continue;
            }

            // Only check TCP sockets
            if (socketInfo.psi.soi_kind != SOCKINFO_TCP) {
                continue;
            }

            struct tcp_sockinfo *tcpInfo = &socketInfo.psi.soi_proto.pri_tcp;

            BOOL matched = NO;

            if (isIPv4 && tcpInfo->tcpsi_ini.insi_vflag == INI_IPV4) {
                // IPv4 matching
                struct in_addr *localAddr = &tcpInfo->tcpsi_ini.insi_laddr.ina_46.i46a_addr4;
                struct in_addr *remoteAddr = &tcpInfo->tcpsi_ini.insi_faddr.ina_46.i46a_addr4;
                uint16_t localPort = ntohs(tcpInfo->tcpsi_ini.insi_lport);
                uint16_t remotePort = ntohs(tcpInfo->tcpsi_ini.insi_fport);

                if (memcmp(localAddr, &srcAddr4, sizeof(struct in_addr)) == 0 &&
                    memcmp(remoteAddr, &dstAddr4, sizeof(struct in_addr)) == 0 &&
                    localPort == sourcePort &&
                    remotePort == destinationPort) {
                    matched = YES;
                }
            } else if (isIPv6 && tcpInfo->tcpsi_ini.insi_vflag == INI_IPV6) {
                // IPv6 matching
                struct in6_addr *localAddr = &tcpInfo->tcpsi_ini.insi_laddr.ina_6;
                struct in6_addr *remoteAddr = &tcpInfo->tcpsi_ini.insi_faddr.ina_6;
                uint16_t localPort = ntohs(tcpInfo->tcpsi_ini.insi_lport);
                uint16_t remotePort = ntohs(tcpInfo->tcpsi_ini.insi_fport);

                if (memcmp(localAddr, &srcAddr6, sizeof(struct in6_addr)) == 0 &&
                    memcmp(remoteAddr, &dstAddr6, sizeof(struct in6_addr)) == 0 &&
                    localPort == sourcePort &&
                    remotePort == destinationPort) {
                    matched = YES;
                }
            }

            if (matched) {
                // Found matching connection! Get process name
                char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
                int pathLen = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));

                result = [[ProcessInfo alloc] init];
                result.pid = pid;

                if (pathLen > 0) {
                    NSString *fullPath = [NSString stringWithUTF8String:pathBuffer];
                    result.executablePath = fullPath;
                    // Extract just the process name from the full path
                    result.processName = [fullPath lastPathComponent];
                } else {
                    // Fallback: try to get process name via proc_name
                    char nameBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
                    if (proc_name(pid, nameBuffer, sizeof(nameBuffer)) > 0) {
                        result.processName = [NSString stringWithUTF8String:nameBuffer];
                    } else {
                        result.processName = [NSString stringWithFormat:@"PID %d", pid];
                    }
                }

                SNBLogInfo("ProcessLookup(native): ✓ Found %{public}@ (PID %d)", result.processName, result.pid);
                free(fdInfo);
                goto cleanup;
            }
        }

        free(fdInfo);
    }

    if (!result) {
        SNBLogInfo("ProcessLookup(native): ✗ No matching process found");
    }

cleanup:
    free(pids);
    return result;
}

@end
