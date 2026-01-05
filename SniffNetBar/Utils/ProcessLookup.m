//
//  ProcessLookup.m
//  SniffNetBar
//
//  Utility for looking up process information for network connections
//

#import "ProcessLookup.h"
#import "Logger.h"
#import <libproc.h>
#import <sys/proc_info.h>
#import <sys/sysctl.h>
#import <netinet/in.h>
#import <netinet/tcp.h>
#import <arpa/inet.h>
#import <string.h>

static dispatch_queue_t SNBProcessLookupQueue(void) {
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("com.sniffnetbar.processlookup", DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}

static BOOL SNBMatchAddress(const struct in_sockinfo *info,
                            BOOL matchLocal,
                            const struct in_addr *addr4,
                            const struct in6_addr *addr6,
                            BOOL has4,
                            BOOL has6) {
    if (info->insi_vflag & INI_IPV4) {
        if (!has4) {
            return NO;
        }
        const struct in_addr *candidate = matchLocal
            ? &info->insi_laddr.ina_46.i46a_addr4
            : &info->insi_faddr.ina_46.i46a_addr4;
        return memcmp(candidate, addr4, sizeof(struct in_addr)) == 0;
    }
    if (info->insi_vflag & INI_IPV6) {
        if (!has6) {
            return NO;
        }
        const struct in6_addr *candidate = matchLocal
            ? &info->insi_laddr.ina_6
            : &info->insi_faddr.ina_6;
        return memcmp(candidate, addr6, sizeof(struct in6_addr)) == 0;
    }
    return NO;
}

static ProcessInfo *SNBFindProcessForConnection(NSString *sourceAddress,
                                                 NSInteger sourcePort,
                                                 NSString *destinationAddress,
                                                 NSInteger destinationPort) {
    struct in_addr src4;
    struct in_addr dst4;
    struct in6_addr src6;
    struct in6_addr dst6;
    BOOL hasSrc4 = sourceAddress.length > 0 &&
        inet_pton(AF_INET, sourceAddress.UTF8String, &src4) == 1;
    BOOL hasDst4 = destinationAddress.length > 0 &&
        inet_pton(AF_INET, destinationAddress.UTF8String, &dst4) == 1;
    BOOL hasSrc6 = sourceAddress.length > 0 &&
        inet_pton(AF_INET6, sourceAddress.UTF8String, &src6) == 1;
    BOOL hasDst6 = destinationAddress.length > 0 &&
        inet_pton(AF_INET6, destinationAddress.UTF8String, &dst6) == 1;

    int pidCount = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pidCount <= 0) {
        return nil;
    }

    pid_t *pids = malloc((size_t)pidCount);
    if (!pids) {
        return nil;
    }

    pidCount = proc_listpids(PROC_ALL_PIDS, 0, pids, pidCount);
    int pidTotal = pidCount / (int)sizeof(pid_t);
    ProcessInfo *result = nil;

    for (int i = 0; i < pidTotal; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) {
            continue;
        }

        int fdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fdSize <= 0) {
            continue;
        }

        struct proc_fdinfo *fdInfos = malloc((size_t)fdSize);
        if (!fdInfos) {
            continue;
        }

        fdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdInfos, fdSize);
        int fdCount = fdSize / (int)sizeof(struct proc_fdinfo);

        for (int f = 0; f < fdCount; f++) {
            if (fdInfos[f].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }

            struct socket_fdinfo socketInfo;
            int sockSize = proc_pidfdinfo(pid, fdInfos[f].proc_fd,
                                          PROC_PIDFDSOCKETINFO,
                                          &socketInfo,
                                          sizeof(socketInfo));
            if (sockSize <= 0) {
                continue;
            }

            if (socketInfo.psi.soi_kind != SOCKINFO_TCP) {
                continue;
            }

            const struct in_sockinfo *inInfo = &socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini;
            int localPort = ntohs((uint16_t)inInfo->insi_lport);
            int remotePort = ntohs((uint16_t)inInfo->insi_fport);

            if (localPort != sourcePort || remotePort != destinationPort) {
                continue;
            }

            if (sourceAddress.length > 0 &&
                !SNBMatchAddress(inInfo, YES, &src4, &src6, hasSrc4, hasSrc6)) {
                continue;
            }
            if (destinationAddress.length > 0 &&
                !SNBMatchAddress(inInfo, NO, &dst4, &dst6, hasDst4, hasDst6)) {
                continue;
            }

            result = [[ProcessInfo alloc] init];
            result.pid = pid;
            result.processName = nil;
            break;
        }

        free(fdInfos);

        if (result) {
            break;
        }
    }

    free(pids);
    return result;
}

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

    if (sourcePort <= 0 || destinationPort <= 0) {
        return nil;
    }

    __block ProcessInfo *result = nil;
    dispatch_sync(SNBProcessLookupQueue(), ^{
        result = SNBFindProcessForConnection(sourceAddress,
                                             sourcePort,
                                             destinationAddress,
                                             destinationPort);
    });

    if (!result) {
        SNBLogInfo("ProcessLookup: ✗ No matching process found");
        return nil;
    }

    result = [self processInfoForPID:result.pid];
    SNBLogInfo("ProcessLookup: ✓ Found %@ (PID %d)",
          result.processName, result.pid);
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
