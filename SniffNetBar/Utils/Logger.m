//
//  Logger.m
//  SniffNetBar
//
//  Runtime log level control implementation
//

#import "Logger.h"
#import "ConfigurationManager.h"

// Returns the runtime log level based on configuration and build type
SNBLogLevel SNBGetRuntimeLogLevel(void) {
    if (SNBConfigurationManagerIsInitializing()) {
#ifdef DEBUG
        return SNBLogLevelInfo;
#else
        return SNBLogLevelWarn;
#endif
    }

    // Prevent re-entrancy if configuration initialization triggers logging.
    static BOOL isResolving = NO;
    if (isResolving) {
#ifdef DEBUG
        return SNBLogLevelInfo;
#else
        return SNBLogLevelWarn;
#endif
    }
    isResolving = YES;

    // Get debug logging flag from configuration
    BOOL debugLogging = [ConfigurationManager sharedManager].debugLogging;

    #ifdef DEBUG
        // DEBUG builds: respect debugLogging flag
        SNBLogLevel level = debugLogging ? SNBLogLevelDebug : SNBLogLevelInfo;
        isResolving = NO;
        return level;
    #else
        // RELEASE builds: more restrictive
        SNBLogLevel level = debugLogging ? SNBLogLevelInfo : SNBLogLevelWarn;
        isResolving = NO;
        return level;
    #endif
}
