//
//  Logger.m
//  SniffNetBar
//
//  Runtime log level control implementation
//

#import "Logger.h"
#import "ConfigurationManager.h"

// Console logging state
static BOOL s_consoleLoggingEnabled = NO;

// Enable/disable console output (in addition to os_log)
void SNBSetConsoleLoggingEnabled(BOOL enabled) {
    s_consoleLoggingEnabled = enabled;
    if (enabled) {
        fprintf(stderr, "[INFO][core] Console logging enabled\n");
        fflush(stderr);
    }
}

BOOL SNBIsConsoleLoggingEnabled(void) {
    return s_consoleLoggingEnabled;
}

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
    SNBLogLevel level = debugLogging ? SNBLogLevelDebug : SNBLogLevelInfo;
#else
    // RELEASE builds now allow opt-in debug logging when the flag is set
    SNBLogLevel level = debugLogging ? SNBLogLevelDebug : SNBLogLevelWarn;
#endif
    isResolving = NO;
    return level;
}
