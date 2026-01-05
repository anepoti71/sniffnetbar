//
//  AppDelegate.m
//  SniffNetBar
//
//  Created from Rust networking code refactoring
//

#import "AppDelegate.h"
#import "AppCoordinator.h"
#import "ConfigurationManager.h"
#import "AuthorizationHelper.h"
#import "KeychainManager.h"
#import "Logger.h"

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    SNBLogInfo("=== applicationDidFinishLaunching START ===");

    if (self.authorizationChecked) {
        SNBLogInfo("Authorization already checked, proceeding to initialize");
        [self initializeApplication];
        return;
    }

    self.authorizationChecked = YES;

    if (![AuthorizationHelper isRunningAsRoot]) {
        SNBLogInfo("Not running as root, requesting ROOT authorization");

        BOOL success = [AuthorizationHelper relaunchAsRoot];
        if (!success) {
            SNBLogError("Failed to relaunch with root privileges");
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Authorization Required";
            alert.informativeText = @"SniffNetBar requires root privileges to capture network packets. The application will now quit.";
            alert.alertStyle = NSAlertStyleWarning;
            [alert addButtonWithTitle:@"OK"];
            [alert runModal];
            [NSApp terminate:nil];
        }
    } else {
        SNBLogInfo("Already running as root");
        [self initializeApplication];
    }
}

- (void)initializeApplication {
    SNBLogInfo("Initializing application");

    // Enable keychain access now that we have root privileges
    NSError *error = nil;
    [KeychainManager requestKeychainAccessWithError:&error];

    // Create status item
    NSStatusBar *statusBar = [NSStatusBar systemStatusBar];
    self.statusItem = [statusBar statusItemWithLength:NSVariableStatusItemLength];
    NSImage *statusImage = [NSImage imageNamed:@"icon_macos"];
    if (!statusImage) {
        NSString *iconPath = [[NSBundle mainBundle] pathForResource:@"icon_macos" ofType:@"png"];
        statusImage = iconPath ? [[NSImage alloc] initWithContentsOfFile:iconPath] : nil;
    }
    if (statusImage) {
        CGFloat targetSize = statusBar.thickness - 2.0;
        statusImage.size = NSMakeSize(targetSize, targetSize);
        statusImage.template = NO;
        self.statusItem.button.image = statusImage;
        self.statusItem.button.imageScaling = NSImageScaleProportionallyDown;
        self.statusItem.button.title = @"";
    } else {
        SNBLogError("Status icon not found in bundle resources.");
        self.statusItem.button.title = @"📊";
    }
    self.statusItem.button.target = self;
    self.statusItem.button.action = @selector(statusItemClicked:);
    [self.statusItem.button sendActionOn:NSEventMaskLeftMouseUp | NSEventMaskRightMouseUp];

    // Create menu
    self.statusMenu = [[NSMenu alloc] init];
    self.statusMenu.delegate = self;

    // Initialize coordinator
    self.coordinator = [[AppCoordinator alloc] initWithStatusItem:self.statusItem
                                                       statusMenu:self.statusMenu];

    // Start the coordinator
    [self.coordinator start];
}

- (void)statusItemClicked:(id)sender {
    NSEvent *event = [NSApp currentEvent];
    if (event.type == NSEventTypeRightMouseUp) {
        [self.statusItem popUpStatusItemMenu:self.statusMenu];
    } else {
        [self.coordinator updateMenu];
        [self.statusItem popUpStatusItemMenu:self.statusMenu];
    }
}

- (void)menuWillOpen:(NSMenu *)menu {
    if (menu != self.statusMenu) {
        return;
    }
    [self.coordinator menuWillOpenWithStats];
}

- (void)menuDidClose:(NSMenu *)menu {
    if (menu != self.statusMenu) {
        return;
    }
    [self.coordinator menuDidClose];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self.coordinator stop];
}

@end
