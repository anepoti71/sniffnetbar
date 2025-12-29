#
# Makefile for SniffNetBar
# Objective-C menubar application for network traffic monitoring
#

APP_NAME = SniffNetBar
BUILD_DIR = build
APP_BUNDLE = $(BUILD_DIR)/$(APP_NAME).app
CONTENTS_DIR = $(APP_BUNDLE)/Contents
MACOS_DIR = $(CONTENTS_DIR)/MacOS
RESOURCES_DIR = $(CONTENTS_DIR)/Resources
INFO_PLIST_SRC = Info.plist
ICON_SRC = ../resources/logos/raw/icon_macos.png
FRAMEWORKS = -framework Cocoa -framework SystemConfiguration -framework WebKit -framework CoreLocation
PCAP_LIBS = -lpcap
CC = clang
CFLAGS = -std=c11 -Wall -Wextra -O2
OBJCFLAGS = -fobjc-arc -fobjc-weak -std=gnu11 -Wall -Wextra -O2

# Find macOS SDK
SDKROOT = $(shell xcrun --show-sdk-path 2>/dev/null || echo /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk)
SDK_FLAGS = -isysroot $(SDKROOT) -mmacosx-version-min=10.13

# Find libpcap (assuming installed via Homebrew)
PCAP_INCLUDE = -I/opt/homebrew/include -I/usr/local/include
PCAP_LIBDIR = -L/opt/homebrew/lib -L/usr/local/lib

# Source files (relative to current directory)
SOURCES = main.m \
          AppDelegate.m \
          MapMenuView.m \
          PacketCaptureManager.m \
          PacketInfo.m \
          TrafficStatistics.m \
          NetworkDevice.m

OBJECTS = $(SOURCES:%.m=$(BUILD_DIR)/%.o)

# Targets
all: $(APP_BUNDLE)

$(APP_BUNDLE): $(MACOS_DIR)/$(APP_NAME) $(INFO_PLIST_SRC) | $(RESOURCES_DIR)
	@cp $(INFO_PLIST_SRC) $(CONTENTS_DIR)/Info.plist
	@cp $(ICON_SRC) $(RESOURCES_DIR)/icon_macos.png

$(MACOS_DIR)/$(APP_NAME): $(OBJECTS) | $(MACOS_DIR)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(OBJECTS) -o $@ $(FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS)

$(BUILD_DIR)/%.o: %.m | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PCAP_INCLUDE) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(MACOS_DIR):
	mkdir -p $(MACOS_DIR)

$(RESOURCES_DIR):
	mkdir -p $(RESOURCES_DIR)

clean:
	rm -rf $(BUILD_DIR)

install: $(APP_BUNDLE)
	@echo "Installing $(APP_NAME)..."
	@mkdir -p ~/Applications
	@cp -R $(APP_BUNDLE) ~/Applications/
	@echo "Installed to ~/Applications/$(APP_NAME).app"
	@echo ""
	@echo "Note: This application requires root privileges to capture packets."
	@echo "You may need to run it with: sudo ~/Applications/$(APP_NAME).app/Contents/MacOS/$(APP_NAME)"

run: $(APP_BUNDLE)
	@echo "Running $(APP_NAME) (requires sudo)..."
	sudo $(APP_BUNDLE)/Contents/MacOS/$(APP_NAME)

.PHONY: all clean install run
