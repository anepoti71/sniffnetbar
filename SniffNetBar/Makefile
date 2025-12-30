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
FRAMEWORKS = -framework Cocoa -framework SystemConfiguration -framework WebKit -framework CoreLocation -framework Security
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

# Include paths for organized folders
PROJECT_INCLUDES = -I. -ICore -IConfig -IModels -INetwork -IThreatIntel -IThreatIntel/Providers -IUI -IUtils -ITests -ITests/ThreatIntel -ITests/ThreatIntel/Providers

# Source files (organized by domain)
CORE_SOURCES = Core/main.m Core/AppDelegate.m
CONFIG_SOURCES = Config/ConfigurationManager.m Config/KeychainManager.m Config/UserDefaultsKeys.m
MODEL_SOURCES = Models/PacketInfo.m Models/TrafficStatistics.m
NETWORK_SOURCES = Network/PacketCaptureManager.m Network/NetworkDevice.m \
                  Network/DeviceManager.m
THREATINTEL_SOURCES = ThreatIntel/ThreatIntelModels.m \
                      ThreatIntel/ThreatIntelProvider.m \
                      ThreatIntel/ThreatIntelCache.m \
                      ThreatIntel/ThreatIntelFacade.m \
                      ThreatIntel/ThreatIntelCoordinator.m \
                      ThreatIntel/Providers/VirusTotalProvider.m \
                      ThreatIntel/Providers/AbuseIPDBProvider.m
UI_SOURCES = UI/MapMenuView.m UI/MenuBuilder.m
UTIL_SOURCES = Utils/ByteFormatter.m Utils/ExpiringCache.m

# Test sources
TEST_SOURCES = Tests/ThreatIntel/ThreatIntelCacheTests.m \
               Tests/ThreatIntel/ThreatIntelModelsTests.m \
               Tests/ThreatIntel/ThreatIntelFacadeTests.m \
               Tests/ThreatIntel/MockThreatIntelProvider.m \
               Tests/ThreatIntel/Providers/ProviderTests.m

# All sources
SOURCES = $(CORE_SOURCES) $(CONFIG_SOURCES) $(MODEL_SOURCES) \
          $(NETWORK_SOURCES) $(THREATINTEL_SOURCES) $(UI_SOURCES) $(UTIL_SOURCES)

# Library sources (for tests - exclude main.m and AppDelegate.m)
LIB_SOURCES = $(CONFIG_SOURCES) $(MODEL_SOURCES) $(NETWORK_SOURCES) \
              $(THREATINTEL_SOURCES) UI/MapMenuView.m UI/MenuBuilder.m $(UTIL_SOURCES)

OBJECTS = $(SOURCES:%.m=$(BUILD_DIR)/%.o)
LIB_OBJECTS = $(LIB_SOURCES:%.m=$(BUILD_DIR)/%.o)
TEST_OBJECTS = $(TEST_SOURCES:%.m=$(BUILD_DIR)/%.o)

# Targets
all: $(APP_BUNDLE) tools

$(APP_BUNDLE): $(MACOS_DIR)/$(APP_NAME) $(INFO_PLIST_SRC) | $(RESOURCES_DIR)
	@cp $(INFO_PLIST_SRC) $(CONTENTS_DIR)/Info.plist
	@cp Config/Configuration.plist $(RESOURCES_DIR)/Configuration.plist
	@cp $(ICON_SRC) $(RESOURCES_DIR)/icon_macos.png

$(MACOS_DIR)/$(APP_NAME): $(OBJECTS) | $(MACOS_DIR)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(OBJECTS) -o $@ $(FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS)

$(BUILD_DIR)/%.o: %.m | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) $(PCAP_INCLUDE) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(MACOS_DIR):
	mkdir -p $(MACOS_DIR)

$(RESOURCES_DIR):
	mkdir -p $(RESOURCES_DIR)

# Command-line tools for API key management
tools: $(BUILD_DIR)/set_apikey $(BUILD_DIR)/remove_apikey $(BUILD_DIR)/list_apikeys

$(BUILD_DIR)/set_apikey: Scripts/set_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o
	@echo "Building set_apikey tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/set_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o -o $(BUILD_DIR)/set_apikey $(FRAMEWORKS)

$(BUILD_DIR)/remove_apikey: Scripts/remove_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o
	@echo "Building remove_apikey tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/remove_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o -o $(BUILD_DIR)/remove_apikey $(FRAMEWORKS)

$(BUILD_DIR)/list_apikeys: Scripts/list_apikeys.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o
	@echo "Building list_apikeys tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/list_apikeys.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o -o $(BUILD_DIR)/list_apikeys $(FRAMEWORKS)

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

# Test targets
TEST_BUNDLE = $(BUILD_DIR)/Tests.xctest
TEST_BUNDLE_DIR = $(TEST_BUNDLE)/Contents/MacOS
TEST_FRAMEWORKS = -framework XCTest

test: $(BUILD_DIR)/TestRunner
	@echo "Running tests..."
	$(BUILD_DIR)/TestRunner

$(BUILD_DIR)/TestRunner: $(LIB_OBJECTS) $(TEST_OBJECTS) | $(BUILD_DIR)
	@echo "Building test runner..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(LIB_OBJECTS) $(TEST_OBJECTS) -o $@ \
		$(FRAMEWORKS) $(TEST_FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS) \
		-Xlinker -bundle_loader -Xlinker /Applications/Xcode.app/Contents/Developer/usr/bin/xctest

test-build: $(LIB_OBJECTS) $(TEST_OBJECTS)
	@echo "Test files compiled successfully"

.PHONY: all clean install run test tools test-build
