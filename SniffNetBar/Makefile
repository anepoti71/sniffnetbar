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
ICNS_SRC = ../resources/logos/raw/sniffnet.icns
FRAMEWORKS = -framework Cocoa -framework SystemConfiguration -framework WebKit -framework CoreLocation -framework Security -framework CoreML
PCAP_LIBS = -lpcap
SQLITE_LIBS = -lsqlite3
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
CORE_SOURCES = Core/main.m Core/AppDelegate.m Core/AppCoordinator.m \
               Core/AnomalyExplainabilityCoordinator.m
CONFIG_SOURCES = Config/ConfigurationManager.m Config/KeychainManager.m Config/UserDefaultsKeys.m
MODEL_SOURCES = Models/PacketInfo.m Models/TrafficStatistics.m \
                Models/AnomalyDetector.m Models/AnomalyStore.m \
                Models/AnomalyPythonScorer.m Models/AnomalyCoreMLScorer.m \
                Models/AnomalyExplanationService.m
NETWORK_SOURCES = Network/PacketCaptureManager.m Network/NetworkDevice.m \
                  Network/DeviceManager.m Network/NetworkAssetMonitor.m
THREATINTEL_SOURCES = ThreatIntel/ThreatIntelModels.m \
                      ThreatIntel/ThreatIntelProvider.m \
                      ThreatIntel/ThreatIntelCache.m \
                      ThreatIntel/ThreatIntelStore.m \
                      ThreatIntel/ThreatIntelFacade.m \
                      ThreatIntel/ThreatIntelCoordinator.m \
                      ThreatIntel/Providers/VirusTotalProvider.m \
                      ThreatIntel/Providers/AbuseIPDBProvider.m \
                      ThreatIntel/Providers/GreyNoiseProvider.m
UI_SOURCES = UI/MapMenuView.m UI/MenuBuilder.m
UTIL_SOURCES = Utils/ByteFormatter.m Utils/ExpiringCache.m Utils/IPAddressUtilities.m Utils/Logger.m Utils/AuthorizationHelper.m Utils/ProcessLookup.m

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
	@cp $(ICNS_SRC) $(RESOURCES_DIR)/sniffnet.icns
	@cp Scripts/anomaly_score.py $(RESOURCES_DIR)/anomaly_score.py
	@cp Scripts/anomaly_train.py $(RESOURCES_DIR)/anomaly_train.py
	@cp Scripts/convert_iforest_to_coreml.py $(RESOURCES_DIR)/convert_iforest_to_coreml.py
	@if [ -d ../resources/anomaly_model.mlmodelc ]; then cp -R ../resources/anomaly_model.mlmodelc $(RESOURCES_DIR)/anomaly_model.mlmodelc; fi

$(MACOS_DIR)/$(APP_NAME): $(OBJECTS) | $(MACOS_DIR)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(OBJECTS) -o $@ $(FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS) $(SQLITE_LIBS)

$(BUILD_DIR)/%.o: %.m | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) $(PCAP_INCLUDE) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(MACOS_DIR):
	mkdir -p $(MACOS_DIR)

$(RESOURCES_DIR):
	mkdir -p $(RESOURCES_DIR)

# Command-line tools for API key management and testing
tools: $(BUILD_DIR)/set_apikey $(BUILD_DIR)/remove_apikey $(BUILD_DIR)/list_apikeys

# Test utilities
test-threat-intel: $(BUILD_DIR)/test_threat_intel
test-process-lookup: $(BUILD_DIR)/test_process_lookup

$(BUILD_DIR)/test_threat_intel: Tools/test_threat_intel.m $(BUILD_DIR)/Tests/ThreatIntel/MockThreatIntelProvider.o $(BUILD_DIR)/ThreatIntel/ThreatIntelFacade.o $(BUILD_DIR)/ThreatIntel/ThreatIntelModels.o $(BUILD_DIR)/ThreatIntel/ThreatIntelCache.o $(BUILD_DIR)/ThreatIntel/ThreatIntelProvider.o $(BUILD_DIR)/Utils/ExpiringCache.o $(BUILD_DIR)/Utils/Logger.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Utils/IPAddressUtilities.o $(BUILD_DIR)/Config/KeychainManager.o | $(BUILD_DIR)
	@echo "Building test_threat_intel tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tools/test_threat_intel.m \
		$(BUILD_DIR)/Tests/ThreatIntel/MockThreatIntelProvider.o \
		$(BUILD_DIR)/ThreatIntel/ThreatIntelFacade.o \
		$(BUILD_DIR)/ThreatIntel/ThreatIntelModels.o \
		$(BUILD_DIR)/ThreatIntel/ThreatIntelCache.o \
		$(BUILD_DIR)/ThreatIntel/ThreatIntelProvider.o \
		$(BUILD_DIR)/Utils/ExpiringCache.o \
		$(BUILD_DIR)/Utils/Logger.o \
		$(BUILD_DIR)/Config/ConfigurationManager.o \
		$(BUILD_DIR)/Utils/IPAddressUtilities.o \
		$(BUILD_DIR)/Config/KeychainManager.o \
		-o $@ $(FRAMEWORKS)

$(BUILD_DIR)/test_process_lookup: Tools/test_process_lookup.m $(BUILD_DIR)/Utils/ProcessLookup.o $(BUILD_DIR)/Utils/Logger.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Config/KeychainManager.o | $(BUILD_DIR)
	@echo "Building test_process_lookup tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Tools/test_process_lookup.m \
		$(BUILD_DIR)/Utils/ProcessLookup.o \
		$(BUILD_DIR)/Utils/Logger.o \
		$(BUILD_DIR)/Config/ConfigurationManager.o \
		$(BUILD_DIR)/Config/KeychainManager.o \
		-o $@ $(FRAMEWORKS)

$(BUILD_DIR)/set_apikey: Scripts/set_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Utils/Logger.o
	@echo "Building set_apikey tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/set_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Utils/Logger.o -o $(BUILD_DIR)/set_apikey $(FRAMEWORKS)

$(BUILD_DIR)/remove_apikey: Scripts/remove_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Utils/Logger.o
	@echo "Building remove_apikey tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/remove_apikey.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Utils/Logger.o -o $(BUILD_DIR)/remove_apikey $(FRAMEWORKS)

$(BUILD_DIR)/list_apikeys: Scripts/list_apikeys.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Utils/Logger.o
	@echo "Building list_apikeys tool..."
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PROJECT_INCLUDES) Scripts/list_apikeys.m $(BUILD_DIR)/Config/KeychainManager.o $(BUILD_DIR)/Config/ConfigurationManager.o $(BUILD_DIR)/Utils/Logger.o -o $(BUILD_DIR)/list_apikeys $(FRAMEWORKS)

clean:
	rm -rf $(BUILD_DIR)

install: $(APP_BUNDLE)
	@echo "Installing $(APP_NAME)..."
	@mkdir -p ~/Applications
	@cp -R $(APP_BUNDLE) ~/Applications/
	@echo "Installed to ~/Applications/$(APP_NAME).app"
	@echo ""
	@echo "Note: The application will request root privileges on startup for packet capture."

dmg: $(APP_BUNDLE)
	@echo "Creating DMG installer..."
	@./Scripts/create_dmg.sh

run: $(APP_BUNDLE)
	@echo "Running $(APP_NAME)..."
	@echo "The application will request root privileges on startup."
	open $(APP_BUNDLE)

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
		$(FRAMEWORKS) $(TEST_FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS) $(SQLITE_LIBS) \
		-Xlinker -bundle_loader -Xlinker /Applications/Xcode.app/Contents/Developer/usr/bin/xctest

test-build: $(LIB_OBJECTS) $(TEST_OBJECTS)
	@echo "Test files compiled successfully"

.PHONY: all clean install dmg run test tools test-build test-threat-intel test-process-lookup
