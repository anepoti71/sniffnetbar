#
# Makefile for SniffNetBar
# Objective-C menubar application for network traffic monitoring
#

APP_NAME = SniffNetBar
BUILD_DIR = build
FRAMEWORKS = -framework Cocoa -framework SystemConfiguration -framework MapKit -framework CoreLocation
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
          MapWindowController.m \
          PacketCaptureManager.m \
          PacketInfo.m \
          TrafficStatistics.m \
          NetworkDevice.m

OBJECTS = $(SOURCES:%.m=$(BUILD_DIR)/%.o)

# Targets
all: $(BUILD_DIR)/$(APP_NAME)

$(BUILD_DIR)/$(APP_NAME): $(OBJECTS) | $(BUILD_DIR)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(OBJECTS) -o $@ $(FRAMEWORKS) $(PCAP_LIBDIR) $(PCAP_LIBS)

$(BUILD_DIR)/%.o: %.m | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(OBJCFLAGS) $(SDK_FLAGS) $(PCAP_INCLUDE) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

install: $(BUILD_DIR)/$(APP_NAME)
	@echo "Installing $(APP_NAME)..."
	@mkdir -p ~/Applications
	@cp $(BUILD_DIR)/$(APP_NAME) ~/Applications/
	@echo "Installed to ~/Applications/$(APP_NAME)"
	@echo ""
	@echo "Note: This application requires root privileges to capture packets."
	@echo "You may need to run it with: sudo ~/Applications/$(APP_NAME)"

run: $(BUILD_DIR)/$(APP_NAME)
	@echo "Running $(APP_NAME) (requires sudo)..."
	sudo $(BUILD_DIR)/$(APP_NAME)

.PHONY: all clean install run
