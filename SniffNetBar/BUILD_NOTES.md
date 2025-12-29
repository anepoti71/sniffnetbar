# Build Notes

## Fixes Applied

1. **Makefile Updates:**
   - Added SDK path detection using `xcrun --show-sdk-path`
   - Added `-isysroot` and `-mmacosx-version-min` flags
   - Changed from `std=c11` to `std=gnu11` for better compatibility
   - Added `-fobjc-weak` flag for ARC compatibility

2. **IPv6 Header Parsing:**
   - Replaced platform-specific `struct ip6_hdr` with manual byte parsing
   - IPv6 header is always 40 bytes
   - Next header field is at byte offset 6
   - Source/destination addresses at offsets 8 and 24

3. **Includes:**
   - Removed `#import <netinet/ip6.h>` (not always available)
   - Removed `#import <netinet/icmp6.h>` (not needed)
   - Removed `#import <ifaddrs.h>` from PacketCaptureManager (moved to TrafficStatistics)
   - Added `#import <string.h>` for memcpy

## Building

```bash
cd SniffNetBar
make clean
make
```

If you still get SDK errors, try:

```bash
export SDKROOT=$(xcrun --show-sdk-path)
make
```

## Common Issues

1. **libpcap not found:**
   ```bash
   brew install libpcap
   ```

2. **SDK path issues:**
   - Make sure Xcode Command Line Tools are installed: `xcode-select --install`
   - Or install full Xcode from App Store

3. **Permission errors:**
   - The app needs root to capture packets: `sudo ./build/SniffNetBar`

