# SniffNetBar

A macOS menubar application for monitoring network traffic, refactored from the Rust networking code in Sniffnet.

## Features

- Real-time network traffic monitoring in the macOS menubar
- Packet capture and analysis using libpcap
- **Network interface selection** - Choose which network interface to monitor (similar to Rust implementation)
- Statistics tracking:
  - Total bytes transferred (incoming/outgoing)
  - Packet counts
  - Top hosts by traffic volume
  - Reverse DNS lookups for hostnames
- Supports TCP, UDP, and ICMP protocols
- IPv4 and IPv6 support
- Device preference persistence - Selected interface is saved and restored on app restart

## Requirements

- macOS 10.13 or later
- libpcap (install via Homebrew: `brew install libpcap`)
- Xcode Command Line Tools

## Building

```bash
make
```

This will create the executable in the `build/` directory.

## Installing

```bash
make install
```

This copies the application to `~/Applications/`.

## Running

**Important**: Packet capture requires root privileges on macOS.

```bash
sudo ~/Applications/SniffNetBar
```

Or if building locally:

```bash
sudo ./build/SniffNetBar
```

## Usage

1. Launch the application (requires sudo for packet capture)
2. Click the menubar icon to view traffic statistics
3. Select "Network Interface" from the menu to choose which interface to monitor
4. The selected interface is automatically saved and restored on next launch

## Architecture

The application is structured as follows:

- **AppDelegate**: Main application delegate managing the menubar item and menu
- **PacketCaptureManager**: Handles packet capture using libpcap and parses packet headers
- **PacketInfo**: Data structure representing parsed packet information
- **TrafficStatistics**: Tracks and aggregates network traffic statistics
- **NetworkDevice**: Represents network interfaces and provides device enumeration (refactored from Rust's `MyDevice`)

## Key Components Refactored from Rust

### Packet Capture
- Original: `src/networking/types/capture_context.rs`, `src/networking/parse_packets.rs`
- Refactored: `PacketCaptureManager.m`

### Packet Analysis
- Original: `src/networking/manage_packets.rs` (analyze_headers, analyze_link_header, analyze_network_header, analyze_transport_header)
- Refactored: `PacketCaptureManager.m` (parsePacket method)

### Traffic Statistics
- Original: `src/networking/manage_packets.rs` (modify_or_insert_in_map, traffic direction detection)
- Refactored: `TrafficStatistics.m`

### Reverse DNS
- Original: `src/networking/parse_packets.rs` (reverse_dns_lookup)
- Refactored: `TrafficStatistics.m` (performReverseDNSLookup)

### Device Selection
- Original: `src/networking/types/my_device.rs`, `src/networking/types/config_device.rs`
- Refactored: `NetworkDevice.m` (device enumeration and selection)

## Differences from Rust Implementation

1. **Memory Management**: Uses ARC (Automatic Reference Counting) instead of Rust's ownership system
2. **Concurrency**: Uses GCD (Grand Central Dispatch) instead of Rust's async/tokio
3. **Packet Parsing**: Simplified IPv6 handling (doesn't parse extension headers fully)
4. **Service Detection**: Not implemented (port-to-service name mapping)
5. **GUI**: Simple menubar menu instead of full GUI application

## License

Based on the original Sniffnet codebase (MIT OR Apache-2.0)

