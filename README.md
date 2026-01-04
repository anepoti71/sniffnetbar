# SniffNetBar

Fork of Sniffnet, extended into a macOS menu bar application with passive threat visibility.

## What it does

- Monitors network traffic in the macOS menubar
- Captures and analyzes packets with libpcap
- Tracks totals, packet counts, top hosts, and top connections
- Resolves hostnames with reverse DNS
- Supports TCP, UDP, ICMP, IPv4, and IPv6
- Includes an embedded map view (Leaflet) for public IP geolocation

## Requirements

- macOS 10.13 or later
- libpcap (install via Homebrew: `brew install libpcap`)
- Xcode Command Line Tools

## Build

```bash
make
```

This creates `build/SniffNetBar.app`.

## Install

```bash
make install
```

This copies `SniffNetBar.app` to `~/Applications/`.

## Run

Packet capture requires root privileges on macOS.

```bash
sudo ~/Applications/SniffNetBar.app/Contents/MacOS/SniffNetBar
```

Or if building locally:

```bash
sudo ./build/SniffNetBar.app/Contents/MacOS/SniffNetBar
```

## Usage

1. Launch the application (requires sudo for packet capture)
2. Click the menubar icon to view traffic statistics
3. Select "Network Interface" to choose which interface to monitor
4. Toggle top hosts/connections and the map view as needed

## Passive threat visibility

- Highlights public IPs from active connections in the map view
- Helps spot unexpected destinations and unusual traffic patterns
- Designed for quick, passive situational awareness from the menubar

## Limitations

- Requires `sudo` to capture packets on macOS
- Simplified IPv6 parsing (extension headers not fully parsed)
- No port-to-service name mapping
- Menubar UI only (no full desktop UI)

## Map provider

The map uses Leaflet + OpenStreetMap tiles and looks up IP locations via a provider:

- `ipinfo.io` (default)
- `ip-api.com` (fallback to `ipinfo.io` on 403)
- Custom provider via UserDefaults:
  - `MapProvider` = `custom`
  - `MapProviderURLTemplate` = e.g. `https://example.com/geo/%@`
  - `MapProviderLatKey` = key path to latitude (default `lat`)
  - `MapProviderLonKey` = key path to longitude (default `lon`)

## License

Based on the original Sniffnet codebase (MIT OR Apache-2.0)
