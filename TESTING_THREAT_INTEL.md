# Testing Threat Intelligence in SniffNetBar

This guide explains how to test the threat intelligence features in SniffNetBar.

## Prerequisites

- SniffNetBar built and installed
- For real provider testing: API keys for VirusTotal and/or AbuseIPDB
- Root privileges (required for packet capture)

## Testing Methods

### Method 1: Mock Provider Test (Recommended for Development)

Use the test utility with mock providers to simulate threat intelligence responses without making real API calls.

**Build the test utility:**
```bash
cd SniffNetBar
make test-threat-intel
```

**Run the test:**
```bash
./build/test_threat_intel
```

This will:
- Create a mock threat intelligence provider
- Test several simulated IPs (malicious, suspicious, clean)
- Display threat intelligence results
- Show cache statistics

### Method 2: Generate Test Network Traffic

Use the included script to generate network traffic that SniffNetBar can capture and analyze.

**Safe mode (TEST-NET IPs):**
```bash
./Scripts/generate_test_traffic.sh
# Select option 1 for safe TEST-NET ranges
```

**DNS queries only:**
```bash
./Scripts/generate_test_traffic.sh
# Select option 2 for DNS lookups
```

**Known bad IPs (CAUTION):**
```bash
./Scripts/generate_test_traffic.sh
# Select option 3 - use with caution, requires confirmation
```

### Method 3: Use Known Malicious IPs with Real Providers

If you have API keys configured, you can test with publicly documented malicious IPs.

**Known test IPs for threat intelligence:**

1. **Tor Exit Nodes** (often flagged):
   - 185.220.101.1
   - 185.220.102.1

2. **IANA Reserved/Test IPs** (should be clean):
   - 192.0.2.1 (TEST-NET-1)
   - 198.51.100.1 (TEST-NET-2)
   - 203.0.113.1 (TEST-NET-3)

**Trigger connections:**
```bash
# Make SniffNetBar capture connections to these IPs
curl --connect-timeout 1 http://185.220.101.1 || true
curl --connect-timeout 1 http://198.51.100.1 || true
```

### Method 4: Configure API Keys for Real Testing

1. **Get API keys:**
   - VirusTotal: https://www.virustotal.com/gui/join-us
   - AbuseIPDB: https://www.abuseipdb.com/register

2. **Configure keys in SniffNetBar:**
   - Launch SniffNetBar
   - Click the menu bar icon
   - Select "Configure API Keys..."
   - Enter your API keys

3. **Enable providers:**
   - Verify in `Config/Configuration.plist`:
     - `VirusTotalEnabled` = `true`
     - `AbuseIPDBEnabled` = `true`

4. **Test with real IPs:**
   ```bash
   # This is a known malicious IP that should be in threat databases
   curl --connect-timeout 1 http://185.220.101.1:80 || true
   ```

5. **Check results:**
   - Click SniffNetBar menu
   - Look for threat intelligence indicators
   - Check the map view for flagged IPs

## Verifying Results

### In the Menu UI

When SniffNetBar detects a threat:
1. The IP should appear in the "Top Hosts" or "Top Connections" list
2. Threat intelligence data should be visible (if UI displays it)
3. The map view may highlight the location differently

### Via Logs

Check system logs for threat intelligence activity:
```bash
log stream --predicate 'subsystem == "com.sniffnetbar"' --level debug
```

Look for:
- `[ThreatIntel]` log entries
- Provider query results
- Cache hits/misses
- Threat scores and verdicts

### Cache Statistics

The test utility shows cache stats. In the running app, check:
```
Cache Stats: {
    hits = X;
    misses = Y;
    size = Z;
}
```

## Interpreting Results

### Threat Scores

- **0-30**: Likely clean
- **31-60**: Suspicious (investigate)
- **61-100**: Malicious (high confidence)

### Verdicts

- `TIThreatVerdictClean`: No threat detected
- `TIThreatVerdictSuspicious`: Potentially malicious
- `TIThreatVerdictMalicious`: High confidence threat
- `TIThreatVerdictUnknown`: No data available

### Provider Categories

Common categories from threat intel providers:
- `malware`: Known malware distribution
- `phishing`: Phishing attempts
- `spam`: Spam source
- `exploit`: Exploit delivery
- `tor`: Tor exit node
- `proxy`: Anonymous proxy

## Troubleshooting

### No Threat Intel Results

1. **Check if enabled:**
   - Verify providers are enabled in Configuration.plist
   - Check API keys are configured (in Keychain)

2. **Check logs:**
   ```bash
   log stream --predicate 'subsystem == "com.sniffnetbar"' | grep -i threat
   ```

3. **Verify network connectivity:**
   ```bash
   curl -I https://www.virustotal.com/api/v3/
   curl -I https://api.abuseipdb.com/api/v2/
   ```

### Rate Limiting

Free API keys have rate limits:
- **VirusTotal**: 4 requests/minute (free tier)
- **AbuseIPDB**: 1,000 requests/day (free tier)

The app caches results to minimize API calls.

### API Key Issues

API keys are stored in macOS Keychain. To check:
```bash
security find-generic-password -s "com.sniffnetbar.virustotal" -g
security find-generic-password -s "com.sniffnetbar.abuseipdb" -g
```

## Best Practices

1. **Start with mock testing** before using real API keys
2. **Use TEST-NET IPs** for development to avoid triggering real alerts
3. **Monitor rate limits** when using free API tiers
4. **Review cache settings** to optimize API usage
5. **Never commit API keys** to version control

## Examples

### Quick Test Workflow

```bash
# 1. Build test utility
cd SniffNetBar
make test-threat-intel

# 2. Run mock test
./build/test_threat_intel

# 3. Run SniffNetBar
sudo ./build/SniffNetBar.app/Contents/MacOS/SniffNetBar

# 4. In another terminal, generate test traffic
./Scripts/generate_test_traffic.sh
```

### Production Testing Workflow

```bash
# 1. Configure API keys via menu
# 2. Run SniffNetBar
sudo ~/Applications/SniffNetBar.app/Contents/MacOS/SniffNetBar

# 3. Monitor normal traffic and check for threats
# 4. View logs
log stream --predicate 'subsystem == "com.sniffnetbar"' --level info
```

## Additional Resources

- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
- [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)
- [RFC 5737 - IPv4 TEST-NET Addresses](https://tools.ietf.org/html/rfc5737)
