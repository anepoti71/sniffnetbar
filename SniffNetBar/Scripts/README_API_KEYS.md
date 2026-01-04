# SniffNetBar API Key Management

API keys for threat intelligence providers (VirusTotal, AbuseIPDB, and GreyNoise) are now stored securely in the macOS Keychain instead of plaintext configuration files.

## Command-Line Tools

Three command-line tools are provided for managing API keys:

### 1. List API Keys

View the current status of all API keys:

```bash
./build/list_apikeys
```

Output:
```
=== SniffNetBar API Keys ===

VirusTotal:
  Identifier: VirusTotalAPIKey
  Status:     ✓ Configured
  Key:        ••••abcd

AbuseIPDB:
  Identifier: AbuseIPDBAPIKey
  Status:     ✗ Not configured
  Key:        (not set)

GreyNoise:
  Identifier: GreyNoiseAPIKey
  Status:     ✗ Not configured
  Key:        (not set)
```

### 2. Set API Key

Add or update an API key:

```bash
./build/set_apikey <provider> <api_key>
```

**Examples:**

```bash
# Set VirusTotal API key
./build/set_apikey virustotal YOUR_VIRUSTOTAL_API_KEY_HERE

# Set AbuseIPDB API key
./build/set_apikey abuseipdb YOUR_ABUSEIPDB_API_KEY_HERE

# Set GreyNoise API key
./build/set_apikey greynoise YOUR_GREYNOISE_API_KEY_HERE
```

**Supported providers:**
- `virustotal` - VirusTotal API key
- `abuseipdb` - AbuseIPDB API key
- `greynoise` - GreyNoise API key

### 3. Remove API Key

Remove an API key from the keychain:

```bash
./build/remove_apikey <provider>
```

**Examples:**

```bash
# Remove VirusTotal API key
./build/remove_apikey virustotal

# Remove AbuseIPDB API key
./build/remove_apikey abuseipdb

# Remove GreyNoise API key
./build/remove_apikey greynoise

# Remove all API keys
./build/remove_apikey all
```

## Getting API Keys

### VirusTotal
1. Create a free account at https://www.virustotal.com/gui/join-us
2. Navigate to your profile settings
3. Copy your API key
4. Run: `./build/set_apikey virustotal YOUR_KEY_HERE`

### AbuseIPDB
1. Create a free account at https://www.abuseipdb.com/register
2. Navigate to API settings
3. Generate an API key
4. Run: `./build/set_apikey abuseipdb YOUR_KEY_HERE`

### GreyNoise
1. Create a free Community account at https://www.greynoise.io/
2. Generate a Community API key
3. Run: `./build/set_apikey greynoise YOUR_KEY_HERE`

## Security

- API keys are stored in your macOS login keychain
- Keys are encrypted at rest
- Keys persist across app restarts and reinstalls
- Keys are never committed to source control
- Keys are accessible only when your Mac is unlocked

## Verifying Configuration

After setting your API keys:

1. **List keys to verify:**
   ```bash
   ./build/list_apikeys
   ```

2. **Run the app:**
   ```bash
   sudo make run
   ```

3. **Check console logs for:**
   ```
   VirusTotal provider configured successfully
   AbuseIPDB provider configured successfully
   GreyNoise provider configured successfully
   ```

4. **Enable threat intelligence:** Click the menu bar icon → "Enable Threat Intelligence"

## Troubleshooting

### Keys not showing as configured

```bash
# Check keychain directly
security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'VirusTotalAPIKey' -w
security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'AbuseIPDBAPIKey' -w
security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'GreyNoiseAPIKey' -w
```

### Remove and re-add keys

```bash
# Remove all keys
./build/remove_apikey all

# Re-add them
./build/set_apikey virustotal YOUR_KEY
./build/set_apikey abuseipdb YOUR_KEY
./build/set_apikey greynoise YOUR_KEY

# Verify
./build/list_apikeys
```

### Manual keychain management

```bash
# View keychain item details
security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'VirusTotalAPIKey'
security find-generic-password -s 'com.sniffnetbar.api-keys' -a 'GreyNoiseAPIKey'

# Delete manually
security delete-generic-password -s 'com.sniffnetbar.api-keys' -a 'VirusTotalAPIKey'
security delete-generic-password -s 'com.sniffnetbar.api-keys' -a 'GreyNoiseAPIKey'
```

## Building the Tools

The tools are built automatically when you run `make`:

```bash
make clean
make
```

The binaries will be in the `build/` directory:
- `build/set_apikey`
- `build/remove_apikey`
- `build/list_apikeys`
