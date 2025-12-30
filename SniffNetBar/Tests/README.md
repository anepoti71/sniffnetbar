# SniffNetBar ThreatIntel Tests

## Overview

This directory contains comprehensive unit tests for the ThreatIntel module of SniffNetBar.

## Test Files

### Core Tests
- **ThreatIntelCacheTests.m**: Tests for the threat intelligence cache
  - Cache set/get operations
  - TTL and expiration handling
  - LRU eviction
  - Cache invalidation
  - Hit rate tracking
  - Support for multiple indicator types

- **ThreatIntelModelsTests.m**: Tests for ThreatIntel data models
  - TIIndicator creation and equality
  - TIVerdict properties
  - TIMetadata initialization
  - TIResult creation
  - TIScoreBreakdown
  - TIScoringResult with verdict mapping
  - TIEnrichmentResponse
  - Error domain and codes

- **ThreatIntelFacadeTests.m**: Tests for the main ThreatIntelFacade
  - Provider management (add/configure)
  - Single and batch indicator enrichment
  - Multi-provider enrichment
  - Partial provider failure handling
  - Cache integration
  - Concurrent enrichment
  - Enable/disable functionality

- **MockThreatIntelProvider.h/m**: Mock provider for testing
  - Controllable responses
  - Simulated delays
  - Error injection
  - Call counting

### Provider Tests
- **Providers/ProviderTests.m**: Tests for VirusTotal and AbuseIPDB providers
  - Provider initialization
  - Configuration with custom URLs
  - Indicator type support
  - Health checks
  - Custom TTL settings

## Running Tests

### Option 1: Using Xcode (Recommended)

1. Open the project in Xcode
2. Create a new Test Target or add these files to an existing test target
3. Run tests using Product > Test or Cmd+U

### Option 2: Command Line (with Xcode installed)

```bash
# Build the test target
xcodebuild test -scheme SniffNetBar

# Or run specific tests
xcodebuild test -scheme SniffNetBar -only-testing:SniffNetBarTests/ThreatIntelCacheTests
```

### Option 3: Manual Verification

The tests are written to be self-documenting. You can review the test cases to understand:
- Expected behavior of each component
- Edge cases being handled
- Integration patterns

## Test Coverage

### ThreatIntelCache (ThreatIntelCacheTests.m)
- ✅ Basic cache operations (set, get, clear)
- ✅ Size tracking
- ✅ TTL-based expiration
- ✅ Stale detection with refresh windows
- ✅ LRU eviction when max size exceeded
- ✅ Selective invalidation (by provider, by indicator)
- ✅ Hit rate calculation
- ✅ Multiple indicator types (IPv4, IPv6)

### ThreatIntelModels (ThreatIntelModelsTests.m)
- ✅ Indicator creation with different types
- ✅ Indicator copying and equality
- ✅ Verdict initialization and properties
- ✅ Metadata with expiration
- ✅ Result creation with verdicts and metadata
- ✅ Score breakdown
- ✅ Scoring result with verdict strings and colors
- ✅ Enrichment response composition
- ✅ Error domain and all error codes

### ThreatIntelFacade (ThreatIntelFacadeTests.m)
- ✅ Provider configuration and management
- ✅ Single indicator enrichment
- ✅ IP address enrichment (IPv4 and IPv6)
- ✅ Disabled state handling
- ✅ Multi-provider enrichment
- ✅ Partial provider failure resilience
- ✅ Batch indicator enrichment
- ✅ Cache statistics
- ✅ Concurrent enrichment

### Providers (ProviderTests.m)
- ✅ VirusTotal provider initialization
- ✅ VirusTotal configuration
- ✅ VirusTotal indicator type support
- ✅ VirusTotal health checks
- ✅ AbuseIPDB provider initialization
- ✅ AbuseIPDB configuration with maxAgeInDays
- ✅ AbuseIPDB indicator type support
- ✅ AbuseIPDB health checks
- ✅ Custom TTL and base URL configuration
- ✅ Indicator type support validation

## Key Test Scenarios

### NSNull Safety
The tests validate that providers handle NSNull values in API responses correctly (addressing the crashes fixed in production code).

### Rate Limiting
Provider tests verify that rate limiting is properly configured and respected.

### Caching Strategy
Tests ensure that:
- Results are cached with appropriate TTL
- Expired entries are removed
- Cache doesn't exceed maximum size
- LRU eviction works correctly

### Multi-Provider Consensus
Facade tests verify that multiple providers can be queried concurrently and results are properly aggregated.

### Error Handling
Tests cover various error scenarios:
- Provider unavailable
- Network timeouts
- Authentication failures
- Rate limiting
- Partial provider failures

## Mock Provider

The `MockThreatIntelProvider` allows controlled testing without network calls:

```objc
MockThreatIntelProvider *mock = [[MockThreatIntelProvider alloc] initWithName:@"TestProvider"];

// Set mock scores
[mock setMockScore:75 forIndicatorValue:@"1.2.3.4"];

// Simulate failures
mock.shouldFail = YES;
mock.errorToReturn = [NSError errorWithDomain:TIErrorDomain code:TIErrorCodeTimeout userInfo:nil];

// Add delay
mock.simulatedDelay = 1.0;

// Track calls
XCTAssertEqual(mock.callCount, expectedCalls);
```

## Future Enhancements

Potential additional tests:
- Integration tests with actual API endpoints (requires API keys)
- Performance benchmarks
- Memory leak detection
- Stress tests with many concurrent requests
- Network failure simulation
- Cache persistence tests
