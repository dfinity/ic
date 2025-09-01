# Config Types Compatibility Tests

This module contains tests to ensure backwards compatibility of the config_types library. This is critical because we need to ensure that after updates, newer versions can always deserialize configurations written by older versions.

Currently, only HostOS config objects are checked for backwards compatibility, as GuestOS config objects are a subset of HostOS config and are fully contained within the HostOS config structure.

## Components

### 1. Fixture Generation System (`fixture.rs`)
- Generates and maintains test fixtures for a given config version
- If fixtures for the current config version already exist but the config structure has changed, the generator will fail with an error message asking you to increment the config_types version
- Stores fixtures in `fixtures/` directory with version information

### 2. Compatibility Tests (`compatibility_tests.rs`)
- Verifies that current code can deserialize all historical configs
- Validates that previously removed fields are not reused
