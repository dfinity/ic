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

## Usage

### Adding New Fields
1. Make the field optional with a default value
2. Increment `CONFIG_VERSION` in the `config_types` crate
3. Generate new fixture: `bazel run //rs/ic_os/config_types/compatibility_tests:generate_config_types_fixture`

### Removing Fields
1. First PR:
   - Make field optional
   - Increment `CONFIG_VERSION` in the `config_types` crate
2. Second PR (after the previous release has reached ALL mainnet nodes):
   - Remove field
   - Add field to `RESERVED_FIELD_NAMES` in the `config_types` crate
   - Increment `CONFIG_VERSION` in the `config_types` crate

