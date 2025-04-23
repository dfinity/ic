# Config Types Compatibility Tests

This module contains tests to ensure backwards compatibility of the config_types library. This is critical because we need to ensure that after updates, newer versions can always deserialize configurations written by older versions.

## Components

### 1. Fixture Generation System (`fixture.rs`)
- Generates and maintains test fixtures for a given config version
- If fixtures for the current version already exist and the config structure has changed, the generator will fail with an error message asking you to increment the config_types version.
- Stores fixtures in `fixtures/` directory with version information

### 2. Compatibility Tests (`compatibility_tests.rs`)
- Verifies that current code can deserialize all historical configs
- Ensures version numbers are incremented when schema changes
- Protects against breaking changes

## Usage

### Running Tests

bazel test //rs/ic_os/config_types:config_types_test

### Adding New Fields
1. Make the field optional with a default value
2. Increment `CONFIG_VERSION` in `lib.rs`
3. Generate new fixture: `bazel run //rs/ic_os/config_types/compatibility_tests:generate_config_types_fixture`

### Removing Fields
1. First PR:
   - Make field optional
   - Increment `CONFIG_VERSION`
2. Second PR (after deployment):
   - Remove field
   - Add to `RESERVED_FIELD_NAMES`
   - Increment `CONFIG_VERSION`

### Generating New Fixtures
```bash
bazel run //rs/ic_os/config_types/compatibility_tests:generate_config_types_fixture
```
