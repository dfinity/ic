# Config Types Compatibility Testing

This module provides tools and tests to ensure backwards compatibility of IC-OS configuration types across versions. This is critical because nodes in the decentralized network may be running different versions, and we need to ensure that newer versions can always deserialize configurations written by older versions.

## Components

### 1. Fixture Generation System (`fixture.rs`)
- Generates and maintains test fixtures for each config version
- Uses the actual config generation tools to create realistic test data
- Stores fixtures in `fixtures/` directory with version information

### 2. Compatibility Tests (`tests.rs`)
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

## Directory Structure
```
compatibility_tests/
├── README.md
├── fixtures/
│   ├── setupos_v1.0.0.json
│   ├── hostos_v1.0.0.json
│   └── guestos_v1.0.0.json
├── src/
│   ├── fixture.rs
│   └── lib.rs
└── tests/
    └── compatibility_tests.rs
``` 