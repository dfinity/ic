# Tools

The `rs/tools/` directory and related utility crates provide operational and development tools for the IC.

## Requirements

### Requirement: Candid Interface Compatibility Checker (check_did)

The `check_did` tool (`rs/tools/check_did/`) verifies backward compatibility of Candid (`.did`) interface files.

#### Scenario: Check interface compatibility
- **WHEN** `check_did new.did old.did` is executed
- **THEN** it parses both Candid interface files
- **AND** verifies that the new interface is a compatible superset of the old interface
- **AND** compatibility is checked using `candid_parser::utils::service_compatible`

#### Scenario: Incompatible interface detected
- **WHEN** the new interface is not compatible with the old interface
- **THEN** the tool panics with a message indicating the incompatibility
- **AND** includes file paths and the specific compatibility error

#### Scenario: Incorrect usage
- **WHEN** the tool is invoked without exactly two arguments
- **THEN** it prints usage information to stderr
- **AND** exits with code 1

### Requirement: CUP Explorer (ic-cup-explorer)

The `ic-cup-explorer` crate (`rs/cup_explorer/`) provides tools for exploring and verifying Catch-Up Packages (CUPs) of IC subnets.

#### Scenario: Explore subnet CUP
- **WHEN** `cup-explorer explore --subnet-id <id>` is executed
- **THEN** it connects to the NNS via the specified URL (default: `https://ic0.app`)
- **AND** retrieves the latest CUP for the specified subnet
- **AND** displays CUP information

#### Scenario: Download CUP
- **WHEN** `--download-path <dir>` is provided with the explore subcommand
- **THEN** the latest CUP is downloaded to the specified directory

#### Scenario: Verify CUP of halted subnet
- **WHEN** `cup-explorer verify-cup-of-halted-subnet --cup-path <path>` is executed
- **THEN** the CUP at the given path is verified against the NNS registry
- **AND** if the subnet was running (not halted), verification fails with a panic
- **AND** the error explains that non-halted subnet CUPs are not guaranteed to be the latest state

#### Scenario: NNS connection configuration
- **WHEN** `--nns-url <url>` is provided
- **THEN** the specified URL is used as the NNS entry point
- **AND** `--nns-pem <path>` optionally specifies a PEM file for verifying registry replies
