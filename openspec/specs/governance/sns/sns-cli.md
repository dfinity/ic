# SNS CLI Tools

**Crates**: `ic-sns-cli`

The SNS CLI (`sns` command) provides tools for interacting with and managing SNS instances. It supports proposing SNS creation, deploying SNS canisters, querying health and status, and managing neuron operations.

## Requirements

### Requirement: SNS Deployment

The CLI supports deploying SNS canisters for testing and development.

#### Scenario: Deploy command
- **WHEN** the `deploy` command is executed
- **THEN** it deploys all SNS canisters (Root, Governance, Ledger, Swap, Index) to the target network

### Requirement: SNS Proposal Submission

The CLI supports submitting proposals related to SNS operations.

#### Scenario: Propose command
- **WHEN** the `propose` command is executed
- **THEN** it formats and submits a proposal to the appropriate governance canister
- **AND** the proposal type depends on the subcommand used

### Requirement: SNS Listing

The CLI supports listing deployed SNS instances.

#### Scenario: List deployed SNSes
- **WHEN** the `list` command is executed
- **THEN** it queries the SNS-WASM canister for all deployed SNS instances
- **AND** returns their canister IDs and metadata

### Requirement: SNS Health Check

The CLI supports checking the health of SNS instances.

#### Scenario: Health command
- **WHEN** the `health` command is executed
- **THEN** it queries the status of all canisters in the SNS
- **AND** reports any issues or unhealthy canisters

### Requirement: Init Config File Management

The CLI supports generating and managing SNS initialization configuration files.

#### Scenario: Init config file generation
- **WHEN** `init-config-file` command is used
- **THEN** it generates a YAML configuration file with all required SnsInitPayload fields
- **AND** the file can be edited and used to create an SNS

#### Scenario: Friendly config format
- **WHEN** the `friendly` subformat is used
- **THEN** human-readable names and descriptions are included
- **AND** values use natural units (e.g., ICP instead of e8s)

### Requirement: SNS Controlled Canister Upgrade

The CLI supports upgrading canisters controlled by an SNS.

#### Scenario: Upgrade SNS controlled canister command
- **WHEN** the `upgrade-sns-controlled-canister` command is executed
- **THEN** it prepares and submits an UpgradeSnsControlledCanister proposal

### Requirement: Neuron ID Conversion

The CLI supports converting between neuron ID formats.

#### Scenario: Neuron ID to candid subaccount
- **WHEN** `neuron-id-to-candid-subaccount` command is executed with a neuron ID
- **THEN** it converts the neuron ID to a Candid-encoded subaccount representation

### Requirement: Canister Preparation

The CLI supports preparing canisters for SNS control.

#### Scenario: Prepare canisters command
- **WHEN** `prepare-canisters` command is executed
- **THEN** it prepares the specified dapp canisters for handover to SNS root
- **AND** this includes setting the appropriate controllers

### Requirement: Extension Registration

The CLI supports registering extensions with an SNS.

#### Scenario: Register extension command
- **WHEN** `register-extension` command is executed
- **THEN** it prepares and submits a RegisterExtension proposal to the SNS

### Requirement: Table Formatting

The CLI provides formatted table output for structured data.

#### Scenario: Table output
- **WHEN** data is displayed to the user
- **THEN** it is formatted in readable tables with aligned columns
