# SNS Extensions

**Crates**: `sns-treasury-manager`

Extensions are additional canisters that can be registered with an SNS to augment its functionality. The first supported extension type is the Treasury Manager, which enables treasury operations such as deposits and withdrawals through decentralized exchanges.

## Requirements

### Requirement: Extension Allowlist

Extensions must be approved before they can be registered with an SNS.

#### Scenario: WASM hash allowlist
- **WHEN** a RegisterExtension proposal is submitted
- **THEN** the extension's WASM hash must match an entry in the `ALLOWED_EXTENSIONS` list
- **AND** each allowlisted hash maps to an `ExtensionSpec` containing name, version, topic, and extension_type
- **AND** unrecognized hashes are rejected

#### Scenario: Extension versioning
- **WHEN** an extension has multiple versions
- **THEN** each version has a distinct WASM hash in the allowlist
- **AND** `ExtensionVersion` is a monotonically increasing integer

### Requirement: Extension Types

Extensions are categorized by type, which determines their capabilities and initialization requirements.

#### Scenario: Treasury Manager extension type
- **WHEN** a Treasury Manager extension is registered
- **THEN** it manages treasury operations including deposits, withdrawals, and allowances
- **AND** it is associated with the `TreasuryAssetManagement` topic
- **AND** it requires initialization with SNS root, governance, and ledger canister IDs, token symbol, transaction fee, and ICP ledger canister ID

### Requirement: Extension Registration Flow

Registering an extension involves multiple steps across governance and root canisters.

#### Scenario: Registration via proposal
- **WHEN** a RegisterExtension proposal is adopted
- **THEN** governance validates the extension spec (WASM hash, type, topic)
- **AND** governance installs the extension canister with the validated init arguments
- **AND** root registers the extension canister ID
- **AND** the extension is controlled by both Root and Governance

#### Scenario: Extension controller setup
- **WHEN** an extension canister is registered with root
- **THEN** Root is set as controller for canister management (upgrades)
- **AND** Governance is set as controller for calling update functions (operations)
- **AND** all other controllers are removed

### Requirement: Extension Operations

Registered extensions can be invoked through governance proposals.

#### Scenario: Execute extension operation
- **WHEN** an ExecuteExtensionOperation proposal is adopted
- **THEN** governance validates the operation against the extension's operation spec
- **AND** the operation is executed by calling the extension canister
- **AND** the operation must match the extension's topic

#### Scenario: Extension operation spec caching
- **WHEN** extension operation specs are queried
- **THEN** they are served from a cache (get_extension_operation_spec_from_cache)
- **AND** the cache is populated during extension registration

### Requirement: Extension Upgrades

Extensions can be upgraded through governance proposals.

#### Scenario: Upgrade extension
- **WHEN** an UpgradeExtension proposal is adopted
- **THEN** the new WASM hash must be in the allowlist
- **AND** the new version must be higher than the current version
- **AND** the extension canister is upgraded with the new WASM

### Requirement: Extension Cleanup

Failed extension registrations can leave partial state that needs cleanup.

#### Scenario: Clean up failed registration
- **WHEN** an extension registration fails mid-process (e.g., install succeeds but root registration fails)
- **THEN** `CleanUpFailedRegisterExtensionRequest` can be sent to root
- **AND** the partial state is cleaned up

### Requirement: Extension Topic Integration

Extensions are integrated into the topic-based governance system.

#### Scenario: Extension operations listed under topics
- **WHEN** `list_topics` is called
- **THEN** registered extension operations appear under their assigned topic
- **AND** each topic's `extension_operations` field contains the operations from registered extensions

#### Scenario: Extension operations in topic descriptions
- **WHEN** topic descriptions are generated
- **THEN** each topic includes a `RegisteredExtensionOperationSpec` for its associated extensions
- **AND** the spec includes the canister_id and operation details

### Requirement: Treasury Manager Operations

The Treasury Manager extension type supports specific financial operations.

#### Scenario: Deposit operation
- **WHEN** a Treasury Manager deposit operation is executed
- **THEN** tokens are deposited from the SNS treasury into the managed service (e.g., DEX liquidity pool)
- **AND** the operation context includes root, governance, ledger canister IDs, token symbol, and fees

#### Scenario: Withdrawal operation
- **WHEN** a Treasury Manager withdrawal operation is executed
- **THEN** tokens are withdrawn from the managed service back to the SNS treasury

#### Scenario: Allowance management
- **WHEN** a Treasury Manager allowance operation is executed
- **THEN** it manages the approval of token spending by the extension on behalf of the treasury
