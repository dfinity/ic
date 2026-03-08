# SNS Root Canister

**Crates**: `ic-sns-root`

The SNS Root canister is the administrative hub of an SNS. It tracks all canisters in the SNS, manages dapp canister registration and settings, provides status summaries, and handles extension canister registration. Root serves as the controller of all SNS-managed canisters (governance, ledger, swap, dapps, archives, index, and extensions).

## Requirements

### Requirement: Canister Registry

The root canister maintains a registry of all canisters in the SNS ecosystem.

#### Scenario: List SNS canisters
- **WHEN** `list_sns_canisters` is called
- **THEN** it returns the principal IDs of: root, governance, ledger, swap, index, dapps, archives, and extensions

#### Scenario: Required canister IDs
- **WHEN** the root canister state is queried for governance, ledger, swap, or index canister IDs
- **AND** any of these fields is None
- **THEN** the accessor panics with "Invalid root canister state: missing {field}"

### Requirement: Canister Status Summary

The root canister can provide detailed status summaries of all SNS canisters.

#### Scenario: Full canister summary
- **WHEN** `get_sns_canisters_summary` is called
- **THEN** it returns a `GetSnsCanistersSummaryResponse` containing:
  - Root canister status summary
  - Governance canister status summary
  - Ledger canister status summary
  - Swap canister status summary
  - Index canister status summary
  - Dapp canister status summaries (one per registered dapp)
  - Archive canister status summaries (one per archive)
- **AND** all status queries are made in parallel using `join!`

#### Scenario: Canister list update during summary
- **WHEN** `get_sns_canisters_summary` is called with `update_canister_list` set to true
- **AND** the caller is SNS Governance
- **THEN** the root canister first polls the ledger for new archive canisters
- **AND** then returns the updated summary

#### Scenario: Summary iteration
- **WHEN** the summary response is iterated
- **THEN** it yields canister summaries paired with their `SnsCanisterType` (Root, Governance, Ledger, Swap, Index, Dapp, Archive)

### Requirement: Dapp Canister Registration

The root canister manages registration of dapp canisters that are controlled by the SNS.

#### Scenario: Register dapp canisters
- **WHEN** `register_dapp_canisters` is called with a non-empty list of canister IDs
- **THEN** each canister must be controlled by the root canister
- **AND** each canister must not be one of the distinguished SNS canisters (root, governance, ledger, swap, index, archives)
- **AND** any controllers on the canister besides root are removed
- **AND** duplicate canister IDs in the request are deduplicated

#### Scenario: Empty registration request rejected
- **WHEN** `register_dapp_canisters` is called with an empty canister_ids list
- **THEN** the call panics with "canister_ids field must not be empty"

#### Scenario: Registration limit
- **WHEN** the total number of registered dapp and extension canisters reaches 100 (DAPP_AND_EXTENSION_CANISTER_REGISTRATION_LIMIT)
- **THEN** no additional canisters can be registered until some are deregistered

#### Scenario: Registration failure handling
- **WHEN** some canister registrations fail (e.g., canister not controlled by root)
- **THEN** the successful registrations still complete
- **AND** errors are collected and reported as a batch failure with details per canister

### Requirement: Dapp Controller Management

The root canister can set or restore controllers of registered dapp canisters.

#### Scenario: Set dapp controllers
- **WHEN** `set_dapp_controllers` is called
- **THEN** the controllers of all specified dapp canisters are updated
- **AND** only registered dapp canisters can have their controllers changed

#### Scenario: Dapp canister settings management
- **WHEN** `ManageDappCanisterSettingsRequest` is processed
- **THEN** the request is validated against the set of registered dapp canister IDs
- **AND** settings (compute_allocation, memory_allocation, freezing_threshold, reserved_cycles_limit, log_visibility, wasm_memory_limit, wasm_memory_threshold) are applied
- **AND** unregistered canister IDs in the request cause a validation error
- **AND** the controllers field in settings is always None (cannot be changed through this path)

### Requirement: Extension Canister Registration

The root canister supports registering extension canisters that augment SNS functionality.

#### Scenario: Register extension canister
- **WHEN** `register_extension` is called with a canister ID
- **THEN** the canister must not be one of the distinguished SNS framework canisters
- **AND** the canister must not already be registered as a dapp canister
- **AND** the canister must not already be registered as an extension (idempotent -- returns Ok)
- **AND** the total dapp + extension count must not exceed 100

#### Scenario: Extension controller requirements
- **WHEN** an extension canister is registered
- **THEN** its controllers are set to exactly Root and Governance (both required)
- **AND** all other controllers are removed
- **AND** the controller configuration is verified after the update

#### Scenario: Extension controller verification failure
- **WHEN** the extension's controllers do not match the expected set after update_settings
- **THEN** the registration is rejected with an error describing the actual controllers

#### Scenario: Extension listed in canister response
- **WHEN** `list_sns_canisters` is called after extension registration
- **THEN** the extension canister IDs appear in the `extensions` field of the response

### Requirement: Archive Canister Discovery

The root canister automatically discovers ledger archive canisters.

#### Scenario: Poll for new archive canisters
- **WHEN** `poll_for_new_archive_canisters` is called
- **THEN** the root canister queries the ledger canister for its archive canisters
- **AND** any newly discovered archive canisters are added to `archive_canister_ids`

### Requirement: Clean Up Failed Extension Registration

Extension registration can fail mid-process, leaving partial state that needs cleanup.

#### Scenario: Clean up failed registration
- **WHEN** `CleanUpFailedRegisterExtensionRequest` is processed
- **THEN** any partial extension registration state is cleaned up
- **AND** the canister's controllers may need to be reverted
