# SNS-WASM Canister

**Crates**: `ic-sns-wasm`

The SNS-WASM canister manages the deployment and upgrade lifecycle of Service Nervous Systems (SNS). It stores SNS canister WASMs, manages version upgrade paths, and orchestrates the deployment of new SNS instances when CreateServiceNervousSystem proposals are adopted.

## Requirements

### Requirement: Canister Identity
The SNS-WASM canister is installed at index 10 on the NNS subnet with canister ID `qaa6y-5yaaa-aaaaa-aaafa-cai`.

#### Scenario: SNS-WASM has a fixed canister ID
- **WHEN** the SNS-WASM canister is deployed
- **THEN** it is assigned index 10 on the NNS subnet

### Requirement: WASM Storage
The SNS-WASM canister stores canister WASMs indexed by their SHA-256 hash in stable memory.

#### Scenario: Add WASM
- **WHEN** an AddWasmRequest is processed
- **THEN** the WASM is stored in stable memory
- **AND** the hash-to-index mapping is recorded in wasm_indexes
- **AND** an AddWasmResponse is returned

#### Scenario: Get WASM
- **WHEN** a GetWasmRequest is processed with a hash
- **THEN** the corresponding WASM is returned from stable memory
- **AND** a GetWasmResponse is returned

#### Scenario: Get WASM metadata
- **WHEN** a GetWasmMetadataRequest is processed
- **THEN** the metadata sections of the WASM are returned
- **AND** a GetWasmMetadataResponse is returned

### Requirement: SNS Canister Types
The SNS-WASM canister manages 6 SNS canister types but installs 5 directly (the archive is spawned by the ledger).

#### Scenario: SNS canister types
- **WHEN** an SNS is deployed
- **THEN** SNS_CANISTER_COUNT_AT_INSTALL (5) canisters are directly installed: Governance, Root, Swap, Ledger, Index
- **AND** the Archive canister (6th type) is spawned by the Ledger canister
- **AND** the total SNS_CANISTER_TYPE_COUNT is 6

### Requirement: Deploy New SNS
The SNS-WASM canister deploys a new SNS when requested by governance.

#### Scenario: Deploy new SNS
- **WHEN** a DeployNewSnsRequest is processed
- **THEN** 5 canisters are created on an allowed SNS subnet
- **AND** each canister receives INITIAL_CANISTER_CREATION_CYCLES (3 trillion cycles)
- **AND** the canisters are installed with the appropriate WASM versions
- **AND** the canisters are initialized with the SnsInitPayload configuration
- **AND** a DeployNewSnsResponse is returned with all canister IDs
- **AND** the deployment is recorded in deployed_sns_list

#### Scenario: SNS memory limits applied
- **WHEN** SNS canisters are configured
- **THEN** the governance canister gets DEFAULT_SNS_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT (4 GiB)
- **AND** non-governance canisters get DEFAULT_SNS_NON_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT (3 GiB)

### Requirement: SNS Version Management
The SNS-WASM canister manages the version upgrade path for SNS canisters.

#### Scenario: Get next SNS version
- **WHEN** a GetNextSnsVersionRequest is processed
- **THEN** the next version in the upgrade path for the given SnsVersion is returned

#### Scenario: List upgrade steps
- **WHEN** a ListUpgradeStepsRequest is processed
- **THEN** the full upgrade path from the given version is returned as a list of ListUpgradeStep entries

#### Scenario: Insert upgrade path entries
- **WHEN** an InsertUpgradePathEntriesRequest is processed
- **THEN** new SnsUpgrade entries are added to the version upgrade path
- **AND** an InsertUpgradePathEntriesResponse is returned

### Requirement: SNS Subnet Management
The SNS-WASM canister maintains a list of subnets where SNS canisters can be deployed.

#### Scenario: Update SNS subnet list
- **WHEN** an UpdateSnsSubnetListRequest is processed
- **THEN** subnets are added to or removed from the allowed list
- **AND** an UpdateSnsSubnetListResponse is returned

#### Scenario: Get SNS subnet IDs
- **WHEN** the SNS subnet list is queried
- **THEN** a GetSnsSubnetIdsResponse with all allowed subnet IDs is returned

### Requirement: Deployed SNS Tracking
The SNS-WASM canister tracks all deployed SNS instances.

#### Scenario: List deployed SNSes
- **WHEN** a ListDeployedSnsesRequest is processed
- **THEN** all deployed SNS instances are returned with their canister IDs (root, governance, ledger, swap, index)

#### Scenario: Get deployed SNS by proposal ID
- **WHEN** a GetDeployedSnsByProposalIdRequest is processed
- **THEN** the SNS deployed by that specific proposal is returned
- **AND** a GetDeployedSnsByProposalIdResponse is returned

### Requirement: WASM Provenance
The SNS-WASM canister tracks which proposal added each WASM.

#### Scenario: Get proposal ID that added WASM
- **WHEN** a GetProposalIdThatAddedWasmRequest is processed
- **THEN** the proposal ID that resulted in adding that WASM is returned
- **AND** a GetProposalIdThatAddedWasmResponse is returned

### Requirement: Controller Management
During SNS deployment, canister controllers are set appropriately.

#### Scenario: Controller handoff
- **WHEN** an SNS is deployed
- **THEN** the SNS Root canister is set as the controller of SNS canisters
- **AND** the NNS Root canister (via ChangeCanisterControllersRequest) is used for controller changes
- **AND** only governance and root are authorized callers
