# NNS Handlers (Root and Lifeline)

**Crates**: `ic-nns-handler-root`, `ic-nns-handler-root-interface`, `ic-nns-handler-lifeline-interface`

The NNS Root canister and Lifeline canister are infrastructure canisters that manage canister lifecycle operations on behalf of NNS governance. Root handles canister creation, upgrades, and management. Lifeline provides a recovery mechanism for upgrading the Root canister itself.

## Requirements

### Requirement: Root Canister Identity
The NNS Root canister is installed at index 3 on the NNS subnet with canister ID `r7inp-6aaaa-aaaaa-aaabq-cai`. It has 1 GiB memory allocation.

#### Scenario: Root canister has a fixed canister ID
- **WHEN** the Root canister is deployed
- **THEN** it is assigned index 3 on the NNS subnet

### Requirement: Lifeline Canister Identity
The Lifeline canister is installed at index 5 on the NNS subnet with canister ID `rno2w-sqaaa-aaaaa-aaacq-cai`. It has 1 GiB memory allocation.

#### Scenario: Lifeline canister has a fixed canister ID
- **WHEN** the Lifeline canister is deployed
- **THEN** it is assigned index 5 on the NNS subnet

### Requirement: Add NNS Canister
The Root canister can create and install new NNS canisters via the registry.

#### Scenario: Add NNS canister
- **WHEN** do_add_nns_canister is called with an AddCanisterRequest
- **THEN** the canister name is reserved in the NNS canister records registry
- **AND** a new canister is created and installed with the specified WASM
- **AND** the canister ID is recorded in the registry under the name
- **AND** if the name is already taken, the operation fails with an assertion error

### Requirement: Canister Upgrade via Root
The Root canister proxies canister upgrade operations from governance proposals.

#### Scenario: Proxied canister management
- **WHEN** the Root canister receives a canister management request
- **THEN** it tracks the proxied call in PROXIED_CANISTER_CALLS_TRACKER
- **AND** it reports in-flight call counts and max age as Prometheus metrics
- **AND** the caller and callee are identified by their principal names

### Requirement: Stop or Start Canisters
The Root canister can stop or start other NNS canisters.

#### Scenario: Stop canister
- **WHEN** a StopOrStartCanisterRequest with action Stop is received
- **THEN** the target canister is stopped via the management canister

#### Scenario: Start canister
- **WHEN** a StopOrStartCanisterRequest with action Start is received
- **THEN** the target canister is started via the management canister

### Requirement: Change Canister Controllers
The Root canister can change the controllers of other NNS canisters.

#### Scenario: Change controllers
- **WHEN** a ChangeCanisterControllersRequest is received
- **THEN** the controllers of the target canister are updated
- **AND** a ChangeCanisterControllersResponse is returned

### Requirement: Update Canister Settings
The Root canister can update settings of other NNS canisters.

#### Scenario: Update settings
- **WHEN** an UpdateCanisterSettingsRequest is received
- **THEN** the settings of the target canister are updated
- **AND** an UpdateCanisterSettingsResponse is returned
- **AND** errors are reported via UpdateCanisterSettingsError

### Requirement: Root Proposals
The Root canister supports governance proposals for managing NNS infrastructure.

#### Scenario: Root proposal execution
- **WHEN** a governance proposal targeting NNS infrastructure is adopted
- **THEN** the Root canister executes the corresponding operation
- **AND** results are reported back to governance

### Requirement: Proxied Call Tracking
The Root canister tracks all proxied canister calls for monitoring.

#### Scenario: In-flight call metrics
- **WHEN** metrics are queried
- **THEN** nns_root_in_flight_proxied_canister_call_max_age_seconds reports the age of the oldest in-flight call per method/caller/callee
- **AND** nns_root_in_flight_proxied_canister_call_count reports the number of in-flight calls per method/caller/callee

### Requirement: Principal Name Resolution
The Root canister resolves principal IDs to human-readable NNS canister names.

#### Scenario: Known canister name resolution
- **WHEN** a principal ID matches a known NNS canister
- **THEN** the human-readable name is returned (e.g., "governance", "ledger", "registry")
- **AND** the mapping covers all core NNS canisters

### Requirement: Lifeline Canister Purpose
The Lifeline canister exists as a recovery mechanism to upgrade the Root canister.

#### Scenario: Lifeline WASM embedded
- **WHEN** the lifeline implementation crate is compiled
- **THEN** the lifeline canister WASM is embedded as a constant (LIFELINE_CANISTER_WASM)
- **AND** this allows other canisters to deploy or verify the lifeline canister

### Requirement: Registry Integration
The Root canister interacts with the registry for NNS canister record management.

#### Scenario: Registry mutations
- **WHEN** the Root canister updates the registry
- **THEN** it uses RegistryMutation with appropriate mutation types (Insert, Update)
- **AND** it uses Preconditions to ensure consistency (optimistic concurrency)
- **AND** NnsCanisterRecords store the mapping from canister name to canister ID
