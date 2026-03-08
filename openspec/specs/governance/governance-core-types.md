# Governance Core Types and Utilities Specification

This specification covers shared nervous system crates that provide foundational types, constants, proto definitions, runtime abstractions, concurrency locks, inter-canister client wrappers, agent utilities, Neurons Fund calculations, string utilities, NNS-specific types, well-known constants, and Cycles Minting Canister operations used across the NNS and SNS governance systems.

---

## Requirements

### Requirement: Nervous System Common Shared Types (ic-nervous-system-common)

The `ic-nervous-system-common` crate (`rs/nervous_system/common`) provides shared types, constants, error types, and utility functions used across both NNS and SNS governance.

#### Scenario: E8 denomination constant
- **WHEN** token amounts are expressed in e8s
- **THEN** the constant E8 equals 100,000,000 (10^8)
- **AND** it is used as the denominations-per-token value for ICP and SNS tokens

#### Scenario: Time duration constants
- **WHEN** governance logic references time durations
- **THEN** ONE_HOUR_SECONDS equals 3,600
- **AND** ONE_DAY_SECONDS equals 86,400
- **AND** ONE_YEAR_SECONDS equals the average of a 4-year cycle including a leap year (365.25 days)
- **AND** ONE_MONTH_SECONDS equals ONE_YEAR_SECONDS / 12

#### Scenario: Default transfer fee
- **WHEN** a transfer fee is needed and no override is provided
- **THEN** DEFAULT_TRANSFER_FEE is 10,000 e8s (0.0001 ICP)

#### Scenario: SNS creation fee
- **WHEN** an SNS is created via SNS-W
- **THEN** SNS_CREATION_FEE is 180 trillion cycles (180 * 10^12)

#### Scenario: Maximum neurons for direct swap participants
- **WHEN** an SNS swap creates neurons for direct participants
- **THEN** MAX_NEURONS_FOR_DIRECT_PARTICIPANTS is 100,000
- **AND** this must not exceed NervousSystemParameters::MAX_NUMBER_OF_NEURONS_CEILING

#### Scenario: Nanoseconds per second constant
- **WHEN** timestamp conversions are performed
- **THEN** NANO_SECONDS_PER_SECOND is 1,000,000,000

#### Scenario: NervousSystemError type
- **WHEN** a governance operation encounters an error
- **THEN** NervousSystemError wraps an error_message string
- **AND** it implements Display, Debug, and From<NervousSystemError> for String
- **AND** new() creates an empty error and new_with_message creates one with a message

#### Scenario: denominations_to_tokens conversion
- **WHEN** denominations_to_tokens is called with a denomination count and denominations_per_token
- **THEN** it returns Some(Decimal) representing the token amount via checked division
- **AND** it returns None if denominations_per_token is 0

#### Scenario: i2d integer to Decimal conversion
- **WHEN** i2d is called with a u64 value
- **THEN** it converts to i64 (panicking if it does not fit) and returns a Decimal with scale 0

#### Scenario: ExplosiveTokens test helper
- **WHEN** ExplosiveTokens is used in tests
- **THEN** it wraps Tokens and provides panicking arithmetic (add_or_die, sub_or_die, mul_or_die, div_or_die)
- **AND** it implements Add, Sub, Mul<u64>, Div<u64>, and AddAssign operators that panic on overflow/underflow
- **AND** it supports from_e8s, into_e8s, and get_e8s conversions
- **AND** mul_div_or_die performs (value * mul / div) using u128 intermediates to avoid overflow

#### Scenario: Permyriad constant
- **WHEN** basis point calculations are performed
- **THEN** UNITS_PER_PERMYRIAD equals the inverse of 10,000 (i.e. 10^-4)

#### Scenario: Wide range of u64 values for testing
- **WHEN** comprehensive u64 test values are needed
- **THEN** WIDE_RANGE_OF_U64_VALUES contains 0, all powers of 2, u64::MAX, and perturbations around these values

#### Scenario: NNS Dapp backend canister ID
- **WHEN** the NNS Dapp backend canister is referenced
- **THEN** NNS_DAPP_BACKEND_CANISTER_ID is "qoctq-giaaa-aaaaa-aaaea-cai"

#### Scenario: HTTP log serving (serve_logs_v2)
- **WHEN** the canister receives an HTTP request for logs at the logs endpoint
- **THEN** it parses query parameters: severity (Info or Error, default Info) and time (nanoseconds since UNIX epoch, default 0)
- **AND** it selects logs of the requested severity or greater
- **AND** it merges and interleaves log entries from info and error LogBuffer sources by timestamp
- **AND** entries with timestamp <= the time parameter are skipped
- **AND** the response size is capped at MAX_LOGS_RESPONSE_SIZE (1 MiB)
- **AND** the JSON response contains an entries array with severity, timestamp, file, line, and message fields

#### Scenario: HTTP log serving (serve_logs, deprecated)
- **WHEN** the deprecated serve_logs function is called
- **THEN** it exports all entries from a single GlobalBuffer as plain text
- **AND** each line contains timestamp, file:line, and message

#### Scenario: HTTP metrics serving
- **WHEN** serve_metrics is called with a metrics encoder callback
- **THEN** it creates a MetricsEncoder with the current timestamp in milliseconds
- **AND** it returns the encoded metrics with Content-Type "text/plain; version=0.0.4" and Cache-Control "no-store"
- **AND** it returns a server error if encoding fails

#### Scenario: Memory size utilities
- **WHEN** total_memory_size_bytes is called on wasm32
- **THEN** it returns the number of WASM pages multiplied by WASM_PAGE_SIZE_BYTES (65,536)
- **AND** stable_memory_size_bytes returns stable memory pages times the page size
- **AND** on non-wasm32 targets, both return 0

#### Scenario: SHA-256 hash to hex string
- **WHEN** hash_to_hex_string is called with a byte slice
- **THEN** it returns a lowercase hexadecimal string representation

#### Scenario: Assertion macros
- **WHEN** assert_is_ok! is called with a Result
- **THEN** it panics with a descriptive message if the result is Err
- **AND** assert_is_err! panics with a descriptive message if the result is Ok

#### Scenario: Obsolete field helper
- **WHEN** obsolete_string_field is called with a field name and optional replacement
- **THEN** it returns a message indicating the field is obsolete
- **AND** if a replacement is provided, the message suggests using it instead

### Requirement: Neuron Subaccount Computation (ic-nervous-system-common ledger module)

The ledger submodule of `ic-nervous-system-common` (`rs/nervous_system/common/src/ledger.rs`) provides deterministic subaccount computation for neuron-related ledger operations.

#### Scenario: Neuron staking subaccount
- **WHEN** compute_neuron_staking_subaccount_bytes is called with a controller PrincipalId and nonce
- **THEN** it computes a SHA-256 hash of the domain "neuron-stake" (length-prefixed), the controller bytes, and the nonce in big-endian
- **AND** the result is a 32-byte subaccount identifier
- **AND** this must be kept in sync with the Nervous System UI equivalent

#### Scenario: Distribution subaccount
- **WHEN** compute_distribution_subaccount_bytes is called with a PrincipalId and nonce
- **THEN** it uses the domain "token-distribution" for the SHA-256 computation

#### Scenario: Neuron disburse subaccount
- **WHEN** compute_neuron_disburse_subaccount_bytes is called
- **THEN** it uses the domain "neuron-split" (historical naming that cannot be changed)

#### Scenario: Neuron split subaccount
- **WHEN** compute_neuron_split_subaccount_bytes is called
- **THEN** it uses the domain "split-neuron" (different from disburse to avoid collision)

#### Scenario: Domain subaccount computation structure
- **WHEN** any domain subaccount is computed
- **THEN** the SHA-256 input is: [domain_length_byte, domain_bytes, controller_bytes, nonce_big_endian_bytes]

### Requirement: Binary Search Utility (ic-nervous-system-common binary_search module)

The binary_search submodule (`rs/nervous_system/common/src/binary_search.rs`) provides generic binary search for monotonic predicates over ordered types.

#### Scenario: Mid trait for midpoint computation
- **WHEN** mid is called on two values of a type implementing Add, Sub, Div, Ord, Copy, and From<u8>
- **THEN** it returns the value halfway between the two, rounded toward negative infinity
- **AND** it returns None if there is no integer value strictly between the two values

#### Scenario: Binary search for predicate transition
- **WHEN** search is called with a monotonic predicate and a range [l, r]
- **THEN** if the predicate transitions from false to true within the range, it returns (Some(highest_false), Some(lowest_true))
- **AND** if the predicate is always true, it returns (None, Some(l))
- **AND** if the predicate is always false, it returns (Some(r), None)
- **AND** if the predicate is not monotonic, it may return (None, None) or an incorrect result

#### Scenario: Fallible binary search
- **WHEN** search_with_fallible_predicate is called with a predicate returning Result
- **THEN** it behaves like search but propagates any Err from the predicate immediately

### Requirement: Nervous System Proto Types (ic-nervous-system-proto)

The `ic-nervous-system-proto` crate (`rs/nervous_system/proto`) defines protobuf message types and their Rust conversions for use across nervous system canisters.

#### Scenario: GlobalTimeOfDay construction
- **WHEN** GlobalTimeOfDay::from_hh_mm is called with hours and minutes
- **THEN** it returns Ok with seconds_after_utc_midnight = hours * 3600 + minutes * 60
- **AND** it returns Err if hours >= 23 or minutes >= 60

#### Scenario: GlobalTimeOfDay display
- **WHEN** to_hh_mm is called on a GlobalTimeOfDay
- **THEN** it returns Some((hours, minutes)) computed from seconds_after_utc_midnight
- **AND** it returns None if seconds_after_utc_midnight is None

#### Scenario: Duration conversion
- **WHEN** a Duration proto is created via from_secs
- **THEN** it wraps the seconds value in an Option
- **AND** TryFrom<Duration> for std::time::Duration extracts the seconds or returns an error if blank
- **AND** From<std::time::Duration> for Duration wraps the seconds value

#### Scenario: Tokens proto type
- **WHEN** Tokens::from_tokens is called with a whole-token amount
- **THEN** it stores e8s as tokens * 10^8 (saturating multiplication)
- **AND** Tokens::from_e8s wraps the raw e8s value
- **AND** checked_add and checked_sub return None on overflow/underflow or if either operand is None

#### Scenario: Percentage proto type
- **WHEN** Percentage::from_percentage is called with a float
- **THEN** it stores basis_points as (percentage * 100).round()
- **AND** it panics if the percentage is negative
- **AND** Percentage::from_basis_points directly stores the basis_points value (const fn)
- **AND** Display formats as "X.YY%" using basis_points / 100 and basis_points % 100
- **AND** Display shows "[unspecified]" if basis_points is None

#### Scenario: Decimal proto conversion
- **WHEN** a Rust Decimal is converted to DecimalPb
- **THEN** it stores the human_readable string representation
- **AND** TryFrom<DecimalPb> for Decimal parses the string back, rejecting strings longer than 40 characters

#### Scenario: Canister proto helper
- **WHEN** Canister::new is called with a PrincipalId
- **THEN** it creates a Canister proto with id set to Some(principal_id)

#### Scenario: Principals proto conversion
- **WHEN** a Vec<PrincipalId> is converted to Principals
- **THEN** it stores the vector directly
- **AND** From<Principals> for Vec<PrincipalId> extracts the principals field

### Requirement: Nervous System Root Canister Management (ic-nervous-system-root)

The `ic-nervous-system-root` crate (`rs/nervous_system/root`) provides canister lifecycle management operations used by NNS and SNS root canisters, including code installation, canister snapshots, and start/stop operations.

#### Scenario: ChangeCanisterRequest structure
- **WHEN** a ChangeCanisterRequest is constructed
- **THEN** it includes: stop_before_installing (bool), mode (CanisterInstallMode), canister_id, wasm_module (bytes), optional chunked_canister_wasm, and arg (bytes)
- **AND** the builder pattern supports with_wasm, with_chunked_wasm, with_arg, and with_mode

#### Scenario: Change canister with stop
- **WHEN** a ChangeCanisterRequest has stop_before_installing = true
- **THEN** the target canister is stopped before install_code is called
- **AND** the canister is started again after installation completes
- **AND** the canister is locked during the operation via exclusively_stop_and_start_canister

#### Scenario: Change canister without stop
- **WHEN** a ChangeCanisterRequest has stop_before_installing = false
- **THEN** install_code is called directly without stopping the canister first
- **AND** this is appropriate for canisters that do not emit inter-canister calls (e.g. Registry)

#### Scenario: Concurrent change canister rejection
- **WHEN** change_canister is called for a canister that already has a lock held
- **THEN** it returns an error indicating another operation is in progress
- **AND** the error message includes the canister ID

#### Scenario: Chunked WASM support
- **WHEN** a WASM exceeds the 2 MiB ingress limit
- **THEN** ChunkedCanisterWasm is used with wasm_module_hash, store_canister_id, and chunk_hashes_list
- **AND** the store canister must be on the same subnet as the target canister
- **AND** Root must be a controller of both canisters
- **AND** install_chunked_code is called on the management canister instead of install_code

#### Scenario: AddCanisterRequest structure
- **WHEN** a new canister is added via Root
- **THEN** AddCanisterRequest includes: name (unique string), wasm_module, arg, compute_allocation, memory_allocation, and initial_cycles

#### Scenario: StopOrStartCanisterRequest
- **WHEN** a canister needs to be stopped or started
- **THEN** StopOrStartCanisterRequest contains canister_id and action (CanisterAction::Stop or CanisterAction::Start)

#### Scenario: Start canister
- **WHEN** start_canister is called with a Runtime type parameter and canister ID
- **THEN** it calls the management canister's start_canister method via call_with_cleanup

#### Scenario: Stop canister
- **WHEN** stop_canister is called and succeeds
- **THEN** the canister has reached the "Stopped" state
- **AND** if stop_canister times out, the caller should call start_canister to avoid leaving it stopped

#### Scenario: Debug output for sensitive fields
- **WHEN** ChangeCanisterRequest or AddCanisterRequest is formatted for Debug/Display
- **THEN** the wasm_module and arg fields are shown as SHA-256 hashes, not raw bytes

#### Scenario: Take canister snapshot
- **WHEN** the root canister takes a snapshot of a managed canister
- **THEN** it delegates to the management canister's take_canister_snapshot method

#### Scenario: Load canister snapshot
- **WHEN** the root canister loads a snapshot into a managed canister
- **THEN** it exclusively stops and starts the canister during the operation
- **AND** it delegates to the management canister's load_canister_snapshot method

### Requirement: Nervous System Runtime Abstraction (ic-nervous-system-runtime)

The `ic-nervous-system-runtime` crate (`rs/nervous_system/runtime`) provides an async trait abstracting the canister execution environment, enabling governance code to run in both production and test contexts.

#### Scenario: Runtime trait definition
- **WHEN** governance code needs to call another canister
- **THEN** it uses the Runtime trait which provides:
  - call_without_cleanup: invokes a Candid method without cleanup on trap
  - call_with_cleanup: invokes a Candid method with cleanup on trap
  - call_bytes_with_cleanup: invokes a method with raw bytes and cleanup on trap
  - spawn_future: spawns an async future
  - canister_version: returns the canister version

#### Scenario: DfnRuntime implementation
- **WHEN** the DfnRuntime is used (production dfn_core backend)
- **THEN** call_without_cleanup delegates to dfn_core::api::call
- **AND** call_with_cleanup delegates to dfn_core::api::call_with_cleanup
- **AND** call_bytes_with_cleanup delegates to dfn_core::api::call_bytes_with_cleanup with zero Funds
- **AND** spawn_future delegates to dfn_core::api::futures::spawn
- **AND** error codes are unwrapped with unwrap_or_default

#### Scenario: CdkRuntime implementation
- **WHEN** the CdkRuntime is used (ic_cdk backend)
- **THEN** call_without_cleanup is unimplemented (no non-cleanup variant in ic_cdk)
- **AND** call_with_cleanup delegates to ic_cdk::api::call::call, converting PrincipalId to Principal
- **AND** call_bytes_with_cleanup delegates to ic_cdk::api::call::call_raw with 0 cycles
- **AND** spawn_future delegates to ic_cdk::spawn

#### Scenario: Runtime parametrization for testing
- **WHEN** unit tests need to mock inter-canister calls
- **THEN** the Runtime trait can be implemented with custom test behavior
- **AND** this avoids dependency on the actual IC execution environment

### Requirement: Nervous System Lock (ic-nervous-system-lock)

The `ic-nervous-system-lock` crate (`rs/nervous_system/lock`) provides non-blocking resource locking for canister operations to prevent concurrent access to shared resources.

#### Scenario: Acquire a simple resource lock
- **WHEN** acquire is called with a thread-local RefCell<Option<ResourceFlag>> that is None
- **THEN** it sets the flag to Some(new_resource_flag)
- **AND** it returns Ok with a ResourceGuard
- **AND** when the ResourceGuard is dropped, the flag is reset to None

#### Scenario: Fail to acquire an already-held lock
- **WHEN** acquire is called and the current_resource_flag is already Some(existing_flag)
- **THEN** it returns Err(existing_flag) immediately
- **AND** it does not block or wait for release

#### Scenario: Acquire a named resource lock from a map
- **WHEN** acquire_for is called with a thread-local RefCell<BTreeMap<K, V>>
- **THEN** if the key is not present, it inserts (key, value) and returns Ok with a NamedResourceGuard
- **AND** when the NamedResourceGuard is dropped, the key is removed from the map

#### Scenario: Fail to acquire a named lock for an existing key
- **WHEN** acquire_for is called and the key already exists in the map
- **THEN** it returns Err with a clone of the existing value immediately
- **AND** no modification is made to the map

#### Scenario: ResourceGuard type constraints
- **WHEN** a ResourceGuard is created
- **THEN** the ResourceFlag type must implement Debug + Copy + 'static
- **AND** the guard uses thread-local storage (LocalKey) for single-threaded canister safety

#### Scenario: NamedResourceGuard type constraints
- **WHEN** a NamedResourceGuard is created
- **THEN** the key type K must implement Ord + Clone + 'static
- **AND** the value type V must implement Clone + 'static

### Requirement: Nervous System Clients (ic-nervous-system-clients)

The `ic-nervous-system-clients` crate (`rs/nervous_system/clients`) provides typed client abstractions for inter-canister communication with IC management and ledger canisters.

#### Scenario: Client modules available
- **WHEN** the clients library is imported
- **THEN** it exposes modules: canister_id_record, canister_metadata, canister_status, delete_canister, ledger_client, load_canister_snapshot, management_canister_client, stop_canister, take_canister_snapshot, update_settings
- **AND** it re-exports the Request type from the request module

#### Scenario: ManagementCanisterClient trait
- **WHEN** governance code interacts with the IC management canister (IC_00)
- **THEN** ManagementCanisterClient provides async methods for: canister_status, update_settings, canister_metadata, canister_version, stop_canister, delete_canister, take_canister_snapshot, and load_canister_snapshot
- **AND** the trait allows injection of mock clients for unit testing

#### Scenario: ManagementCanisterClientImpl
- **WHEN** ManagementCanisterClientImpl is instantiated with a Runtime type and optional ProxiedCanisterCallsTracker
- **THEN** it implements ManagementCanisterClient by delegating to the crate's typed functions
- **AND** it tracks proxied calls if a tracker is provided

#### Scenario: LimitedOutstandingCallsManagementCanisterClient
- **WHEN** management canister calls need rate limiting
- **THEN** LimitedOutstandingCallsManagementCanisterClient wraps another ManagementCanisterClient
- **AND** it decrements an available_slot_count before each call and increments it (via SlotLoan drop) after
- **AND** if available_slot_count is 0, it returns Err with SysTransient reject code
- **AND** VIP callers (is_caller_vip = true) bypass the slot limit

#### Scenario: MockManagementCanisterClient for testing
- **WHEN** unit tests need a mock management canister client
- **THEN** MockManagementCanisterClient accepts a queue of pre-configured replies
- **AND** it records all calls for later assertion
- **AND** it panics on drop if not all replies were consumed

#### Scenario: CanisterStatusType enumeration
- **WHEN** canister status is queried
- **THEN** CanisterStatusType can be Running, Stopping, or Stopped
- **AND** the serde rename attributes match the IC management canister Candid interface

#### Scenario: CanisterStatusResult types
- **WHEN** canister status is returned from the management canister
- **THEN** CanisterStatusResultFromManagementCanister contains all required fields from the management canister response
- **AND** CanisterStatusResult is a partial copy with optional fields for use by NNS/SNS Root
- **AND** CanisterStatusResultV2 provides a versioned result with DefiniteCanisterSettingsArgs
- **AND** From conversions between these types wrap required fields in Option

#### Scenario: DefiniteCanisterSettings
- **WHEN** canister settings are returned
- **THEN** they include: controllers, compute_allocation, memory_allocation, freezing_threshold, reserved_cycles_limit, wasm_memory_limit, log_visibility, and wasm_memory_threshold

#### Scenario: LedgerCanister client
- **WHEN** a LedgerCanister is created with a ledger_canister_id
- **THEN** it wraps an ICRC1Client with CdkRuntime
- **AND** it implements the ICRC1Ledger trait for transfer_funds, total_supply, account_balance, icrc2_approve, and icrc3_get_blocks
- **AND** transfer_funds converts amount_e8s and fee_e8s to Nat and calls icrc1_transfer
- **AND** errors are wrapped in NervousSystemError with descriptive messages

### Requirement: Nervous System Agent (ic-nervous-system-agent)

The `ic-nervous-system-agent` crate (`rs/nervous_system/agent`) provides an abstraction for interacting with governance canisters from external environments (tests, CLI tools, PocketIC).

#### Scenario: CallCanisters trait
- **WHEN** external code needs to call governance canisters
- **THEN** it uses the CallCanisters trait which provides: caller(), call(canister_id, request), and canister_info(canister_id)
- **AND** the trait is sealed (via the sealed::Sealed supertrait) to prevent external implementations
- **AND** the Error type must implement Display + Send + std::error::Error + 'static

#### Scenario: CanisterInfo result
- **WHEN** canister_info is called on a canister
- **THEN** it returns a CanisterInfo struct with module_hash (Option<Vec<u8>>) and controllers (BTreeSet<Principal>)

#### Scenario: Request trait for agent
- **WHEN** an agent request type is defined
- **THEN** it implements the agent Request trait with: method() returning the method name, update() indicating query vs. update, payload() returning Candid-encoded bytes, and optional effective_canister_id()
- **AND** it has an associated Response type that must implement CandidType + DeserializeOwned + Send

#### Scenario: NNS submodules
- **WHEN** the nns module is used
- **THEN** it provides submodules for: cmc, governance, ledger, node_rewards, registry, sns_wasm

#### Scenario: SNS struct and operations
- **WHEN** the sns module is used
- **THEN** the Sns struct aggregates canister references for: ledger, governance, index, swap, root, and archive (Vec)
- **AND** remaining_upgrade_steps queries the current deployed version from governance and lists upgrade steps from SNS-WASM

#### Scenario: AgentFor trait
- **WHEN** agent_for is called with a Principal
- **THEN** it returns a CallCanisters implementation scoped to that principal
- **AND** AgentFor is also sealed to prevent external implementations

#### Scenario: ProgressNetwork trait
- **WHEN** test code needs to advance network time
- **THEN** ProgressNetwork::progress(duration) simulates the passage of time
- **AND** this is used for scenarios like waiting for proposal adoption or swap opening
- **AND** ProgressNetwork is also sealed

#### Scenario: CallCanistersWithStoppedCanisterError trait
- **WHEN** a call to a canister might fail because the canister is stopped
- **THEN** is_canister_stopped_error checks if the error indicates a stopped canister
- **AND** this enables retry logic or graceful handling of stopped-canister scenarios

#### Scenario: Multiple CallCanisters implementations
- **WHEN** the agent crate is compiled
- **THEN** it provides implementations: agent_impl (using ic-agent), pocketic_impl (using PocketIC), and optionally state_machine_impl (behind the "test" feature flag)
- **AND** a mock module is provided for testing

### Requirement: Neurons Fund Matched Funding (ic-neurons-fund)

The `ic-neurons-fund` crate (`rs/nervous_system/neurons_fund`) implements the mathematical model for computing how much NNS Neurons Fund maturity participates in SNS token swaps as a function of direct participation (Matched Funding).

#### Scenario: u64 to Decimal conversion
- **WHEN** u64_to_dec is called with a u64 value
- **THEN** it returns Ok(Decimal) representing that value
- **AND** it returns Err if the conversion fails (should not happen for u64)

#### Scenario: Decimal to u64 conversion
- **WHEN** dec_to_u64 is called with a Decimal value
- **THEN** it rounds to the nearest even integer and returns the u64 value
- **AND** it returns Err if the value is negative or exceeds u64::MAX

#### Scenario: ICP rescaling
- **WHEN** rescale_to_icp is called with an e8s amount
- **THEN** it returns the amount in ICP as a Decimal (multiplied by 0.00000001)
- **AND** rescale_to_icp_e8s converts back from ICP Decimal to u64 e8s

#### Scenario: MatchingFunction trait
- **WHEN** a MatchingFunction is applied to a direct participation amount in e8s
- **THEN** apply returns the matched amount in ICP as a Decimal
- **AND** apply_and_rescale_to_icp_e8s returns the matched amount in e8s as u64

#### Scenario: InvertibleFunction trait
- **WHEN** a function implementing MatchingFunction is used
- **THEN** InvertibleFunction is automatically implemented (blanket impl for all MatchingFunction)
- **AND** invert uses binary search to find the argument x where f(x) is closest to target_y
- **AND** max_argument_icp_e8s finds the least argument at which the function reaches its supremum
- **AND** plot generates (x, f(x)) sample pairs for debugging

#### Scenario: InvertError variants
- **WHEN** inversion of a matching function fails
- **THEN** InvertError can be: ValueIsNegative, MaxArgumentValueError, FunctionApplicationError, MonotonicityAssumptionViolation, InvertValueAboveU64Range, or InvertValueBelowU64Range

#### Scenario: PolynomialMatchingFunction construction
- **WHEN** PolynomialMatchingFunction::new is called with total maturity equivalent, participation limits, and enable_logging
- **THEN** cap is min(global_cap, 0.1 * total_maturity_equivalent) in ICP
- **AND** t_4 = 2 * cap (200% of cap)
- **AND** t_1, t_2, t_3 are set from the participation limits (contribution_threshold, one_third_milestone, full_participation_milestone)
- **AND** polynomial coefficients for f_1, f_2, f_3 are precomputed and cached

#### Scenario: PolynomialMatchingFunction piecewise evaluation
- **WHEN** PolynomialMatchingFunction::apply is called with x_icp_e8s
- **THEN** for x < t_1, it returns 0
- **AND** for t_1 <= x < t_2, it evaluates f_1 (capped at 0.5 * x and cap)
- **AND** for t_2 <= x < t_3, it evaluates f_2 (capped at x and cap)
- **AND** for t_3 <= x < t_4, it evaluates f_3 (capped at x and cap)
- **AND** for x >= t_4, it returns cap

#### Scenario: PolynomialMatchingFunction serialization
- **WHEN** a PolynomialMatchingFunction is serialized
- **THEN** it serializes persistent_data (t_1, t_2, t_3, t_4, cap) as JSON
- **AND** MAX_MATCHING_FUNCTION_SERIALIZED_REPRESENTATION_SIZE_BYTES is 1,000
- **AND** deserialization via from_repr parses JSON and recomputes the polynomial cache

#### Scenario: ValidatedLinearScalingCoefficient
- **WHEN** scaling coefficients are validated for Neurons Fund participation
- **THEN** each coefficient has: from_direct_participation_icp_e8s, to_direct_participation_icp_e8s, slope_numerator, slope_denominator, and intercept_icp_e8s
- **AND** the default covers [0, u64::MAX) with slope 1/1 and intercept 0

#### Scenario: ValidatedNeuronsFundParticipationConstraints
- **WHEN** Neurons Fund participation constraints are validated
- **THEN** they include: min_direct_participation_threshold_icp_e8s, max_neurons_fund_participation_icp_e8s, coefficient_intervals, and ideal_matched_participation_function

#### Scenario: MatchedParticipationFunction evaluation
- **WHEN** MatchedParticipationFunction::apply is called with direct_participation_icp_e8s
- **THEN** it finds the matching coefficient interval using binary search via HalfOpenInterval
- **AND** it computes ideal_icp from the ideal_matched_participation_function
- **AND** it applies the linear scaling: effective = min(hard_cap, intercept + (slope_num/slope_denom) * ideal)
- **AND** it rescales the result to e8s

#### Scenario: HalfOpenInterval trait
- **WHEN** intervals are searched for a value
- **THEN** HalfOpenInterval::contains checks from <= x < to
- **AND** HalfOpenInterval::find uses binary search over a sorted slice of intervals

#### Scenario: Maximum linear scaling coefficient count
- **WHEN** linear scaling coefficients are provided
- **THEN** MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN is 100,000

### Requirement: Nervous System String Utilities (ic-nervous-system-string)

The `ic-nervous-system-string` crate (`rs/nervous_system/string`) provides string manipulation utilities for governance logging and display.

#### Scenario: Clamp string length
- **WHEN** clamp_string_len is called with a string and max_len
- **THEN** if the string length is at most max_len, it returns the string unchanged
- **AND** if max_len <= 3, it truncates to max_len characters
- **AND** otherwise, it replaces middle characters with "..." keeping head and tail portions
- **AND** the tail gets half of the available content length (rounded down), the head gets the rest

#### Scenario: Clamp debug length
- **WHEN** clamp_debug_len is called with an object implementing Debug and a max_len
- **THEN** it formats the object with {:#?} and then applies clamp_string_len

### Requirement: NNS Common Types (ic-nns-common)

The `ic-nns-common` crate (`rs/nns/common`) defines NNS-specific types including identifiers, access control, registry utilities, and payload types.

#### Scenario: NeuronId proto type
- **WHEN** a NeuronId proto is created
- **THEN** it wraps a u64 id field
- **AND** it defines MIN (u64::MIN) and MAX (u64::MAX) constants
- **AND** next() returns the successor NeuronId or None at MAX
- **AND** it implements Storable for stable memory with fixed 8-byte size
- **AND** it implements LowerBounded and UpperBounded
- **AND** From<NeuronId> for u64 extracts the id

#### Scenario: NeuronId Candid type
- **WHEN** the NeuronId Candid type (from types module) is used
- **THEN** it wraps a u64 as NeuronId(pub u64)
- **AND** it converts to/from the proto NeuronId
- **AND** it implements FromStr parsing a u64 from a string

#### Scenario: ProposalId proto type
- **WHEN** a ProposalId proto is created
- **THEN** it wraps a u64 id field
- **AND** it defines MIN (u64::MIN) and MAX (u64::MAX) constants
- **AND** it implements Storable for stable memory with fixed 8-byte size

#### Scenario: ProposalId Candid type
- **WHEN** the ProposalId Candid type (from types module) is used
- **THEN** it wraps a u64 as ProposalId(pub u64) with Default trait
- **AND** it converts to/from the proto ProposalId
- **AND** Display formats as "proposal {id}"

#### Scenario: UpdateIcpXdrConversionRatePayload
- **WHEN** an exchange rate proposal payload is created
- **THEN** it includes: data_source (String), timestamp_seconds, xdr_permyriad_per_icp, and optional reason
- **AND** the reason can be OldRate, DivergedRate, or EnableAutomaticExchangeRateUpdates

#### Scenario: CallCanisterRequest
- **WHEN** a proposal to call a canister is created
- **THEN** it includes: canister_id (CanisterId), method_name (String), and payload (bytes)

#### Scenario: Access control checks
- **WHEN** an NNS canister method is called
- **THEN** check_caller_is_root panics unless the caller is the Root canister
- **AND** check_caller_is_ledger panics unless the caller is the Ledger canister
- **AND** check_caller_is_gtc panics unless the caller is the GTC canister
- **AND** check_caller_is_governance panics unless the caller is the Governance canister
- **AND** check_caller_is_sns_w panics unless the caller is the SNS-WASM canister

#### Scenario: Registry get_value utility
- **WHEN** get_value is called with a key and optional version
- **THEN** it calls the Registry canister's get_value method via call_raw
- **AND** it deserializes and dechunkifies the response
- **AND** it decodes the protobuf value to the requested type T
- **AND** it returns (value, version) where version is the mutation version

#### Scenario: Registry mutate_registry utility
- **WHEN** mutate_registry is called with mutations and preconditions
- **THEN** it calls the Registry canister's atomic_mutate method
- **AND** on success, it returns the version at which the mutation occurred
- **AND** on failure, it returns a descriptive error string

#### Scenario: Registry subnet utilities
- **WHEN** get_subnet_record is called with a SubnetId
- **THEN** it retrieves the SubnetRecord protobuf from the Registry
- **AND** get_subnet_list_record retrieves the SubnetListRecord (returning None if key not present)
- **AND** get_subnet_ids_from_subnet_list converts raw bytes to SubnetId values
- **AND** get_latest_version returns the latest Registry version number

#### Scenario: MAX_NUM_SSH_KEYS constant
- **WHEN** SSH key limits are checked
- **THEN** MAX_NUM_SSH_KEYS is 50

### Requirement: NNS Constants (ic-nns-constants)

The `ic-nns-constants` crate (`rs/nns/constants`) defines well-known canister IDs, indices, and configuration values for the NNS.

#### Scenario: NNS canister indices
- **WHEN** NNS canisters are installed on the NNS subnet
- **THEN** they are assigned sequential indices: Registry (0), Governance (1), Ledger (2), Root (3), CMC (4), Lifeline (5), GTC (6), Identity (7), NNS-UI (8), ICP Ledger Archive (9), SNS-WASM (10), Ledger Index (11), ICP Ledger Archive 1 (12), Subnet Rental (13), ICP Ledger Archive 2 (14), ICP Ledger Archive 3 (15), Node Rewards (16), Migration (17)

#### Scenario: NNS canister ID constants
- **WHEN** a canister ID constant is referenced
- **THEN** REGISTRY_CANISTER_ID is constructed from index 0
- **AND** GOVERNANCE_CANISTER_ID from index 1
- **AND** LEDGER_CANISTER_ID from index 2
- **AND** ROOT_CANISTER_ID from index 3
- **AND** CYCLES_MINTING_CANISTER_ID from index 4
- **AND** LIFELINE_CANISTER_ID from index 5
- **AND** GENESIS_TOKEN_CANISTER_ID from index 6
- **AND** NNS_UI_CANISTER_ID from index 8
- **AND** ICP_LEDGER_ARCHIVE_CANISTER_ID from index 9
- **AND** SNS_WASM_CANISTER_ID from index 10
- **AND** LEDGER_INDEX_CANISTER_ID from index 11
- **AND** NODE_REWARDS_CANISTER_ID from index 16
- **AND** MIGRATION_CANISTER_ID from index 17

#### Scenario: Non-NNS-subnet canister indices
- **WHEN** canisters on other subnets are referenced
- **THEN** EXCHANGE_RATE_CANISTER_INDEX is 0x_0210_0001 (II subnet, zur34)
- **AND** CYCLES_LEDGER_CANISTER_INDEX is 0x_0210_0002 (II subnet)
- **AND** CYCLES_LEDGER_INDEX_CANISTER_INDEX is 0x_0210_0003 (II subnet)
- **AND** BITCOIN_TESTNET_CANISTER_INDEX is 0x_01A0_0001 (Bitcoin subnet, w4rem)
- **AND** BITCOIN_MAINNET_CANISTER_INDEX is 0x_01A0_0004 (Bitcoin subnet)
- **AND** BITCOIN_WATCHDOG_CANISTER_INDEX is 0x_01A0_0005 (Bitcoin subnet)
- **AND** DOGECOIN_CANISTER_INDEX is 0x_01A0_0007 (Bitcoin subnet)
- **AND** DOGECOIN_WATCHDOG_CANISTER_INDEX is 0x_01A0_0009 (Bitcoin subnet)
- **AND** SNS_AGGREGATOR_CANISTER_INDEX is 0x_0200_0010 (SNS subnet, x33ed)

#### Scenario: ALL_NNS_CANISTER_IDS list
- **WHEN** the complete list of NNS canister IDs is needed
- **THEN** ALL_NNS_CANISTER_IDS contains 18 entries covering all NNS subnet canisters
- **AND** this list does not include non-NNS subnet canisters or ledger archive/index

#### Scenario: PROTOCOL_CANISTER_IDS list
- **WHEN** determining if a canister is a protocol canister
- **THEN** PROTOCOL_CANISTER_IDS contains 23 entries
- **AND** it includes NNS canisters plus Bitcoin, Exchange Rate, Cycles Ledger, Dogecoin, and watchdog canisters

#### Scenario: Memory allocation per canister
- **WHEN** memory_allocation_of is called with a canister ID
- **THEN** ICP Ledger Archive gets 8 GiB
- **AND** Ledger gets 4 GiB
- **AND** Root, CMC, Lifeline, and GTC get 1 GiB
- **AND** all other canisters get 0 (best-effort allocation)

#### Scenario: SNS memory limits
- **WHEN** SNS canister memory limits are queried
- **THEN** DEFAULT_SNS_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT is 4 GiB (1 << 32)
- **AND** DEFAULT_SNS_NON_GOVERNANCE_CANISTER_WASM_MEMORY_LIMIT is 3 GiB (3 * (1 << 30))

#### Scenario: NNS canister WASM names
- **WHEN** NNS canisters are deployed
- **THEN** NNS_CANISTER_WASMS lists 15 WASM file names for deployment
- **AND** this includes registry, governance, ledger, root, CMC, lifeline, GTC, identity, NNS-UI, SNS-WASM, ICRC-1 ledger, ckBTC minter, and migration canisters

#### Scenario: Canister ID to name mapping
- **WHEN** canister_id_to_nns_canister_name is called
- **THEN** it returns a human-readable name for known NNS canister IDs (e.g. "governance", "ledger", "root")
- **AND** the mapping covers 19 known canisters
- **AND** it returns the canister ID string for unknown IDs

### Requirement: Cycles Minting Canister Types (cycles-minting-canister)

The `cycles-minting-canister` crate (`rs/nns/cmc`) defines types, constants, and operations for the Cycles Minting Canister which converts ICP to cycles for canister operations.

#### Scenario: Cycles-per-XDR default rate
- **WHEN** cycles pricing is initialized
- **THEN** DEFAULT_CYCLES_PER_XDR is 1,000,000,000,000 (1T cycles = 1 XDR)

#### Scenario: Default ICP-XDR conversion rate
- **WHEN** the exchange rate has not been updated
- **THEN** DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS is 1,620,633,600 (10 May 2021)
- **AND** DEFAULT_XDR_PERMYRIAD_PER_ICP_CONVERSION_RATE is 1,000,000 (1 ICP = 100 XDR)

#### Scenario: Refund fee constants
- **WHEN** canister creation or top-up is refunded
- **THEN** CREATE_CANISTER_REFUND_FEE is 4 times the DEFAULT_TRANSFER_FEE
- **AND** TOP_UP_CANISTER_REFUND_FEE is 2 times the DEFAULT_TRANSFER_FEE
- **AND** MINT_CYCLES_REFUND_FEE is 2 times the DEFAULT_TRANSFER_FEE

#### Scenario: Bad request cycles penalty
- **WHEN** a bad request is processed that incurs significant computation
- **THEN** BAD_REQUEST_CYCLES_PENALTY is 100,000,000 cycles

#### Scenario: Memo constants for ICP operations
- **WHEN** ICP is sent to the CMC with a memo
- **THEN** MEMO_CREATE_CANISTER is 0x41455243 ('CREA')
- **AND** MEMO_TOP_UP_CANISTER is 0x50555054 ('TPUP')
- **AND** MEMO_MINT_CYCLES is 0x544e494d ('MINT')
- **AND** 0 is never used as a memo value to distinguish intentional from accidental transfers

#### Scenario: TokensToCycles conversion
- **WHEN** TokensToCycles::to_cycles is called with a Tokens amount
- **THEN** it computes: tokens_e8s * xdr_permyriad_per_icp * cycles_per_xdr / (TOKEN_SUBDIVIDABLE_BY * 10,000)
- **AND** all arithmetic uses u128 to avoid overflow

#### Scenario: IcpXdrConversionRate type
- **WHEN** an exchange rate is stored or queried
- **THEN** IcpXdrConversionRate contains timestamp_seconds and xdr_permyriad_per_icp
- **AND** From<ExchangeRate> converts from the exchange rate canister format, adjusting decimal places to permyriad (4 decimal places)
- **AND** From<UpdateIcpXdrConversionRatePayload> converts from the NNS proposal payload format

#### Scenario: IcpXdrConversionRateCertifiedResponse
- **WHEN** a certified exchange rate is returned
- **THEN** it includes the IcpXdrConversionRate data, a hash_tree, and a certificate for verification

#### Scenario: NotifyTopUp request
- **WHEN** a canister top-up notification is sent to the CMC
- **THEN** NotifyTopUp contains block_index and canister_id

#### Scenario: NotifyCreateCanister request
- **WHEN** a canister creation notification is sent to the CMC
- **THEN** NotifyCreateCanister contains block_index, controller (must match caller), optional subnet_selection, and optional settings
- **AND** the deprecated subnet_type field is still present for backward compatibility

#### Scenario: CreateCanister request
- **WHEN** a canister is created directly through the CMC
- **THEN** CreateCanister contains optional subnet_selection (Filter or specific Subnet) and optional settings
- **AND** the deprecated subnet_type field is still present

#### Scenario: SubnetSelection options
- **WHEN** a subnet is selected for canister creation
- **THEN** SubnetSelection::Filter allows selection by subnet_type string
- **AND** SubnetSelection::Subnet allows selection of a specific SubnetId

#### Scenario: NotifyError handling
- **WHEN** a notification to the CMC fails
- **THEN** NotifyError can be: Refunded (with reason and optional block_index), InvalidTransaction, TransactionTooOld, Processing, or Other (with error_code and error_message)
- **AND** is_retriable returns false only for Refunded errors (permanent failures)
- **AND** Display provides human-readable error messages

#### Scenario: NotifyErrorCode enumeration
- **WHEN** error codes are classified
- **THEN** Internal = 1, FailedToFetchBlock = 2, RefundFailed = 3, BadSubnetSelection = 4, Unauthorized = 5, DepositMemoTooLong = 6

#### Scenario: create_canister_txn helper
- **WHEN** a create-canister transaction is prepared
- **THEN** it constructs SendArgs with MEMO_CREATE_CANISTER, the specified amount, DEFAULT_TRANSFER_FEE
- **AND** the destination is the CMC account with a subaccount derived from the creator's PrincipalId

#### Scenario: top_up_canister_txn helper
- **WHEN** a top-up transaction is prepared
- **THEN** it constructs SendArgs with MEMO_TOP_UP_CANISTER, the specified amount, DEFAULT_TRANSFER_FEE
- **AND** the destination is the CMC account with a subaccount derived from the target canister ID

#### Scenario: NotifyMintCyclesArg and success result
- **WHEN** notify_mint_cycles is called
- **THEN** the argument includes block_index, optional to_subaccount, and optional deposit_memo
- **AND** on success, NotifyMintCyclesSuccess returns the cycles ledger block_index, minted amount, and new balance

#### Scenario: CyclesCanisterInitPayload
- **WHEN** the CMC is initialized
- **THEN** CyclesCanisterInitPayload includes optional fields for: ledger_canister_id, governance_canister_id, minting_account_id, last_purged_notification, exchange_rate_canister, and cycles_ledger_canister_id

#### Scenario: ExchangeRateCanister configuration
- **WHEN** the exchange rate canister is configured
- **THEN** ExchangeRateCanister::Set(canister_id) enables it with a specific ID
- **AND** ExchangeRateCanister::Unset disables it

#### Scenario: Subnet type management
- **WHEN** subnet types are managed through the CMC
- **THEN** UpdateSubnetTypeArgs allows Add or Remove of a subnet type string
- **AND** UpdateSubnetTypeError reports: Duplicate, TypeDoesNotExist, or TypeHasAssignedSubnets
- **AND** ChangeSubnetTypeAssignmentArgs allows Add or Remove of SubnetListWithType
- **AND** ChangeSubnetTypeAssignmentError reports: TypeDoesNotExist, SubnetsAreAssigned, SubnetsAreAuthorized, or SubnetsAreNotAssigned

#### Scenario: Authorized subnets management
- **WHEN** authorized subnets are managed
- **THEN** SetAuthorizedSubnetworkListArgs specifies optional who (PrincipalId) and subnets list
- **AND** RemoveSubnetFromAuthorizedSubnetListArgs specifies a single subnet to remove

#### Scenario: mint_cycles128 system call
- **WHEN** the CMC needs to mint cycles
- **THEN** ic0_mint_cycles128 calls the ic0 mint_cycles128 import with amount_high and amount_low
- **AND** it returns the actual number of cycles minted as a Cycles value
- **AND** on non-wasm32 targets, this function panics

#### Scenario: Permyriad decimal places
- **WHEN** exchange rates are converted between formats
- **THEN** PERMYRIAD_DECIMAL_PLACES is 4
- **AND** conversion adjusts rates by powers of 10 based on the difference in decimal places
