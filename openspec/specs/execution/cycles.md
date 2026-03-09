# Cycles Accounting and Management

**Crates**: `ic-cycles-account-manager`

This specification covers how cycles are charged, transferred, and managed for canisters on the Internet Computer.

## Requirements

### Requirement: Cycles Account Manager

The `CyclesAccountManager` is responsible for all cycles-related accounting operations. Fees are scaled by subnet size relative to a reference subnet size.

#### Scenario: Fee scaling by subnet size
- **WHEN** a cycles fee is calculated
- **THEN** the fee is scaled by `(subnet_size / reference_subnet_size)`
- **AND** if the canister has a `Free` cost schedule, the fee is zero

#### Scenario: Free cost schedule
- **WHEN** a canister has `CanisterCyclesCostSchedule::Free`
- **THEN** all execution, messaging, and storage fees are zero
- **AND** cycles can still be transferred and withdrawn

### Requirement: Execution Cycles

Canisters pay for instruction execution.

#### Scenario: Prepay execution cycles
- **WHEN** a message begins execution
- **THEN** cycles are prepaid based on the message instruction limit
- **AND** the prepaid amount equals `execution_cost(max_instructions)`
- **AND** the prepaid cycles are deducted from the canister's balance

#### Scenario: Refund unused execution cycles
- **WHEN** a message finishes execution having used fewer instructions than prepaid
- **THEN** the canister is refunded cycles for the unused instructions
- **AND** the refund equals the cost of `(prepaid_instructions - used_instructions)`

#### Scenario: Insufficient cycles for execution
- **WHEN** a canister does not have enough cycles above the freezing threshold to prepay execution
- **THEN** the message execution fails with `CanisterOutOfCycles`
- **AND** the message is not executed

#### Scenario: Execution cost calculation
- **WHEN** execution cost is computed for a given number of instructions
- **THEN** the cost is `scale_cost(instructions * ten_update_instructions_execution_fee / 10)`
- **AND** the cost accounts for the subnet size

### Requirement: Freezing Threshold

The freezing threshold prevents canisters from running out of cycles for storage.

#### Scenario: Freezing threshold calculation
- **WHEN** the freezing threshold is evaluated
- **THEN** it is computed as: `idle_cycles_burned_rate * freeze_threshold_seconds / seconds_per_day`
- **AND** `idle_cycles_burned_rate` includes costs for memory, message memory, and compute allocation
- **AND** the reserved balance is subtracted from the threshold

#### Scenario: Operations blocked by freezing threshold
- **WHEN** an operation would reduce the canister's balance below the freezing threshold
- **THEN** the operation fails with `CanisterOutOfCycles`
- **AND** the error reports the available balance, requested amount, and threshold

#### Scenario: Reveal top-up information
- **WHEN** a `CanisterOutOfCycles` error occurs and the caller is a controller
- **THEN** the error message reveals the canister's current balance (including top-up amounts)

### Requirement: Ingress Message Fees

Receiving ingress messages costs cycles.

#### Scenario: Ingress induction cost
- **WHEN** an ingress message is inducted for a canister
- **THEN** the canister is charged an ingress message received fee plus per-byte fee
- **AND** the cost is `ingress_message_reception_fee + ingress_byte_reception_fee * payload_size`

#### Scenario: Delayed ingress induction cost for update_settings
- **WHEN** an `update_settings` ingress message has a small payload (<=324 bytes)
- **THEN** the ingress induction cost is delayed (charged after applying settings)
- **AND** this allows users to unfreeze canisters by lowering the freezing threshold

#### Scenario: Ingress cost with paused execution
- **WHEN** a canister has a paused execution and receives an ingress message
- **THEN** the ingress cost is added to the postponed charges debit
- **AND** the debit is applied when the paused execution completes

### Requirement: Inter-Canister Call Fees

Sending messages between canisters costs cycles.

#### Scenario: Xnet call fee
- **WHEN** a canister sends an inter-canister request
- **THEN** cycles are charged for the call: `xnet_call_fee + xnet_byte_transmission_fee * payload_size`
- **AND** cycles for the maximum response size are also reserved

#### Scenario: Response transmission refund
- **WHEN** a response is received that is smaller than the maximum reserved size
- **THEN** the canister is refunded for the unused transmission bytes

### Requirement: Canister Creation Fee

Creating a canister incurs a one-time fee.

#### Scenario: Creation fee charged
- **WHEN** a new canister is created
- **THEN** the `canister_creation_fee` is charged from the cycles provided
- **AND** the remaining cycles become the canister's initial balance

### Requirement: Storage Fees

Canisters pay for memory usage over time.

#### Scenario: Idle cycles burn rate
- **WHEN** a canister exists on the subnet
- **THEN** it burns cycles per day based on:
  - Memory usage (or memory allocation if set): `gib_storage_per_second_fee * memory_bytes * duration / GiB`
  - Message memory usage: same rate applied to message queue memory
  - Compute allocation: `compute_allocation_fee * allocation * duration`
- **AND** these costs are charged during round execution

#### Scenario: Memory cost calculation
- **WHEN** memory cost is calculated for a given amount and duration
- **THEN** the cost is `gib_storage_per_second_fee * bytes * duration_seconds / GiB_in_bytes`
- **AND** the fee is scaled by subnet size

### Requirement: Resource Reservation

When subnet resources become scarce, canisters must reserve cycles for future storage costs.

#### Scenario: Resource saturation scaling
- **WHEN** subnet resource usage exceeds the saturation threshold
- **THEN** a reservation factor is computed as `(usage - threshold) / (capacity - threshold)`
- **AND** the reservation amount for new allocations is scaled by this factor

#### Scenario: Storage reservation for memory growth
- **WHEN** a canister grows its memory (heap or stable) during execution
- **THEN** cycles may be moved from the canister's main balance to its reserved balance
- **AND** the amount depends on the resource saturation level
- **AND** the reserved balance is used to cover future storage costs

#### Scenario: Reserved cycles limit
- **WHEN** a canister has a `reserved_cycles_limit` set
- **THEN** the total reserved balance cannot exceed this limit
- **AND** if a reservation would exceed the limit, the operation fails

### Requirement: Cycles Transfer

Canisters can send and receive cycles via inter-canister calls.

#### Scenario: Attach cycles to a call
- **WHEN** a canister calls `ic0.call_cycles_add128(high, low)` during call construction
- **THEN** the specified cycles are attached to the outgoing call
- **AND** the cycles are deducted from the canister's balance (subject to freezing threshold)

#### Scenario: Accept cycles from incoming call
- **WHEN** a canister calls `ic0.msg_cycles_accept128(max_amount_high, max_amount_low)`
- **THEN** up to `max_amount` cycles from the incoming call are accepted
- **AND** the accepted cycles are added to the canister's balance

#### Scenario: Unaccepted cycles returned in response
- **WHEN** a canister does not accept all cycles from an incoming call
- **THEN** the unaccepted cycles are returned to the caller in the response refund

#### Scenario: Cycles balance query
- **WHEN** a canister calls `ic0.canister_cycle_balance128`
- **THEN** the canister's current cycle balance is returned as a 128-bit value

### Requirement: HTTP Outcall Fees

HTTP outcalls have specific pricing.

#### Scenario: HTTP request fee
- **WHEN** a canister makes an HTTP outcall
- **THEN** the fee is based on the request size, response size limit, and subnet size
- **AND** the fee covers both the request and the maximum possible response

### Requirement: Cycles on System Subnets

System subnets have special cycles handling.

#### Scenario: System subnet free execution
- **WHEN** a canister runs on a system subnet
- **THEN** no cycles are charged for execution, storage, or messaging
- **AND** canisters still have a cycles balance for inter-canister transfers

### Requirement: Mint Cycles

The Cycles Minting Canister can mint new cycles.

#### Scenario: Mint cycles
- **WHEN** the Cycles Minting Canister calls `ic0.mint_cycles`
- **THEN** new cycles are created and added to its balance
- **AND** only the CMC (on the NNS subnet) is allowed to mint cycles

### Requirement: Signature Operation Fees

Threshold signature operations (ECDSA, Schnorr, VetKd) charge per-signature fees, scaled by subnet size.

#### Scenario: ECDSA signature fee
- **WHEN** a canister requests an ECDSA signature
- **THEN** the canister is charged the `ecdsa_signature_fee` scaled by subnet size
- **AND** if the canister has a `Free` cost schedule, the fee is zero

#### Scenario: Schnorr signature fee
- **WHEN** a canister requests a Schnorr signature
- **THEN** the canister is charged the `schnorr_signature_fee` scaled by subnet size
- **AND** if the canister has a `Free` cost schedule, the fee is zero

#### Scenario: VetKd fee
- **WHEN** a canister requests a VetKd key derivation
- **THEN** the canister is charged the `vetkd_fee` scaled by subnet size
- **AND** if the canister has a `Free` cost schedule, the fee is zero

### Requirement: Canister Log Fetching Fees

Fetching canister logs incurs a fee based on response size.

#### Scenario: Fetch canister logs fee
- **WHEN** canister logs are fetched with a given response size
- **THEN** the fee is `(fetch_canister_logs_base_fee + fetch_canister_logs_per_byte_fee * response_size) * subnet_size`
- **AND** if the canister has a `Free` cost schedule, the fee is zero

#### Scenario: Maximum fetch canister logs fee
- **WHEN** the maximum fetch canister logs fee is computed (e.g., for prepayment)
- **THEN** the fee is calculated using `MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES` as the response size
- **AND** this represents the worst-case cost of a log fetch operation

### Requirement: HTTP Request Fee Variants

Multiple HTTP outcall fee formulas exist to support different pricing models.

#### Scenario: HTTP request fee (v1)
- **WHEN** a canister makes an HTTP outcall using the v1 fee model
- **THEN** the fee is `(http_request_linear_baseline_fee + http_request_quadratic_baseline_fee * subnet_size + http_request_per_byte_fee * request_size + http_response_per_byte_fee * response_size) * subnet_size`
- **AND** if no response size limit is specified, `MAX_CANISTER_HTTP_RESPONSE_BYTES` is used as the default
- **AND** if the canister has a `Free` cost schedule, the fee is zero

#### Scenario: HTTP request fee v2 (with roundtrip time)
- **WHEN** a canister makes an HTTP outcall using the v2 fee model
- **THEN** the fee accounts for request size, raw response size, transformed response size, HTTP roundtrip time, and transform instructions
- **AND** the formula is `(1_000_000 + 50 * request_size + 140_000 * n + 800 * n^2 + 50 * raw_response_size + 300 * roundtrip_time_ms + transform_instructions / 13 + (10 * n + 650) * transformed_response_size) * n` where `n = subnet_size`
- **AND** if the canister has a `Free` cost schedule, the fee is zero

#### Scenario: HTTP request fee beta (payload-based)
- **WHEN** a canister makes an HTTP outcall using the beta fee model
- **THEN** the fee is `(4_000_000 + 50_000 * subnet_size + 50 * request_size + 50 * max_response_size + 750 * payload_size + 30 * subnet_size * payload_size) * subnet_size`
- **AND** if no response size limit is specified, `MAX_CANISTER_HTTP_RESPONSE_BYTES` is used as the default
- **AND** if the canister has a `Free` cost schedule, the fee is zero

### Requirement: Cycles Burn

Canisters can explicitly burn cycles, subject to the freezing threshold.

#### Scenario: Burn cycles respecting freezing threshold
- **WHEN** a canister calls `ic0.cycles_burn128` to burn a specified amount
- **THEN** the actual amount burned is `min(amount_to_burn, balance - freezing_threshold)`
- **AND** if the balance is at or below the freezing threshold, zero cycles are burned
- **AND** the burned cycles are deducted from the canister's balance and reported as consumed

### Requirement: Canister Deletion Leftover Cycles

When a canister is deleted, any remaining cycles (main balance and reserved balance) are recorded as leftover.

#### Scenario: Compute leftover cycles on deletion
- **WHEN** a canister is being deleted
- **THEN** the leftover cycles are computed as `balance + reserved_balance`
- **AND** the leftover is converted to `NominalCycles` for accounting purposes
- **AND** these cycles are effectively destroyed (not transferred)

### Requirement: Paused Execution Debit

When a canister has a paused execution, ingress induction charges are deferred to avoid interfering with the in-progress execution.

#### Scenario: Ingress charge deferred during paused execution
- **WHEN** a canister has a paused execution or paused install_code and receives an ingress message
- **THEN** the ingress induction cost is checked against `debited_balance - freezing_threshold` (not the actual balance)
- **AND** if sufficient cycles exist, the cost is added to `postponed_charge_to_ingress_induction_cycles_debit`
- **AND** the debit is settled when the paused execution completes

#### Scenario: Insufficient debited balance during paused execution
- **WHEN** a canister has a paused execution and its debited balance minus the freezing threshold is less than the ingress cost
- **THEN** the ingress induction fails with `CanisterOutOfCycles`
- **AND** the error reports the debited balance as the available amount

### Requirement: Reserved Balance Draining

For resource-related charges (memory, compute allocation, uninstall), the reserved balance is drained before the main balance.

#### Scenario: Resource charges drain reserved balance first
- **WHEN** a canister is charged for `Memory`, `ComputeAllocation`, or `Uninstall` use cases
- **THEN** the effective balance for threshold comparison is `balance + reserved_balance`
- **AND** the charge is first deducted from the reserved balance
- **AND** only after the reserved balance is exhausted is the main balance used

#### Scenario: Non-resource charges use main balance only
- **WHEN** a canister is charged for non-resource use cases (e.g., `IngressInduction`, `Instructions`, `RequestAndResponseTransmission`, `ECDSAOutcalls`, `SchnorrOutcalls`, `VetKd`, `HTTPOutcalls`, `CanisterCreation`, `BurnedCycles`, `DroppedMessages`)
- **THEN** only the main balance is considered for the charge
- **AND** the reserved balance is not used and not included in threshold comparison

### Requirement: Mint Cycles Validation

The `mint_cycles` operation is restricted to the Cycles Minting Canister (CMC).

#### Scenario: Mint cycles from non-CMC canister
- **WHEN** a canister other than the Cycles Minting Canister calls `ic0.mint_cycles128`
- **THEN** the operation fails with `CyclesAccountManagerError::ContractViolation`
- **AND** the error message states that `ic0.mint_cycles128 cannot be executed on non Cycles Minting Canister`

#### Scenario: Mint cycles overflow saturation
- **WHEN** the CMC mints cycles that would cause the balance to overflow `u128`
- **THEN** the balance saturates at the maximum value
- **AND** the returned amount equals the actual increase (which may be less than the requested mint amount)

### Requirement: Wasm32 vs Wasm64 Execution Fees

Different per-instruction fee rates apply depending on whether the canister runs in Wasm32 or Wasm64 mode.

#### Scenario: Wasm32 execution cost
- **WHEN** a canister running in `Wasm32` execution mode executes instructions
- **THEN** the per-instruction cost uses the `ten_update_instructions_execution_fee` rate
- **AND** the cost is `instructions * ten_update_instructions_execution_fee / 10`

#### Scenario: Wasm64 execution cost
- **WHEN** a canister running in `Wasm64` execution mode executes instructions
- **THEN** the per-instruction cost uses the `ten_update_instructions_execution_fee_wasm64` rate
- **AND** this rate may differ from the Wasm32 rate to reflect the different resource usage of 64-bit execution

#### Scenario: Execution cost includes message execution fee
- **WHEN** execution cost is computed for any Wasm mode
- **THEN** the total cost is `scale_cost(update_message_execution_fee + instruction_cost, subnet_size, cost_schedule)`
- **AND** the `update_message_execution_fee` is a fixed per-message component added to the per-instruction cost

### Requirement: Message Memory Tracking

Memory usage and message memory usage are tracked and billed separately to properly account for canister resources.

#### Scenario: Idle burn rate includes message memory
- **WHEN** the idle cycles burn rate is calculated for a canister
- **THEN** three components are summed: heap/stable memory cost, message memory cost, and compute allocation cost
- **AND** heap/stable memory cost is based on `memory_allocation` (if set) or actual `memory_usage`
- **AND** message memory cost is based on the total message memory (`message_memory_usage.total()`) at the same per-byte rate as heap memory
- **AND** compute allocation cost is based on the canister's `compute_allocation`

#### Scenario: Freezing threshold accounts for message memory
- **WHEN** the freezing threshold is evaluated for a canister
- **THEN** the threshold is `idle_cycles_burned_rate * freeze_threshold_seconds / seconds_per_day`
- **AND** the idle burn rate used in this calculation includes message memory costs
- **AND** this ensures that canisters with large message queues have a proportionally higher freezing threshold

#### Scenario: Resource allocation charging covers message memory
- **WHEN** a canister is periodically charged for resource allocation and usage
- **THEN** it is charged separately for each resource: memory, message memory, and compute allocation
- **AND** each resource charge uses the `consume_with_threshold` method with a zero threshold (allowing charges down to zero balance)
- **AND** resource charges drain the reserved balance before the main balance
