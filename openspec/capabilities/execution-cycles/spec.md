# Execution: Cycles Accounting Capability Specification

**Source narrative**: `openspec/specs/execution/cycles.md`
**Crates**: `ic-cycles-account-manager`
**Key files**: `rs/cycles_account_manager/src/lib.rs`

---

## REQ-CYC-001: Fee Scaling by Subnet Size

All cycles fees MUST be scaled proportionally to subnet size relative to a reference subnet size.

### SCENARIO-CYC-001: Fee scaling calculation
**Given** a cycles fee is calculated
**When** the fee is computed
**Then** it is scaled by `subnet_size / reference_subnet_size`
**And** if the canister has a `Free` cost schedule, the fee is zero

### SCENARIO-CYC-002: Free cost schedule
**Given** a canister has `CanisterCyclesCostSchedule::Free`
**When** any fee is computed
**Then** all execution, messaging, and storage fees are zero
**And** cycles can still be transferred and withdrawn

---

## REQ-CYC-002: Execution Cycles

Canisters MUST pay for instruction execution via prepay-and-refund.

### SCENARIO-CYC-003: Prepay execution cycles
**Given** a message begins execution
**When** cycles are prepaid
**Then** the prepaid amount equals `execution_cost(max_instructions)`
**And** the prepaid cycles are deducted from the canister's balance

### SCENARIO-CYC-004: Refund unused execution cycles
**Given** a message finishes with fewer instructions than prepaid
**When** the refund is calculated
**Then** the canister is refunded `cost(prepaid_instructions - used_instructions)`

### SCENARIO-CYC-005: Insufficient cycles for execution
**Given** a canister does not have enough cycles above the freezing threshold to prepay
**When** prepayment is attempted
**Then** the message fails with `CanisterOutOfCycles`
**And** the message is not executed

### SCENARIO-CYC-006: Execution cost calculation
**Given** execution cost is computed for a given number of instructions
**When** the cost is determined
**Then** it equals `scale_cost(instructions * ten_update_instructions_execution_fee / 10, subnet_size)`

---

## REQ-CYC-003: Freezing Threshold

The freezing threshold MUST prevent canisters from running out of cycles for storage.

### SCENARIO-CYC-007: Freezing threshold calculation
**Given** the freezing threshold is evaluated
**When** the calculation runs
**Then** it equals `idle_cycles_burned_rate * freeze_threshold_seconds / seconds_per_day`
**And** `idle_cycles_burned_rate` includes costs for memory, message memory, and compute allocation
**And** the reserved balance is subtracted from the threshold

### SCENARIO-CYC-008: Operations blocked by freezing threshold
**Given** an operation would reduce balance below the freezing threshold
**When** the operation is attempted
**Then** the operation fails with `CanisterOutOfCycles`
**And** the error reports available balance, requested amount, and threshold

### SCENARIO-CYC-009: Reveal top-up information to controllers
**Given** a `CanisterOutOfCycles` error occurs and the caller is a controller
**When** the error is returned
**Then** the error message reveals the canister's current balance

---

## REQ-CYC-004: Ingress Message Fees

Receiving ingress messages MUST cost cycles.

### SCENARIO-CYC-010: Ingress induction cost
**Given** an ingress message is inducted for a canister
**When** the cost is charged
**Then** the cost equals `ingress_message_reception_fee + ingress_byte_reception_fee * payload_size`

### SCENARIO-CYC-011: Delayed ingress cost for update_settings
**Given** an `update_settings` ingress has a small payload (≤324 bytes)
**When** the cost is applied
**Then** the ingress induction cost is delayed (charged after applying settings)
**And** this allows users to unfreeze canisters by lowering the freezing threshold first

### SCENARIO-CYC-012: Ingress cost deferred during paused execution
**Given** a canister has a paused execution and receives an ingress message
**When** the cost is handled
**Then** the ingress cost is added to `postponed_charge_to_ingress_induction_cycles_debit`
**And** the debit is applied when the paused execution completes

---

## REQ-CYC-005: Inter-Canister Call Fees

Sending inter-canister messages MUST cost cycles.

### SCENARIO-CYC-013: Xnet call fee
**Given** a canister sends an inter-canister request
**When** the fee is charged
**Then** cycles are charged: `xnet_call_fee + xnet_byte_transmission_fee * payload_size`
**And** cycles for the maximum response size are also reserved

### SCENARIO-CYC-014: Response transmission refund
**Given** a response is smaller than the maximum reserved size
**When** the response is received
**Then** the canister is refunded for unused transmission bytes

---

## REQ-CYC-006: Canister Creation Fee

Creating a canister MUST incur a one-time creation fee.

### SCENARIO-CYC-015: Creation fee charged
**Given** a new canister is created
**When** creation completes
**Then** the `canister_creation_fee` is charged from provided cycles
**And** remaining cycles become the canister's initial balance

---

## REQ-CYC-007: Storage Fees

Canisters MUST pay for memory usage over time.

### SCENARIO-CYC-016: Idle cycles burn rate components
**Given** a canister exists on the subnet
**When** the idle burn rate is computed
**Then** it includes: memory cost + message memory cost + compute allocation cost
**And** memory cost = `gib_storage_per_second_fee * memory_bytes * duration / GiB`
**And** compute allocation cost = `compute_allocation_fee * allocation * duration`

### SCENARIO-CYC-017: Memory cost calculation
**Given** memory cost is calculated for an amount and duration
**When** the cost is computed
**Then** cost = `gib_storage_per_second_fee * bytes * duration_seconds / GiB_in_bytes`
**And** the fee is scaled by subnet size

---

## REQ-CYC-008: Resource Reservation

When subnet resources are scarce, canisters MUST reserve cycles for future storage costs.

### SCENARIO-CYC-018: Resource saturation scaling
**Given** subnet resource usage exceeds the saturation threshold
**When** a reservation factor is computed
**Then** it equals `(usage - threshold) / (capacity - threshold)`
**And** new allocation reservations are scaled by this factor

### SCENARIO-CYC-019: Storage reservation on memory growth
**Given** a canister grows its memory during execution
**When** subnet resources are saturated
**Then** cycles may be moved from the canister's main balance to its reserved balance
**And** the reserved balance covers future storage costs

### SCENARIO-CYC-020: Reserved cycles limit
**Given** a canister has a `reserved_cycles_limit` configured
**When** a reservation would exceed the limit
**Then** the total reserved balance cannot exceed this limit
**And** the operation that would exceed it fails

---

## REQ-CYC-009: Cycles Transfer

Canisters MUST be able to send and receive cycles via inter-canister calls.

### SCENARIO-CYC-021: Attach cycles to a call
**Given** a canister calls `ic0.call_cycles_add128(high, low)` during call construction
**When** the call executes
**Then** the specified cycles are attached to the outgoing call
**And** deducted from the canister's balance (subject to freezing threshold)

### SCENARIO-CYC-022: Accept cycles from incoming call
**Given** a canister calls `ic0.msg_cycles_accept128(max_amount)`
**When** the call executes
**Then** up to `max_amount` cycles from the incoming call are accepted
**And** added to the canister's balance

### SCENARIO-CYC-023: Unaccepted cycles returned in response
**Given** a canister does not accept all cycles from an incoming call
**When** the response is sent
**Then** unaccepted cycles are returned to the caller in the response refund

### SCENARIO-CYC-024: Cycles balance query
**Given** a canister calls `ic0.canister_cycle_balance128`
**When** the call executes
**Then** the canister's current cycle balance is returned as a 128-bit value

---

## REQ-CYC-010: HTTP Outcall Fees

HTTP outcalls MUST have specific pricing based on request/response sizes and subnet size.

### SCENARIO-CYC-025: HTTP request fee (v1)
**Given** a canister makes an HTTP outcall using the v1 fee model
**When** the fee is computed
**Then** fee = `(http_request_linear_baseline_fee + http_request_quadratic_baseline_fee * subnet_size + http_request_per_byte_fee * request_size + http_response_per_byte_fee * response_size) * subnet_size`
**And** if no response size limit is specified, `MAX_CANISTER_HTTP_RESPONSE_BYTES` is used

### SCENARIO-CYC-043: HTTP request fee (v2 — with roundtrip time)
**Given** a canister makes an HTTP outcall using the v2 fee model
**When** the fee is computed
**Then** fee = `(1_000_000 + 50 * request_size + 140_000 * n + 800 * n^2 + 50 * raw_response_size + 300 * roundtrip_time_ms + transform_instructions / 13 + (10 * n + 650) * transformed_response_size) * n` where `n = subnet_size`

### SCENARIO-CYC-044: HTTP request fee (beta — payload-based)
**Given** a canister makes an HTTP outcall using the beta fee model
**When** the fee is computed
**Then** fee = `(4_000_000 + 50_000 * subnet_size + 50 * request_size + 50 * max_response_size + 750 * payload_size + 30 * subnet_size * payload_size) * subnet_size`
**And** if no response size limit is specified, `MAX_CANISTER_HTTP_RESPONSE_BYTES` is used

---

## REQ-CYC-011: System Subnet Free Execution

System subnets MUST waive execution fees.

### SCENARIO-CYC-026: System subnet free execution
**Given** a canister runs on a system subnet
**When** fees are computed
**Then** no cycles are charged for execution, storage, or messaging
**And** canisters still have a cycles balance for inter-canister transfers

---

## REQ-CYC-012: Mint Cycles

Only the Cycles Minting Canister MUST be allowed to mint new cycles.

### SCENARIO-CYC-027: Mint cycles by CMC
**Given** the Cycles Minting Canister calls `ic0.mint_cycles`
**When** minting executes
**Then** new cycles are created and added to its balance

### SCENARIO-CYC-028: Mint cycles rejected for non-CMC
**Given** a canister other than the CMC calls `ic0.mint_cycles128`
**When** the call executes
**Then** the operation fails with `CyclesAccountManagerError::ContractViolation`

### SCENARIO-CYC-029: Mint cycles overflow saturation
**Given** minting cycles would overflow `u128`
**When** the mint executes
**Then** the balance saturates at the maximum value
**And** the returned amount equals the actual increase

---

## REQ-CYC-013: Signature Operation Fees

Threshold signature operations MUST charge per-signature fees scaled by subnet size.

### SCENARIO-CYC-030: ECDSA signature fee
**Given** a canister requests an ECDSA signature
**When** the fee is charged
**Then** the `ecdsa_signature_fee` is charged scaled by subnet size

### SCENARIO-CYC-031: Schnorr signature fee
**Given** a canister requests a Schnorr signature
**When** the fee is charged
**Then** the `schnorr_signature_fee` is charged scaled by subnet size

### SCENARIO-CYC-032: VetKd fee
**Given** a canister requests VetKd key derivation
**When** the fee is charged
**Then** the `vetkd_fee` is charged scaled by subnet size

---

## REQ-CYC-014: Canister Log Fetching Fees

Fetching canister logs MUST incur a response-size-based fee.

### SCENARIO-CYC-033: Fetch canister logs fee
**Given** canister logs are fetched with a given response size
**When** the fee is charged
**Then** fee = `(fetch_canister_logs_base_fee + fetch_canister_logs_per_byte_fee * response_size) * subnet_size`

### SCENARIO-CYC-034: Maximum fetch canister logs fee
**Given** the maximum log fetch fee is computed
**When** prepayment is calculated
**Then** it uses `MAX_FETCH_CANISTER_LOGS_RESPONSE_BYTES` as the response size

---

## REQ-CYC-014b: Canister Deletion Leftover Cycles

When a canister is deleted, remaining cycles MUST be accounted for.

### SCENARIO-CYC-045: Compute leftover cycles on deletion
**Given** a canister is being deleted
**When** leftover cycles are computed
**Then** leftover = `balance + reserved_balance`
**And** the leftover is converted to `NominalCycles` for accounting purposes
**And** these cycles are destroyed (not transferred elsewhere)

---

## REQ-CYC-015: Cycles Burn

Canisters MUST be able to explicitly burn cycles, subject to the freezing threshold.

### SCENARIO-CYC-035: Burn cycles respecting freezing threshold
**Given** a canister calls `ic0.cycles_burn128` to burn a specified amount
**When** the burn executes
**Then** actual burned = `min(amount_to_burn, balance - freezing_threshold)`
**And** if balance ≤ freezing threshold, zero cycles are burned

---

## REQ-CYC-016: Reserved Balance Draining

Resource-related charges MUST drain the reserved balance before the main balance.

### SCENARIO-CYC-036: Resource charges drain reserved balance first
**Given** a canister is charged for Memory, ComputeAllocation, or Uninstall use cases
**When** the charge is applied
**Then** the effective balance for threshold comparison is `balance + reserved_balance`
**And** the charge is first deducted from the reserved balance
**And** only after reserved balance is exhausted is the main balance used

### SCENARIO-CYC-037: Non-resource charges use main balance only
**Given** a canister is charged for non-resource use cases (IngressInduction, Instructions, etc.)
**When** the charge is applied
**Then** only the main balance is used
**And** the reserved balance is not included in threshold comparison

---

## REQ-CYC-017: Wasm32 vs Wasm64 Execution Fees

Different per-instruction fee rates MUST apply for Wasm32 and Wasm64 execution modes.

### SCENARIO-CYC-038: Wasm32 execution cost
**Given** a canister running in Wasm32 mode executes instructions
**When** the cost is computed
**Then** cost = `instructions * ten_update_instructions_execution_fee / 10`

### SCENARIO-CYC-039: Wasm64 execution cost
**Given** a canister running in Wasm64 mode executes instructions
**When** the cost is computed
**Then** it uses the `ten_update_instructions_execution_fee_wasm64` rate
**And** this rate may differ from the Wasm32 rate

### SCENARIO-CYC-040: Execution cost includes per-message fee
**Given** execution cost is computed for any Wasm mode
**When** the total is determined
**Then** total = `scale_cost(update_message_execution_fee + instruction_cost, subnet_size, cost_schedule)`

---

## REQ-CYC-018: Message Memory Billing

Message memory MUST be tracked and billed separately from heap/stable memory.

### SCENARIO-CYC-041: Idle burn rate includes message memory
**Given** the idle burn rate is calculated
**When** components are summed
**Then** three components are summed: heap/stable memory cost + message memory cost + compute allocation cost
**And** message memory cost uses `message_memory_usage.total()` at the same per-byte rate as heap memory

### SCENARIO-CYC-042: Freezing threshold accounts for message memory
**Given** the freezing threshold is evaluated
**When** the threshold is computed
**Then** the idle burn rate used includes message memory costs
**And** canisters with large message queues have proportionally higher freezing thresholds

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-CYC-001 | Fee scaling | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-002 | Execution cycles | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-003 | Freezing threshold | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-004 | Ingress fees | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-005 | Inter-canister call fees | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-006 | Creation fee | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-007 | Storage fees | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-008 | Resource reservation | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-009 | Cycles transfer | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-010 | HTTP outcall fees | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-011 | System subnet | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-012 | Mint cycles | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-013 | Signature fees | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-014 | Log fetch fees | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-015 | Cycles burn | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-016 | Reserved balance draining | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-017 | Wasm32/Wasm64 fees | narrative | rs/cycles_account_manager/tests/ |
| REQ-CYC-018 | Message memory billing | narrative | rs/cycles_account_manager/tests/ |
