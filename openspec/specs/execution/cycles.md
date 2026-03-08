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
