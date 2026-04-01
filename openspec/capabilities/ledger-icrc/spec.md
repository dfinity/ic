# Ledger: ICRC Standards Capability Specification

**Source narrative**: `openspec/specs/ledger/icrc-standards.md`
**Crates**: `icrc-ledger`, `icrc1-ledger`, `ic-icrc1-tokens-u64`, `ic-icrc1-tokens-u256`
**Key files**: `rs/ledger_suite/icrc1/`

---

## REQ-ICRC-001: ICRC-1 Transfer

The ledger MUST implement the ICRC-1 core fungible token interface.

### SCENARIO-ICRC-001: Successful icrc1_transfer
**Given** a caller transfers `amount` from their account to a destination
**And** the caller's balance ≥ amount + fee
**When** `icrc1_transfer` runs
**Then** the caller's balance decreases by `amount + fee`
**And** the destination balance increases by `amount`
**And** a block of type "xfer" is recorded
**And** the block index (Nat) is returned

### SCENARIO-ICRC-002: Transfer with explicit fee mismatch
**Given** a transfer specifies `fee` that does not match the ledger's current fee
**When** `icrc1_transfer` runs
**Then** the transfer fails with `BadFee { expected_fee }`

### SCENARIO-ICRC-003: Burn via transfer to minting account
**Given** a transfer is sent to the minting account
**When** `icrc1_transfer` runs
**Then** the operation is treated as a burn
**And** no fee is charged and a block of type "burn" is recorded

### SCENARIO-ICRC-004: Mint from minting account
**Given** the minting account transfers tokens to a regular account
**When** `icrc1_transfer` runs
**Then** new tokens are minted, no fee charged, block of type "mint" recorded

---

## REQ-ICRC-002: ICRC-1 Metadata

The ledger MUST expose token metadata via `icrc1_metadata`.

### SCENARIO-ICRC-005: Query standard metadata
**Given** `icrc1_metadata` is called
**When** the response is returned
**Then** it includes `icrc1:symbol`, `icrc1:name`, `icrc1:decimals`, and `icrc1:fee`

---

## REQ-ICRC-003: ICRC-2 Approve

The ledger MUST support ICRC-2 approve for delegated transfers.

### SCENARIO-ICRC-006: Successful icrc2_approve
**Given** an owner calls `icrc2_approve` with a spender and amount
**When** the approval runs
**Then** the approval fee is deducted from the owner's balance
**And** the allowance for (owner, spender) is set to the specified amount
**And** a block of type "approve" is recorded

### SCENARIO-ICRC-007: Self-approval rejected
**Given** an owner attempts to approve themselves as spender
**When** the approval runs
**Then** the approval is rejected

### SCENARIO-ICRC-008: Approve with expected_allowance
**Given** an approval specifies `expected_allowance` and the current allowance does not match
**When** the approval runs
**Then** the approval fails with the current allowance in the error

---

## REQ-ICRC-004: ICRC-2 Transfer From

The ledger MUST support delegated transfers via `icrc2_transfer_from`.

### SCENARIO-ICRC-009: Successful icrc2_transfer_from
**Given** spender S has allowance ≥ amount for owner A and A has sufficient balance
**When** `icrc2_transfer_from` runs
**Then** the transfer succeeds and the allowance decreases accordingly

### SCENARIO-ICRC-010: Insufficient allowance
**Given** spender S has allowance < amount for owner A
**When** `icrc2_transfer_from` runs
**Then** the transfer fails with `InsufficientAllowance { allowance }`

---

## REQ-ICRC-005: ICRC-1 Supported Standards

The ledger MUST advertise supported standards.

### SCENARIO-ICRC-011: Query supported standards
**Given** `icrc1_supported_standards` is called
**When** the response is returned
**Then** it includes at minimum an entry for "ICRC-1" with its URL
**And** additional standards (ICRC-2, ICRC-3, ICRC-21) are listed if supported

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-ICRC-001 | ICRC-1 transfer | narrative | rs/ledger_suite/icrc1/tests/ |
| REQ-ICRC-002 | ICRC-1 metadata | narrative | rs/ledger_suite/icrc1/tests/ |
| REQ-ICRC-003 | ICRC-2 approve | narrative | rs/ledger_suite/icrc1/tests/ |
| REQ-ICRC-004 | ICRC-2 transfer_from | narrative | rs/ledger_suite/icrc1/tests/ |
| REQ-ICRC-005 | Supported standards | narrative | rs/ledger_suite/icrc1/tests/ |
