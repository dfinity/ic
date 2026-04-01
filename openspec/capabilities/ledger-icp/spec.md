# Ledger: ICP Ledger Capability Specification

**Source narrative**: `openspec/specs/ledger/icp-ledger.md`
**Crates**: `icp-ledger`, `ledger-canister`
**Key files**: `rs/ledger_suite/icp/ledger/`

---

## REQ-ICP-001: Token Representation

ICP tokens MUST be represented as `Tokens` (wrapper around `u64` in e8s, 10^-8 ICP).

### SCENARIO-ICP-001: Construct tokens from whole and fractional parts
**Given** a caller constructs `Tokens::new(12, 200)`
**When** the value is examined
**Then** `get_e8s()` returns `1_200_000_200` and `get_tokens()` returns `12`

### SCENARIO-ICP-002: Reject fractional part ≥ one token
**Given** a caller constructs `Tokens::new(1, 100_000_000)`
**When** construction runs
**Then** construction fails (fractional part must be < `TOKEN_SUBDIVIDABLE_BY`)

---

## REQ-ICP-002: Account Identification

ICP MUST use `AccountIdentifier` (SHA-224 hash of principal + subaccount).

### SCENARIO-ICP-003: Derive account identifier from principal
**Given** an `AccountIdentifier` is computed from a `PrincipalId` and `Subaccount`
**When** the computation runs
**Then** the result is SHA-224 of domain separator + principal bytes + subaccount bytes
**And** the first 4 bytes are a CRC-32 checksum of the remaining 28 bytes

---

## REQ-ICP-003: Transfer Operation

Transfers MUST move tokens from one account to another deducting a fee.

### SCENARIO-ICP-004: Successful transfer
**Given** account A has balance ≥ amount + fee
**When** a transfer of `amount` from A to B is submitted
**Then** A's balance decreases by `amount + fee`
**And** B's balance increases by `amount`
**And** the fee is burned (or credited to fee collector if configured)
**And** a new block is appended and its index/hash returned

### SCENARIO-ICP-005: Insufficient funds
**Given** account A has balance < amount + fee
**When** a transfer is attempted
**Then** the transfer fails with `InsufficientFunds { balance }`
**And** no balances are modified

---

## REQ-ICP-004: Minting and Burning

The minting account MUST be able to mint and burn tokens without fees.

### SCENARIO-ICP-006: Successful mint
**Given** the minting account initiates a mint of `amount` to account B
**When** the mint runs
**Then** B's balance increases by `amount`
**And** no fee is charged

### SCENARIO-ICP-007: Successful burn
**Given** account A has balance ≥ amount and initiates a burn
**When** the burn runs
**Then** A's balance decreases by `amount`
**And** no fee is charged

---

## REQ-ICP-005: ICRC-2 Approvals

The ICP ledger MUST support ICRC-2 approve/transfer_from for delegated transfers.

### SCENARIO-ICP-008: Successful approval
**Given** account A approves spender S for `allowance`
**When** the approval runs
**Then** the approval fee is deducted from A's balance (burned)
**And** the allowance for (A, S) is set to `allowance`

### SCENARIO-ICP-009: Approval with expected_allowance check
**Given** an approval specifies `expected_allowance` and the current allowance does not match
**When** the approval runs
**Then** the approval fails with `AllowanceChanged { current_allowance }`

### SCENARIO-ICP-010: Successful transfer_from
**Given** spender S has allowance ≥ amount for owner A and A has balance ≥ amount
**When** transfer_from runs
**Then** the transfer succeeds and the allowance decreases by the used amount

### SCENARIO-ICP-011: Insufficient allowance
**Given** spender S has allowance < amount for owner A
**When** transfer_from runs
**Then** the transfer fails with `InsufficientAllowance { allowance }`

---

## REQ-ICP-006: Transaction Deduplication

The ledger MUST detect duplicate transactions within a configurable time window.

### SCENARIO-ICP-012: Duplicate detection within window
**Given** a transaction with `created_at_time` and identical content is submitted twice within the window
**When** the second submission is processed
**Then** it is rejected as a duplicate

---

## Traceability

| ID | Description | Status | Tests |
|----|-------------|--------|-------|
| REQ-ICP-001 | Token representation | narrative | rs/ledger_suite/icp/tests/ |
| REQ-ICP-002 | Account identification | narrative | rs/ledger_suite/icp/tests/ |
| REQ-ICP-003 | Transfer operation | narrative | rs/ledger_suite/icp/tests/ |
| REQ-ICP-004 | Mint and burn | narrative | rs/ledger_suite/icp/tests/ |
| REQ-ICP-005 | ICRC-2 approvals | narrative | rs/ledger_suite/icp/tests/ |
| REQ-ICP-006 | Deduplication | narrative | rs/ledger_suite/icp/tests/ |
