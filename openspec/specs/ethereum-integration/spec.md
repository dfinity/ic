# Ethereum Integration

## Requirements

### Requirement: ckETH Minter - Deposit (ETH to ckETH)
The ckETH minter scrapes Ethereum logs from a helper smart contract to detect ETH and ERC-20 deposits, then mints corresponding ckETH or ckERC20 tokens on the IC ledger.

#### Scenario: Ethereum log scraping
- **WHEN** the scraping timer fires (every 3 minutes, `SCRAPING_ETH_LOGS_INTERVAL`)
- **THEN** the minter queries the latest block number via the EVM RPC canister
- **AND** it scrapes logs from the helper smart contract in the range (last_scraped + 1, latest_block)
- **AND** logs are scraped in chunks with a maximum block spread of 500

#### Scenario: ETH deposit event detected
- **WHEN** a `ReceivedEthEvent` log is parsed from the helper contract
- **THEN** the event source (transaction hash + log index) is recorded
- **AND** the deposit amount and beneficiary IC account are extracted
- **AND** the event is queued for minting

#### Scenario: ERC-20 deposit event detected
- **WHEN** a `ReceivedErc20Event` log is parsed
- **THEN** the ERC-20 contract address is validated against supported tokens
- **AND** the corresponding ckERC20 ledger is identified
- **AND** the event is queued for minting with the correct token symbol

#### Scenario: Deposit with subaccount support
- **WHEN** a deposit event is detected from the deposit-with-subaccount helper contract
- **THEN** both ETH and ERC-20 deposits with subaccount specification are supported
- **AND** a separate log scraping instance tracks this contract

#### Scenario: Blocked address deposit rejected
- **WHEN** a deposit event is from a blocked (OFAC-sanctioned) address
- **THEN** the deposit is recorded as `InvalidDeposit` with reason "blocked address"
- **AND** no tokens are minted for the deposit
- **AND** the ETH/ERC-20 balance is NOT updated

#### Scenario: Minting ckETH tokens
- **WHEN** events are ready to mint
- **THEN** a mint timer is immediately scheduled
- **AND** for each event, an ICRC-1 transfer is made to the beneficiary account
- **AND** a memo encoding the deposit details is included
- **AND** on success, a `MintedCkEth` event is recorded with the block index

#### Scenario: Minting ckERC20 tokens
- **WHEN** an ERC-20 deposit event is minted
- **THEN** the transfer is sent to the ckERC20-specific ledger canister
- **AND** a `MintedCkErc20` event is recorded with the ERC-20 contract address and token symbol

#### Scenario: Double-minting prevention
- **WHEN** a mint operation is in progress
- **THEN** a scope guard quarantines the event if a panic occurs during the callback
- **AND** quarantined deposits are marked `QuarantinedDeposit` and will not be processed again
- **AND** successful mints are moved from `events_to_mint` to `minted_events`

#### Scenario: Mint failure with retry
- **WHEN** a mint operation fails (ledger unreachable or transfer error)
- **THEN** the event remains in `events_to_mint`
- **AND** minting is retried after 3 minutes (`MINT_RETRY_DELAY`)
- **AND** the error count is tracked

#### Scenario: Response too large - block range halving
- **WHEN** an `eth_getLogs` call returns a response that is too large
- **THEN** the block range is split in half
- **AND** each half is retried independently
- **AND** if a single block is too large, it is skipped with a `SkippedBlockForContract` event

---

### Requirement: ckETH Minter - Withdrawal (ckETH to ETH)
Users burn ckETH to withdraw real ETH to an Ethereum address. The minter creates, signs, and sends EIP-1559 transactions.

#### Scenario: Withdrawal request processing
- **WHEN** `process_retrieve_eth_requests` is triggered (every 6 minutes)
- **THEN** pending withdrawal requests are processed in batches of 5
- **AND** the gas fee estimate is refreshed
- **AND** transactions are created, signed, sent, and finalized in sequence

#### Scenario: EIP-1559 transaction creation
- **WHEN** a withdrawal request is processed
- **THEN** an `Eip1559TransactionRequest` is created with:
  - `chain_id` matching the Ethereum network
  - `nonce` from the minter's next transaction nonce
  - `max_priority_fee_per_gas` from the gas fee estimate
  - `max_fee_per_gas = 2 * base_fee_per_gas + max_priority_fee_per_gas`
  - `gas_limit` of 21,000 for ETH withdrawals or 65,000 for ERC-20 withdrawals
  - `destination` as the withdrawal Ethereum address
  - `amount` as the withdrawal amount minus transaction fees

#### Scenario: Transaction signing with threshold ECDSA
- **WHEN** a transaction is signed
- **THEN** the EIP-1559 transaction hash is computed as `keccak256(0x02 || rlp([fields...]))`
- **AND** the hash is signed using `sign_with_ecdsa` with the minter's key
- **AND** the recovery ID is computed to determine `signature_y_parity`
- **AND** the raw signed transaction is `0x02 || rlp([fields..., y_parity, r, s])`

#### Scenario: Transaction sending
- **WHEN** signed transactions are ready to send
- **THEN** they are sent in batches of 5 via `eth_sendRawTransaction` through the EVM RPC canister
- **AND** `NonceTooLow` responses are acceptable (transaction may have been mined from resubmission)
- **AND** `InsufficientFunds` or `NonceTooHigh` are logged for later retry

#### Scenario: Transaction finalization
- **WHEN** the finalized transaction count exceeds a sent transaction's nonce
- **THEN** the transaction receipt is fetched via `eth_getTransactionReceipt`
- **AND** a `FinalizedTransaction` event is recorded
- **AND** the ETH balance is updated based on the transaction status

#### Scenario: Transaction resubmission with fee bumping
- **WHEN** a sent transaction has not been mined
- **THEN** a new transaction is created with at least 10% higher `max_priority_fee_per_gas`
- **AND** the `max_fee_per_gas` is increased only to the minimum required
- **AND** for `ReduceEthAmount` strategy, the ETH amount is reduced to cover the higher fee
- **AND** for `GuaranteeEthAmount` strategy, the ETH amount stays the same

#### Scenario: Insufficient transaction fee for creation
- **WHEN** the withdrawal amount cannot cover the transaction fee
- **THEN** the request is rescheduled to the end of the queue
- **AND** an informational log is emitted

#### Scenario: Reimbursement processing
- **WHEN** a transaction fails or has unspent fees
- **THEN** reimbursement requests are created for the affected users
- **AND** ckETH or ckERC20 tokens are minted back to the user
- **AND** a quarantine guard prevents double reimbursement on panic

---

### Requirement: ckETH Minter - Ethereum Address Handling
The minter derives its Ethereum address from its ECDSA public key.

#### Scenario: Minter address derivation
- **WHEN** the minter's Ethereum address is needed
- **THEN** the ECDSA public key is lazily fetched from the management canister
- **AND** the uncompressed public key (without 0x04 prefix) is hashed with Keccak-256
- **AND** the last 20 bytes of the hash form the Ethereum address

#### Scenario: Destination address validation
- **WHEN** a withdrawal destination address is validated
- **THEN** the address must parse as a valid Ethereum address
- **AND** the zero address (0x0000...0000) is rejected as unsupported
- **AND** addresses on the OFAC blocklist are rejected as blocked

---

### Requirement: ckETH Minter - Gas Fee Estimation
The minter estimates Ethereum gas fees using the EIP-1559 fee model.

#### Scenario: Gas fee estimation from fee history
- **WHEN** the gas fee estimate is refreshed
- **THEN** `eth_feeHistory` is called for the last 5 blocks with the 20th reward percentile
- **AND** `base_fee_per_gas` is the last entry in the response (next block estimate)
- **AND** `max_priority_fee_per_gas` is the median of the 5 reward values
- **AND** the minimum priority fee is 1.5 gwei (`MIN_MAX_PRIORITY_FEE_PER_GAS`)
- **AND** `max_fee_per_gas = 2 * base_fee_per_gas + max_priority_fee_per_gas`

#### Scenario: Gas fee estimate caching
- **WHEN** the fee estimate is younger than 60 seconds
- **THEN** the cached estimate is returned without querying the network

#### Scenario: Fee estimation overflow protection
- **WHEN** `max_fee_per_gas` would overflow
- **THEN** `WeiPerGas::MAX` is used instead

---

### Requirement: ckETH Minter - EIP-1559 Transaction Encoding
Ethereum transactions follow the EIP-1559 encoding standard.

#### Scenario: Transaction RLP encoding
- **WHEN** an EIP-1559 transaction is encoded
- **THEN** the format is `0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount, data, access_list])`
- **AND** for signed transactions, `[..., signature_y_parity, r, s]` is appended inside the RLP

#### Scenario: Transaction hash computation
- **WHEN** a signed transaction hash is computed
- **THEN** the hash is `keccak256(0x02 || rlp([all_fields_including_signature]))`

#### Scenario: Transaction finalization validation
- **WHEN** a signed transaction is finalized with a receipt
- **THEN** the receipt's transaction hash must match the signed transaction hash
- **AND** `effective_gas_price <= max_fee_per_gas`
- **AND** `gas_used <= gas_limit`

---

### Requirement: ckETH Minter - State Management
The minter maintains a comprehensive state tracking deposits, withdrawals, and token balances.

#### Scenario: State configuration validation
- **WHEN** the minter state is validated
- **THEN** `ecdsa_key_name` must not be blank
- **AND** `cketh_ledger_id` must not be the anonymous principal
- **AND** `minimum_withdrawal_amount` must be positive
- **AND** `minimum_withdrawal_amount` must cover the ledger transfer fee (2 trillion Wei for mainnet, 10 billion for Sepolia)

#### Scenario: ETH balance tracking
- **WHEN** deposits and withdrawals occur
- **THEN** `eth_balance` is incremented on deposits and decremented on withdrawals
- **AND** `total_effective_tx_fees` tracks actual gas fees paid
- **AND** `total_unspent_tx_fees` tracks the difference between charged and actual fees

#### Scenario: ERC-20 balance tracking
- **WHEN** ERC-20 deposits and withdrawals occur
- **THEN** balances are tracked per ERC-20 contract address
- **AND** subtracting below zero panics (indicates a bug)

#### Scenario: Event-sourced state equivalence
- **WHEN** the state is reconstructed from the event log after upgrade
- **THEN** the reconstructed state is equivalent to the pre-upgrade state for all practical purposes
- **AND** computed fields (like `ecdsa_public_key`) and transient fields (like `active_tasks`) are excluded from comparison

#### Scenario: Concurrent task prevention
- **WHEN** a timer task attempts to run
- **THEN** a `TimerGuard` is acquired for the task type
- **AND** if the guard is already held, the task is skipped
- **AND** task types include: Mint, RetrieveEth, ScrapEthLogs, RefreshGasFeeEstimate, Reimbursement, MintCkErc20

#### Scenario: ckERC20 token management
- **WHEN** a new ckERC20 token is added
- **THEN** the token symbol must be unique across all supported tokens
- **AND** the ledger ID and ERC-20 contract address must be unique
- **AND** the ERC-20 network must match the minter's Ethereum network

#### Scenario: Skipped blocks tracking
- **WHEN** a block is skipped due to response size limits
- **THEN** the block number and contract address are recorded
- **AND** the same block cannot be skipped twice

---

### Requirement: ckETH Minter - EVM RPC Integration
The minter communicates with Ethereum through the EVM RPC canister using multi-call patterns.

#### Scenario: Multi-provider RPC calls
- **WHEN** the minter makes an RPC call
- **THEN** the call is sent to multiple providers through the EVM RPC canister
- **AND** results are reduced using strategies: `NoReduction` (all must agree), `MinByKey`, `StrictMajorityByKey`, or `AnyOf`

#### Scenario: Minimum attached cycles
- **WHEN** an RPC call is made through the EVM RPC canister
- **THEN** a minimum number of cycles is attached (`MIN_ATTACHED_CYCLES`)

---

### Requirement: ckETH Minter - Blocklist (OFAC Compliance)
The minter maintains a blocklist of Ethereum addresses for sanctions compliance.

#### Scenario: Blocked deposit address
- **WHEN** a deposit event's `from_address` is on the blocklist
- **THEN** the deposit is recorded as invalid with reason "blocked address"
- **AND** no tokens are minted

#### Scenario: Blocked withdrawal address
- **WHEN** a withdrawal destination address is on the blocklist
- **THEN** the withdrawal is rejected with `AddressValidationError::Blocked`

---

### Requirement: Ledger Suite Orchestrator
The orchestrator manages the lifecycle of ckERC20 ledger suites (ledger + index + archive canisters).

#### Scenario: Install new ledger suite
- **WHEN** a new ERC-20 token is added via `AddErc20Arg`
- **THEN** a task is scheduled to install a new ledger suite
- **AND** a ledger canister, index canister, and potentially archive canisters are created
- **AND** the ERC-20 token is registered with the minter via `NotifyErc20Added`

#### Scenario: Upgrade ledger suite
- **WHEN** an upgrade is triggered for existing canisters
- **THEN** each canister (ledger, index, archive) is upgraded with new WASM
- **AND** upgrades are processed as tasks in the scheduler

#### Scenario: Periodic top-up
- **WHEN** the `MaybeTopUp` periodic task runs
- **THEN** managed canisters are checked for cycle balance
- **AND** canisters below the threshold are topped up

#### Scenario: Archive discovery
- **WHEN** the `DiscoverArchives` periodic task runs
- **THEN** the orchestrator queries ledger canisters for their archive canister IDs
- **AND** newly discovered archives are added to the managed canister set

#### Scenario: Task scheduling
- **WHEN** multiple tasks are scheduled
- **THEN** only one copy of each task type is kept (with the earliest deadline)
- **AND** periodic tasks are rescheduled after execution
- **AND** non-periodic tasks (install, upgrade, notify) run once

---

### Requirement: ckETH Minter - Memo Encoding
Transaction memos encode deposit and withdrawal metadata for auditability.

#### Scenario: Deposit memo
- **WHEN** ckETH or ckERC20 is minted from a deposit
- **THEN** the memo encodes the Ethereum transaction details (event source, amounts)
- **AND** the memo size does not exceed 80 bytes (`CKETH_LEDGER_MEMO_SIZE`)

#### Scenario: Reimbursement memo
- **WHEN** a reimbursement is processed
- **THEN** the memo encodes the original burn details and reimbursement reason
