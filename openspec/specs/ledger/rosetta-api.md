# Rosetta API

**Crates**: `ic-rosetta-api`

The Rosetta API implementation provides a standard interface (Coinbase Rosetta specification) for interacting with the ICP and ICRC-1 ledgers. There are two separate implementations: one for ICP (with neuron management extensions) and one for ICRC-1 tokens (supporting multiple tokens). Both implement the Construction API and Data API.

## Requirements

### Requirement: ICP Rosetta - Network Identification

The ICP Rosetta node identifies its network using the blockchain name and the ledger canister ID.

#### Scenario: Network list
- **WHEN** `/network/list` is called
- **THEN** the response includes the network identifier with blockchain name (default: "Internet Computer") and the hex-encoded ledger canister ID

#### Scenario: Network options
- **WHEN** `/network/options` is called
- **THEN** the response includes the API version, node version, and allowed operation types
- **AND** the allowed operation types include: TRANSACTION, MINT, BURN, FEE, STAKE, START_DISSOLVE, STOP_DISSOLVE, SET_DISSOLVE_TIMESTAMP, DISBURSE, ADD_HOT_KEY, REMOVE_HOTKEY, SPAWN, REGISTER_VOTE, STAKE_MATURITY, NEURON_INFO, LIST_NEURONS, FOLLOW, REFRESH_VOTING_POWER, CHANGE_AUTO_STAKE_MATURITY, DISBURSE_MATURITY

#### Scenario: Network status
- **WHEN** `/network/status` is called
- **THEN** the response includes the current block identifier (index and hash)
- **AND** the genesis block identifier
- **AND** the current timestamp

### Requirement: ICP Rosetta - Data API

The Data API provides block and transaction queries.

#### Scenario: Get block by index
- **WHEN** `/block` is called with a block index
- **THEN** the corresponding block is returned with its transactions
- **AND** the block identifier includes the index and hash

#### Scenario: Get block by hash
- **WHEN** `/block` is called with a block hash
- **THEN** the corresponding block is returned

#### Scenario: Get block transaction
- **WHEN** `/block/transaction` is called with block and transaction identifiers
- **THEN** the specific transaction within the block is returned

#### Scenario: Search transactions
- **WHEN** `/search/transactions` is called
- **THEN** up to 10,000 matching transactions are returned
- **AND** results can be filtered by account, transaction type, or other criteria

#### Scenario: Account balance
- **WHEN** `/account/balance` is called with an account identifier
- **THEN** the current balance is returned
- **AND** historical balance lookup is supported (at a specific block height)

### Requirement: ICP Rosetta - Construction API

The Construction API enables offline transaction construction and online submission.

#### Scenario: Construction derive
- **WHEN** `/construction/derive` is called with a public key
- **THEN** the corresponding account identifier is derived
- **AND** the account uses the standard ICP `AccountIdentifier` derivation

#### Scenario: Construction preprocess
- **WHEN** `/construction/preprocess` is called with operations
- **THEN** the options needed for metadata lookup are returned
- **AND** required public keys are identified

#### Scenario: Construction metadata
- **WHEN** `/construction/metadata` is called with options
- **THEN** the suggested fee and other metadata are returned

#### Scenario: Construction payloads
- **WHEN** `/construction/payloads` is called with operations and metadata
- **THEN** unsigned transaction payloads are generated
- **AND** signing payloads for each required signer are returned

#### Scenario: Construction combine
- **WHEN** `/construction/combine` is called with an unsigned transaction and signatures
- **THEN** the signed transaction is assembled

#### Scenario: Construction parse
- **WHEN** `/construction/parse` is called with a signed or unsigned transaction
- **THEN** the operations within the transaction are extracted
- **AND** the signers are identified (for signed transactions)

#### Scenario: Construction hash
- **WHEN** `/construction/hash` is called with a signed transaction
- **THEN** the transaction hash (using IC request domain separator) is returned

#### Scenario: Construction submit
- **WHEN** `/construction/submit` is called with a signed transaction
- **THEN** the transaction is submitted to the ledger
- **AND** the transaction identifier and block index are returned on success

### Requirement: ICP Rosetta - Transfer Operations

ICP Rosetta maps ledger transfers to Rosetta operations.

#### Scenario: Transfer operation mapping
- **WHEN** a transfer is represented in Rosetta
- **THEN** it includes three operations:
  1. TRANSACTION (debit from sender, negative amount)
  2. TRANSACTION (credit to receiver, positive amount)
  3. FEE (debit from sender, negative fee amount)
- **AND** all operations have status "COMPLETED"

#### Scenario: Mint operation mapping
- **WHEN** a mint is represented in Rosetta
- **THEN** it includes a single MINT operation with positive amount
- **AND** the account is the recipient

#### Scenario: Burn operation mapping
- **WHEN** a burn is represented in Rosetta
- **THEN** it includes a single BURN operation with negative amount
- **AND** the account is the sender

### Requirement: ICP Rosetta - Neuron Management

ICP Rosetta supports NNS governance neuron management operations.

#### Scenario: Stake neuron
- **WHEN** a STAKE operation is submitted
- **THEN** ICP tokens are transferred to a neuron account
- **AND** a manage_neuron call is made to claim or refresh the neuron

#### Scenario: Start dissolving
- **WHEN** a START_DISSOLVE operation is submitted with a neuron_index
- **THEN** a manage_neuron call starts the dissolve process

#### Scenario: Stop dissolving
- **WHEN** a STOP_DISSOLVE operation is submitted with a neuron_index
- **THEN** a manage_neuron call stops the dissolve process

#### Scenario: Set dissolve timestamp
- **WHEN** a SET_DISSOLVE_TIMESTAMP operation is submitted
- **THEN** the neuron's dissolve timestamp is set to the specified value

#### Scenario: Disburse neuron
- **WHEN** a DISBURSE operation is submitted
- **THEN** the neuron's staked ICP is returned to the specified account

#### Scenario: Add hotkey
- **WHEN** an ADD_HOT_KEY operation is submitted
- **THEN** the specified principal is added as a hotkey to the neuron

#### Scenario: Remove hotkey
- **WHEN** a REMOVE_HOTKEY operation is submitted
- **THEN** the specified principal is removed as a hotkey from the neuron

#### Scenario: Spawn neuron
- **WHEN** a SPAWN operation is submitted
- **THEN** maturity is used to create a new neuron

#### Scenario: Register vote
- **WHEN** a REGISTER_VOTE operation is submitted
- **THEN** the neuron votes on the specified proposal

#### Scenario: Stake maturity
- **WHEN** a STAKE_MATURITY operation is submitted
- **THEN** the neuron's maturity is staked

#### Scenario: Follow
- **WHEN** a FOLLOW operation is submitted
- **THEN** the neuron follows the specified neurons for the given topic

#### Scenario: Neuron info query
- **WHEN** a NEURON_INFO operation is submitted
- **THEN** the neuron's state, dissolve delay, and other information are returned

#### Scenario: List neurons
- **WHEN** a LIST_NEURONS operation is submitted
- **THEN** the neurons controlled by the caller are returned

#### Scenario: Refresh voting power
- **WHEN** a REFRESH_VOTING_POWER operation is submitted
- **THEN** the neuron's voting power is refreshed

#### Scenario: Disburse maturity
- **WHEN** a DISBURSE_MATURITY operation is submitted
- **THEN** the neuron's maturity is disbursed to the specified account

#### Scenario: Change auto-stake maturity
- **WHEN** a CHANGE_AUTO_STAKE_MATURITY operation is submitted
- **THEN** the neuron's auto-stake maturity setting is toggled

### Requirement: ICP Rosetta - Block Synchronization

ICP Rosetta synchronizes blocks from the ledger and its archives.

#### Scenario: Initial sync
- **WHEN** ICP Rosetta starts
- **THEN** it fetches all blocks from the ledger and archive canisters
- **AND** blocks are stored locally for query serving

#### Scenario: Ongoing sync
- **WHEN** new blocks are produced on the ledger
- **THEN** Rosetta periodically fetches and stores the new blocks

#### Scenario: Rosetta blocks mode
- **WHEN** Rosetta is configured in a specific blocks mode
- **THEN** it can serve blocks in the configured format (raw or Rosetta blocks)

### Requirement: ICRC-1 Rosetta - Network Identification

ICRC-1 Rosetta supports multiple tokens via a multi-token architecture.

#### Scenario: Network list for multiple tokens
- **WHEN** `/network/list` is called
- **THEN** the response includes a network identifier for each configured ledger
- **AND** each network uses blockchain "Internet Computer" and the ledger canister ID as network ID

#### Scenario: Network options
- **WHEN** `/network/options` is called for a specific ledger
- **THEN** the response includes the Rosetta version, node version, and allowed operation types
- **AND** operation types include the ICRC-1 operation types (Transfer, Approve, Burn, Mint, SpenderTransfer)

### Requirement: ICRC-1 Rosetta - Data API

#### Scenario: Network status
- **WHEN** `/network/status` is called
- **THEN** the highest processed block index and its hash are returned
- **AND** the genesis block identifier is included

#### Scenario: Account balance
- **WHEN** `/account/balance` is called with an ICRC-1 account
- **THEN** the balance for that account is returned from the storage client
- **AND** historical balance lookup is supported

#### Scenario: Get block
- **WHEN** `/block` is called with a block identifier
- **THEN** the ICRC-1 Rosetta block is converted to a Rosetta core block
- **AND** the block's transactions include all ICRC-1 operations

#### Scenario: Search transactions
- **WHEN** `/search/transactions` is called
- **THEN** matching transactions are returned
- **AND** the maximum results per request is configurable (default limited)

#### Scenario: Query block range
- **WHEN** a block range query is issued
- **THEN** blocks within the range are returned
- **AND** the maximum blocks per range request is enforced

### Requirement: ICRC-1 Rosetta - Construction API

#### Scenario: Construction derive
- **WHEN** `/construction/derive` is called with an Ed25519 or secp256k1 public key
- **THEN** the principal ID is derived from the public key
- **AND** the ICRC-1 account (principal with no subaccount) is returned

#### Scenario: Construction preprocess
- **WHEN** `/construction/preprocess` is called with transfer operations
- **THEN** the caller principal is extracted from the operations
- **AND** required public keys are returned

#### Scenario: Construction metadata
- **WHEN** `/construction/metadata` is called with `suggested_fee: true`
- **THEN** the ledger's current fee is queried via the ICRC-1 agent
- **AND** the fee is returned in the response currency

#### Scenario: Construction payloads
- **WHEN** `/construction/payloads` is called with ICRC-1 transfer operations
- **THEN** unsigned transaction payloads are generated
- **AND** the payloads include the ICRC-1 transfer arguments

#### Scenario: Construction submit
- **WHEN** `/construction/submit` is called with a signed ICRC-1 transaction
- **THEN** the transaction is submitted to the ICRC-1 ledger canister
- **AND** the transaction identifier (block index hash) is returned

#### Scenario: Construction hash
- **WHEN** `/construction/hash` is called with a signed transaction
- **THEN** the hash of the signed transaction envelope is returned

#### Scenario: Construction combine
- **WHEN** `/construction/combine` is called
- **THEN** the unsigned transaction and signature are combined into a signed transaction

### Requirement: ICRC-1 Rosetta - Block Synchronization

#### Scenario: Synchronize from ledger and archives
- **WHEN** the block synchronizer runs
- **THEN** it fetches blocks from the ICRC-1 ledger using `icrc3_get_blocks`
- **AND** it discovers archive canisters
- **AND** blocks are stored in the local storage client

#### Scenario: Gap detection and repair
- **WHEN** gaps are detected in the local block storage
- **THEN** the synchronizer identifies the missing ranges
- **AND** fetches the missing blocks to fill the gaps

#### Scenario: Recurrent synchronization
- **WHEN** the synchronizer is in `Recurrent` mode
- **THEN** it periodically checks for new blocks
- **AND** uses configurable min/max wait times with exponential backoff on failures

#### Scenario: One-shot synchronization
- **WHEN** the synchronizer is in `OneShot` mode
- **THEN** it synchronizes once and stops

### Requirement: ICRC-1 Rosetta - Metadata

ICRC-1 Rosetta extracts metadata from the ledger for currency representation.

#### Scenario: Currency from metadata
- **WHEN** the ICRC-1 Rosetta starts
- **THEN** it queries the ledger for `icrc1:symbol` and `icrc1:decimals`
- **AND** uses these to construct the Rosetta `Currency` object

### Requirement: ICRC-1 Rosetta - Storage

The ICRC-1 Rosetta node stores synchronized blocks locally.

#### Scenario: Block storage and retrieval
- **WHEN** blocks are synchronized
- **THEN** they are stored as `RosettaBlock` entries in the storage client
- **AND** blocks can be retrieved by index or hash

#### Scenario: Highest processed block
- **WHEN** the highest processed block is queried
- **THEN** the index of the most recently stored block is returned

### Requirement: Rosetta Error Handling

Both Rosetta implementations return structured errors.

#### Scenario: Invalid network identifier
- **WHEN** a request includes a network identifier that does not match
- **THEN** an error with appropriate code and message is returned

#### Scenario: Block not found
- **WHEN** a requested block index or hash does not exist
- **THEN** an error indicating the block was not found is returned

#### Scenario: Ledger communication failure
- **WHEN** the Rosetta node cannot communicate with the ledger canister
- **THEN** an error indicating communication failure is returned

#### Scenario: Transaction submission failure
- **WHEN** a submitted transaction is rejected by the ledger
- **THEN** the ledger's error is mapped to a Rosetta error response
