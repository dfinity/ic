# Bitcoin Integration

**Crates**: `ic-btc-adapter`, `ic-btc-adapter-client`, `ic-btc-checker`, `ic-btc-consensus`, `ic-btc-replica-types`, `ic-btc-service`, `ic-btc-validation`

## Requirements

### Requirement: Bitcoin Adapter P2P Networking
The Bitcoin adapter connects to the Bitcoin P2P network to obtain blocks and publish transactions. It interacts with the Bitcoin system component to provide blocks and collect outgoing transactions. The adapter supports both Bitcoin and Dogecoin networks through a generic `BlockchainNetwork` abstraction.

#### Scenario: Adapter starts in idle mode
- **WHEN** the adapter starts up
- **THEN** it is in idle mode (no requests received yet)
- **AND** it does not download Bitcoin data unnecessarily
- **AND** it transitions to active mode only after receiving a request

#### Scenario: Adapter enters idle after inactivity
- **WHEN** no requests have been received for the configured `idle_seconds` (default: 3600 seconds)
- **THEN** the adapter transitions to idle mode
- **AND** the block cache is cleared
- **AND** the address book active addresses are cleared

#### Scenario: Adapter connects to Bitcoin network
- **WHEN** the adapter is active and has DNS seeds configured
- **THEN** it resolves seed addresses via DNS lookup
- **AND** it shuffles discovered addresses randomly
- **AND** it establishes TCP (or SOCKS proxy) connections to discovered peers
- **AND** it performs a version handshake within 5 seconds

#### Scenario: IPv6-only mode filtering
- **WHEN** the adapter is configured with `ipv6_only: true`
- **THEN** IPv4 seed addresses are filtered out during DNS resolution
- **AND** IPv4 addresses received in `addr` messages are skipped

#### Scenario: Address book management
- **WHEN** addresses are received in an `addr` message from a peer
- **THEN** up to 1000 addresses per message are accepted
- **AND** only addresses with NETWORK service flag are accepted
- **AND** the sender's own address is excluded
- **AND** addresses are stored until `max_addresses` limit is reached (network-dependent: Bitcoin mainnet 2000, testnet 1000)
- **AND** receiving more than 1000 addresses returns a `TooManyAddresses` error

#### Scenario: Address book provides random addresses
- **WHEN** an address is requested from the address book
- **THEN** a random address is selected from known addresses
- **AND** it is moved from known to active addresses
- **AND** when no addresses remain, `AddressesDepleted` error is returned

#### Scenario: Misbehaving peer address discarded
- **WHEN** a peer misbehaves and has DNS seeds configured
- **THEN** the address is completely removed from the book
- **AND** when no DNS seeds exist (e.g., regtest), the address is returned to known addresses

---

### Requirement: Bitcoin Adapter Configuration
The adapter supports multiple Bitcoin-family networks with network-specific configuration defaults.

#### Scenario: Network-specific address limits
- **WHEN** the adapter is configured for Bitcoin mainnet
- **THEN** address limits are (min: 500, max: 2000)

#### Scenario: Testnet address limits
- **WHEN** the adapter is configured for Bitcoin testnet
- **THEN** address limits are (min: 100, max: 1000)

#### Scenario: Regtest address limits
- **WHEN** the adapter is configured for Bitcoin regtest
- **THEN** address limits are (min: 1, max: 1)

#### Scenario: Request timeout defaults
- **WHEN** the adapter is configured for Bitcoin regtest
- **THEN** the request timeout is 5 seconds
- **AND** for all other networks the request timeout is 30 seconds

#### Scenario: SOCKS proxy support
- **WHEN** a `socks_proxy` URL is configured (e.g., `socks5://socksproxy.com:1080`)
- **THEN** the adapter routes all Bitcoin P2P connections through the SOCKS proxy

---

### Requirement: Blockchain State Management
The adapter maintains a local cache of Bitcoin block headers and blocks, supporting fork detection and active chain selection based on cumulative proof of work.

#### Scenario: Adding valid headers successfully
- **WHEN** a sequence of valid headers is received from Bitcoin peers
- **THEN** all headers are added to the header cache
- **AND** the active chain tip height is updated
- **AND** the tip reflects the header with the highest cumulative work

#### Scenario: Adding mainnet headers with difficulty adjustment
- **WHEN** 2500 mainnet headers are added (covering at least one difficulty adjustment period)
- **THEN** all 2499 headers after genesis are successfully added (genesis is height 0)
- **AND** difficulty adjustments are validated correctly

#### Scenario: Fork handling when adding headers
- **WHEN** headers creating a fork at a given height are added
- **THEN** both forks are tracked as separate tips
- **AND** the active chain tip is the one with the most cumulative work
- **AND** forks are sorted by work in descending order

#### Scenario: Adding duplicate headers
- **WHEN** headers already present in the cache are submitted again
- **THEN** no duplicate entries are created
- **AND** no error is returned

#### Scenario: Adding headers with invalid header
- **WHEN** a sequence of headers contains an invalid header (e.g., `prev_blockhash` set to all zeros)
- **THEN** all valid headers before the invalid one are added
- **AND** an `InvalidHeader` error is returned for the invalid header
- **AND** the tip height reflects only the successfully added headers

#### Scenario: Adding blocks to the cache
- **WHEN** a valid block is submitted
- **THEN** the block's header is validated (added to header cache if missing)
- **AND** the block's merkle root is verified
- **AND** the serialized block is stored in the block cache
- **AND** block size metric is recorded

#### Scenario: Block with invalid merkle root rejected
- **WHEN** a block with a tampered merkle root is submitted
- **THEN** an `InvalidMerkleRoot` error is returned
- **AND** the block is not added to the cache

#### Scenario: Block without preceding header rejected
- **WHEN** a block whose parent header is not in the cache is submitted
- **THEN** an `InvalidHeader(PrevHeaderNotFound)` error is returned

#### Scenario: Block cache size threshold
- **WHEN** the block cache exceeds 10 MB
- **THEN** new `getdata` messages are not sent to peers
- **AND** inflight `getdata` messages remain active

#### Scenario: Pruning blocks from cache
- **WHEN** specific block hashes are pruned
- **THEN** those blocks are removed from the block cache
- **AND** other blocks remain in the cache

#### Scenario: Pruning blocks below height
- **WHEN** blocks below a given height are pruned
- **THEN** only blocks at or above the specified height remain in the cache

#### Scenario: Locator hashes for chain synchronization
- **WHEN** locator hashes are requested
- **THEN** the most recent 8 block hashes from the tip are included
- **AND** exponentially spaced hashes follow (step doubles after 7)
- **AND** the genesis hash is always included as the last element

---

### Requirement: Header Validation
Block headers are validated against network-specific consensus rules including difficulty targets and proof of work.

#### Scenario: Bitcoin header validation
- **WHEN** a Bitcoin header is received
- **THEN** it is validated using `ic_btc_validation::validate_header`
- **AND** the previous header must exist in the cache
- **AND** the header must meet the required difficulty target

#### Scenario: Dogecoin header validation with AuxPow
- **WHEN** a Dogecoin header is received
- **THEN** it is validated using `DogecoinHeaderValidator` with AuxPow (merged mining) support
- **AND** the header must meet Dogecoin-specific difficulty rules

---

### Requirement: Hybrid Header Cache
Headers are stored in a hybrid in-memory and on-disk cache to handle the full Bitcoin header chain efficiently.

#### Scenario: In-memory header storage
- **WHEN** no cache directory is configured
- **THEN** all headers are stored in memory only

#### Scenario: Disk-backed header storage
- **WHEN** a cache directory is configured
- **THEN** headers below the anchor point are persisted to disk
- **AND** headers above the anchor remain in memory
- **AND** disk persistence runs as a background task

---

### Requirement: Bitcoin Consensus Payload Building
The Bitcoin payload builder integrates with the IC consensus layer to produce self-validating payloads containing Bitcoin adapter responses.

#### Scenario: Payload built from adapter responses
- **WHEN** the consensus layer requests a new payload
- **THEN** the payload builder queries the adapter for available responses
- **AND** responses are included in the `SelfValidatingPayload`
- **AND** the payload size does not exceed `MAX_BITCOIN_PAYLOAD_IN_BYTES`

#### Scenario: Adapter supports both Bitcoin and Dogecoin
- **WHEN** the payload builder is initialized
- **THEN** it holds separate adapter clients for Bitcoin mainnet, Bitcoin testnet, Dogecoin mainnet, and Dogecoin testnet

---

### Requirement: GetSuccessors Handler
The handler returns requested blocks to the Bitcoin canister in BFS order for security.

#### Scenario: Blocks returned in BFS order
- **WHEN** the Bitcoin canister requests successor blocks
- **THEN** blocks are returned in breadth-first search order
- **AND** this prevents a malicious fork from being prioritized by DFS, which could ignore honest forks

---

### Requirement: Bitcoin Transaction Store
The adapter manages outgoing transactions from the Bitcoin system component.

#### Scenario: Transaction broadcast
- **WHEN** a `SendTransaction` command is received
- **THEN** the raw transaction bytes are broadcast to connected Bitcoin peers

---

### Requirement: ckBTC Minter - Address Derivation
The ckBTC minter derives unique Bitcoin addresses for each IC account (principal + subaccount) using threshold ECDSA.

#### Scenario: Deriving a P2WPKH address for an account
- **WHEN** `get_btc_address` is called with an owner principal and optional subaccount
- **THEN** the ECDSA public key is lazily initialized if not already present
- **AND** a BIP-32 derivation path is constructed from [schema_v1, principal_bytes, effective_subaccount]
- **AND** the derived public key is hashed with HASH160 to produce a P2WPKH address
- **AND** the address is encoded in bech32 format with the correct human-readable prefix ("bc" for mainnet, "tb" for testnet, "bcrt" for regtest)

#### Scenario: Anonymous principal rejected
- **WHEN** `get_btc_address` is called with the anonymous principal
- **THEN** the call panics with "the owner must be non-anonymous"

#### Scenario: ECDSA public key initialization
- **WHEN** the ECDSA public key has not been fetched yet
- **THEN** the minter requests it from the management canister via `ecdsa_public_key`
- **AND** stores it in the minter state for reuse

---

### Requirement: ckBTC Minter - Bitcoin Address Parsing
The minter parses and validates multiple Bitcoin address formats.

#### Scenario: P2WPKH address parsing (bech32 v0, 20-byte witness)
- **WHEN** a bech32-encoded address with witness version 0 and 20-byte data is parsed
- **THEN** a `BitcoinAddress::P2wpkhV0` is returned

#### Scenario: P2WSH address parsing (bech32 v0, 32-byte witness)
- **WHEN** a bech32-encoded address with witness version 0 and 32-byte data is parsed
- **THEN** a `BitcoinAddress::P2wshV0` is returned

#### Scenario: P2TR address parsing (bech32m v1, 32-byte witness)
- **WHEN** a bech32m-encoded address with witness version 1 and 32-byte data is parsed
- **THEN** a `BitcoinAddress::P2trV1` is returned

#### Scenario: P2PKH address parsing (base58)
- **WHEN** a base58-encoded address with mainnet prefix (0x00) or testnet prefix (0x6F) is parsed
- **THEN** a `BitcoinAddress::P2pkh` is returned with the 20-byte pubkey hash
- **AND** the checksum (double SHA-256) is validated

#### Scenario: P2SH address parsing (base58)
- **WHEN** a base58-encoded address with mainnet P2SH prefix (0x05) or testnet P2SH prefix (0xC4) is parsed
- **THEN** a `BitcoinAddress::P2sh` is returned

#### Scenario: Wrong network detection
- **WHEN** a mainnet address is parsed with a testnet network parameter
- **THEN** a `WrongNetwork` error is returned specifying expected and actual networks

#### Scenario: Invalid bech32 variant detection
- **WHEN** a v0 witness address uses bech32m encoding (or v1 uses bech32)
- **THEN** an `InvalidBech32Variant` error is returned

#### Scenario: Unsupported witness version
- **WHEN** a witness version other than 0 or 1 is encountered
- **THEN** an `UnsupportedWitnessVersion` error is returned

---

### Requirement: ckBTC Minter - Deposit (Update Balance)
Users deposit BTC by sending it to their derived address; the minter detects new UTXOs and mints ckBTC.

#### Scenario: Successful deposit and minting
- **WHEN** `update_balance` is called for an account
- **THEN** the minter fetches UTXOs for the account's derived Bitcoin address
- **AND** new UTXOs with sufficient confirmations are identified
- **AND** each UTXO undergoes a Bitcoin check (OFAC/compliance) via the btc_checker canister
- **AND** for each passing UTXO, ckBTC tokens are minted on the ledger
- **AND** the UTXO is recorded in the minter state to prevent double-minting

#### Scenario: UTXO value too small
- **WHEN** a UTXO's value does not cover the Bitcoin check cost
- **THEN** a `ValueTooSmall` status is returned for that UTXO

#### Scenario: Tainted UTXO
- **WHEN** the Bitcoin check identifies issues with a UTXO
- **THEN** a `Tainted` status is returned for that UTXO

#### Scenario: Insufficient confirmations
- **WHEN** no new UTXOs have enough confirmations
- **THEN** a `NoNewUtxos` error is returned with `current_confirmations` and `required_confirmations`
- **AND** pending UTXOs are listed with their current confirmation count

#### Scenario: Concurrent update_balance calls
- **WHEN** two `update_balance` calls are made for the same principal
- **THEN** the second call returns `AlreadyProcessing`

#### Scenario: Check transaction retry limit
- **WHEN** a transaction check is retried with cycle payment
- **THEN** it is retried at most 10 times (`MAX_CHECK_TRANSACTION_RETRY`)
- **AND** retries stop to avoid spending excessive cycles

---

### Requirement: ckBTC Minter - Withdrawal (Retrieve BTC)
Users burn ckBTC to withdraw real BTC to a specified Bitcoin address.

#### Scenario: Successful BTC retrieval
- **WHEN** `retrieve_btc` is called with a valid amount and address
- **THEN** the address is parsed and validated
- **AND** the address undergoes a compliance check
- **AND** the specified amount of ckBTC is burned from the caller's withdrawal account
- **AND** a `RetrieveBtcRequest` is queued
- **AND** the block index of the burn transaction is returned

#### Scenario: Amount too low
- **WHEN** the requested withdrawal amount is below `retrieve_btc_min_amount`
- **THEN** a `RetrieveBtcError::AmountTooLow` error is returned with the minimum amount

#### Scenario: Malformed address
- **WHEN** the destination address cannot be parsed
- **THEN** a `RetrieveBtcError::MalformedAddress` error is returned

#### Scenario: Insufficient funds
- **WHEN** the withdrawal account balance is below the requested amount
- **THEN** a `RetrieveBtcError::InsufficientFunds` error is returned with the current balance

#### Scenario: Too many concurrent requests
- **WHEN** more than 5000 pending requests are in the queue (`MAX_CONCURRENT_PENDING_REQUESTS`)
- **THEN** a `TemporarilyUnavailable` error is returned

#### Scenario: Tainted address detected
- **WHEN** the destination Bitcoin address fails the compliance check
- **THEN** a `GenericError` with `ErrorCode::TaintedAddress` is returned

#### Scenario: Retrieve BTC with approval (ICRC-2)
- **WHEN** `retrieve_btc_with_approval` is called
- **THEN** the minter uses `transfer_from` instead of `transfer` to burn ckBTC
- **AND** the `from_subaccount` parameter allows burning from a specific subaccount
- **AND** insufficient allowance returns `InsufficientAllowance`

---

### Requirement: ckBTC Minter - Transaction Building and Signing
The minter constructs and signs Bitcoin P2WPKH transactions using threshold ECDSA.

#### Scenario: Unsigned transaction construction
- **WHEN** pending withdrawal requests are batched for processing
- **THEN** an `UnsignedTransaction` is created with selected UTXOs as inputs
- **AND** outputs include the withdrawal destinations and a change output to the minter
- **AND** transaction version is 2 (`TX_VERSION`)
- **AND** transaction uses SegWit (P2WPKH) encoding

#### Scenario: Transaction signing with threshold ECDSA
- **WHEN** an unsigned transaction is signed
- **THEN** for each input, a BIP-143 sighash is computed
- **AND** the sighash is signed using `sign_with_ecdsa` from the management canister
- **AND** the SEC1 signature is converted to DER format with SIGHASH_ALL appended
- **AND** the signed transaction includes witness data (signature + pubkey per input)

#### Scenario: Transaction ID computation (SegWit)
- **WHEN** a signed transaction's txid is computed
- **THEN** the txid is computed by double-SHA256 of the base transaction (excluding witness data)
- **AND** the wtxid includes the witness data

#### Scenario: Virtual transaction size
- **WHEN** the vsize of a signed transaction is calculated
- **THEN** `vsize = ceil((base_size * 3 + total_size) / 4)` per BIP-141

#### Scenario: DER signature encoding
- **WHEN** a SEC1 signature (64 bytes: 32-byte R + 32-byte S) is converted to DER
- **THEN** the DER format is `0x30 [length] 0x02 [R-length] [R] 0x02 [S-length] [S]`
- **AND** leading zeros are stripped from R and S
- **AND** a 0x00 prefix is added if the high bit is set (to prevent negative interpretation)
- **AND** the maximum encoded signature length is 73 bytes

#### Scenario: Signature validation
- **WHEN** a DER-encoded signature is validated
- **THEN** minimum length is 9 bytes and maximum is 73 bytes
- **AND** the compound type marker is 0x30
- **AND** R and S are non-zero, non-negative, and have no unnecessary zero padding

---

### Requirement: ckBTC Minter - Fee Estimation
The minter estimates Bitcoin transaction fees based on network fee percentiles.

#### Scenario: Median fee estimation on mainnet/testnet
- **WHEN** fee percentiles are available (at least 100 entries)
- **THEN** the 50th percentile (median) is selected
- **AND** the fee is floored at the minimum fee per vbyte (1500 millisat/vbyte for mainnet, 1000 for testnet)

#### Scenario: Fee estimation on regtest
- **WHEN** the network is regtest
- **THEN** a default fee rate of 5000 millisat/vbyte is used regardless of fee percentiles

#### Scenario: Minter fee evaluation
- **WHEN** the minter fee for a transaction is evaluated
- **THEN** the fee is `max(146 * num_inputs + 4 * num_outputs + 26, 300)` satoshi
- **AND** the minimum (300 sats) covers the P2WPKH dust limit

#### Scenario: Dynamic minimum withdrawal amount
- **WHEN** the minimum withdrawal amount is recomputed based on current fees
- **THEN** it accounts for RBF (replace-by-fee) bounds, vsize bounds, minter fees, and check fees
- **AND** it is rounded up to the nearest 50,000 satoshi increment plus the base `retrieve_btc_min_amount`

#### Scenario: Dust limit enforcement
- **WHEN** a transaction output is constructed
- **THEN** the output value must be at least 546 satoshi (P2PKH dust threshold)

#### Scenario: Fee rate from signed transaction
- **WHEN** a fee rate is computed from a signed transaction
- **THEN** `fee_rate = ceil(fee * 1000 / vsize)` in millisat/vbyte

---

### Requirement: ckBTC Minter - UTXO Management
The minter tracks UTXOs owned by each account and manages consolidation.

#### Scenario: UTXO tracking per account
- **WHEN** new UTXOs are discovered for an account
- **THEN** they are added to the account's UTXO set in the minter state
- **AND** previously seen UTXOs are deduplicated

#### Scenario: UTXO consolidation threshold
- **WHEN** the number of available UTXOs exceeds `UTXOS_COUNT_THRESHOLD`
- **THEN** a consolidation transaction is triggered to merge small UTXOs

---

### Requirement: ckBTC Minter - State Management and Event Log
The minter uses an event-sourcing pattern for state management, enabling state reconstruction from an event log.

#### Scenario: State reconstruction from events
- **WHEN** the minter is upgraded
- **THEN** the state is reconstructed by replaying the event log from stable storage

#### Scenario: Finalized request history limit
- **WHEN** finalized BTC retrieval requests are recorded
- **THEN** at most 100 are kept in history (`MAX_FINALIZED_REQUESTS`)

---

### Requirement: Bitcoin Checker (OFAC Compliance)
The Bitcoin checker canister validates transactions and addresses against blocklists.

#### Scenario: Transaction checking with cycle payment
- **WHEN** `check_transaction` is called
- **THEN** the caller must attach at least 40 billion cycles (`CHECK_TRANSACTION_CYCLES_REQUIRED`)
- **AND** a service fee of 100 million cycles is charged per call

#### Scenario: HTTP response size management
- **WHEN** fetching transaction data from external providers
- **THEN** initial response size is limited to 4 KB (`INITIAL_MAX_RESPONSE_BYTES`)
- **AND** if insufficient, retried with 400 KB (`RETRY_MAX_RESPONSE_BYTES`)
- **AND** transactions larger than 2 MB cannot be handled (subnet limit)

#### Scenario: Cycle cost calculation for transaction check
- **WHEN** the cycle cost for checking a transaction is computed
- **THEN** `cost = (3M + 60K * n) * n + 400 * n * 1024 + 800 * n * max_response_bytes`
- **AND** `n` is the number of subnet nodes

---

### Requirement: Bitcoin Header Validation Library
The validation library implements Bitcoin consensus rules for header validation.

#### Scenario: Header difficulty and proof-of-work check
- **WHEN** a Bitcoin header is validated
- **THEN** the proof of work must meet the target difficulty
- **AND** the previous header must exist in the header store
- **AND** the difficulty target must not exceed `max_target` for the network

#### Scenario: Dogecoin AuxPow validation
- **WHEN** a Dogecoin header with auxiliary proof of work is validated
- **THEN** the merged mining proof chain is verified
- **AND** the parent block's proof of work meets the required Dogecoin difficulty

---

### Requirement: Bitcoin Mock Canister
The mock canister provides a testing implementation of the Bitcoin integration.

#### Scenario: Mock Bitcoin responses
- **WHEN** tests interact with the Bitcoin mock canister
- **THEN** it provides deterministic responses for UTXO queries and block data
- **AND** it supports regtest-like behavior for integration tests
