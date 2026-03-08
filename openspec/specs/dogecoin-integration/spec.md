# Dogecoin Integration

## Requirements

### Requirement: Dogecoin Adapter (Shared with Bitcoin)
The Dogecoin adapter reuses the Bitcoin adapter infrastructure with Dogecoin-specific network parameters. The adapter supports Dogecoin through the generic `BlockchainNetwork` abstraction.

#### Scenario: Dogecoin network selection
- **WHEN** the adapter is configured with `AdapterNetwork::Dogecoin`
- **THEN** a Dogecoin-specific config is created with Dogecoin network parameters
- **AND** the adapter connects to the Dogecoin P2P network using Dogecoin protocol messages

#### Scenario: Dogecoin address limits
- **WHEN** the adapter is configured for Dogecoin mainnet
- **THEN** address limits are (min: 200, max: 1000)
- **AND** for Dogecoin testnet, limits are (min: 20, max: 100)
- **AND** for Dogecoin regtest, limits are (min: 1, max: 1)

#### Scenario: Dogecoin header validation with AuxPow
- **WHEN** a Dogecoin block header is received by the adapter
- **THEN** it is validated using `DogecoinHeaderValidator` which supports auxiliary proof of work (merged mining)
- **AND** the `ValidateAuxPowHeaderError` type is used for validation errors

---

### Requirement: ckDOGE Minter - Runtime and Integration
The ckDOGE minter reuses the ckBTC minter infrastructure (`ic_ckbtc_minter`) with Dogecoin-specific overrides via the `CanisterRuntime` trait.

#### Scenario: Dogecoin canister interaction
- **WHEN** the ckDOGE minter needs UTXO data
- **THEN** it calls `dogecoin_get_utxos` on the Dogecoin canister (not the Bitcoin canister)
- **AND** the Dogecoin canister ID for mainnet is `gordg-fyaaa-aaaan-aaadq-cai`
- **AND** the same canister is used for both mainnet and regtest

#### Scenario: Dogecoin fee percentiles
- **WHEN** fee estimation is needed
- **THEN** `dogecoin_get_current_fee_percentiles` is called on the Dogecoin canister
- **AND** fee rates are expressed in millikoinu per byte (`MillikoinuPerByte`)
- **AND** fee percentiles are refreshed every 6 minutes

#### Scenario: Transaction sending
- **WHEN** a signed Dogecoin transaction is broadcast
- **THEN** `dogecoin_send_transaction` is called on the Dogecoin canister
- **AND** the call uses unbounded wait (no timeout)

#### Scenario: No OFAC checking for Dogecoin
- **WHEN** `check_transaction` is called for a Dogecoin UTXO
- **THEN** it always returns `CheckTransactionResponse::Passed`
- **AND** `check_address` always returns `BtcAddressCheckStatus::Clean`
- **AND** `check_fee` must be 0 (validated during initialization)

#### Scenario: Block time configuration
- **WHEN** the minter queries the block time for Dogecoin
- **THEN** mainnet and testnet return 60 seconds
- **AND** regtest returns 1 second

---

### Requirement: ckDOGE Minter - Address Derivation
The ckDOGE minter derives unique Dogecoin P2PKH addresses for each IC account.

#### Scenario: Deriving a P2PKH address for an account
- **WHEN** `get_doge_address` is called with an owner principal and optional subaccount
- **THEN** a BIP-32 key derivation is performed from the minter's ECDSA public key
- **AND** the derived public key (compressed, 33 bytes) is HASH160-hashed
- **AND** the result is encoded as a P2PKH address with the correct Dogecoin prefix

#### Scenario: Dogecoin mainnet address prefix
- **WHEN** a P2PKH address is displayed for Dogecoin mainnet
- **THEN** the version byte is 30 (0x1E), producing addresses starting with 'D'
- **AND** P2SH addresses use version byte 22 (0x16)

#### Scenario: Dogecoin regtest address prefix
- **WHEN** a P2PKH address is displayed for Dogecoin regtest
- **THEN** the version byte is 111 (0x6F), matching Bitcoin testnet conventions
- **AND** P2SH addresses use version byte 196 (0xC4)

#### Scenario: Minter address derivation
- **WHEN** the minter's own address is derived
- **THEN** it uses the main account (canister self principal, no subaccount)
- **AND** the address type is P2PKH (no SegWit for Dogecoin)

---

### Requirement: ckDOGE Minter - Dogecoin Address Parsing
The ckDOGE minter parses and validates Dogecoin-specific addresses.

#### Scenario: Valid P2PKH address parsing
- **WHEN** a base58-encoded Dogecoin address with the correct network prefix is parsed
- **THEN** a `DogecoinAddress::P2pkh` is returned with the 20-byte pubkey hash
- **AND** the double-SHA256 checksum is validated

#### Scenario: Valid P2SH address parsing
- **WHEN** a base58-encoded Dogecoin address with the P2SH prefix is parsed
- **THEN** a `DogecoinAddress::P2sh` is returned

#### Scenario: Address length limit
- **WHEN** an address with more than 50 base-58 characters is provided
- **THEN** a `MalformedAddress` error is returned

#### Scenario: Wrong network detection
- **WHEN** a mainnet Dogecoin address is parsed with a regtest network parameter
- **THEN** a `WrongNetwork` error is returned specifying expected and actual networks

#### Scenario: Unsupported address type
- **WHEN** an address with an unknown version byte is parsed
- **THEN** an `UnsupportedAddressType` error is returned
- **AND** the error message states "ckDOGE supports only P2PKH and P2SH addresses"

#### Scenario: Checksum validation
- **WHEN** an address with an invalid checksum is parsed
- **THEN** a `MalformedAddress` error is returned with the expected and actual checksum values

---

### Requirement: ckDOGE Minter - Transaction Building and Signing
Dogecoin transactions use Version 1 (no BIP-68 support) and legacy P2PKH signing (no SegWit).

#### Scenario: Transaction version
- **WHEN** a Dogecoin transaction is constructed
- **THEN** the transaction version is 1 (`Version::ONE`)
- **AND** BIP-68 sequence semantics are not supported

#### Scenario: P2PKH transaction signing
- **WHEN** a Dogecoin transaction is signed
- **THEN** for each input, a legacy sighash is computed using `legacy_signature_hash`
- **AND** the sighash is signed with threshold ECDSA (`sign_with_ecdsa`)
- **AND** the SEC1 signature is converted to DER format with SIGHASH_ALL appended
- **AND** the `script_sig` is constructed as `[signature] [compressed_public_key]`

#### Scenario: Script pubkey for P2PKH outputs
- **WHEN** a transaction output targets a P2PKH address
- **THEN** the script pubkey is `OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG`

#### Scenario: Script pubkey for P2SH outputs
- **WHEN** a transaction output targets a P2SH address
- **THEN** the script pubkey is `OP_HASH160 <script_hash> OP_EQUAL`

#### Scenario: Only P2PKH and P2SH addresses supported
- **WHEN** a transaction output targets an address other than P2PKH or P2SH
- **THEN** the transaction construction panics (Dogecoin does not support SegWit addresses)

#### Scenario: Fee rate computation
- **WHEN** a signed Dogecoin transaction's fee rate is computed
- **THEN** it is `ceil(fee * 1000 / serialized_size)` in millikoinu per byte
- **AND** the serialized size is the full transaction size (no SegWit discount)

#### Scenario: Fake signing for fee estimation
- **WHEN** the minter estimates transaction fees before actual signing
- **THEN** a fake signature of maximum length (73 bytes) and a zero pubkey are used
- **AND** the resulting transaction size provides an upper bound for fee calculation

#### Scenario: Maximum inputs per transaction
- **WHEN** building a Dogecoin transaction
- **THEN** at most 500 inputs are used (`DOGECOIN_MAX_NUM_INPUTS_IN_TRANSACTION`)

---

### Requirement: ckDOGE Minter - Fee Estimation
The ckDOGE minter uses the Dogecoin-specific `DogecoinFeeEstimator` that builds on the Bitcoin fee estimation framework.

#### Scenario: Fee estimation from state
- **WHEN** fees are estimated
- **THEN** the `DogecoinFeeEstimator` is constructed from the minter state
- **AND** it uses the same `FeeEstimator` trait as Bitcoin with Dogecoin-specific parameters

---

### Requirement: ckDOGE Minter - Event Logging
The ckDOGE minter uses a `CkDogeEventLogger` for recording events compatible with the shared ckBTC event framework.

#### Scenario: Bitcoin-to-Dogecoin address conversion in events
- **WHEN** events are recorded that reference addresses
- **THEN** the `bitcoin_to_dogecoin` conversion function maps `BitcoinAddress::P2pkh` to `DogecoinAddress::P2pkh`
- **AND** `BitcoinAddress::P2sh` maps to `DogecoinAddress::P2sh`
- **AND** other address types cause a trap (unsupported)

---

### Requirement: ckDOGE Minter - Dashboard
The ckDOGE minter provides a dashboard for monitoring its state.

#### Scenario: Dashboard display
- **WHEN** the dashboard is rendered
- **THEN** account addresses are displayed in Dogecoin format
- **AND** transaction URLs link to `blockexplorer.one/dogecoin/mainnet`
- **AND** the token name is displayed as "ckDOGE"
- **AND** the native token is displayed as "DOGE"

---

### Requirement: ckDOGE Minter - Configuration Validation
The ckDOGE minter validates its configuration during initialization.

#### Scenario: Check fee validation
- **WHEN** the minter is initialized
- **THEN** `check_fee` must be 0 (Dogecoin transactions are not checked for compliance)
- **AND** `check_fee` cannot be greater than `retrieve_btc_min_amount`
- **AND** `ecdsa_key_name` must not be empty

---

### Requirement: ckDOGE Minter - Deposit and Withdrawal
The ckDOGE minter reuses the ckBTC deposit and withdrawal flow with Dogecoin-specific adaptations.

#### Scenario: Deposit (update_balance)
- **WHEN** a user calls `update_balance` on the ckDOGE minter
- **THEN** the minter fetches UTXOs from the Dogecoin canister for the user's derived Dogecoin address
- **AND** new UTXOs with sufficient confirmations are minted as ckDOGE tokens
- **AND** no OFAC/compliance check is performed (always passes)

#### Scenario: Withdrawal (retrieve_btc equivalent)
- **WHEN** a user requests a withdrawal
- **THEN** the destination address is parsed as a Dogecoin address (P2PKH or P2SH only)
- **AND** ckDOGE tokens are burned from the user's account
- **AND** a Dogecoin transaction is constructed and signed
- **AND** the transaction is broadcast via the Dogecoin canister
