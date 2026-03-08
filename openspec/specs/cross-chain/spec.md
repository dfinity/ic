# Cross-Chain Operations

**Crates**: `ic-ckbtc-agent`, `ic-ckbtc-minter`, `ic-ckdoge-agent`, `ic-ckdoge-minter`, `ic-cketh-minter`

## Requirements

### Requirement: Canister Blob Store
The blob store canister provides content-addressable storage for WASM binaries and other data used in cross-chain canister management. Data is stored in IC stable memory and addressed by SHA-256 hash.

#### Scenario: Blob insertion
- **WHEN** an authorized caller inserts a blob with `insert`
- **THEN** the SHA-256 hash of the data is computed
- **AND** the provided hash is validated against the computed hash
- **AND** if the hashes match, the blob is stored in the `StableBTreeMap`
- **AND** the hash is returned as confirmation

#### Scenario: Duplicate blob insertion rejected
- **WHEN** a blob with a hash that already exists in the store is inserted
- **THEN** an `AlreadyExists` error is returned
- **AND** no data is overwritten

#### Scenario: Hash mismatch on insertion
- **WHEN** the provided hash does not match the SHA-256 of the data
- **THEN** a `HashMismatch` error is returned with both expected and actual hash values

#### Scenario: Invalid hash format
- **WHEN** a hash string that cannot be parsed as a 32-byte hex value is provided
- **THEN** an `InvalidHash` error is returned with the reason

#### Scenario: Unauthorized insertion
- **WHEN** a caller that is not authorized attempts to insert a blob
- **THEN** a `NotAuthorized` error is returned

#### Scenario: Blob retrieval
- **WHEN** `get` is called with a valid hash
- **THEN** the corresponding blob data is returned
- **AND** the blob is reconstructed with `Blob::new_unchecked` (hash already validated)

#### Scenario: Blob not found
- **WHEN** `get` is called with a hash that does not exist in the store
- **THEN** a `NotFound` error is returned

#### Scenario: Stable memory persistence
- **WHEN** the canister is upgraded
- **THEN** all stored blobs persist in stable memory via `StableBTreeMap`
- **AND** the memory manager uses `MemoryId(0)` for the blob store

---

### Requirement: Hash Type
The `Hash` type provides a 32-byte SHA-256 digest with serialization and stable storage support.

#### Scenario: Hash computation
- **WHEN** `Hash::sha256(data)` is called
- **THEN** the SHA-256 digest of the data is computed and returned

#### Scenario: Hash from hex string
- **WHEN** a hex string (optionally prefixed with "0x") is parsed
- **THEN** the 32-byte hash is decoded from hex

#### Scenario: Hash display
- **WHEN** a hash is displayed
- **THEN** it is rendered as a lowercase hex string (64 characters)

#### Scenario: Hash stable storage
- **WHEN** a hash is stored in stable memory
- **THEN** it is stored as exactly 32 bytes (fixed size, bounded)

---

### Requirement: Blob Type
The `Blob` type pairs data with its content hash for integrity verification.

#### Scenario: Blob creation with hash computation
- **WHEN** `Blob::new(data)` is called
- **THEN** the SHA-256 hash is computed from the data
- **AND** both data and hash are stored together

#### Scenario: Unchecked blob creation
- **WHEN** `Blob::new_unchecked(data, hash)` is called
- **THEN** the blob is created without recomputing the hash
- **AND** this is used when the hash is already known to be correct (e.g., retrieved from store)

---

### Requirement: Cross-Chain Proposal CLI
The proposal CLI automates the creation of NNS governance proposals for upgrading and installing cross-chain canisters (ckBTC minter, ckETH minter, ledger suite orchestrator, etc.).

#### Scenario: Canister upgrade proposal generation
- **WHEN** the `upgrade` command is run with target canisters, `--from` and `--to` git commit hashes
- **THEN** the git repository is cloned and release notes are generated between the two commits
- **AND** the repository is checked out to the target commit
- **AND** upgrade arguments are encoded (Candid binary format)
- **AND** the compressed WASM artifact is built
- **AND** the last upgrade proposal ID is fetched from the IC dashboard
- **AND** a proposal summary markdown file is generated
- **AND** binary upgrade args are written to `args.bin`
- **AND** the WASM artifact is copied to the output directory

#### Scenario: Canister install proposal generation
- **WHEN** the `install` command is run with target canisters and `--at` git commit hash
- **THEN** the repository is checked out to the specified commit
- **AND** initialization arguments are encoded
- **AND** the WASM artifact is built
- **AND** a proposal summary is generated

#### Scenario: Proposal summary size validation
- **WHEN** a proposal summary is generated
- **THEN** the summary must not exceed 30,000 bytes (`GOVERNANCE_PROPOSAL_SUMMARY_BYTES_MAX`)
- **AND** exceeding this limit produces an error (the governance canister would reject it)

#### Scenario: ic-admin submit script generation
- **WHEN** the `ic-admin` subcommand is provided
- **THEN** a `submit.sh` executable script is generated
- **AND** the script contains the `ic-admin` command with correct paths to WASM, args, and summary files

#### Scenario: Forum post creation
- **WHEN** the `create-forum-post` command is run with proposal IDs
- **THEN** proposal details are retrieved from the IC dashboard
- **AND** a forum topic is constructed for the upgrade proposals
- **AND** the topic is submitted to the DFINITY forum via the Discourse API
- **AND** the user is prompted for confirmation before posting

#### Scenario: Multiple canisters per git repository
- **WHEN** multiple canisters from the same git repository are specified
- **THEN** the repository is cloned only once
- **AND** all canisters are processed in a single pass
- **AND** each canister gets its own output subdirectory

#### Scenario: Output directory validation
- **WHEN** an output directory is specified
- **THEN** it must exist, be a directory (not a file), and be writable
- **AND** previous output for the same canister and commit is removed before writing
