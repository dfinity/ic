# Manifest and State Sync

The manifest system provides a content-addressable description of a checkpoint's files and chunks, enabling efficient state synchronization between replicas.

## Requirements

### Requirement: Manifest Structure

A manifest describes all files in a checkpoint, broken into fixed-size chunks with cryptographic hashes.

#### Scenario: Manifest composition
- **WHEN** a manifest is computed for a checkpoint
- **THEN** it contains:
  - A version number (`StateSyncVersion`)
  - A file table listing all files with their relative paths, sizes, and hashes
  - A chunk table listing all chunks with file indices, offsets, sizes, and hashes

#### Scenario: File chunking
- **WHEN** a file is added to the manifest
- **THEN** it is split into chunks of `DEFAULT_CHUNK_SIZE` (1 MiB)
- **AND** the last chunk may be smaller than the default size
- **AND** each chunk's SHA-256 hash is computed

#### Scenario: File hash computation
- **WHEN** a file's hash is computed for the manifest
- **THEN** it is derived from the hashes of all its chunks using a domain-separated hash
- **AND** the hash includes the file's relative path

#### Scenario: Manifest root hash
- **WHEN** the manifest root hash is computed
- **THEN** it is a hash of all file hashes in the manifest
- **AND** the root hash is used as the `CryptoHashOfState`

### Requirement: Meta-Manifest

The meta-manifest provides a hierarchical structure for efficient manifest transfer during state sync.

#### Scenario: Meta-manifest creation
- **WHEN** a manifest is encoded and split into sub-manifests
- **THEN** the encoded manifest is divided into sub-manifest chunks
- **AND** a `MetaManifest` is created containing:
  - The state sync version
  - A list of hashes, one per sub-manifest chunk

#### Scenario: Bundled manifest
- **WHEN** a `BundledManifest` is computed
- **THEN** it contains:
  - The root hash (`CryptoHashOfState`)
  - The full `Manifest`
  - The `MetaManifest` (wrapped in `Arc`)

### Requirement: Incremental Manifest Computation

Manifest computation reuses hashes from a previous manifest to avoid redundant hashing.

#### Scenario: Reusing chunk hashes from base manifest
- **WHEN** a manifest is computed and a base manifest is available
- **THEN** for each chunk, if the file path and chunk position match the base manifest:
  - The base manifest's hash is reused (avoiding re-hashing)
  - Every `REHASH_EVERY_NTH_CHUNK` (10th) chunk is re-hashed and compared to detect corruption
- **AND** reused bytes, hashed bytes, and hashed-and-compared bytes are tracked in metrics

#### Scenario: Detecting chunk hash corruption
- **WHEN** a re-hashed chunk's hash differs from the reused hash
- **THEN** the newly computed hash is used
- **AND** a `reused_chunk_hash_error_count` critical error metric is incremented

### Requirement: File Grouping

Small files are grouped into virtual chunks for efficient transfer during state sync.

#### Scenario: Grouping canister.pbuf files
- **WHEN** files named `canister.pbuf` are encountered during manifest computation
- **AND** they are smaller than the grouping size limit
- **THEN** they are grouped into virtual `FileGroupChunks`
- **AND** each group chunk contains multiple small files concatenated together
- **AND** group chunks have IDs starting at `FILE_GROUP_CHUNK_ID_OFFSET`

#### Scenario: Size limits for grouping by version
- **WHEN** the grouping size limit is determined
- **THEN** for state sync versions V0-V3, the limit is 8 KiB (`MAX_FILE_SIZE_TO_GROUP_V3`)
- **AND** for state sync version V4+, the limit is 128 KiB (`MAX_FILE_SIZE_TO_GROUP_V4`)
- **AND** this ensures at least 8 files fit per 1 MiB chunk

### Requirement: Manifest Validation

Manifests are validated to ensure integrity.

#### Scenario: Validating manifest root hash
- **WHEN** `validate_manifest(manifest, root_hash)` is called
- **THEN** the manifest's computed root hash is compared against the expected hash
- **AND** if they do not match, `InvalidRootHash` error is returned

#### Scenario: Validating file hashes
- **WHEN** manifest files are validated against disk
- **THEN** each file's chunks are re-hashed
- **AND** if a file's computed hash does not match the manifest, `InvalidFileHash` error is returned

#### Scenario: Validating manifest version
- **WHEN** a manifest is received during state sync
- **THEN** its version is checked against `MAX_SUPPORTED_STATE_SYNC_VERSION`
- **AND** if the version is unsupported, `UnsupportedManifestVersion` error is returned

#### Scenario: Validating chunk integrity
- **WHEN** a chunk is received during state sync
- **THEN** its size and hash are validated against the manifest
- **AND** `InvalidChunkHash`, `InvalidChunkSize`, or `InvalidChunkIndex` errors are returned on mismatch

### Requirement: Manifest Splitting for Subnet Split

Manifests can be split to predict the manifests resulting from a subnet split.

#### Scenario: Splitting a manifest
- **WHEN** `split_manifest` is called with a manifest and canister migration ranges
- **THEN** the manifest is split into two parts:
  - One for the original subnet (retaining non-migrated canisters)
  - One for the new subnet (containing migrated canisters)
- **AND** system metadata files are adjusted for each resulting subnet
- **AND** file and chunk hashes are recomputed as needed

### Requirement: State Sync Protocol

State sync transfers checkpoint data between replicas using a chunked protocol.

#### Scenario: State sync chunk ID space
- **WHEN** chunk IDs are assigned during state sync
- **THEN** the ID space is partitioned:
  - Chunk 0: meta-manifest chunk
  - Chunks `1..MANIFEST_CHUNK_ID_OFFSET`: sub-manifest chunks
  - Chunks `MANIFEST_CHUNK_ID_OFFSET..FILE_CHUNK_ID_OFFSET`: reserved
  - Chunks `FILE_CHUNK_ID_OFFSET..FILE_GROUP_CHUNK_ID_OFFSET`: individual file chunks
  - Chunks `FILE_GROUP_CHUNK_ID_OFFSET..`: file group chunks

#### Scenario: Monitoring chunk ID usage
- **WHEN** chunk IDs approach their range limits
- **THEN** a `chunk_id_usage_nearing_limits` critical error metric is incremented
- **AND** this provides early warning of potential ID space exhaustion

### Requirement: State Sync Chunkable Protocol

The `IncompleteState` implements the `Chunkable` interface for progressive state download.

#### Scenario: Starting a state sync
- **WHEN** state sync begins for a target height and root hash
- **THEN** an `IncompleteState` is created
- **AND** the first chunk requested is the meta-manifest (chunk ID 0)

#### Scenario: Receiving the meta-manifest
- **WHEN** the meta-manifest chunk is received and validated
- **THEN** sub-manifest chunks are requested based on the meta-manifest's hash list

#### Scenario: Receiving manifest chunks
- **WHEN** all sub-manifest chunks are received
- **THEN** they are assembled into the full manifest
- **AND** the manifest's root hash is validated against the expected hash
- **AND** the file group chunks are built from the manifest

#### Scenario: Hardlinking files from existing checkpoints
- **WHEN** the manifest is available and existing checkpoints have matching files
- **THEN** files with matching hashes are hardlinked from existing checkpoints
- **AND** this avoids downloading unchanged files from the network

#### Scenario: Copying chunks from cache
- **WHEN** chunks are available in the state sync cache (from a previously aborted sync)
- **THEN** matching chunks are copied from the cache
- **AND** their hashes are validated after copying

#### Scenario: Fetching remaining chunks
- **WHEN** some chunks are not available locally or in cache
- **THEN** they are fetched from peer replicas via the P2P layer
- **AND** each received chunk's hash is validated against the manifest

#### Scenario: Completing state sync
- **WHEN** all chunks have been received and validated
- **THEN** the files are assembled into a complete checkpoint
- **AND** the checkpoint is delivered to the state manager
- **AND** the state is loaded and registered

#### Scenario: Aborting state sync
- **WHEN** state sync is aborted (e.g., due to a newer state being available)
- **THEN** downloaded chunks are cached for potential reuse by a future sync
- **AND** metrics record the abort status

#### Scenario: State sync validation decision
- **WHEN** state sync completes at a height
- **AND** the last verified checkpoint is more than `MAX_HEIGHT_DIFFERENCE_WITHOUT_VALIDATION` (10,000) heights old
- **THEN** the synced checkpoint is fully validated (loaded and verified)
- **AND** it is marked as a verified checkpoint
- **WHEN** a recent verified checkpoint exists within the threshold
- **THEN** the synced checkpoint is loaded without full validation
- **AND** it remains unverified (marked with checkpoint markers)

### Requirement: State Sync Cache

A cache preserves chunks from aborted state syncs for reuse.

#### Scenario: Populating the cache
- **WHEN** a state sync is aborted
- **THEN** the scratchpad path, manifest, and downloaded chunk set are cached

#### Scenario: Using cached chunks
- **WHEN** a new state sync starts and the cache contains relevant chunks
- **THEN** matching chunks are copied from the cached scratchpad
- **AND** chunk hashes are re-verified after copying

#### Scenario: Cache invalidation
- **WHEN** a new state sync begins
- **THEN** the previous cache entry is replaced
