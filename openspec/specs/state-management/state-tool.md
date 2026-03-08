# State Tool

**Crates**: `ic-state-tool`

The `state_tool` is a command-line utility for managing, inspecting, and manipulating Internet Computer replicated state checkpoints.

## Requirements

### Requirement: Checkpoint Hash Computation

The tool computes the partial state hash used for certification.

#### Scenario: Computing a checkpoint hash
- **WHEN** `state_tool chash --height <H> --state <path>` is executed
- **THEN** the checkpoint at the given path is loaded
- **AND** the canonical state hash tree is computed
- **AND** the root hash used for certification is displayed

### Requirement: Checkpoint Diff

The tool computes differences between checkpoints.

#### Scenario: Computing canonical tree diff
- **WHEN** `state_tool cdiff <path_a> <path_b>` is executed
- **THEN** both checkpoints are loaded
- **AND** their canonical state trees are compared
- **AND** differences are reported

### Requirement: Manifest Computation

The tool computes and displays checkpoint manifests.

#### Scenario: Computing a manifest
- **WHEN** `state_tool manifest --state <path>` is executed
- **THEN** the checkpoint at the given path is scanned
- **AND** a manifest is computed listing all files and chunks with their hashes
- **AND** the manifest is displayed in human-readable form

### Requirement: Manifest Verification

The tool verifies the integrity of a manifest file.

#### Scenario: Verifying a manifest
- **WHEN** `state_tool verify_manifest --file <path>` is executed
- **THEN** the manifest is parsed from the file
- **AND** the root hash is recomputed from the manifest contents
- **AND** the recomputed hash is compared against the hash stored in the manifest
- **AND** the result (match or mismatch) is reported

### Requirement: State Listing

The tool enumerates persisted states.

#### Scenario: Listing states
- **WHEN** `state_tool list --config <path>` is executed
- **THEN** the state layout at the configured path is inspected
- **AND** all checkpoint heights are listed

### Requirement: State Import

The tool imports replicated state from an external location.

#### Scenario: Importing state (deprecated)
- **WHEN** `state_tool import --state <path> --config <config> --height <H>` is executed
- **THEN** the state at the given path is copied into the state layout
- **AND** it is registered as a checkpoint at the specified height

### Requirement: State Copy

The tool copies states between state layout directories with flexible height selection.

#### Scenario: Copying all states
- **WHEN** `state_tool copy <source> <destination>` is executed without height filters
- **THEN** all checkpoints from the source are copied to the destination
- **AND** state metadata is preserved

#### Scenario: Copying the latest state only
- **WHEN** `state_tool copy <source> <destination> --latest` is executed
- **THEN** only the most recent checkpoint is copied

#### Scenario: Copying specific heights
- **WHEN** `state_tool copy <source> <destination> --heights 1,3` is executed
- **THEN** only checkpoints at heights 1 and 3 are copied

#### Scenario: Copying and renaming heights
- **WHEN** `state_tool copy <source> <destination> --heights 1->2` is executed
- **THEN** the checkpoint at height 1 is copied and registered as height 2 in the destination

### Requirement: State Decoding

The tool decodes and displays protobuf state files.

#### Scenario: Decoding a state file
- **WHEN** `state_tool decode --file <path>` is executed
- **THEN** the protobuf file is deserialized
- **AND** the contents are displayed in a human-readable debug format

### Requirement: Canister ID Conversion

The tool converts between canister ID representations.

#### Scenario: Canister ID to hex
- **WHEN** `state_tool canister_id_to_hex --canister_id <id>` is executed
- **THEN** the textual principal representation is converted to hex

#### Scenario: Canister ID from hex
- **WHEN** `state_tool canister_id_from_hex --canister_id <hex>` is executed
- **THEN** the hex representation is converted to textual principal form

#### Scenario: Principal from bytes
- **WHEN** `state_tool principal_from_bytes --bytes <bytes>` is executed
- **THEN** the byte array is encoded as a principal ID

### Requirement: Subnet Split

The tool supports splitting replicated state as part of a subnet split operation.

#### Scenario: Splitting state
- **WHEN** `state_tool split --root <path> --subnet_id <id> --retain <ranges>` is executed
- **THEN** the latest checkpoint under the root is loaded
- **AND** the state is pruned to retain only canisters in the specified ranges
- **AND** the pruned state is written back as a new checkpoint

#### Scenario: Specifying ranges to drop
- **WHEN** `--drop <ranges>` is used instead of `--retain`
- **THEN** the retained ranges are computed as the complement of the dropped ranges

#### Scenario: Setting batch time for new subnet
- **WHEN** `--batch_time_nanos <time>` is specified
- **THEN** the new subnet's batch time is set to the provided value
- **AND** the original subnet retains its original batch time

### Requirement: Manifest Splitting

The tool can split a manifest to predict the outcome of a subnet split.

#### Scenario: Splitting a manifest
- **WHEN** `state_tool split_manifest --path <manifest> --from_subnet <id> --to_subnet <id> --subnet_type <type> --batch_time_nanos <time> --migrated_ranges <ranges>` is executed
- **THEN** the manifest is parsed
- **AND** it is split based on which files belong to migrated canisters
- **AND** the resulting manifests for both subnets are computed and displayed

### Requirement: Overlay File Parsing

The tool can display overlay file contents.

#### Scenario: Parsing an overlay file
- **WHEN** `state_tool parse_overlay --path <path>` is executed
- **THEN** the overlay file's index section is parsed
- **AND** the page index entries are displayed in human-readable form

### Requirement: Canister Metrics Extraction

The tool can extract canister metrics from checkpoints.

#### Scenario: Extracting canister metrics
- **WHEN** `state_tool canister_metrics --checkpoint <path> --output <file>` is executed
- **THEN** the checkpoint is loaded
- **AND** per-canister metrics (cycles, memory usage, etc.) are extracted
- **AND** results are written to the output file in CSV format
