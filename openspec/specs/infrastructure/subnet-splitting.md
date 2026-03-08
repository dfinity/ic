# Subnet Splitting Specification

- **Crate**: `ic-subnet-splitting`
- **Source**: `rs/recovery/subnet_splitting/`
- **Purpose**: Orchestrates the process of splitting one IC Application subnet into two subnets by redistributing canisters across a source subnet and a newly created destination subnet. This is a recovery-style operation that halts the source subnet, downloads its state, partitions it by canister ID ranges, and uploads the resulting states to both subnets.

## Requirements

### Requirement: Subnet Precondition Validation

Both the source and destination subnets must satisfy strict preconditions before a split operation may begin. This prevents accidental data loss or corruption from operating on unsuitable subnets.

#### Scenario: Source subnet type validation
- **WHEN** a subnet splitting operation is initiated
- **THEN** the source subnet must be of type `Application` or `VerifiedApplication`
- **AND** validation fails with `RecoveryError::ValidationFailed` if the subnet type is not in the allow list

#### Scenario: Chain key subnet rejection
- **WHEN** either the source or destination subnet has a non-empty `chain_key_config.key_configs`
- **THEN** validation fails with a message "Subnet should not be a Chain key subnet"
- **AND** the splitting operation is aborted

#### Scenario: Destination subnet must be halted
- **WHEN** the destination subnet record is fetched from the registry
- **THEN** its `is_halted` field must be `true`
- **AND** validation fails if the destination subnet is not halted

#### Scenario: Destination subnet must have zero height
- **WHEN** the destination subnet's node metrics are queried
- **THEN** all nodes must report a `finalization_height` of `0`
- **AND** validation fails if any node has a non-zero height, ensuring the destination has not produced any blocks

#### Scenario: Subnets must match in type and size
- **WHEN** both subnet records are retrieved from the registry
- **THEN** both subnets must have the same `subnet_type`
- **AND** both subnets must have the same membership count (number of nodes)
- **AND** validation fails if either condition is not met

---

### Requirement: Canister Migration Registry Preparation

Before the source subnet is halted, the registry must be updated to record the pending canister migration and reroute canister ranges.

#### Scenario: Prepare canister migration proposal
- **WHEN** the `PrepareCanisterMigration` step executes
- **THEN** an NNS proposal is submitted via `ic-admin` to prepare the canister migration entry
- **AND** the proposal specifies the canister ID ranges to move, source subnet ID, and destination subnet ID

#### Scenario: Registry canister migrations entry check
- **WHEN** the `CheckRegistryForCanisterMigrationsEntry` step executes
- **THEN** the tool reads the most recent canister migrations entry from the registry
- **AND** displays the entry to the operator for manual confirmation

#### Scenario: Reroute canister ranges proposal
- **WHEN** the `RerouteCanisterRanges` step executes
- **THEN** an NNS proposal is submitted to reroute the specified canister ID ranges from the source subnet to the destination subnet
- **AND** the routing table is updated so that ingress messages are directed to the correct subnet

#### Scenario: Routing table entry verification
- **WHEN** the `CheckRegistryForRoutingTableEntry` step executes
- **THEN** the tool queries the routing table from the registry
- **AND** displays the canister ranges assigned to both the source and destination subnets

---

### Requirement: Source Subnet Halt and State Download

The source subnet must be halted at a CUP height and its state downloaded to the recovery machine.

#### Scenario: Halt source subnet at CUP height
- **WHEN** the `HaltSourceSubnetAtCupHeight` step executes
- **THEN** an NNS proposal is submitted to halt the source subnet at its current CUP height
- **AND** an optional readonly SSH public key is deployed to the subnet for state download access

#### Scenario: Pre-halt Grafana dashboard check
- **WHEN** the operator reaches the `HaltSourceSubnetAtCupHeight` step in interactive mode
- **THEN** a Grafana dashboard URL is displayed containing the destination subnet ID and latest registry version
- **AND** the operator must manually confirm it is safe to proceed

#### Scenario: Download state from source subnet
- **WHEN** the `DownloadStateFromSourceSubnet` step executes with a `download_node_source` IP
- **THEN** the IC state (including checkpoints and CUP) is downloaded from the specified node via rsync
- **AND** the operator may choose to preserve the original downloaded state locally
- **AND** SSH access uses either readonly or admin credentials depending on whether a readonly key was provided

#### Scenario: Download step skipped when no node IP
- **WHEN** the `DownloadStateFromSourceSubnet` step executes without a `download_node_source` IP
- **THEN** a `RecoveryError::StepSkipped` error is returned
- **AND** execution continues to the next step

---

### Requirement: CUP and State Manifest Validation

The downloaded CUP and state manifest are validated cryptographically before any state splitting occurs.

#### Scenario: NNS state tree validation
- **WHEN** the `ValidateSourceSubnetCup` step executes
- **THEN** the NNS-signed state tree is fetched via `ic-agent` for the source subnet
- **AND** the pruned state tree is saved to disk at `pruned_state_tree.cbor`
- **AND** the subnet's public key is extracted and saved as a PEM file

#### Scenario: CUP signature verification
- **WHEN** the source subnet's CUP is validated
- **THEN** the CUP's signature is verified against the subnet's public key extracted from the NNS state tree
- **AND** the state hash is extracted from the CUP for manifest comparison

#### Scenario: State manifest hash matching
- **WHEN** the state manifest is validated against the CUP
- **THEN** the manifest root hash is recomputed from the checkpoint
- **AND** the recomputed hash must match the state hash from the CUP
- **AND** validation fails if the hashes differ

---

### Requirement: Expected Manifest Computation

Before the actual state split, expected manifests are pre-computed to enable post-split validation.

#### Scenario: Compute expected manifests
- **WHEN** the `ComputeExpectedManifestsStep` executes
- **THEN** the `state-tool split-manifests` command is invoked with the original state manifest
- **AND** the tool computes expected root hashes for both source and destination subnets
- **AND** the results are stored at `expected_manifests.data` containing per-subnet root hashes

---

### Requirement: State Splitting

The downloaded state is split into two separate states: one for the source subnet (dropping moved canisters) and one for the destination subnet (retaining only moved canisters).

#### Scenario: Copy working directory for destination
- **WHEN** the `CopyDir` step executes
- **THEN** the `ic_state` directory is copied from the source working directory to the destination working directory via rsync
- **AND** both directories contain identical state data before splitting begins

#### Scenario: Split state for source subnet (drop strategy)
- **WHEN** the `SplitOutSourceState` step executes
- **THEN** the `resolve_ranges_and_split` function is called with the `Drop` strategy
- **AND** the specified canister ID ranges are removed from the source state
- **AND** the batch time is NOT overridden (remains `None` for the source)
- **AND** all checkpoints except the highest are removed after splitting

#### Scenario: Split state for destination subnet (retain strategy)
- **WHEN** the `SplitOutDestinationState` step executes
- **THEN** the `resolve_ranges_and_split` function is called with the `Retain` strategy
- **AND** only the specified canister ID ranges are kept in the destination state
- **AND** the batch time from the pre-split source CUP is applied to the destination state
- **AND** all checkpoints except the highest are removed after splitting

#### Scenario: Post-split state hash validation
- **WHEN** either `SplitOutSourceState` or `SplitOutDestinationState` completes the split
- **THEN** the state manifest is computed for the latest checkpoint
- **AND** the manifest is verified for integrity
- **AND** the actual state hash is compared against the expected state hash from `expected_manifests.data`
- **AND** the step fails with `RecoveryError::ValidationFailed` if the hashes do not match

---

### Requirement: Recovery CUP Proposal and State Upload

After splitting, a recovery CUP is proposed for each subnet and the new state is uploaded.

#### Scenario: Propose CUP for a target subnet
- **WHEN** either `ProposeCupForSourceSubnet` or `ProposeCupForDestinationSubnet` executes
- **THEN** the latest checkpoint name and height are read from the split state
- **AND** the state hash is computed from the latest checkpoint
- **AND** a recovery CUP is proposed at the recovery height (latest checkpoint height + 1)

#### Scenario: Upload state to a target subnet
- **WHEN** either `UploadStateToSourceSubnet` or `UploadStateToDestinationSubnet` executes
- **THEN** the split `ic_state` directory is uploaded to the specified node via SSH
- **AND** the node is restarted after upload
- **AND** the step is skipped if no upload node IP was provided

#### Scenario: Wait for CUP on a target subnet
- **WHEN** either `WaitForCUPOnSourceSubnet` or `WaitForCUPOnDestinationSubnet` executes
- **THEN** the tool polls the upload node for the recovery CUP at the expected height
- **AND** the expected state hash is compared with the CUP on the node

---

### Requirement: Subnet Unhalting and Migration Completion

After both subnets are running with their split states, they are unhalted and the migration is finalized.

#### Scenario: Unhalt source subnet
- **WHEN** the `UnhaltSourceSubnet` step executes
- **THEN** the source subnet is unhalted by setting `is_halted` to `false` via NNS proposal

#### Scenario: Unhalt destination subnet with dashboard check
- **WHEN** the `UnhaltDestinationSubnet` step executes in interactive mode
- **THEN** a Grafana dashboard URL is displayed for the source subnet
- **AND** the operator must confirm it is safe to unhalt the destination subnet
- **AND** the destination subnet is unhalted via NNS proposal

#### Scenario: Complete canister migration
- **WHEN** the `CompleteCanisterMigration` step executes
- **THEN** an NNS proposal is submitted to complete the canister migration
- **AND** the canister migrations registry entry is cleaned up
- **AND** the `CheckRegistryForCanisterMigrationsEntryAgain` step verifies the entry is removed

#### Scenario: Cleanup
- **WHEN** the `Cleanup` step executes
- **THEN** temporary recovery working directories are cleaned up

---

### Requirement: Step Ordering and Recovery State Persistence

The splitting operation follows a strict step ordering and supports resume from any step.

#### Scenario: Deterministic step ordering
- **WHEN** the subnet splitting tool runs
- **THEN** steps execute in the following order: PrepareCanisterMigration, CheckRegistryForCanisterMigrationsEntry, HaltSourceSubnetAtCupHeight, RerouteCanisterRanges, CheckRegistryForRoutingTableEntry, DownloadStateFromSourceSubnet, ValidateSourceSubnetCup, ComputeExpectedManifestsStep, CopyDir, SplitOutSourceState, SplitOutDestinationState, ProposeCupForSourceSubnet, UploadStateToSourceSubnet, ProposeCupForDestinationSubnet, UploadStateToDestinationSubnet, WaitForCUPOnSourceSubnet, WaitForCUPOnDestinationSubnet, UnhaltSourceSubnet, UnhaltDestinationSubnet, CompleteCanisterMigration, CheckRegistryForCanisterMigrationsEntryAgain, Cleanup

#### Scenario: Resume from a specific step
- **WHEN** the `--resume` flag is provided with a `StepType` value
- **THEN** execution begins at the specified step, skipping all prior steps
- **AND** recovery state (including all args) is serialized and persisted between runs

---

### Requirement: Post-Split Load and State Size Estimation

The tool provides estimation capabilities to plan subnet splits based on canister load and state size data.

#### Scenario: Estimate state sizes
- **WHEN** a state manifest and canister ID ranges are provided
- **THEN** the total file sizes are partitioned into source and destination estimates
- **AND** files belonging to canisters in the move ranges are attributed to the destination
- **AND** all other files are attributed to the source

#### Scenario: Estimate canister load distribution
- **WHEN** load sample CSVs and a baseline are provided along with canister ID ranges
- **THEN** per-canister metrics (instructions, ingress, remote/local subnet messages, HTTP outcalls, heartbeats) are aggregated
- **AND** the baseline is subtracted from the samples
- **AND** totals are partitioned into source and destination estimates based on canister ranges

---

### Requirement: Working Directory Layout

The tool maintains a well-defined directory layout for all artifacts produced during the split.

#### Scenario: Directory structure
- **WHEN** a subnet splitting operation is initialized
- **THEN** the recovery directory contains: NNS public key (`nns.pem`), pruned state tree (`pruned_state_tree.cbor`), original state manifest (`original_source_manifest.data`), expected manifests (`expected_manifests.data`), per-subnet manifest files (`{subnet_id}.manifest`), per-subnet public key files (`{subnet_id}.pem`)
- **AND** the source working directory is at the default recovery work dir path
- **AND** the destination working directory is at `{recovery_dir}/destination_working_dir/`
- **AND** each working directory contains `data/ic_state/checkpoints/` with checkpoint subdirectories
