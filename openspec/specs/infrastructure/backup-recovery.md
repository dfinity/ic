# Backup and Recovery

**Crates**: `ic-backup`, `ic-recovery`, `ic_nested_nns_recovery_common`

The backup and recovery subsystems provide mechanisms for backing up subnet state, verifying backups through replay, and recovering failed subnets. The system supports application subnet recovery, NNS recovery on same nodes, and NNS recovery on failover nodes.

## Requirements

### Requirement: State Backup Infrastructure
The backup system continuously syncs consensus artifacts from subnet nodes, replays them to verify integrity, and manages storage lifecycle across hot and cold tiers.

#### Scenario: Backup manager initialization
- **WHEN** the backup manager starts
- **THEN** it loads configuration from a JSON config file
- **AND** a registry replicator is started to maintain registry state
- **AND** backup helpers are created for each configured subnet
- **AND** configuration validation ensures NNS URL, SSH credentials, and disk thresholds are valid

#### Scenario: Artifact synchronization from nodes
- **WHEN** the sync period elapses (default 30 seconds)
- **THEN** artifacts are synced from up to `nodes_syncing` (default 5) randomly selected subnet nodes via rsync
- **AND** the backup user authenticates with the configured SSH private key
- **AND** artifacts are stored in a spool directory organized by `{subnet_id}/{replica_version}/{bucket}/{height}`

#### Scenario: Backup replay verification
- **WHEN** the replay period elapses (default 240 seconds)
- **THEN** the backup helper replays finalized blocks from the spool against the current state
- **AND** `ic-replay` is invoked with the `RestoreFromBackup` subcommand
- **AND** if replay succeeds, the state checkpoint is valid and the backup is verified
- **AND** if replay fails with an upgrade requirement, new binaries are downloaded for the target version

#### Scenario: Binary download for replay
- **WHEN** replay requires binaries for a specific replica version
- **THEN** `ic-replay`, `sandbox_launcher`, `canister_sandbox`, and `compiler_sandbox` are downloaded
- **AND** the `ic.json5` configuration file is synced from a subnet node
- **AND** a download mutex prevents concurrent downloads
- **AND** downloads are retried up to 3 times on failure

#### Scenario: Node selection for sync
- **WHEN** nodes need to be selected for artifact sync
- **THEN** the registry is queried for the current subnet membership
- **AND** blacklisted nodes (configured in `blacklisted_nodes`) are excluded
- **AND** nodes are randomly shuffled to distribute load

### Requirement: Storage Lifecycle Management
The backup system manages data across hot and cold storage tiers with configurable retention policies.

#### Scenario: Hot to cold storage migration
- **WHEN** states are older than `DAYS_TO_KEEP_STATES_IN_HOT_STORAGE` (1 day)
- **THEN** they are moved from hot storage to the cold storage directory
- **AND** cold storage migration runs hourly (COLD_STORAGE_PERIOD = 3600 seconds)

#### Scenario: Artifact archiving
- **WHEN** artifacts have been replayed and verified
- **THEN** they are moved to an archive directory organized by height
- **AND** an archiving timestamp is recorded in `archiving_timestamp.txt`

#### Scenario: Disk resource monitoring
- **WHEN** disk usage exceeds `hot_disk_resource_threshold_percentage`
- **THEN** warnings are raised and older data may be cleaned up
- **WHEN** cold disk usage exceeds `cold_disk_resource_threshold_percentage`
- **THEN** similar warnings are raised for the cold storage

#### Scenario: Version retention in hot storage
- **WHEN** managing hot storage
- **THEN** only `versions_hot` (default 2) most recent versions are kept in hot storage
- **AND** older versions are moved to cold storage or deleted

#### Scenario: Cold storage disabled
- **WHEN** `disable_cold_storage` is true for a subnet
- **THEN** cold storage operations are skipped for that subnet

### Requirement: Backup Configuration
The backup system is configured via a JSON configuration file with subnet-specific and global settings.

#### Scenario: Configuration validation
- **WHEN** the backup configuration is loaded
- **THEN** NNS URL must be present
- **AND** SSH private key file must exist on disk
- **AND** hot and cold disk thresholds must be below 100%
- **AND** at least one subnet must be configured (unless using a placeholder Slack token)

#### Scenario: Subnet-specific configuration
- **WHEN** per-subnet backup is configured
- **THEN** each subnet has: `subnet_id`, `initial_replica_version`, `nodes_syncing`, `sync_period_secs`, `replay_period_secs`, `thread_id`, and `disable_cold_storage`

#### Scenario: Notification client
- **WHEN** backup operations encounter issues or complete milestones
- **THEN** notifications are sent via the `NotificationClient` (Slack integration)
- **AND** the Slack token is configured globally in the backup config

### Requirement: Periodic Metrics Push
The backup system periodically pushes metrics about its operations.

#### Scenario: Metrics reporting
- **WHEN** the metrics push period elapses (every 5 minutes)
- **THEN** backup operation metrics are pushed to the configured metrics URLs

## Recovery

### Requirement: Application Subnet Recovery
Application subnet recovery is a multi-step process that recovers a stalled or broken application subnet.

#### Scenario: Recovery step sequence
- **WHEN** an application subnet recovery is initiated
- **THEN** the following steps are executed in order:
  1. **Halt** - halt the subnet via ic-admin proposal and optionally deploy SSH keys
  2. **DownloadCertifications** - pull certification pools from as many nodes as possible
  3. **MergeCertificationPools** - merge certifications and check for state divergence
  4. **DownloadConsensusPool** - download finalized consensus artifacts from an up-to-date node
  5. **DownloadState** - download subnet state from a node (can be local if on-node)
  6. **ICReplay** - replay finalized blocks on top of downloaded state using ic-replay
  7. **ValidateReplayOutput** - verify replay height matches highest finalized height
  8. **BlessVersion** - optionally bless a new replica version
  9. **UpgradeVersion** - propose subnet upgrade to the new version
  10. **ProposeCup** - propose a recovery CUP with the state hash from replay
  11. **UploadState** - upload the recovered state to a subnet node
  12. **WaitForCUP** - wait for the node to receive the recovery CUP
  13. **Unhalt** - resume subnet computation and remove readonly SSH keys
  14. **Cleanup** - delete the working directory

#### Scenario: State divergence detection
- **WHEN** certification pools are merged
- **THEN** certifications from at least `n - f` nodes must be present (where f = (n-1)/3)
- **AND** conflicting certifications at the same height indicate potential state divergence
- **AND** manual intervention is required if divergence is detected

#### Scenario: Target replay height for deterministic bug
- **WHEN** recovery is caused by a panic at a specific execution height
- **THEN** a `replay_until_height` can be specified to stop replay before the panic
- **AND** this height must be above or equal to the last certification height
- **AND** the resulting checkpoint is used for the recovery CUP

#### Scenario: Recovery CUP proposal
- **WHEN** the ProposeCup step executes
- **THEN** an ic-admin proposal is created with the state hash from replay
- **AND** the CUP height is set strictly higher than the latest finalized height
- **AND** optional new node IDs can be specified if recovering on different nodes
- **AND** Chain key backup subnets are specified if the subnet has Chain keys

### Requirement: NNS Recovery on Same Nodes
NNS recovery on the same set of nodes requires a different process because the NNS cannot halt itself via a proposal.

#### Scenario: NNS same-nodes recovery step sequence
- **WHEN** NNS recovery on the same nodes is initiated
- **THEN** the following steps are executed:
  1. **StopReplica** - manually stop replica on the admin node (no halt proposal possible for NNS)
  2. **DownloadCertifications** - pull certification pools
  3. **MergeCertificationPools** - check for divergence
  4. **DownloadConsensusPool** - download finalized artifacts
  5. **DownloadState** - download state (admin access required, no readonly key deployment)
  6. **ICReplay** - replay with ingress messages for version upgrade and registry update
  7. **ValidateReplayOutput** - verify output height
  8. **UpdateRegistryLocalStore** - create new registry local store from canister state
  9. **CreateRegistryTar** - create tarball of updated registry
  10. **GetRecoveryCUP** - create recovery CUP with state hash and DKG transcripts
  11. **CreateArtifacts** - package recovery CUP and registry archive
  12. **UploadState** - upload state to admin node
  13. **UploadRecoveryArtifacts** - deploy recovery artifacts to admin node
  14. **WaitForCUP** - wait for recovery CUP acknowledgment
  15. **Unhalt** - resume computation
  16. **Cleanup** - clean up working directory

#### Scenario: Registry local store update during NNS recovery
- **WHEN** the ICReplay step runs for NNS recovery
- **THEN** ingress messages are added to: bless a new replica version and update the subnet record
- **AND** the `UpdateRegistryLocalStore` step extracts the registry canister state into a local store
- **AND** this updated local store indicates to nodes that they should upgrade

### Requirement: NNS Recovery on Failover Nodes
NNS recovery on a new set of nodes creates an entirely new NNS subnet from an existing state.

#### Scenario: NNS failover recovery step sequence
- **WHEN** NNS recovery on failover nodes is initiated
- **THEN** the following additional steps are included:
  1. **ProposeToCreateSubnet** - create a new subnet proposal on the parent NNS
  2. **DownloadParentNNSStore** - download registry from the parent NNS
  3. **ICReplayWithRegistryContent** - replay with additional registry mutations
  4. **UploadAndHostTar** - upload registry archive to an auxiliary host
  5. **ProposeCUP** - propose CUP with registry store URI pointing to the hosted archive
  6. **UploadStateToChildNNSHost** - upload state to a node in the new subnet

### Requirement: Recovery State Persistence
Recovery progress can be saved and resumed across sessions.

#### Scenario: Recovery state serialization
- **WHEN** recovery progress needs to be saved
- **THEN** the `RecoveryState` is serialized to disk
- **AND** recovery can be resumed from the last completed step

#### Scenario: Recovery argument merging
- **WHEN** recovery is resumed from saved state
- **THEN** the `ArgsMerger` combines saved arguments with any new command-line arguments
- **AND** new arguments override saved values

### Requirement: Recovery Tooling
The recovery system provides helper utilities for SSH, file synchronization, and command execution.

#### Scenario: SSH helper
- **WHEN** recovery needs to interact with remote nodes
- **THEN** `SshHelper` provides authenticated SSH connections
- **AND** both admin and readonly SSH users are supported

#### Scenario: File sync helper
- **WHEN** state or artifacts need to be transferred
- **THEN** rsync is used for efficient file synchronization
- **AND** `rsync_includes` allows selective file transfer

#### Scenario: Admin helper
- **WHEN** NNS proposals need to be submitted
- **THEN** `AdminHelper` wraps `ic-admin` CLI commands
- **AND** both HSM-based and key-file-based signing are supported
- **AND** the IC_ADMIN_PATH environment variable can override the binary location

## Replay

### Requirement: State Replay for Debugging and Recovery
The ic-replay tool replays past finalized blocks to reconstruct state at any height, used for both debugging and recovery.

#### Scenario: Basic state replay
- **WHEN** ic-replay runs with a config file and subnet ID
- **THEN** it loads the consensus pool and state from the configured paths
- **AND** replays all finalized blocks that have not yet been executed
- **AND** creates a checkpoint of the resulting state

#### Scenario: Replay from backup
- **WHEN** ic-replay runs with the `RestoreFromBackup` subcommand
- **THEN** it initializes a `Player` with the backup spool path and registry local store
- **AND** blocks are replayed starting from the specified `start_height`
- **AND** if an upgrade is required (different replica version), replay stops and reports the required version

#### Scenario: Replay with target height
- **WHEN** a `replay_until_height` is specified
- **THEN** replay stops at the given height and creates a checkpoint
- **AND** a warning is issued that the checkpoint may not be at a CUP height

#### Scenario: Replay with registry mutations
- **WHEN** the `UpgradeSubnetToReplicaVersion` subcommand is used
- **THEN** ingress messages are injected to upgrade the subnet to a new replica version
- **WHEN** the `AddRegistryContent` subcommand is used
- **THEN** additional registry mutations are applied during replay

#### Scenario: Registry local store update
- **WHEN** the `UpdateRegistryLocalStore` subcommand is used
- **THEN** after replay, the registry local store is updated to match the registry canister state

#### Scenario: Recovery CUP generation
- **WHEN** the `GetRecoveryCup` subcommand is used
- **THEN** a recovery CUP is created using the latest CUP's DKG transcripts
- **AND** the CUP height and state hash are overridden with the provided values
- **AND** the result is written to the specified output file in protobuf format

#### Scenario: Test-mode subcommands
- **WHEN** test subcommands are used (`WithNeuronForTests`, `WithLedgerAccountForTests`, `WithTrustedNeuronsFollowingNeuronForTests`)
- **THEN** test-specific ingress messages are injected for setting up test environments
