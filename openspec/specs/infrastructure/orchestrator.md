# Orchestrator

**Crates**: `ic-image-upgrader`

The orchestrator is a component of the Internet Computer that manages the replica process on each node. It continuously determines the correct replica binary to run, manages upgrades, firewall rules, SSH access, and other node-level configuration.

## Requirements

### Requirement: Orchestrator Initialization
The orchestrator must initialize all subsystems on startup, including generating node keys, loading the replica version, setting up the registry replicator, and creating crypto components.

#### Scenario: Successful orchestrator startup
- **WHEN** the orchestrator binary starts with valid arguments and configuration
- **THEN** node keys are generated (or loaded if they already exist) via `generate_node_keys_once`
- **AND** the replica version is loaded from the version file specified in command-line arguments
- **AND** a metrics HTTP endpoint is created and begins serving at the configured address
- **AND** the registry replicator is started and begins polling for registry updates
- **AND** the crypto component is initialized with the registry client
- **AND** node registration is attempted if provisional registration is enabled

#### Scenario: Version file read failure
- **WHEN** the orchestrator starts and the version file cannot be read or parsed
- **THEN** a `VersionFileError` is returned and the orchestrator fails to instantiate

#### Scenario: Key generation failure
- **WHEN** the orchestrator starts and key generation encounters a transient internal error
- **THEN** a `KeyGenerationError` is returned and the orchestrator fails to instantiate

### Requirement: Task Management
The orchestrator spawns and manages multiple concurrent asynchronous tasks, each responsible for a different subsystem. All tasks are tracked and monitored for panics.

#### Scenario: All tasks spawned on startup
- **WHEN** the orchestrator starts its tasks via `start_tasks`
- **THEN** the following tasks are spawned: GuestOS_upgrade, HostOS_upgrade, boundary_node_management, ssh_key_firewall_rules_ipv4_config, dashboard, and key_rotation
- **AND** each task runs in a loop with a 10-second check interval until cancellation

#### Scenario: Task panic detection
- **WHEN** any spawned task panics during execution
- **THEN** the `TaskTracker` catches the panic via `JoinSet`
- **AND** the `critical_error_task_failed` metric is incremented with label "panic"
- **AND** other tasks continue running unaffected

#### Scenario: Graceful task completion
- **WHEN** a task completes without error
- **THEN** the `TaskTracker` logs the graceful completion
- **AND** no error metrics are incremented

#### Scenario: Cancellation signal
- **WHEN** the cancellation token is triggered
- **THEN** all tasks observe the cancellation via `tokio::select!` on `cancellation_token.cancelled()`
- **AND** all tasks exit their loops gracefully

### Requirement: Replica Process Management
The orchestrator manages the lifecycle of the replica process, including starting, stopping, and version-based restarts.

#### Scenario: Starting the replica process
- **WHEN** the orchestrator determines the replica should be running (node is assigned to a subnet)
- **THEN** the `ProcessManager` spawns the replica binary with the correct version, arguments, and configuration
- **AND** the process PID is tracked in a shared `PIDCell`
- **AND** a background thread waits for the process to exit and clears the PID on termination

#### Scenario: Replica already running with correct version
- **WHEN** the `ProcessManager` is asked to start a process that is already running with the same version
- **THEN** no action is taken and the existing process continues

#### Scenario: Replica version change requires restart
- **WHEN** the `ProcessManager` is asked to start a process with a different version than the currently running one
- **THEN** the currently running process group is sent SIGTERM
- **AND** the new process configuration is stored for restart on next start call

#### Scenario: Stopping the replica process
- **WHEN** `stop()` is called on the `ProcessManager`
- **THEN** the entire process group is sent SIGTERM (using negative PID)
- **AND** this ensures all child processes spawned by the replica are also terminated

### Requirement: GuestOS Upgrade Orchestration
The orchestrator periodically checks whether the replica should be upgraded to a new version based on the registry and catch-up packages (CUPs).

#### Scenario: Upgrade check for assigned node
- **WHEN** the upgrade check runs for a node assigned to a subnet
- **THEN** the local CUP is read from disk
- **AND** the latest CUP is fetched from peers or the registry
- **AND** the registry version referenced in the CUP is used to determine the expected replica version
- **AND** if the expected version differs from the running version, an upgrade is initiated

#### Scenario: Upgrade execution
- **WHEN** a version mismatch is detected between the running and expected replica version
- **THEN** the new image is downloaded if not already prepared
- **AND** the upgrade is executed via the `ImageUpgrader` trait
- **AND** the orchestrator returns `OrchestratorControlFlow::Stop` to trigger a reboot

#### Scenario: Upgrade check for unassigned node
- **WHEN** the upgrade check runs and the node is not assigned to any subnet
- **THEN** the orchestrator checks the `unassigned_replica_version` from the registry
- **AND** if a different version is specified, the node upgrades to that version

#### Scenario: Upgrade check timeout
- **WHEN** the upgrade check takes longer than 15 minutes
- **THEN** it is cancelled via `tokio::time::timeout`
- **AND** the `failed_consecutive_upgrade_checks` metric is incremented
- **AND** the check is retried on the next interval

#### Scenario: Recalled replica version blocks upgrade
- **WHEN** the target replica version is in the list of recalled versions for the subnet
- **THEN** the upgrade is not executed
- **AND** an error is returned from `ensure_upgrade_should_be_executed`

#### Scenario: Node leaves subnet gracefully
- **WHEN** the node is no longer listed in the subnet membership at the latest registry version
- **AND** the node's CUP registry version has not yet reached the version where membership changed
- **THEN** the orchestrator enters the `Leaving` state to allow graceful departure
- **AND** once the CUP catches up, the node transitions to `Unassigned`
- **AND** the replica process is stopped and node state is removed

### Requirement: HostOS Upgrade Management
The orchestrator monitors the registry for HostOS version changes and triggers HostOS upgrades when necessary.

#### Scenario: HostOS upgrade detected
- **WHEN** the registry specifies a different HostOS version for this node than the currently running one
- **THEN** the HostOS version record is fetched from the registry
- **AND** the upgrade image is downloaded and the upgrade is executed via `UtilityCommand`

#### Scenario: HostOS upgrade loop with exponential backoff
- **WHEN** the HostOS upgrade check runs
- **THEN** it uses an exponential backoff starting at 1 minute, multiplied by 1.75x, maxing at 2 hours
- **AND** a random jitter of +/- 50% is applied to each delay
- **AND** a 15-minute liveness timeout restarts the check if no progress is made

#### Scenario: HostOS version unavailable
- **WHEN** the HostOS version cannot be determined at orchestrator startup
- **THEN** the HostOS upgrade task is not spawned
- **AND** an error is logged

### Requirement: Catch-Up Package (CUP) Management
The orchestrator fetches, verifies, and persists catch-up packages to determine the correct state of the subnet.

#### Scenario: CUP fetched from own replica first
- **WHEN** the orchestrator checks for a new CUP
- **THEN** it first attempts to fetch the CUP from its own replica's CUP endpoint
- **AND** only if no newer CUP is available does it try random peers
- **AND** requests include the local CUP version to avoid unnecessary data transfer

#### Scenario: CUP from registry indicates recovery
- **WHEN** the latest CUP is unsigned (i.e., a registry CUP)
- **THEN** the orchestrator detects a subnet genesis or recovery scenario
- **AND** if it is an NNS subnet recovery, the new registry is downloaded and the node restarts

#### Scenario: CUP persistence
- **WHEN** a new CUP is obtained that is newer than the locally persisted one
- **THEN** the CUP is written to disk in protobuf format at `cup.types.v1.CatchUpPackage.pb`
- **AND** the CUP is stored in a backwards-compatible protobuf format

#### Scenario: CUP deserialization failure
- **WHEN** a local CUP protobuf exists but cannot be deserialized
- **THEN** the `critical_error_cup_deserialization_failed` metric is incremented
- **AND** the orchestrator attempts to extract the subnet ID from the NiDkgId as a fallback

### Requirement: Firewall Management
The orchestrator monitors the registry for firewall rule changes and updates the node's firewall configuration accordingly.

#### Scenario: Firewall rules updated from registry
- **WHEN** the registry version changes and new firewall rules are available
- **THEN** rules are fetched from all relevant scopes (global, subnet, node, replica_nodes)
- **AND** the compiled firewall configuration is written to the configured file path
- **AND** the `last_applied_version` is updated

#### Scenario: Role-based firewall rules
- **WHEN** the firewall checks the node's role
- **THEN** if the node is an assigned replica, subnet-specific rules are applied
- **AND** if the node is an unassigned replica, only global and node-specific rules apply
- **AND** if the node is a boundary node, boundary-node-specific rules apply

#### Scenario: Firewall disabled in test mode
- **WHEN** the firewall configuration file path is the default path (test mode)
- **THEN** firewall updates are disabled and a warning is logged

#### Scenario: First-time firewall write
- **WHEN** the orchestrator starts for the first time
- **THEN** the firewall configuration is written even if no registry change is detected (`must_write` flag)

### Requirement: SSH Access Management
The orchestrator manages SSH access keys for readonly, backup, and recovery accounts based on registry configuration.

#### Scenario: SSH keys updated from registry
- **WHEN** the registry version changes or the subnet assignment changes
- **THEN** readonly, backup, and recovery SSH key sets are fetched from the registry
- **AND** keys are deployed to the appropriate OS accounts via `write_ssh_keys.sh`
- **AND** the `last_applied_parameters` are updated with the current registry version and subnet ID

#### Scenario: SSH keys for assigned vs unassigned nodes
- **WHEN** the node is assigned to a subnet
- **THEN** subnet-level readonly and backup keys are fetched along with global recovery keys
- **WHEN** the node is unassigned
- **THEN** only the unassigned nodes configuration is used for readonly and backup keys

#### Scenario: SSH key update waits for subnet knowledge
- **WHEN** the subnet assignment is still `Unknown` (orchestrator just started)
- **THEN** SSH key updates are skipped to avoid incorrectly purging keys

### Requirement: Node Registration and Key Rotation
The orchestrator handles initial node registration with the NNS and periodic key rotation for assigned nodes.

#### Scenario: Node registration on first boot
- **WHEN** provisional registration is enabled
- **THEN** the orchestrator calls `register_node()` which will not return until registration succeeds
- **AND** the registration payload includes the node's public keys, IP addresses, and domain

#### Scenario: iDKG key rotation check
- **WHEN** the key rotation task runs and the node is assigned to a subnet
- **THEN** `check_all_keys_registered_otherwise_register` is called
- **AND** if iDKG encryption key rotation is due, the crypto component performs the rotation
- **AND** the rotated key is registered with the NNS registry

#### Scenario: Key rotation frequency
- **WHEN** calculating the key rotation interval
- **THEN** a 15% delay compensation factor (DELAY_COMPENSATION = 0.85) is applied
- **AND** this ensures the registry accepts key updates from the subnet at an appropriate rate

### Requirement: IPv4 Network Configuration
The orchestrator monitors the registry for IPv4 configuration changes and applies them to the node.

#### Scenario: IPv4 configuration updated
- **WHEN** the registry contains a new IPv4 configuration for this node
- **THEN** the orchestrator applies the network configuration changes
- **AND** the `last_applied_version` is updated

### Requirement: Boundary Node Management
The orchestrator manages boundary node configuration for nodes that serve as API boundary nodes.

#### Scenario: Boundary node check
- **WHEN** the boundary node management task runs
- **THEN** the `BoundaryNodeManager` checks the registry for boundary node configuration updates
- **AND** appropriate actions are taken based on changes

### Requirement: Orchestrator Dashboard
The orchestrator exposes an HTTP dashboard showing the current state of the node.

#### Scenario: Dashboard serves node status
- **WHEN** a request is made to the orchestrator dashboard endpoint
- **THEN** the dashboard returns information about the node including: registry status, subnet assignment, replica version, HostOS version, firewall state, SSH access state, IPv4 configuration, and replica process status

### Requirement: Registry Replication
The registry replicator component ensures the node has an up-to-date copy of the NNS registry.

#### Scenario: Registry polling
- **WHEN** the registry replicator is started
- **THEN** it polls one of the configured NNS nodes for registry updates on a regular basis
- **AND** responses are verified using the configured NNS public key
- **AND** verified changelog entries are applied to the Registry Local Store

#### Scenario: NNS switch-over
- **WHEN** a subnet record with `start_as_nns` is detected
- **THEN** the registry replicator creates a fresh registry state
- **AND** the new state contains all versions up to the switch-over version with appropriate modifications
- **AND** `nns_subnet_id`, `subnet_list`, and `routing_table` are updated for the new NNS

### Requirement: Metrics and Observability
The orchestrator exposes comprehensive metrics for monitoring its health and operations.

#### Scenario: Orchestrator info metric
- **WHEN** the orchestrator starts
- **THEN** the `orchestrator_info` metric is set with the current replica version as a label

#### Scenario: Reboot duration metric
- **WHEN** the orchestrator starts after a reboot
- **THEN** the `reboot_duration` metric is set to the elapsed time since the last reboot trigger

#### Scenario: Failed upgrade checks metric
- **WHEN** an upgrade check fails or times out
- **THEN** the `failed_consecutive_upgrade_checks` metric is incremented
- **WHEN** an upgrade check succeeds
- **THEN** the `failed_consecutive_upgrade_checks` metric is reset to zero

#### Scenario: Master public key change detection
- **WHEN** the orchestrator detects a new CUP with a different height than the previous one
- **THEN** it compares the master public keys between the old and new CUPs
- **AND** if any key has changed, an alert metric is raised and the change is persisted to disk

#### Scenario: Host notification
- **WHEN** the orchestrator starts or detects important state changes
- **THEN** it sends notifications to the host via `UtilityCommand::notify_host`
- **AND** periodic status messages include node ID, replica version, IPv4, and IPv6 addresses

### Requirement: Upgrade Precondition - Registry Replicator Sync
Before executing an upgrade on non-NNS subnets, the orchestrator must verify that the local registry replicator has caught up with all registry versions certified before the orchestrator's initialization. This ensures the node has an accurate view of recalled replica versions before proceeding.

#### Scenario: Registry replicator has not caught up
- **WHEN** an upgrade is pending for a node on a non-NNS subnet
- **AND** `registry_replicator.has_replicated_all_versions_certified_before_init()` returns `false`
- **AND** fewer than 30 minutes have elapsed since orchestrator initialization (`init_time.elapsed() < TIMEOUT_IGNORE_UP_TO_DATE_REPLICATOR`)
- **THEN** the upgrade is delayed and an `UpgradeError` is returned
- **AND** the `orchestrator_replica_version_upgrade_prevented_total` metric is incremented with the label `replicator_not_caught_up`

#### Scenario: Registry replicator has caught up
- **WHEN** an upgrade is pending for a node on a non-NNS subnet
- **AND** `registry_replicator.has_replicated_all_versions_certified_before_init()` returns `true`
- **THEN** the replicator sync check passes and the upgrade proceeds to the recalled version check

#### Scenario: Registry replicator timeout after 30 minutes
- **WHEN** an upgrade is pending for a node on a non-NNS subnet
- **AND** `registry_replicator.has_replicated_all_versions_certified_before_init()` returns `false`
- **AND** 30 minutes or more have elapsed since orchestrator initialization (`init_time.elapsed() >= TIMEOUT_IGNORE_UP_TO_DATE_REPLICATOR`, where `TIMEOUT_IGNORE_UP_TO_DATE_REPLICATOR` is `Duration::from_secs(1800)`)
- **THEN** the replicator sync check is skipped as a safeguard against staying stuck indefinitely (e.g., if the NNS subnet is unreachable)
- **AND** the upgrade proceeds to the recalled version check

### Requirement: NNS Subnet Upgrade Exemption
Nodes on the NNS (root) subnet are exempt from all upgrade precondition checks. Neither the registry replicator sync check nor the recalled version check is applied. This ensures that NNS subnet upgrades always proceed unconditionally.

#### Scenario: Upgrade on NNS subnet skips all precondition checks
- **WHEN** an upgrade is pending for a node on the NNS subnet (i.e., `subnet_id == registry.get_root_subnet_id(latest_registry_version)`)
- **THEN** `ensure_upgrade_should_be_executed` returns `Ok(())` immediately
- **AND** the registry replicator sync check is not evaluated
- **AND** the recalled version check is not evaluated
- **AND** the upgrade proceeds unconditionally

### Requirement: Upgrade Check Timeout and Failure Metrics
The `check_for_upgrade()` call is wrapped in a 15-minute timeout (`UPGRADE_TIMEOUT = Duration::from_secs(60 * 15)`). Both timeouts and errors increment the `failed_consecutive_upgrade_checks` metric. A successful check resets the metric to zero.

#### Scenario: Upgrade check succeeds
- **WHEN** `check_for_upgrade()` completes successfully within 15 minutes
- **THEN** `failed_consecutive_upgrade_checks` is reset to zero via `reset()`
- **AND** the returned `OrchestratorControlFlow` is processed normally

#### Scenario: Upgrade check returns an error
- **WHEN** `check_for_upgrade()` completes within 15 minutes but returns an `Err`
- **THEN** a warning is logged: "Check for upgrade failed: {err}"
- **AND** `failed_consecutive_upgrade_checks` is incremented by one via `inc()`

#### Scenario: Upgrade check times out at 15 minutes
- **WHEN** `check_for_upgrade()` does not complete within 15 minutes
- **THEN** the call is cancelled via `tokio::time::timeout`
- **AND** a warning is logged: "Check for upgrade timed out: {err}"
- **AND** `failed_consecutive_upgrade_checks` is incremented by one via `inc()`
- **AND** the check is retried after the next `CHECK_INTERVAL_SECS` sleep
