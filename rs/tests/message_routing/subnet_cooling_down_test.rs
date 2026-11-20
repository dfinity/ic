/* tag::catalog[]
Title:: Draining and merging a subnet that is "cooling down".

Goal:: Verify that a subnet holding what a subnet merge has to drain violates
the individual terms of the "merge readiness" condition, i.e. that the
condition the subnet merging tool waits for before merging such a subnet away
is one that the subnet does not satisfy to begin with; and that once the tool
(`rs/recovery/subnet_merging`) has labeled the subnet "cooling down", the
subnet rejects ingress messages and query calls, the tool eventually finds the
condition to hold, and it then halts the subnet and the subnet it is told to
merge it into at their next CUP, downloads and validates the state each halted
at, assembles the merged state from them, has the canister ID ranges of the
subnet rerouted to the subnet it is merged into, and recovers the destination
subnet at the merged state without losing any of the state of either subnet.
The cooling down subnet also holds calls waiting for responses that do not
arrive before the merge: they are not drained, but make it possible to assert
that a subnet merge populates the ingress history properly, as every ingress
message that is in progress across the merge completes after it.

The subnet that is cooled down, i.e. the one that is merged away, is
called `S`, and the Application subnet the tool is told to merge `S` into is
called `D`. `S` exchanges the same calls with `D` as with a third Application
subnet `O`, which is not part of the merge: once the merge goes ahead, the
messages and calls between `D` and the canisters of `S` become messages and
calls within the destination subnet, whereas those between `O` and the
canisters of `S` have to be rerouted to `D` by a subnet that is not itself
part of the merge.

The NNS subnet is none of these: it has to stay available throughout, as it is
where the proposals of the merge are executed, including the one recovering `D`
at the merged state. Every proposal of the merge is submitted by the tool,
through `ic-admin` with the test neuron; this test submits none.

"Executing" an update call below always means submitting it as an ingress
message without waiting for it to complete: most of the calls of this test only
complete after the merge.

Runbook::
0. Set up an IC with an NNS subnet (with the NNS canisters installed) and three
   Application subnets `S`, `D` and `O`, of `SUBNET_SIZE` nodes each.
1. Install two universal canisters on `S` and one on each of `D` and `O`:
   `USD` and `USO` on `S`, `UDS` on `D` and `UOS` on `O`.
2. Make an ingress call to each of them with a payload that calls its peer on
   another subnet in a loop: `USD` and `UDS` call each other, and so do `USO`
   and `UOS`.
3. Wait until all loops have completed a few iterations, i.e. messages are
   actually flowing between `S` and each of `D` and `O` in both directions.
4. Install the universal canisters of the steps below (`U1`, `U3`, `U5`, `U6`,
   `U9`, `U10`, `U12` and `U14` on `S`, `U4` and `U7` on `D`, `U8`, `U11` and
   `U13` on `O`) and create two empty canisters `U2a` and `U2b` on `S`,
   controlled by `U1`. Then give `U12` the state that has to survive the merge:
   a blob in its stable memory, a canister snapshot, and a cycles balance to
   compare against later.
5. Start the endless loops, each of which calls the management canister's
   `canister_status` method for the looping canister over and over until the
   global data of that canister is set to `LOOP_BREAK_TRIGGER`, which this test
   only does after the merge (step 26):
   a. execute an update call on `U3` (on `S`) with the loop as its payload;
   b. execute an update call on `U4` (on `D`) that calls `U5` (on `S`) with the
      loop as its payload, so that `S` holds a canister looping in a call from
      another subnet that it cannot respond to before the merge;
   c. execute an update call on `U6` (on `S`) that calls `U7` (on `D`) with the
      loop as its payload, so that `S` holds a canister waiting for a response
      from another subnet that does not arrive before the merge;
   d. execute an update call on `U8` (on `O`) that calls `U9` (on `S`), like b;
   e. execute an update call on `U10` (on `S`) that calls `U11` (on `O`), like
      c;
   f. execute an update call on `U13` (on `O`) making a best effort call to
      `U14` (on `S`) that carries cycles and has the loop as its payload, so
      that `U14` holds the call context of a best effort call whose deadline
      passes before the merge.
   Wait until all of these loops are running.
6. Execute an update call on `U1` that makes two calls to the management
   canister's `install_code` method, one per `U2x`, in mode `install`, with the
   universal canister module and an `arg` that makes `canister_init` burn
   `INIT_INSTRUCTIONS` instructions. Wait until both requests have left
   `U1`'s output queue, i.e. until one of them is executing and the other is
   enqueued in `S`'s subnet input queues. This comes right before step 7
   because the other one stays enqueued only for as long as the first one
   executes, i.e. for a fixed number of rounds.
7. Evaluate the terms of the "merge readiness" condition for `S` and check that
   none of the `VIOLATED_CONDITIONS` holds: `D` and `O` hold messages in their
   streams to `S` and `S` holds messages in its own streams (the loops of step
   2), the ingress history holds terminal entries (the calls of the steps above
   that did complete), `S`'s subnet input queues hold messages (`U1`'s
   `install_code` requests) and its subnet call context manager holds call
   contexts (the `install_code` calls that are executing). The remaining three
   terms are expected to hold and are only logged; `VIOLATED_CONDITIONS` says
   why.
8. Hand over to the subnet merging tool, which runs all of its steps one at a
   time, in the order in which `StepType` declares them; the checks below are
   made in between its steps, right after the step each of them names. The
   following steps of the tool are executed:
   `CoolDownSourceSubnet`, which labels `S` as "cooling down", and
   `CheckRegistryForCoolingDownFlag`, which records the registry version `V`
   at which it reads the label back.
9. After `CheckRegistryForCoolingDownFlag`: wait until `S` rejects ingress
   messages, and then until it rejects query calls too. Then wait until `U13`'s
   best effort call of step 5f timed out, i.e. its deadline has passed before
   the merge.
10. The following step of the tool is executed: `CheckMergeReadiness`, which
   waits until `S` is "merge ready" for `V`, i.e. until every term of the
   condition of step 7 holds.
11. After `CheckMergeReadiness`: check that the loops of `UDS` and `UOS` of step
   2 are stalled, i.e. that their iteration counters do not advance, as read
   via queries to `D` and `O`. The counters of `USD` and `USO` cannot be read,
   as `S` rejects query calls.
12. The following steps of the tool are executed: `HaltSourceSubnetAtCupHeight`
   and `HaltDestinationSubnetAtCupHeight`, which set the `halt_at_cup_height`
   flag of `S` and `D`, and `WaitForHaltingCupOnSourceSubnet` and
   `WaitForHaltingCupOnDestinationSubnet`, which wait until the node of each
   subnet that its state is downloaded from serves the halting CUP.
13. After `WaitForHaltingCupOnDestinationSubnet`: check that both subnets are
   halted, i.e. that every one of their nodes certifies the height its subnet
   halts at and none goes past it, even after `HALT_OBSERVATION_PERIOD`.
14. The following steps of the tool are executed, over SSH with the admin key
   (or locally, if the tool runs on the node):
   `Stop{Source,Destination}Replica`, which wait until the node of each subnet
   holds a finished checkpoint at the height of the CUP its subnet halts at
   and then stop its replica;
   `DownloadStateFrom{Source,Destination}Subnet`, which download the
   checkpoint at the height of the CUP each subnet halted at; and
   `Validate{Source,Destination}SubnetCup`, which validate each downloaded state
   against the CUP its subnet halted at and the subnet's public key in the NNS
   signed state tree.
15. The following steps of the tool are executed:
   `ComputeExpectedMergedManifest`, which derives the manifest the merged state
   is expected to have from the manifests of the two validated states; and
   `MergeStates`, which assembles the merged state locally, as a checkpoint
   holding the state of `D` with the canisters and canister snapshots of `S`
   added to it, and checks that its manifest has the expected root hash.
16. After `MergeStates`: check that the merged state is a single checkpoint that
   holds exactly the canisters of the two downloaded checkpoints of `S` and `D`.
17. The following steps of the tool are executed: `MergeSubnets`, which submits
   a proposal rerouting the canister ID ranges of `S` to `D`, and
   `CheckRegistryForRoutingTableEntry`, which waits until the registry routes
   no canister ID range to `S` anymore and records the registry version at
   which it read this.
18. After `CheckRegistryForRoutingTableEntry`: check that the registry version
   the tool recorded is recorded for `S`, is newer than the one at which `S`
   was labeled "cooling down", and is one at which the registry routes no
   canister ID range to `S` and every canister ID range `S` started out with
   to `D`.
19. The following step of the tool is executed:
   `ProposeCupForDestinationSubnet`, which submits a proposal for a recovery CUP
   of `D` at the merged state. The CUP is stamped with the time it is proposed
   at, which the tool checks to be past the times of the CUPs both subnets
   halted at. Executing the proposal runs a fresh DKG for the nodes of `D`.
20. After `ProposeCupForDestinationSubnet`: wait until the registry holds the
   recovery CUP contents of `D`, which it only does once the fresh DKG for `D`
   has completed. Check their height, state hash and time:
   * The height is the one of the merged checkpoint, which is above the heights
     both subnets halted at.
   * The state hash is the one of the merged checkpoint, computed from the
     checkpoint itself rather than read from the manifest the tool wrote.
   * The time is past the times of the CUPs both subnets halted at.

   Recovering a subnet that was instructed to halt at its next CUP replaces
   that instruction with a plain halt, so also check that `D` is halted: it
   stays halted until `UnhaltDestinationSubnet`.
21. The following step of the tool is executed:
   `UploadStateToDestinationSubnet`, which uploads the merged state to `D`'s
   node, replacing the state directory holding the checkpoint it halted at, and
   starts its replica back up. Deleting that checkpoint is what makes the
   recovery unambiguous: it does not hold the canisters of `S`, so a replica
   coming up on it would serve a state that silently lost them.
22. After `UploadStateToDestinationSubnet`: check that the checkpoints directory
   of `D`'s node holds exactly the merged checkpoint, and that the replica on
   that node is running again and started from it.
23. The following steps of the tool are executed:
   `WaitForCupOnDestinationSubnet`, which waits until `D`'s node reports the
   recovery CUP, i.e. it came up on the merged state, and
   `UnhaltDestinationSubnet`, which submits a proposal unhalting `D`.
24. After `UnhaltDestinationSubnet`: wait until `D` is healthy, then check that
   `U12`, now served by `D`, kept the stable memory, the snapshot and (up to
   what an idle canister burns) the cycles balance of step 4, and that `U7`,
   which `D` hosted all along, can call `U12` now that both are on the same
   subnet.
25. Check that `U2a` and `U2b`, also served by `D` now, have been installed,
   i.e. that the `install_code` calls of step 6 ran to completion while `S` was
   cooling down rather than being lost or rejected.
26. Set the global data of `U3`, `U5`, `U7`, `U9`, `U11` and `U14` to
   `LOOP_BREAK_TRIGGER`, ending the endless loops, and check that every ingress
   message that was in progress across the merge completed. The canisters of
   `S` are reached through `D`, which serves them after the merge. Then stop
   `U14`, which only succeeds once the call context of `U13`'s best effort call,
   which the merge carried over, is closed.

Success::
Every term of the "merge readiness" condition that this scenario exercises is
violated before `S` starts cooling down; `S` then rejects ingress messages and
query calls and becomes "merge ready", and the loops of `UDS` and `UOS` of step
2 are stalled; the tool then halts `S` and `D` at their next CUP, the states it
downloads from them pass validation, the merged state it assembles from them
holds exactly the canisters of both, and the registry version the tool records
routes the canister ID ranges of `S` to `D`; the registry holds the recovery
CUP contents of `D` at the merged state, with `D` halted; the replica on `D`'s
node runs on the merged state the tool uploaded to it; and once `D` is
recovered at the merged state, the canisters of `S` kept their state and `U2a`
and `U2b` are installed, every ingress message that was in progress across the
merge completes, and the call context of the best effort call whose deadline
passed before the merge is closed.

end::catalog[] */

use anyhow::{Result, anyhow, bail};
use candid::{Decode, Encode, Principal};
use ic_agent::{
    Agent, RequestId,
    agent::{RejectCode, RequestStatusResponse},
};
use ic_management_canister_types::{
    CanisterIdRecord, ListCanisterSnapshotsArgs, ListCanisterSnapshotsResult, SnapshotId,
    TakeCanisterSnapshotArgs, TakeCanisterSnapshotResult,
};
use ic_protobuf::registry::subnet::v1::catch_up_package_contents::CupType;
use ic_recovery::{
    CHECKPOINTS, IC_STATE, RECOVERY_DIRECTORY_NAME, RecoveryArgs, get_node_metrics,
    registry_helper::{RegistryHelper, RegistryPollingStrategy},
    util::DataLocation,
};
use ic_registry_client_helpers::{routing_table::RoutingTableRegistry, subnet::SubnetRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_subnet_merging::metrics_helper::{
    Labels, MetricsByReplica, ScrapeError, fetch_available_metrics, replica_values,
};
use ic_subnet_merging::readiness::{
    Condition, METRIC_SUBNET_CALL_CONTEXTS, METRIC_SUBNET_INPUT_QUEUE_MESSAGES, SubnetNodeIps,
    Term, evaluate_merge_readiness,
};
use ic_subnet_merging::subnet_merging::{StepType, SubnetMerging, SubnetMergingArgs};
use ic_subnet_tools::utils::{get_cup, get_state_hash};
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
    NnsInstallationBuilder, READY_WAIT_TIMEOUT, RETRY_BACKOFF, SshSession, SubnetSnapshot,
    TopologySnapshot, get_guestos_img_version,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    UniversalCanister, assert_create_agent, create_canister, set_controller,
};
use ic_types::{Height, RegistryVersion, consensus::HasHeight};
use ic_universal_canister::management::InstallMode;
use ic_universal_canister::{
    CallInterface, PayloadBuilder, call_args, get_universal_canister_wasm, management, wasm,
};
use slog::{Logger, info};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
use strum::IntoEnumIterator;
use tokio::runtime::Runtime;

/// The value of the `type` label selecting the `install_code` call contexts of
/// `METRIC_SUBNET_CALL_CONTEXTS`.
const LABEL_INSTALL_CODE: &str = "install_code";

/// Number of loop iterations each universal canister must have completed before
/// the conditions are evaluated, so that the loops are known to be making
/// cross-subnet calls by then.
const MIN_LOOP_ITERATIONS: u64 = 3;

/// One billion, the unit `INIT_INSTRUCTIONS` is expressed in.
const B: u64 = 1_000_000_000;

/// The names of the canisters `U1` installs code on.
/// Two of them, so that while one executes (holding a call context), the other
/// waits in the subnet input queues.
const INSTALL_CODE_TARGETS: [&str; 2] = ["U2a", "U2b"];

/// Instructions the `canister_init` of every canister installed by `U1` burns,
/// i.e. how long each of `U1`'s `install_code` calls runs. The point is to make
/// them as long-running as possible, so that the subnet holds `install_code`
/// calls that span hundreds of rounds, i.e. calls that a merge would have to
/// drain before it can go ahead.
///
/// An `install_code` message may consume at most
/// `MAX_INSTRUCTIONS_PER_INSTALL_CODE` = 300B instructions on an Application
/// subnet (`rs/config/src/subnet_config.rs`) and that budget also has to cover
/// compiling the module; hence the budget for `canister_init` has to leave room
/// for it.
const INIT_INSTRUCTIONS: u64 = 295 * B;

/// Where in the stable memory of `U12` the blob that has to survive the merge is
/// stored, and the blob itself.
const STABLE_MEMORY_OFFSET: u32 = 0;
const STABLE_MEMORY_BLOB: &[u8] = b"this blob has to survive the subnet merge";

/// The cycles the best effort call of step 5f carries, and its timeout. The
/// point of the call is that its callee holds the call context of a best effort
/// call across the merge whose deadline has passed: the callee does not respond
/// before the merge, the caller's side of the call times out well before it
/// (the merge is many minutes away), and the cycles the call carries are held by
/// the callee's open call context, which the merge has to carry over like any
/// other canister state.
const BEST_EFFORT_CALL_CYCLES: u128 = 1_000_000_000;
const BEST_EFFORT_CALL_TIMEOUT_SECONDS: u32 = 60;

/// The reject code (`SYS_UNKNOWN`) a best effort call is rejected with when its
/// deadline passes before a response arrived.
const REJECT_CODE_SYS_UNKNOWN: u32 = 6;

/// How long the test waits for the best effort call of step 5f to time out,
/// from the moment `S` is cooling down, which is about as long after the call
/// was made as its timeout.
const BEST_EFFORT_CALL_EXPIRY_TIMEOUT: Duration = Duration::from_secs(120);

/// What the canister of the destination subnet gets back from the canister that
/// the merge moved onto it.
const MERGED_CALL_REPLY: &[u8] = b"hello from the merged subnet";

/// The fraction of its cycles balance that the canister holding the state that
/// has to survive the merge may have burned in between the two readings, as one
/// in `MAX_BURNED_CYCLES_FRACTION`.
///
/// A share rather than an amount because the two readings are however many
/// minutes apart the waits of the steps in between take, and generous because
/// what this is meant to catch is a balance that the merge did not carry over at
/// all, which would be a loss of everything, rather than the resource charges of
/// an idle canister, which have been observed to be some three billion cycles of
/// a hundred trillion.
const MAX_BURNED_CYCLES_FRACTION: u128 = 1_000;

/// The global data value that ends the endless loops of `U3`, `U5`, `U7`, `U9`,
/// `U11` and `U14`. The test only sets it after the merge (step 26), so those
/// loops run across it.
const LOOP_BREAK_TRIGGER: &[u8] = b"break";

/// The number of nodes of every subnet. More than one so that the merge has to
/// get the merged state to the other nodes of the destination subnet the way a
/// recovery does, i.e. by state sync from the one node it was uploaded to, and so
/// that the terms of the merge readiness condition, which must hold together on
/// the same quorum of the replicas of a subnet, range over more than one
/// replica.
const SUBNET_SIZE: usize = 4;

/// The DKG interval length of all subnets, i.e. one less than the
/// distance between two consecutive checkpoints (and CUPs). The default is long
/// enough for an `install_code` burning `INIT_INSTRUCTIONS` to complete within
/// one interval, which matters because a paused `install_code` is aborted at
/// every checkpoint and has to start over afterwards.
const DKG_INTERVAL_LENGTH: u64 = 499;

/// How long the terms of the merge readiness condition are evaluated for before
/// the test gives up on seeing all of `VIOLATED_CONDITIONS` violated at once,
/// and how long it waits in between two evaluations. Longer than a driver retry
/// because every evaluation scrapes the metrics of all subnets.
const CONDITIONS_TIMEOUT: Duration = Duration::from_secs(120);
const CONDITIONS_BACKOFF: Duration = Duration::from_secs(5);

/// How long the test waits for `U1`'s `install_code` requests to be inducted,
/// and how long it waits in between two checks. Induction takes a few rounds,
/// so this is much shorter than a driver retry.
const INDUCTION_TIMEOUT: Duration = Duration::from_secs(60);
const INDUCTION_BACKOFF: Duration = Duration::from_secs(1);

/// The directory the merging tool works in, relative to the base directory of
/// the test environment.
const MERGING_DIR: &str = "subnet_merging";

/// The checkpoints directory of the replica on a node.
const NODE_CHECKPOINTS_DIR: &str = "/var/lib/ic/data/ic_state/checkpoints";

/// The height of the latest state the state manager of a replica holds, which
/// it sets to the height of the checkpoint it starts from.
const METRIC_MAX_RESIDENT_HEIGHT: &str = "state_manager_max_resident_height";

/// The duration of a round that the timeouts counted in rounds assume. Every
/// subnet is `Subnet::fast`, i.e. aims at rounds of a fraction of this; the
/// rest is slack for slow testnets.
const ROUND_MILLIS: u64 = 800;

/// The number of rounds in two DKG intervals, the most it takes a subnet to
/// reach the CUP it is instructed to halt at.
const TWO_DKG_INTERVALS: u64 = 2 * (DKG_INTERVAL_LENGTH + 1);

/// Timeout for the subnet to become "merge ready". The binding terms are the
/// `install_code` calls of step 6, which take a couple of hundred rounds each
/// (and are executed one at a time, as at most one long-running `install_code`
/// makes progress per round), and the ingress history, which only becomes free
/// of terminal statuses once the entries of the ingress messages submitted
/// before the subnet started cooling down are pruned, i.e. at their (up to
/// `MAX_INGRESS_TTL` = 5 minutes away) expiry times. Hence `MAX_INGRESS_TTL`
/// plus 400 rounds. The 400 rounds cover the `install_code` calls: each burns
/// `INIT_INSTRUCTIONS` at 2B instructions per round, i.e. takes about 150
/// rounds. The two are added up, as the TTL only starts ticking once the
/// `install_code` calls finish.
const MERGE_READY_TIMEOUT: Duration = Duration::from_millis(5 * 60 * 1000 + 400 * ROUND_MILLIS);
/// Timeout for the registry to reflect a proposal that `ic-admin` reported as
/// executed. Also bounds the wait for the recovery CUP contents of `D`, which
/// the registry only holds once the NNS subnet has completed a fresh DKG for
/// `D`: the NNS subnet runs that DKG in its data blocks, i.e. within a few
/// rounds of the proposal's execution.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(120);
/// Timeout for the replica on the node of `D` the merged state is uploaded to
/// to start from the merged checkpoint (step 22). Starting from a checkpoint of
/// the size of this scenario's takes seconds.
const REPLICA_RESTART_TIMEOUT: Duration = Duration::from_secs(300);
/// How long the merging tool waits between two evaluations of a condition it
/// waits for. Longer than a driver retry because every evaluation scrapes the
/// metrics of all subnets.
const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Timeout for a subnet to reach the CUP it halts at. As a DKG summary takes
/// its registry version from the previous summary, that CUP is up to two DKG
/// intervals away. Shorter than the default of the tool so that the test fits
/// into the timeout of its Bazel target.
const HALT_TIMEOUT: Duration = Duration::from_millis(TWO_DKG_INTERVALS * ROUND_MILLIS);

/// Timeout for an ingress message that was in progress across the merge to
/// complete once the loop it is waiting for is broken. Generous because the
/// destination subnet has just resumed from the merged state and is busy
/// recomputing its manifest and draining the message loops of step 2 at the same
/// time: this has been observed to take up to four minutes.
const INGRESS_COMPLETION_TIMEOUT: Duration = Duration::from_secs(480);

/// How long the loops of `UDS` and `UOS` are observed to be stalled (step 11).
const STALL_OBSERVATION_PERIOD: Duration = Duration::from_secs(15);

/// How long the certified heights of the nodes of `S` and `D` are observed to
/// stay at the height their subnet halts at (step 13).
const HALT_OBSERVATION_PERIOD: Duration = Duration::from_secs(30);

/// Timeouts of the test itself.
///
/// The timeout of the test is above the sum of the timeouts of the waits that
/// dominate it (`MERGE_READY_TIMEOUT`, `HALT_TIMEOUT`, `REPLICA_RESTART_TIMEOUT`
/// and `INGRESS_COMPLETION_TIMEOUT`, about 2200s together) plus ten minutes for
/// everything else, so that a stuck step fails with its own error.
/// `HALT_TIMEOUT` is counted once although it applies to each of the two
/// subnets: both are scheduled to halt before either is waited for, so the two
/// waits overlap. Likewise `INGRESS_COMPLETION_TIMEOUT`, as the ingress
/// messages it applies to complete concurrently.
///
/// The overall timeout additionally covers the setup (booting the IC and
/// installing the NNS) and has to stay below the 3600s of the `eternal` timeout
/// of the Bazel target, which also covers what runs outside of the test
/// driver's own timeouts.
const PER_TEST_TIMEOUT: Duration = Duration::from_secs(2800);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(3300);

/// The conditions this scenario violates, i.e. the ones step 7 checks. This
/// includes `CommonQuorum`, since the replicas do not satisfy the individual
/// conditions together. The three that are missing are expected to hold:
///
/// * `RegistryVersion`, because step 7 evaluates the condition at the version
///   of the test's topology snapshot, which every subnet has long observed,
///   rather than at the version labeling `S` as "cooling down", which only
///   exists from step 8 on.
/// * `SubnetOutputQueues`, because the stream builder routes the responses of
///   the management canister out of the subnet output queues in the same round
///   they are produced in, i.e. before the metrics are observed on the state
///   committed at the end of that round. It only holds on to a response whose
///   stream is full or whose destination subnet is cooling down while this one
///   is not, and the responses of this scenario all go into the loopback
///   stream, which is never considered full.
/// * `RefundPool`, because nothing in this scenario produces an anonymous
///   refund, and the pool only holds on to refunds whose destination subnet
///   is cooling down while this one is not, or whose stream is full (which
///   would require a more complex test setup).
const VIOLATED_CONDITIONS: [Condition; 6] = [
    Condition::IncomingStreams,
    Condition::OutgoingStreams,
    Condition::IngressHistory,
    Condition::SubnetInputQueues,
    Condition::SubnetCallContexts,
    Condition::CommonQuorum,
];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TEST_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        // Recovering `D` at the merged state makes the orchestrator of each of
        // its nodes restart the replica on the recovery CUP, so those nodes
        // legitimately start the replica twice. The metrics to check have to
        // stay prefix-free, so this updates the entry of the default set rather
        // than adding a more specific one.
        .update_orchestrator_metrics_to_check("orchestrator_processes_start_attempts_total", 2)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let logger = env.logger();
    info!(
        logger,
        "Step 0: Setting up the IC and installing the NNS canisters"
    );
    let subnet = |subnet_type| {
        Subnet::fast(subnet_type, SUBNET_SIZE)
            .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH))
    };
    InternetComputer::new()
        .add_subnet(subnet(SubnetType::System))
        .add_subnet(subnet(SubnetType::Application))
        .add_subnet(subnet(SubnetType::Application))
        .add_subnet(subnet(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("failed to install NNS canisters");
    info!(
        logger,
        "Step 0 done: the IC is up and the NNS canisters are installed"
    );
}

pub fn test(env: TestEnv) {
    // One runtime for the whole test, kept alive across all of its phases: the
    // agents of the phase that sets the scenario up are used again by the phase
    // that checks the outcome.
    //
    // The merging tool runs in between, on this thread, which is deliberately
    // not inside that runtime: every registry read, ssh command and rsync of
    // `ic-recovery` blocks on a runtime of its own, which a thread that is
    // driving one cannot do.
    let runtime = Runtime::new().expect("failed to create a tokio runtime");

    let context = runtime.block_on(prepare(&env));
    merge(&env, &context, &runtime);
}

/// Everything the checks made in between the steps of the merging tool need
/// from the phase that set the scenario up.
///
/// Canister ids and agents rather than `UniversalCanister`s, which borrow the
/// agent they were created with: the canisters of the subnet that is merged
/// away are reached through a different agent after the merge than before it.
struct Context {
    logger: Logger,
    s_subnet: SubnetSnapshot,
    /// The subnet `S` is merged into.
    d_subnet: SubnetSnapshot,
    s_agent: Agent,
    d_agent: Agent,
    o_agent: Agent,
    /// A canister on `S` calling another subnet in a loop, `USO`.
    uso: Principal,
    /// The canisters on `D` and `O` calling `S` in a loop, `UDS` and `UOS`.
    uds: Principal,
    uos: Principal,
    /// The canisters looping in the endless loops of step 5: `U3`, `U5`, `U9`
    /// and `U14` on `S`, `U7` on `D` and `U11` on `O`.
    u3: Principal,
    u5: Principal,
    u7: Principal,
    u9: Principal,
    u11: Principal,
    u14: Principal,
    /// The canister on `S` whose state has to survive the merge, and that state.
    u12: Principal,
    u12_snapshot: SnapshotId,
    u12_cycles_before: u128,
    /// The caller of the best effort call of step 5f, on `O`, and the ingress
    /// message that made it call.
    u13: Principal,
    u13_request_id: RequestId,
    /// The canisters `U1` installs code on while `S` is cooling down.
    targets: Vec<Principal>,
    /// The ingress messages that are in progress when the merge happens, with
    /// the agent each of them has to be read through afterwards.
    pending_ingress_messages: Vec<(&'static str, Agent, Principal, RequestId)>,
}

/// Steps 1 to 7: set the scenario up and check that `S` violates the
/// individual conditions for merging it away.
async fn prepare(env: &TestEnv) -> Context {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    // The three Application subnets: `S` is the one that is set up to be
    // cooled down and merged away, and `D` is the one it is merged into. `S`
    // exchanges the same calls with `D` as with `O`, which is not part of the
    // merge.
    let app_subnets: Vec<_> = topology
        .subnets()
        .filter(|subnet| subnet.subnet_type() == SubnetType::Application)
        .collect();
    assert_eq!(
        app_subnets.len(),
        3,
        "expected exactly 3 Application subnets"
    );
    let s_subnet = app_subnets[0].clone();
    let d_subnet = app_subnets[1].clone();
    let o_subnet = app_subnets[2].clone();
    let s_node = s_subnet.nodes().next().unwrap();
    let d_node = d_subnet.nodes().next().unwrap();
    let o_node = o_subnet.nodes().next().unwrap();
    let s_agent = assert_create_agent(s_node.get_public_url().as_str()).await;
    let d_agent = assert_create_agent(d_node.get_public_url().as_str()).await;
    let o_agent = assert_create_agent(o_node.get_public_url().as_str()).await;
    info!(
        logger,
        "Subnets under test:\n  S={}\n  D={}\n  O={}\n  NNS={}",
        s_subnet.subnet_id,
        d_subnet.subnet_id,
        o_subnet.subnet_id,
        topology.root_subnet_id(),
    );

    let s_id = s_node.effective_canister_id();
    let d_id = d_node.effective_canister_id();
    let o_id = o_node.effective_canister_id();

    // Step 1: Install two universal canisters on `S` and one on each of `D`
    // and `O`.
    info!(
        logger,
        "Step 1: Installing universal canisters USD, USO, UDS and UOS"
    );
    let usd = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let uso = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let uds = UniversalCanister::new_with_retries(&d_agent, d_id, &logger).await;
    let uos = UniversalCanister::new_with_retries(&o_agent, o_id, &logger).await;
    info!(
        logger,
        "Step 1 done: USD={}, USO={} on S; UDS={} on D; UOS={} on O",
        usd.canister_id(),
        uso.canister_id(),
        uds.canister_id(),
        uos.canister_id(),
    );

    // Step 2: Start a loop of calls to the peer on the other subnet on every
    // universal canister of step 1.
    info!(
        logger,
        "Step 2: Starting the USD <-> UDS and USO <-> UOS call loops"
    );
    start_call_loop(&usd, uds.canister_id()).await;
    start_call_loop(&uds, usd.canister_id()).await;
    start_call_loop(&uso, uos.canister_id()).await;
    start_call_loop(&uos, uso.canister_id()).await;
    info!(logger, "Step 2 done: all call loops started");

    // Step 3: Wait until all loops have completed a few iterations.
    info!(
        logger,
        "Step 3: Waiting for {MIN_LOOP_ITERATIONS} iterations of all call loops"
    );
    for (canister, name) in [(&usd, "USD"), (&uds, "UDS"), (&uso, "USO"), (&uos, "UOS")] {
        retry_with_msg_async!(
            format!("waiting for {MIN_LOOP_ITERATIONS} iterations of {name}'s call loop"),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let iterations = global_counter(canister).await?;
                if iterations < MIN_LOOP_ITERATIONS {
                    bail!("{name}'s call loop is at iteration {iterations}");
                }
                Ok(())
            }
        )
        .await
        .unwrap_or_else(|e| panic!("{name}'s call loop did not make progress: {e}"));
    }
    info!(logger, "Step 3 done: all call loops are making progress");

    // Step 4: Install all the canisters of the steps below. Every installation
    // has to happen before step 6 starts `U1`'s `install_code` calls: at most
    // one long-running `install_code` makes progress per round, and while one
    // is in progress no other `install_code` on the same subnet is executed at
    // all, so any installation attempted here later would be stuck behind
    // `U1`'s calls for as long as they run.
    info!(
        logger,
        "Step 4: Installing U1, U3, U5, U6, U9, U10, U12, U14 on S, U4, U7 on D and U8, U11, \
         U13 on O, and creating {} canisters for U1 to install code on",
        INSTALL_CODE_TARGETS.len(),
    );
    let u1 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let u3 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let u4 = UniversalCanister::new_with_retries(&d_agent, d_id, &logger).await;
    let u5 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let u6 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let u7 = UniversalCanister::new_with_retries(&d_agent, d_id, &logger).await;
    let u8 = UniversalCanister::new_with_retries(&o_agent, o_id, &logger).await;
    let u9 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let u10 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let u11 = UniversalCanister::new_with_retries(&o_agent, o_id, &logger).await;
    // `U12` carries the state that has to survive the merge, and `U13` on `O`
    // and `U14` on `S` are the two ends of the best effort call of step 5f.
    let u12 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let u13 = UniversalCanister::new_with_retries(&o_agent, o_id, &logger).await;
    let u14 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    info!(
        logger,
        "Step 4: U1={}, U3={}, U5={}, U6={}, U9={}, U10={}, U12={}, U14={} on S; U4={}, U7={} \
         on D; U8={}, U11={}, U13={} on O",
        u1.canister_id(),
        u3.canister_id(),
        u5.canister_id(),
        u6.canister_id(),
        u9.canister_id(),
        u10.canister_id(),
        u12.canister_id(),
        u14.canister_id(),
        u4.canister_id(),
        u7.canister_id(),
        u8.canister_id(),
        u11.canister_id(),
        u13.canister_id(),
    );
    let mut targets = Vec::new();
    for name in INSTALL_CODE_TARGETS {
        let target = create_canister(&s_agent, s_id).await;
        set_controller(&target, &u1.canister_id(), &s_agent).await;
        info!(logger, "Step 4: {name}={target} on S, controlled by U1");
        targets.push(target);
    }
    // The state of `U12` that the merge has to carry over: a blob in its
    // stable memory, a canister snapshot, and its cycles balance.
    u12.store_to_stable(STABLE_MEMORY_OFFSET, STABLE_MEMORY_BLOB)
        .await;
    let u12_snapshot = take_canister_snapshot(&s_agent, u12.canister_id()).await;
    let u12_cycles_before = cycles_balance(&u12).await.unwrap();
    info!(
        logger,
        "Step 4 done: all canisters installed; U12 holds {} bytes in its stable memory, snapshot \
         {} and {u12_cycles_before} cycles",
        STABLE_MEMORY_BLOB.len(),
        hex::encode(&u12_snapshot),
    );

    // Step 5: Start the endless loops.
    info!(logger, "Step 5: Starting the endless loops");
    // The ingress messages that stay in progress across the merge, so that step
    // 23 can check that all of them eventually completed, each with the agent
    // it has to be read through after the merge: the canisters of `S` are
    // served by `D` by then.
    let mut pending_ingress_messages = Vec::new();
    for (canister, name, callee, agent_after_merge) in [
        (&u3, "U3", None, &d_agent),
        (&u4, "U4", Some(&u5), &d_agent),
        (&u6, "U6", Some(&u7), &d_agent),
        (&u8, "U8", Some(&u9), &o_agent),
        (&u10, "U10", Some(&u11), &d_agent),
    ] {
        let payload = match callee {
            None => endless_loop(),
            Some(callee) => endless_loop_call(callee.canister_id()),
        };
        let request_id = canister
            .submit_update(payload)
            .await
            .unwrap_or_else(|e| panic!("submitting {name}'s update call should succeed: {e}"))
            .unwrap_or_else(|| panic!("{name}'s update call should not have completed already"));
        pending_ingress_messages.push((
            name,
            agent_after_merge.clone(),
            canister.canister_id(),
            request_id,
        ));
    }
    // `U14` does not respond before the merge, so `U13` gets to see the call
    // time out, and replies to its ingress message with the reject code.
    let u13_request_id = u13
        .submit_update(
            wasm().call_simple_with_cycles_and_best_effort_response(
                u14.canister_id(),
                "update",
                call_args()
                    .other_side(endless_loop())
                    .on_reject(wasm().reject_code().int_to_blob().append_and_reply()),
                BEST_EFFORT_CALL_CYCLES,
                BEST_EFFORT_CALL_TIMEOUT_SECONDS,
            ),
        )
        .await
        .expect("submitting U13's best effort call should succeed")
        .expect("U13's best effort call should not have completed already");
    // `U14` looping means that `U13`'s best effort call made it to `S` before
    // `S` starts cooling down, i.e. that `U14` holds its call context.
    for (canister, name) in [
        (&u3, "U3"),
        (&u5, "U5"),
        (&u7, "U7"),
        (&u9, "U9"),
        (&u11, "U11"),
        (&u14, "U14"),
    ] {
        await_loop_started(canister, name, &logger).await;
    }
    info!(
        logger,
        "Step 5 done: U3 is looping, U5, U7, U9 and U11 are looping in calls from U4, U6, U8 and \
         U10, respectively, and U14 is looping in a best effort call from U13"
    );

    // Step 6: Have `U1` install code on the canisters it controls. Step 7 has
    // to follow right away: the second `install_code` request only stays in
    // the subnet input queues while the first one executes.
    info!(
        logger,
        "Step 6: Executing the update call on U1 making the {} `install_code` calls",
        targets.len(),
    );
    u1.submit_update(install_code_payload(&targets))
        .await
        .expect("submitting U1's `install_code` calls should succeed");
    await_install_code_requests_inducted(&s_subnet, &logger).await;
    info!(
        logger,
        "Step 6 done: all of U1's `install_code` requests left its output queue"
    );

    // Step 7: Check that the scenario violates the individual conditions.
    check_conditions_violated(&topology, &s_subnet, &logger).await;

    Context {
        logger,
        s_subnet,
        d_subnet,
        uso: uso.canister_id(),
        uds: uds.canister_id(),
        uos: uos.canister_id(),
        u3: u3.canister_id(),
        u5: u5.canister_id(),
        u7: u7.canister_id(),
        u9: u9.canister_id(),
        u11: u11.canister_id(),
        u14: u14.canister_id(),
        u12: u12.canister_id(),
        u12_snapshot,
        u12_cycles_before,
        u13: u13.canister_id(),
        u13_request_id,
        targets,
        pending_ingress_messages,
        s_agent,
        d_agent,
        o_agent,
    }
}

/// Steps 8 to 26: hand the scenario over to the subnet merging tool, and make
/// the checks of the steps in between its steps.
///
/// Plain synchronous code, like `rs/tests/consensus/subnet_splitting_test.rs`:
/// the tool's steps block on runtimes of their own, and the asynchronous checks
/// of this test are driven through `runtime`, which this thread is not inside.
fn merge(env: &TestEnv, context: &Context, runtime: &Runtime) {
    let logger = &context.logger;
    let topology = env.topology_snapshot();

    let recovery_args = RecoveryArgs {
        dir: env.get_path(MERGING_DIR),
        nns_url: topology
            .root_subnet()
            .nodes()
            .next()
            .unwrap()
            .get_public_url(),
        replica_version: Some(get_guestos_img_version()),
        admin_key_file: Some(
            env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
                .join(SSH_USERNAME),
        ),
        test_mode: true,
        skip_prompts: true,
    };
    let merging_args = SubnetMergingArgs {
        source_subnet_id: context.s_subnet.subnet_id,
        destination_subnet_id: context.d_subnet.subnet_id,
        source_node: Some(DataLocation::Remote(merge_node(&context.s_subnet))),
        destination_node: Some(DataLocation::Remote(merge_node(&context.d_subnet))),
        merge_ready_timeout_secs: MERGE_READY_TIMEOUT.as_secs(),
        halt_timeout_secs: HALT_TIMEOUT.as_secs(),
        registry_timeout_secs: REGISTRY_TIMEOUT.as_secs(),
        poll_interval_secs: POLL_INTERVAL.as_secs(),
        next_step: None,
        skip: None,
    };

    info!(
        logger,
        "Step 8: Merging subnet S ({}) into subnet D ({})",
        context.s_subnet.subnet_id,
        context.d_subnet.subnet_id,
    );
    let merging = SubnetMerging::new(
        logger.clone(),
        recovery_args,
        /*neuron_args=*/ None,
        merging_args,
    );

    let mut executed_steps = vec![];
    for (step_type, step) in merging {
        info!(logger, "Next step: {step_type:?}");
        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {step_type:?} failed: {e}"));
        executed_steps.push(step_type);

        match step_type {
            StepType::CoolDownSourceSubnet => {}
            StepType::CheckRegistryForCoolingDownFlag => {
                info!(logger, "Step 8 done: subnet S is labeled \"cooling down\"");
                runtime.block_on(check_ingress_and_queries_rejected(context));
                runtime.block_on(check_best_effort_call_timed_out(context));
            }
            StepType::CheckMergeReadiness => {
                info!(logger, "Step 10 done: subnet S is \"merge ready\"");
                runtime.block_on(check_loops_stalled(context));
            }
            StepType::HaltSourceSubnetAtCupHeight => {}
            StepType::HaltDestinationSubnetAtCupHeight => {}
            StepType::WaitForHaltingCupOnSourceSubnet => {}
            StepType::WaitForHaltingCupOnDestinationSubnet => {
                info!(
                    logger,
                    "Step 12 done: the nodes of S and D the states would be downloaded from \
                     serve the CUPs their subnets halt at"
                );
                runtime.block_on(check_subnets_halted(context));
            }
            StepType::StopSourceReplica => {}
            StepType::StopDestinationReplica => {}
            StepType::DownloadStateFromSourceSubnet => {}
            StepType::DownloadStateFromDestinationSubnet => {}
            StepType::ValidateSourceSubnetCup => {}
            StepType::ValidateDestinationSubnetCup => {
                info!(
                    logger,
                    "Step 14 done: the states S and D halted at are downloaded and valid"
                );
            }
            StepType::ComputeExpectedMergedManifest => {}
            StepType::MergeStates => {
                info!(
                    logger,
                    "Step 15 done: the merged state is assembled and has the expected state hash"
                );
                check_merged_state(env, context);
            }
            StepType::MergeSubnets => {}
            StepType::CheckRegistryForRoutingTableEntry => {
                info!(
                    logger,
                    "Step 17 done: the registry routes no canister ID range to subnet S anymore"
                );
                check_merge_registry_version(env, context);
            }
            StepType::ProposeCupForDestinationSubnet => {
                info!(
                    logger,
                    "Step 19 done: the recovery CUP of subnet D at the merged state is proposed"
                );
                check_recovery_cup_contents(env, context);
            }
            StepType::UploadStateToDestinationSubnet => {
                info!(
                    logger,
                    "Step 21 done: the merged state is uploaded to the node of subnet D"
                );
                runtime.block_on(check_merged_state_uploaded(env, context));
            }
            StepType::WaitForCupOnDestinationSubnet => {}
            StepType::UnhaltDestinationSubnet => {
                info!(
                    logger,
                    "Step 23 done: subnet D came up on the merged state and is unhalted"
                );
                runtime.block_on(verify_after_merge(context));
            }
        }
    }
    // The tool skips a step it fails to create, and the checks above only run
    // after the steps they are attached to.
    assert_eq!(
        executed_steps,
        StepType::iter().collect::<Vec<_>>(),
        "the subnet merging tool did not execute all of its steps in order"
    );
    info!(logger, "Subnet S has been merged into subnet D");
}

/// Step 18: check the registry version the tool recorded in
/// `merge_registry_version.json`: it is recorded for `S`, it is newer than the
/// version recorded in `cooling_down_registry_version.json`, and at it the
/// registry routes no canister ID range to `S` and every canister ID range `S`
/// started out with to `D`. At the cooling down version, `S` still holds its
/// ranges, so the version records the rerouting rather than a version that
/// happens to precede it.
///
/// The routing tables are read through a registry helper of the test's own,
/// with a local store separate from the one of the tool.
fn check_merge_registry_version(env: &TestEnv, context: &Context) {
    let logger = &context.logger;
    let recovery_dir = env.get_path(MERGING_DIR).join(RECOVERY_DIRECTORY_NAME);
    let s_subnet_id = context.s_subnet.subnet_id;
    let d_subnet_id = context.d_subnet.subnet_id;

    let read_recorded_version = |file_name: &str| {
        let path = recovery_dir.join(file_name);
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let recorded: serde_json::Value = serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
        assert_eq!(
            recorded["source_subnet_id"],
            serde_json::to_value(s_subnet_id).unwrap(),
            "{} is not recorded for subnet S: {contents}",
            path.display(),
        );
        let version = recorded["registry_version"]
            .as_u64()
            .unwrap_or_else(|| panic!("{} holds no registry version: {contents}", path.display()));
        RegistryVersion::from(version)
    };
    let merge_version = read_recorded_version("merge_registry_version.json");
    let cooling_down_version = read_recorded_version("cooling_down_registry_version.json");
    info!(
        logger,
        "Step 18: Checking the recorded merge registry version {merge_version} against the \
         cooling down registry version {cooling_down_version}"
    );
    assert!(
        merge_version > cooling_down_version,
        "the merge registry version {merge_version} is not newer than the cooling down registry \
         version {cooling_down_version}",
    );

    let registry_helper = test_registry_helper(env, logger);
    let latest_version = registry_helper
        .latest_registry_version()
        .expect("failed to fetch the latest registry version");
    assert!(
        latest_version >= merge_version,
        "the registry is at version {latest_version}, before the recorded merge registry version \
         {merge_version}",
    );
    let registry_client = registry_helper.registry_client();
    let routing_table = |version: RegistryVersion| {
        registry_client
            .get_routing_table(version)
            .unwrap_or_else(|e| {
                panic!("failed to read the routing table at version {version}: {e}")
            })
            .unwrap_or_else(|| panic!("no routing table at version {version}"))
    };

    // The ranges of `S` as of the topology snapshot taken before the merge.
    let original_ranges = context.s_subnet.subnet_canister_ranges();
    assert!(
        !original_ranges.is_empty(),
        "subnet S held no canister ID range before the merge"
    );
    let at_cooling_down = routing_table(cooling_down_version);
    let at_merge = routing_table(merge_version);
    assert_eq!(
        at_cooling_down
            .ranges(s_subnet_id)
            .iter()
            .collect::<Vec<_>>(),
        original_ranges.iter().collect::<Vec<_>>(),
        "subnet S did not hold its original canister ID ranges at the cooling down registry \
         version {cooling_down_version}",
    );
    assert!(
        at_merge.ranges(s_subnet_id).is_empty(),
        "subnet S still holds canister ID ranges at the merge registry version {merge_version}: \
         {:?}",
        at_merge.ranges(s_subnet_id),
    );
    for range in &original_ranges {
        for canister_id in [range.start, range.end] {
            let routed_to = at_merge
                .lookup_entry(canister_id)
                .map(|(_, subnet_id)| subnet_id);
            assert_eq!(
                routed_to,
                Some(d_subnet_id),
                "canister {canister_id} of the original range {range:?} of subnet S is routed to \
                 {routed_to:?} rather than subnet D at the merge registry version {merge_version}",
            );
        }
    }
    info!(
        logger,
        "Step 18 done: at the merge registry version {merge_version}, the canister ID ranges \
         {original_ranges:?} of S are routed to D"
    );
}

/// The test's own registry helper, which fetches the latest registry version
/// on every read. It uses a local store separate from the one of the tool.
fn test_registry_helper(env: &TestEnv, logger: &Logger) -> RegistryHelper {
    let recovery_dir = env.get_path(MERGING_DIR).join(RECOVERY_DIRECTORY_NAME);
    RegistryHelper::new(
        logger.clone(),
        env.topology_snapshot()
            .root_subnet()
            .nodes()
            .next()
            .unwrap()
            .get_public_url(),
        env.get_path("test_registry_local_store"),
        &recovery_dir.join("nns.pem"),
        RegistryPollingStrategy::WithEveryRead,
    )
}

/// Step 20: wait until the registry holds the recovery CUP contents of `D`,
/// and check them, at the registry version they were first read at: their
/// height is the one of the merged checkpoint, above the heights both subnets
/// halted at; their state hash is the one of that checkpoint, computed from
/// the checkpoint itself rather than read from the manifest the tool wrote;
/// and their time is past the times of the CUPs both subnets halted at. Also
/// check that `D` is halted, as the recovery turned its instruction to halt at
/// its next CUP into a plain halt.
fn check_recovery_cup_contents(env: &TestEnv, context: &Context) {
    let logger = &context.logger;
    let recovery_dir = env.get_path(MERGING_DIR).join(RECOVERY_DIRECTORY_NAME);
    let d_subnet_id = context.d_subnet.subnet_id;
    info!(
        logger,
        "Step 20: Checking the recovery CUP contents of subnet D in the registry"
    );

    // `ic-admin` returns once the proposal is submitted, but the registry only
    // holds the recovery CUP contents (and halts `D`) once the DKG for `D` has
    // completed (see `REGISTRY_TIMEOUT`), so poll for them.
    let registry_helper = test_registry_helper(env, logger);
    let registry_client = registry_helper.registry_client();
    let deadline = Instant::now() + REGISTRY_TIMEOUT;
    let (registry_version, recovery_args) = loop {
        let latest_version = registry_helper
            .latest_registry_version()
            .expect("failed to fetch the latest registry version");
        let cup_type = registry_client
            .get_cup_contents(d_subnet_id, latest_version)
            .unwrap_or_else(|e| {
                panic!(
                    "failed to read the CUP contents of subnet D at version {latest_version}: {e}"
                )
            })
            .value
            .unwrap_or_else(|| panic!("no CUP contents of subnet D at version {latest_version}"))
            .cup_type;
        if let Some(CupType::Recovery(recovery_args)) = cup_type {
            break (latest_version, recovery_args);
        }
        assert!(
            Instant::now() < deadline,
            "the CUP contents of subnet D are not for a recovery at version {latest_version}, \
             {REGISTRY_TIMEOUT:?} after the recovery CUP was proposed: {cup_type:?}",
        );
        info!(
            logger,
            "The CUP contents of subnet D are not for a recovery yet at version {latest_version}"
        );
        std::thread::sleep(POLL_INTERVAL);
    };

    let (merged_checkpoint, merged_height) = merged_checkpoint(env);
    assert_eq!(
        recovery_args.height, merged_height,
        "the recovery CUP of subnet D is not at the height of the merged checkpoint",
    );

    // Hash the checkpoint itself rather than trust the manifest the tool wrote.
    let merged_state_hash = get_state_hash(&merged_checkpoint).unwrap_or_else(|e| {
        panic!(
            "failed to compute the state hash of {}: {e}",
            merged_checkpoint.display()
        )
    });
    assert_eq!(
        hex::encode(&recovery_args.state_hash),
        merged_state_hash,
        "the state hash of the recovery CUP of subnet D is not the one of {}",
        merged_checkpoint.display(),
    );

    for (name, subnet_id) in [
        ("S", context.s_subnet.subnet_id),
        ("D", context.d_subnet.subnet_id),
    ] {
        let halting_cup_file = recovery_dir.join(format!("halting_cup_{subnet_id}.pb"));
        let halting_cup = get_cup(&halting_cup_file).unwrap_or_else(|e| {
            panic!(
                "failed to read the CUP subnet {name} halted at from {}: {e}",
                halting_cup_file.display()
            )
        });
        let halting_height = halting_cup.height().get();
        let halting_time = halting_cup.content.block.as_ref().context.time;
        assert!(
            recovery_args.height > halting_height,
            "the recovery CUP of subnet D is at height {}, not above the height {halting_height} \
             subnet {name} halted at",
            recovery_args.height,
        );
        assert!(
            recovery_args.time > halting_time.as_nanos_since_unix_epoch(),
            "the recovery CUP of subnet D has the time {} ns, not past the time {halting_time} of \
             the CUP subnet {name} halted at",
            recovery_args.time,
        );
    }

    let d_subnet_record = registry_client
        .get_subnet_record(d_subnet_id, registry_version)
        .unwrap_or_else(|e| {
            panic!("failed to read the subnet record of D at version {registry_version}: {e}")
        })
        .unwrap_or_else(|| panic!("no subnet record of D at version {registry_version}"));
    assert!(
        d_subnet_record.is_halted && !d_subnet_record.halt_at_cup_height,
        "subnet D is not plainly halted after its recovery was proposed: is_halted = {}, \
         halt_at_cup_height = {}",
        d_subnet_record.is_halted,
        d_subnet_record.halt_at_cup_height,
    );

    info!(
        logger,
        "Step 20 done: the recovery CUP contents of subnet D are at height {merged_height}, with \
         the state hash {merged_state_hash}, and D is halted"
    );
}

/// The merged checkpoint the tool assembled, and its height.
fn merged_checkpoint(env: &TestEnv) -> (PathBuf, u64) {
    let merged_checkpoints_dir = env
        .get_path(MERGING_DIR)
        .join(RECOVERY_DIRECTORY_NAME)
        .join("merged_working_dir")
        .join("data")
        .join(IC_STATE)
        .join(CHECKPOINTS);
    let merged_checkpoints = std::fs::read_dir(&merged_checkpoints_dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", merged_checkpoints_dir.display()))
        .map(|entry| entry.expect("failed to read a directory entry").path())
        .collect::<Vec<_>>();
    let [merged_checkpoint] = merged_checkpoints.as_slice() else {
        panic!("expected a single merged checkpoint, got {merged_checkpoints:?}");
    };
    let name = merged_checkpoint.file_name().unwrap().to_string_lossy();
    let merged_height = u64::from_str_radix(&name, 16)
        .unwrap_or_else(|e| panic!("checkpoint {name} is not named by its height: {e}"));
    (merged_checkpoint.clone(), merged_height)
}

/// Step 22: check that `UploadStateToDestinationSubnet` put the merged state in
/// place on `D`'s node and that the replica on that node started from it:
/// * the checkpoints directory of the node holds exactly the merged checkpoint,
///   i.e. the checkpoint `D` halted at was replaced;
/// * the replica reports `METRIC_MAX_RESIDENT_HEIGHT` at the height of the
///   merged checkpoint. The state manager sets it to the height of the
///   checkpoint it starts from, and no other node holds a checkpoint at that
///   height, so the replica runs again and started from the uploaded one.
async fn check_merged_state_uploaded(env: &TestEnv, context: &Context) {
    let logger = &context.logger;
    let node = merge_node_snapshot(&context.d_subnet);
    let node_ip = node.get_ip_addr();
    let (merged_checkpoint, merged_height) = merged_checkpoint(env);
    let merged_checkpoint_name = merged_checkpoint
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    info!(
        logger,
        "Step 22: Checking that node {node_ip} of subnet D runs on the merged checkpoint \
         {merged_checkpoint_name}"
    );

    let checkpoints = node
        .block_on_bash_script(&format!("sudo ls {NODE_CHECKPOINTS_DIR}"))
        .unwrap_or_else(|e| panic!("failed to list {NODE_CHECKPOINTS_DIR} on node {node_ip}: {e}"));
    let checkpoints: Vec<&str> = checkpoints.split_whitespace().collect();
    assert_eq!(
        checkpoints,
        [merged_checkpoint_name.as_str()],
        "{NODE_CHECKPOINTS_DIR} on node {node_ip} does not hold exactly the merged checkpoint",
    );

    retry_with_msg_async!(
        format!("node {node_ip} reporting {METRIC_MAX_RESIDENT_HEIGHT} {merged_height}"),
        logger,
        REPLICA_RESTART_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let metrics = fetch_metrics(&[node_ip], &[METRIC_MAX_RESIDENT_HEIGHT]).await?;
            let heights: Vec<f64> = metrics
                .get(&node_ip)
                .map(|metrics| {
                    replica_values(metrics, METRIC_MAX_RESIDENT_HEIGHT, |_| true).collect()
                })
                .unwrap_or_default();
            if heights != [merged_height as f64] {
                bail!("node {node_ip} reports {METRIC_MAX_RESIDENT_HEIGHT} {heights:?}");
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| {
        panic!("the replica on node {node_ip} did not start from the merged checkpoint: {e}")
    });

    info!(
        logger,
        "Step 22 done: node {node_ip} of subnet D holds only the merged checkpoint \
         {merged_checkpoint_name} and its replica started from it"
    );
}

/// Step 16: check that the merged state the tool assembled is a single
/// checkpoint holding exactly the canisters of the checkpoints downloaded from
/// `S` and `D`.
fn check_merged_state(env: &TestEnv, context: &Context) {
    let recovery_dir = env.get_path(MERGING_DIR).join(RECOVERY_DIRECTORY_NAME);
    let single_checkpoint = |working_dir: &str| {
        let checkpoints_dir = recovery_dir
            .join(working_dir)
            .join("data")
            .join(IC_STATE)
            .join(CHECKPOINTS);
        let checkpoints: Vec<_> = std::fs::read_dir(&checkpoints_dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", checkpoints_dir.display()))
            .map(|entry| entry.expect("failed to read a directory entry").path())
            .collect();
        let [checkpoint] = checkpoints.as_slice() else {
            panic!("expected a single checkpoint in {working_dir}, got {checkpoints:?}");
        };
        checkpoint.clone()
    };

    let merged_checkpoint = single_checkpoint("merged_working_dir");
    let actual = canisters_in_checkpoint(&merged_checkpoint);
    let downloaded: BTreeSet<String> = ["source_working_dir", "destination_working_dir"]
        .into_iter()
        .flat_map(|working_dir| canisters_in_checkpoint(&single_checkpoint(working_dir)))
        .collect();
    assert_eq!(
        actual,
        downloaded,
        "the canisters in the merged checkpoint {} are not those of the checkpoints downloaded \
         from S and D",
        merged_checkpoint.display(),
    );

    info!(
        context.logger,
        "Step 16 done: the merged checkpoint {} holds exactly the {} canisters of S and D",
        merged_checkpoint.display(),
        actual.len(),
    );
}

/// The names of the directories `checkpoint` keeps the states of its canisters
/// in, i.e. the hex encodings of their IDs.
fn canisters_in_checkpoint(checkpoint: &std::path::Path) -> BTreeSet<String> {
    let canister_states_dir = checkpoint.join("canister_states");
    std::fs::read_dir(&canister_states_dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", canister_states_dir.display()))
        .map(|entry| {
            entry
                .expect("failed to read a directory entry")
                .file_name()
                .into_string()
                .expect("a canister directory name is not valid UTF-8")
        })
        .collect()
}

/// The node of `subnet` the tool works with: the one it waits for the halting
/// CUP on and downloads the state of `subnet` from and, for the destination
/// subnet, the one it uploads the merged state to.
fn merge_node(subnet: &SubnetSnapshot) -> IpAddr {
    merge_node_snapshot(subnet).get_ip_addr()
}

/// The node of `subnet` that `merge_node` returns the IP address of.
fn merge_node_snapshot(subnet: &SubnetSnapshot) -> IcNodeSnapshot {
    subnet.nodes().next().unwrap()
}

/// Step 13: check that `S` and `D` are halted, i.e. that every one of their
/// nodes certifies the height its subnet halts at, and that it still does so
/// after `HALT_OBSERVATION_PERIOD`.
///
/// The tool only waits for the node of each subnet the state would be
/// downloaded from, so the other nodes are waited for to catch up with the
/// halting height.
async fn check_subnets_halted(context: &Context) {
    let logger = &context.logger;
    let subnets = [&context.s_subnet, &context.d_subnet];
    let mut halting_heights = Vec::new();

    for subnet in subnets {
        let subnet_id = subnet.subnet_id;
        // The tool has checked that the download node serves the CUP the subnet
        // halts at, and no CUP follows that one.
        let download_node = merge_node(subnet);
        let halting_height = get_node_metrics(logger, &download_node)
            .await
            .unwrap_or_else(|| panic!("failed to get the metrics of node {download_node}"))
            .catch_up_package_height;
        info!(
            logger,
            "Step 13: Waiting until every node of subnet {subnet_id} has certified the height \
             {halting_height} it halts at"
        );
        retry_with_msg_async!(
            format!(
                "waiting until every node of subnet {subnet_id} has certified height \
                 {halting_height}"
            ),
            logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                for node in subnet.nodes() {
                    let ip = node.get_ip_addr();
                    let Some(metrics) = get_node_metrics(logger, &ip).await else {
                        bail!("failed to get the metrics of node {ip}");
                    };
                    let height = metrics.certification_height;
                    assert!(
                        height <= halting_height,
                        "node {ip} of subnet {subnet_id} certified height {height}, past the \
                         height {halting_height} the subnet halts at"
                    );
                    if height < halting_height {
                        bail!(
                            "node {ip} of subnet {subnet_id} has certified up to height {height}"
                        );
                    }
                }
                Ok(())
            }
        )
        .await
        .expect("not every node certified the height its subnet halts at");
        info!(
            logger,
            "Step 13: every node of subnet {subnet_id} has certified the height {halting_height} \
             it halts at"
        );
        halting_heights.push(halting_height);
    }

    info!(
        logger,
        "Step 13: Checking that the certified heights stay put over {HALT_OBSERVATION_PERIOD:?}"
    );
    tokio::time::sleep(HALT_OBSERVATION_PERIOD).await;
    for (subnet, halting_height) in subnets.into_iter().zip(halting_heights) {
        let subnet_id = subnet.subnet_id;
        for node in subnet.nodes() {
            let ip = node.get_ip_addr();
            let height = get_node_metrics(logger, &ip)
                .await
                .unwrap_or_else(|| panic!("failed to get the metrics of node {ip}"))
                .certification_height;
            assert_eq!(
                height, halting_height,
                "node {ip} of subnet {subnet_id} certified height {height} rather than the \
                 height {halting_height} the subnet halts at, {HALT_OBSERVATION_PERIOD:?} after \
                 reaching it"
            );
        }
    }

    info!(logger, "Step 13 done: subnets S and D are halted");
}

/// Step 9: wait until the replicas of `S` observed the "cooling down" label,
/// i.e. until `S` rejects ingress messages, and then until it rejects query
/// calls too.
///
/// Both are waited for rather than checked once: the replica a call is sent to
/// rejects ingress messages based on its latest state, but query calls based on
/// its latest certified state, which may still be one before the label took
/// effect.
async fn check_ingress_and_queries_rejected(context: &Context) {
    let logger = &context.logger;
    let uso = UniversalCanister::from_canister_id(&context.s_agent, context.uso);

    info!(
        logger,
        "Step 9: Waiting until subnet S rejects ingress messages"
    );
    retry_with_msg_async!(
        "waiting until subnet S rejects ingress messages",
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            // Submitted rather than called: an ingress message that is still
            // accepted is never executed by a cooling down subnet, so waiting for
            // its completion would only wait for it to expire.
            match uso.submit_update(wasm().reply_data(&[])).await {
                Ok(_) => bail!("ingress message to USO was still accepted"),
                Err(err) => {
                    let err = err.to_string();
                    if !err.contains("cooling down") {
                        bail!("ingress message to USO failed unexpectedly: {err}");
                    }
                    Ok(())
                }
            }
        }
    )
    .await
    .expect("subnet S did not start rejecting ingress messages");
    info!(
        logger,
        "Step 9: subnet S rejects ingress messages, so it is cooling down"
    );

    retry_with_msg_async!(
        "waiting until subnet S rejects query calls",
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            match uso.query(wasm().reply_data(&[])).await {
                Ok(_) => bail!("query call to USO was still answered"),
                Err(err) => {
                    let err = err.to_string();
                    if !err.contains("cooling down") {
                        bail!("query call to USO failed unexpectedly: {err}");
                    }
                    Ok(())
                }
            }
        }
    )
    .await
    .expect("subnet S did not start rejecting query calls");
    info!(
        logger,
        "Step 9 done: subnet S rejects ingress messages and query calls"
    );
}

/// Step 11: check that the call loops of `UDS` and `UOS` of step 2 are stalled,
/// i.e. that their iteration counters, read via queries to `D` and `O`, do not
/// advance. The counters of `USD` and `USO` cannot be read, as `S` rejects
/// query calls.
///
/// Iterations whose call to `S` was rejected with `SYS_TRANSIENT` do not count
/// (see `start_call_loop`).
async fn check_loops_stalled(context: &Context) {
    let logger = &context.logger;
    info!(
        logger,
        "Step 11: Checking that the call loops of UDS and UOS are stalled over \
         {STALL_OBSERVATION_PERIOD:?}"
    );
    let uds = UniversalCanister::from_canister_id(&context.d_agent, context.uds);
    let uos = UniversalCanister::from_canister_id(&context.o_agent, context.uos);
    let canisters = [(&uds, "UDS"), (&uos, "UOS")];
    let mut before = Vec::new();
    for (canister, _) in canisters {
        before.push(global_counter(canister).await.unwrap());
    }
    tokio::time::sleep(STALL_OBSERVATION_PERIOD).await;
    for ((canister, name), before) in canisters.into_iter().zip(before) {
        let after = global_counter(canister).await.unwrap();
        assert_eq!(
            before, after,
            "{name}'s call loop advanced from iteration {before} to {after} while subnet S was \
             cooling down",
        );
        info!(
            logger,
            "Step 11: {name}'s call loop is stalled at iteration {after}"
        );
    }
    info!(
        logger,
        "Step 11 done: the call loops of UDS and UOS are stalled"
    );
}

/// Step 7: check that none of the `VIOLATED_CONDITIONS` of the "merge
/// readiness" condition holds for `s_subnet`, i.e. that the condition a subnet
/// merging tool waits for is one this scenario does not satisfy.
///
/// The terms are evaluated by `ic_subnet_merging::readiness`, i.e. by the same
/// code a subnet merging tool evaluates them with. Every term is evaluated
/// repeatedly until all of `VIOLATED_CONDITIONS` are violated at the same
/// evaluation with every replica successfully scraped, so missing data cannot
/// stand in for the violations this scenario is meant to exercise.
async fn check_conditions_violated(
    topology: &TopologySnapshot,
    s_subnet: &SubnetSnapshot,
    logger: &Logger,
) {
    // Not the registry version a proposal labeling `S` as "cooling down" would
    // create, which this test does not submit, but the one of the snapshot the
    // test works with: `Condition::RegistryVersion` holds for it, see
    // `VIOLATED_CONDITIONS`.
    let registry_version = topology.get_registry_version().get();
    info!(
        logger,
        "Step 7: Checking that subnet S violates the individual conditions for merging it away, \
         for V={registry_version}",
    );

    let subnets = subnet_node_ips(topology);
    let terms = retry_with_msg_async!(
        format!(
            "waiting for subnet {} to violate the conditions {VIOLATED_CONDITIONS:?} all at once",
            s_subnet.subnet_id
        ),
        logger,
        CONDITIONS_TIMEOUT,
        CONDITIONS_BACKOFF,
        || async {
            let readiness =
                evaluate_merge_readiness(&subnets, s_subnet.subnet_id, registry_version).await?;
            if !readiness.scrape_failures.is_empty() {
                bail!(
                    "cannot check readiness violations with incomplete metrics: {}",
                    readiness
                        .scrape_failures
                        .iter()
                        .map(|(subnet_id, err)| format!("subnet {subnet_id}: {err}"))
                        .collect::<Vec<_>>()
                        .join("; "),
                );
            }
            let terms = readiness.terms;
            let satisfied: Vec<&str> = VIOLATED_CONDITIONS
                .iter()
                .map(|condition| term(&terms, *condition))
                .filter(|term| term.satisfied)
                .map(|term| term.description.as_str())
                .collect();
            if !satisfied.is_empty() {
                bail!(
                    "{} of the {} conditions hold: {}",
                    satisfied.len(),
                    VIOLATED_CONDITIONS.len(),
                    satisfied.join("; "),
                );
            }
            Ok(terms)
        }
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "subnet S did not violate all the conditions for merging it away that this scenario \
             is meant to violate, or they could not be evaluated: {e}"
        )
    });

    for term in &terms {
        let mark = if term.satisfied { "x" } else { " " };
        info!(logger, "  [{mark}] {}", term.description);
    }
    info!(
        logger,
        "Step 7 done: subnet S violates all of the conditions {VIOLATED_CONDITIONS:?}"
    );
}

/// The nodes of every subnet, which is what the merge readiness condition is
/// evaluated on.
fn subnet_node_ips(topology: &TopologySnapshot) -> SubnetNodeIps {
    topology
        .subnets()
        .map(|subnet| {
            (
                subnet.subnet_id,
                subnet.nodes().map(|node| node.get_ip_addr()).collect(),
            )
        })
        .collect()
}

/// The term of `terms` stating `condition`.
fn term(terms: &[Term], condition: Condition) -> &Term {
    terms
        .iter()
        .find(|term| term.condition == condition)
        .unwrap_or_else(|| panic!("the readiness condition has no term for {condition:?}"))
}

/// Steps 24 to 26: check that the merge carried the state of `S`'s canisters
/// over, that `S`'s `install_code` calls completed, and that every ingress
/// message that was in progress across the merge completes.
async fn verify_after_merge(context: &Context) {
    let logger = &context.logger;

    // The tool has unhalted `D`; a halted subnet delivers no batches, so none of
    // the calls below would be answered before it is healthy again.
    context
        .d_subnet
        .nodes()
        .next()
        .unwrap()
        .await_status_is_healthy_async()
        .await
        .expect("subnet D did not become healthy after the merge");
    info!(logger, "Step 24: subnet D is healthy");

    // Step 24: `U12` was hosted by `S` and is served by `D` now.
    info!(logger, "Step 24: Checking the state of U12 after the merge");
    let u12 = UniversalCanister::from_canister_id(&context.d_agent, context.u12);
    // `D` now hosts the canister ID ranges of `S`, but the NNS delegation it
    // serves responses with only lists them once it has fetched a new one; until
    // then, it rejects requests with a `503 Service Unavailable` because its
    // delegation is inconsistent with its state. So the first request is
    // retried until `D` serves a consistent delegation.
    let u12_stable_memory = retry_with_msg_async!(
        "reading the stable memory of U12 from subnet D",
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            u12.read_stable(
                STABLE_MEMORY_OFFSET,
                STABLE_MEMORY_BLOB.len().try_into().unwrap(),
            )
            .await
            .map_err(|err| anyhow!("could not read the stable memory of U12: {err}"))
        }
    )
    .await
    .expect("subnet D did not serve U12 after the merge");
    assert_eq!(
        u12_stable_memory, STABLE_MEMORY_BLOB,
        "the stable memory of U12 did not survive the merge",
    );
    assert!(
        canister_snapshot_ids(&context.d_agent, context.u12)
            .await
            .contains(&context.u12_snapshot),
        "the snapshot of U12 did not survive the merge",
    );
    let u12_cycles_after = cycles_balance(&u12)
        .await
        .expect("failed to read the cycles balance of U12 after the merge");
    let u12_cycles_before = context.u12_cycles_before;
    assert!(
        u12_cycles_after <= u12_cycles_before
            && u12_cycles_before - u12_cycles_after
                <= u12_cycles_before / MAX_BURNED_CYCLES_FRACTION,
        "the cycles balance of U12 went from {u12_cycles_before} to {u12_cycles_after} across \
         the merge, a difference of more than the one in {MAX_BURNED_CYCLES_FRACTION} an idle \
         canister is expected to burn",
    );

    // `U7` was hosted by `D` all along. Now that `U12` is on `D` too, they must
    // be able to call each other.
    let u7 = UniversalCanister::from_canister_id(&context.d_agent, context.u7);
    let u7_reply = u7
        .update(wasm().call_simple(
            context.u12,
            "update",
            call_args().other_side(wasm().push_bytes(MERGED_CALL_REPLY).append_and_reply()),
        ))
        .await
        .expect("U7 should be able to call a canister that was hosted by S");
    assert_eq!(
        u7_reply, MERGED_CALL_REPLY,
        "U7 got an unexpected reply from U12",
    );
    info!(
        logger,
        "Step 24 done: U12 kept its stable memory, snapshot and cycles, and U7 can call it"
    );

    // Step 25: `U1`'s `install_code` calls ran while `S` was cooling down, and
    // whether they installed the universal canister module shows in a query: a
    // canister that has no module rejects every query. `D` has to be the one
    // asked, as `S` answered no query from the moment it started cooling down
    // until it was halted for the merge.
    info!(
        logger,
        "Step 25: Checking that {} have been installed",
        INSTALL_CODE_TARGETS.join(", "),
    );
    for (&target, name) in context.targets.iter().zip(INSTALL_CODE_TARGETS) {
        let canister = UniversalCanister::from_canister_id(&context.d_agent, target);
        let reply = canister
            .query(wasm().reply_data(name.as_bytes()))
            .await
            .unwrap_or_else(|e| {
                panic!("{name} ({target}) does not answer queries, so it was not installed: {e}")
            });
        assert_eq!(
            reply,
            name.as_bytes(),
            "{name} ({target}) answered a query with an unexpected reply",
        );
    }
    info!(
        logger,
        "Step 25 done: {} have been installed",
        INSTALL_CODE_TARGETS.join(", "),
    );

    // Step 26: Let the endless loops finish and check that every ingress message
    // that was still in progress when the merge happened completed.
    //
    // The canisters of `S` now live on `D`, which serves them under the same
    // canister IDs, so the agent for `D` is what reaches them. `U11` did not
    // move: it is on `O`.
    info!(
        logger,
        "Step 26: Breaking the endless loops and waiting for the pending ingress messages"
    );
    for (agent, canister_id, name) in [
        (&context.d_agent, context.u3, "U3"),
        (&context.d_agent, context.u5, "U5"),
        (&context.d_agent, context.u7, "U7"),
        (&context.d_agent, context.u9, "U9"),
        (&context.o_agent, context.u11, "U11"),
        (&context.d_agent, context.u14, "U14"),
    ] {
        let canister = UniversalCanister::from_canister_id(agent, canister_id);
        retry_with_msg_async!(
            format!("setting the global data of {name} to {LOOP_BREAK_TRIGGER:?}"),
            logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                canister
                    .update(wasm().set_global_data(LOOP_BREAK_TRIGGER).reply_data(&[]))
                    .await
                    .map(|_| ())
                    .map_err(|e| anyhow!("failed to break {name}'s loop: {e}"))
            }
        )
        .await
        .unwrap_or_else(|e| panic!("could not break {name}'s endless loop: {e}"));
        info!(logger, "Step 26: broke {name}'s endless loop");
    }

    await_ingress_messages_replied(&context.pending_ingress_messages, logger).await;
    // `U14` now replies to `U13`'s best effort call, whose deadline passed
    // before the merge, closing the call context the merge carried over. A
    // canister only stops once it has no open call context, so `U14` stopping
    // shows that.
    stop_canister(&context.d_agent, context.u14).await;
    info!(
        logger,
        "Step 26 done: all the ingress messages that were pending across the merge completed, \
         and U14 closed the call context of U13's best effort call"
    );
}

/// Step 9, continued: wait until `U13`'s best effort call to `U14` timed out,
/// i.e. until the ingress message that made `U13` call is replied to with the
/// reject code of a timeout. From here on, `U14` holds the call context of a
/// best effort call whose deadline has passed.
///
/// This is checked now rather than after the merge because the status of the
/// ingress message is only kept for `MAX_INGRESS_TTL`.
async fn check_best_effort_call_timed_out(context: &Context) {
    let logger = &context.logger;
    info!(
        logger,
        "Step 9: Waiting until U13's best effort call to U14 timed out"
    );
    let reply = retry_with_msg_async!(
        "waiting for U13's best effort call to time out",
        logger,
        BEST_EFFORT_CALL_EXPIRY_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let (status, _) = context
                .o_agent
                .request_status_raw(&context.u13_request_id, context.u13)
                .await
                .map_err(|e| anyhow!("failed to read the status of U13's message: {e}"))?;
            match status {
                RequestStatusResponse::Replied(reply) => Ok(reply.arg),
                RequestStatusResponse::Rejected(reject) => {
                    panic!("U13's ingress message was rejected: {reject:?}")
                }
                other => bail!("U13's ingress message is {other:?}"),
            }
        }
    )
    .await
    .expect("U13's best effort call did not time out");
    assert_eq!(
        reply,
        REJECT_CODE_SYS_UNKNOWN.to_le_bytes(),
        "U13's best effort call was not rejected with SYS_UNKNOWN, i.e. it did not time out",
    );
    info!(
        logger,
        "Step 9 done: U13's best effort call to U14 timed out"
    );
}

/// Step 26: waits until every one of `messages` is replied, i.e. until the
/// update call each carries completed successfully.
///
/// The ingress history only keeps the status of a replied message for
/// `MAX_INGRESS_TTL` after the reply, which is shorter than
/// `INGRESS_COMPLETION_TIMEOUT`. Hence every round polls each message that has
/// not been seen replied yet, rather than waiting for the messages one after
/// the other: a message replied while the test still waited for another one
/// could otherwise be pruned before the test polls it.
async fn await_ingress_messages_replied(
    messages: &[(&'static str, Agent, Principal, RequestId)],
    logger: &Logger,
) {
    let replied_names = Mutex::new(BTreeSet::<&'static str>::new());
    retry_with_msg_async!(
        "waiting for the pending ingress messages to complete",
        logger,
        INGRESS_COMPLETION_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let mut pending_names = Vec::<&'static str>::new();
            for (name, agent, canister_id, request_id) in messages {
                if replied_names.lock().unwrap().contains(name) {
                    continue;
                }
                let (status, _) = agent
                    .request_status_raw(request_id, *canister_id)
                    .await
                    .map_err(|e| anyhow!("failed to read the status of {name}'s message: {e}"))?;
                match status {
                    RequestStatusResponse::Replied(_) => {
                        replied_names.lock().unwrap().insert(name);
                        info!(logger, "Step 26: {name}'s ingress message completed");
                    }
                    RequestStatusResponse::Rejected(reject) => {
                        panic!("{name}'s ingress message was rejected: {reject:?}")
                    }
                    other => {
                        info!(logger, "{name}'s ingress message is {other:?}");
                        pending_names.push(name);
                    }
                }
            }
            if !pending_names.is_empty() {
                bail!("the ingress messages of {pending_names:?} have not completed yet");
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| panic!("not every pending ingress message completed: {e}"));
}

/// Starts an endless loop of calls from `canister` to `peer` (on another
/// subnet): `canister` is made to execute the loop body below once, via an
/// ingress message; from there on the reply (or reject) callback of every call
/// to `peer` fires a new call.
///
/// The loop body cannot contain itself, so its continuation re-enters it
/// indirectly: `canister` holds the loop body in its global data and the
/// continuation calls `canister` itself, passing the global data as the payload
/// for the callee (i.e. `canister`) to execute.
///
/// The loop body replies (to the ingress message or to the self-call that
/// triggered this iteration) as soon as it has fired the call to `peer`. This
/// keeps the number of open call contexts bounded (had it not replied, every
/// iteration would have left behind one open call context) and it makes each
/// iteration consist of one self-call plus one cross-subnet call.
///
/// The iteration counter (the global counter of `canister`) does not count the
/// iterations whose call to `peer` was rejected with `SYS_TRANSIENT`, so that
/// it stalls while messages to `peer` are held back, e.g. because `peer`'s
/// subnet is cooling down.
async fn start_call_loop(canister: &UniversalCanister<'_>, peer: Principal) {
    // The continuation: run `ops`, then re-enter the loop body. Its callbacks
    // must not reply, as the loop body has already replied.
    let continuation = |ops: PayloadBuilder| {
        ops.call_simple(
            canister.canister_id(),
            "update",
            call_args()
                .eval_other_side(wasm().get_global_data())
                .on_reply(wasm().noop())
                .on_reject(wasm().noop()),
        )
        .build()
    };
    // The loop body: call `peer`, counting the iteration unless the call is
    // rejected with `SYS_TRANSIENT`, and continue the loop.
    let loop_body = wasm()
        .call_simple(
            peer,
            "update",
            call_args()
                .other_side(wasm().reply_data(&[]))
                .on_reply(continuation(wasm().inc_global_counter()))
                .on_reject(continuation(wasm().reject_code().int_to_blob().if_neq(
                    (RejectCode::SysTransient as u32).to_le_bytes(),
                    wasm().inc_global_counter(),
                ))),
        )
        .reply_data(&[])
        .build();

    canister
        .update(wasm().set_global_data(&loop_body).reply_data(&[]))
        .await
        .expect("setting the loop body as the global data should succeed");
    canister
        .update(loop_body)
        .await
        .expect("starting the call loop should succeed");
}

/// The payload of the endless loops of `U3`, `U5`, `U7`, `U9`, `U11` and `U14`:
/// bump the global counter, so that the test can observe (via a query) that the
/// payload started executing, and then loop until the global data is set to
/// `LOOP_BREAK_TRIGGER`, which this test only does after the merge.
///
/// The canister only responds to the call it is executing once the loop ends,
/// so that call context stays open until then.
fn endless_loop() -> Vec<u8> {
    wasm()
        .inc_global_counter()
        .loop_until_global_data_set(LOOP_BREAK_TRIGGER, &[])
        .build()
}

/// The payload of an update call that calls `callee` with `endless_loop()` as the
/// payload for `callee` to execute. As `callee` does not respond until its global
/// data is set, neither does the caller, so the caller's ingress message stays
/// `processing` until then.
fn endless_loop_call(callee: Principal) -> Vec<u8> {
    wasm()
        .call_simple(callee, "update", call_args().other_side(endless_loop()))
        .build()
}

/// The payload of the update call on `U1`: one management canister
/// `install_code` call per canister in `targets`, installing the universal
/// canister module with an `arg` that makes `canister_init` burn
/// `INIT_INSTRUCTIONS` instructions, followed by a reply.
///
/// `U1` replies as soon as all the calls have been made, which keeps its
/// ingress message from lingering in the ingress history as a `processing`
/// entry; neither callback of the `install_code` calls may respond to that
/// already responded call context, so both are no-ops.
fn install_code_payload(targets: &[Principal]) -> Vec<u8> {
    let init = wasm()
        .instruction_counter_is_at_least(INIT_INSTRUCTIONS)
        .build();
    let module = get_universal_canister_wasm();
    let mut payload = wasm();
    for target in targets {
        payload = payload.call(
            management::install_code(target.as_slice(), &module)
                .with_mode(InstallMode::Install)
                .with_arg(init.clone())
                .on_reply(wasm().noop())
                .on_reject(wasm().noop()),
        );
    }
    payload.reply_data(&[]).build()
}

/// Waits until all of `U1`'s `install_code` requests have left `U1`'s output
/// queue, i.e. until, on every replica, one of them is executing (and hence
/// holds a call context in the subnet call context manager) and the others are
/// enqueued in `subnet`'s subnet input queues. Every `install_code` call
/// executes `INIT_INSTRUCTIONS` instructions, so the first one keeps executing
/// for long enough to observe this state.
///
/// Every subnet message this test made before `U1`'s calls (creating and
/// installing canisters, setting their controller) was waited for. The endless
/// loops of step 5 keep calling `canister_status`, but a paused `install_code`
/// only holds up subnet messages that install code themselves, so these calls
/// keep being executed rather than piling up behind `U1`'s calls. `U1` makes all
/// of its calls in one execution, so they are inducted together: once one of
/// them is executing, the others are enqueued.
async fn await_install_code_requests_inducted(subnet: &SubnetSnapshot, logger: &Logger) {
    let expected_queued = (INSTALL_CODE_TARGETS.len() - 1) as f64;
    let node_ips: Vec<_> = subnet.nodes().map(|node| node.get_ip_addr()).collect();
    retry_with_msg_async!(
        format!(
            "waiting until all {} `install_code` requests are inducted on subnet {}",
            INSTALL_CODE_TARGETS.len(),
            subnet.subnet_id
        ),
        logger,
        INDUCTION_TIMEOUT,
        INDUCTION_BACKOFF,
        || async {
            let metrics = fetch_metrics(
                &node_ips,
                &[
                    METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
                    METRIC_SUBNET_CALL_CONTEXTS,
                ],
            )
            .await?;
            let queued = min_across_replicas(
                &metrics,
                METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
                |labels| labels.get("kind").is_some_and(|kind| kind == "canister"),
                &node_ips,
            );
            let executing = min_across_replicas(
                &metrics,
                METRIC_SUBNET_CALL_CONTEXTS,
                |labels| {
                    labels
                        .get("type")
                        .is_some_and(|ty| ty == LABEL_INSTALL_CODE)
                },
                &node_ips,
            );
            if queued < expected_queued || executing < 1.0 {
                bail!(
                    "at least {queued} request(s) enqueued and {executing} executing per \
                     replica; expected {expected_queued} enqueued and 1 executing"
                );
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| panic!("U1's `install_code` requests were not inducted: {e}"));
}

/// Fetches all series of the given metrics from the given nodes.
///
/// Fails if any node cannot be scraped: a condition evaluated across the nodes
/// could otherwise hold on partial data. A series that no node reports is
/// absent though, as a node that responds simply does not export that series.
async fn fetch_metrics(
    node_ips: &[IpAddr],
    metrics: &[&str],
) -> Result<MetricsByReplica, ScrapeError> {
    match fetch_available_metrics(node_ips, metrics).await {
        (metrics, None) => Ok(metrics),
        (_, Some(err)) => Err(err),
    }
}

/// The smallest value any of the given replicas reports for any series of
/// `metric` whose labels match `labels_match`. A replica that reports no such
/// series, or whose metrics are not in `metrics`, reads as zero, and so does
/// an empty `replicas`.
fn min_across_replicas(
    metrics: &MetricsByReplica,
    metric: &str,
    labels_match: impl Fn(&Labels) -> bool,
    replicas: &[IpAddr],
) -> f64 {
    replicas
        .iter()
        .map(|ip| {
            metrics
                .get(ip)
                .and_then(|metrics| replica_values(metrics, metric, &labels_match).reduce(f64::min))
                .unwrap_or(0.0)
        })
        .reduce(f64::min)
        .unwrap_or(0.0)
}

/// Waits until `canister`'s global counter is non-zero, i.e. until the payload
/// of `endless_loop()` started executing on it.
async fn await_loop_started(canister: &UniversalCanister<'_>, name: &str, logger: &Logger) {
    retry_with_msg_async!(
        format!("waiting until {name}'s endless loop started"),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            if global_counter(canister).await? == 0 {
                bail!("{name} has not started executing the endless loop yet");
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| panic!("{name}'s endless loop did not start: {e}"));
}

/// Takes a snapshot of `canister_id` and returns its ID.
///
/// Calls the management canister directly rather than through `ic_utils`, whose
/// `ic-management-canister-types` is a different version than this workspace's.
async fn take_canister_snapshot(agent: &Agent, canister_id: Principal) -> SnapshotId {
    let args = TakeCanisterSnapshotArgs {
        canister_id,
        replace_snapshot: None,
        sender_canister_version: None,
        uninstall_code: None,
    };
    let reply = agent
        .update(&Principal::management_canister(), "take_canister_snapshot")
        .with_arg(Encode!(&args).unwrap())
        .with_effective_canister_id(canister_id)
        .call_and_wait()
        .await
        .expect("taking a canister snapshot should succeed");
    Decode!(&reply, TakeCanisterSnapshotResult)
        .expect("failed to decode the snapshot taken")
        .id
}

/// Stops `canister_id`, which only succeeds once it has no open call context.
async fn stop_canister(agent: &Agent, canister_id: Principal) {
    agent
        .update(&Principal::management_canister(), "stop_canister")
        .with_arg(Encode!(&CanisterIdRecord { canister_id }).unwrap())
        .with_effective_canister_id(canister_id)
        .call_and_wait()
        .await
        .unwrap_or_else(|e| panic!("stopping canister {canister_id} should succeed: {e}"));
}

/// The IDs of the snapshots `canister_id` holds.
async fn canister_snapshot_ids(agent: &Agent, canister_id: Principal) -> Vec<SnapshotId> {
    let args = ListCanisterSnapshotsArgs { canister_id };
    let reply = agent
        .update(&Principal::management_canister(), "list_canister_snapshots")
        .with_arg(Encode!(&args).unwrap())
        .with_effective_canister_id(canister_id)
        .call_and_wait()
        .await
        .expect("listing the canister snapshots should succeed");
    Decode!(&reply, ListCanisterSnapshotsResult)
        .expect("failed to decode the canister snapshots")
        .into_iter()
        .map(|snapshot| snapshot.id)
        .collect()
}

/// `canister`'s cycles balance, read via a query.
async fn cycles_balance(canister: &UniversalCanister<'_>) -> Result<u128> {
    let reply = canister
        .query(wasm().cycles_balance128().append_and_reply())
        .await
        .map_err(|e| anyhow!("failed to read the cycles balance: {e}"))?;
    let reply: [u8; 16] = reply
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 16 bytes, got {} bytes: {reply:?}", reply.len()))?;
    Ok(u128::from_le_bytes(reply))
}

/// Returns `canister`'s global counter, read via a query.
async fn global_counter(canister: &UniversalCanister<'_>) -> Result<u64> {
    let reply = canister
        .query(wasm().get_global_counter().reply_int64())
        .await
        .map_err(|e| anyhow!("failed to read the global counter: {e}"))?;
    let reply: [u8; 8] = reply
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 8 bytes, got {} bytes: {reply:?}", reply.len()))?;
    Ok(u64::from_le_bytes(reply))
}
