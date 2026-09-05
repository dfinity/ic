/* tag::catalog[]
Title:: Draining a subnet that is "cooling down".

Goal:: Verify that a subnet labeled "cooling down" in its subnet record quiesces
while its canisters are busy making cross-subnet calls in a loop, installing
code on one another and waiting for responses that never arrive, i.e. that it
reaches the "merge readiness" condition of the `Subnet merging` dashboard (see
`bases/apps/ic-dashboards/core/subnet-merging.json` on branch
`mraszyk/subnet-merging-dashboard` of `dfinity/k8s`) for `V` = the registry
version at which the subnet was labeled "cooling down" and a pending refund
budget (the dashboard's `R`) of 0 cycles.

The subnet that is cooling down, i.e. the one that is merged away, is called `M`
and the Application subnet it is merged into is called `R`. A third Application
subnet `T` holds the canisters at the other end of `M`'s cross-subnet calls. The
NNS subnet is none of these: it has to stay available throughout, as it is where
the proposals of this test are executed, including the one recovering `R` at the
merged state.

"Executing" an update call below always means submitting it as an ingress
message without waiting for it to complete: most of the calls of this test are
never meant to complete.

Runbook::
0. Set up an IC with an NNS subnet (with the NNS canisters installed) and three
   Application subnets `M`, `T` and `R`, of `SUBNET_SIZE` nodes each.
1. Install a universal canister on each of `M` and `T`: `US` on `M`, `UT` on `T`.
2. Make an ingress call to each of `US` and `UT` with a payload that calls the
   universal canister on the other subnet in a loop: the reply (or reject)
   callback of every call fires a new call.
3. Wait until both loops have completed a few iterations, i.e. messages are
   actually flowing between `M` and `T` in both directions.
4. Install the universal canisters of the steps below (`U1`, `U3`, `U5`, `U6`,
   `U8` and `U10` on `M`, `U4`, `U7` and `U9` on `T`, `UR` on `R`) and create
   five empty canisters `U2a` .. `U2e` on `M`, controlled by `U1`. All of this
   has to happen before step 5: a long-running `install_code` blocks every other
   `install_code` on the same subnet. Then give `U8` the state that has to
   survive the merge: a blob in its stable memory, a canister snapshot, and a
   cycles balance to compare against later.
5. Execute an update call on `U1` that makes five calls to the management
   canister's `install_code` method, one per `U2x`, in mode `install`, with the
   universal canister module and an `arg` that makes `canister_init` burn
   `INIT_INSTRUCTIONS` instructions. Wait until all five requests have left
   `U1`'s output queue: a request still sitting there when `M` starts cooling
   down would never be routed, not even into the loopback stream, and the code
   would never be installed.
6. Execute an update call on `U9` (on `T`) making a best effort call to `U10`
   (on `M`) that carries cycles and that `U10` never answers, so that a best
   effort message, whose deadline passes while `M` is cooling down, is in flight
   across the merge. Then start three endless loops, each of which runs
   until the global data of the looping canister is set to `LOOP_BREAK_TRIGGER`,
   which this test never does:
   a. execute an update call on `U3` that loops on `U3` itself;
   b. execute an update call on `U4` (on `T`) that calls `U5` (on `M`) with the
      loop as its payload, so that `M` holds a canister looping in a call from
      another subnet that it can never respond to;
   c. execute an update call on `U6` (on `M`) that calls `U7` (on `T`) with the
      loop as its payload, so that `M` holds a canister waiting for a response
      from another subnet that never arrives.
   Wait until all three loops are running.
7. Submit (and adopt) an `UpdateConfigOfSubnet` NNS proposal labeling `M` as
   "cooling down" in its subnet record, and record the registry version `V` it
   creates.
8. Wait until `M` rejects ingress messages, i.e. the replicas of `M` observed
   the "cooling down" label.
9. Check that `M` is not "merge ready" yet, so that the wait below is known to
   be waiting for something, and then wait until it is, according to the
   dashboard's condition for `V` and `MAX_REFUND_VALUE_CYCLES`: all subnets have
   reached registry version `V`, no stream in either direction holds a message
   (loopback included), the ingress history holds nothing but `processing`
   entries, `M`'s subnet input and output queues are empty, `M`'s subnet call
   context manager holds no call context, and the pending anonymous refunds are
   worth at most `MAX_REFUND_VALUE_CYCLES`.
10. Check that `U2a` .. `U2e` have been installed, i.e. that the `install_code`
   calls of step 5 ran to completion rather than being lost or rejected while
   `M` was cooling down.
11. Check that the two loops of step 2 are indeed stalled (their iteration
   counters, read via queries, no longer advance): while `M` is cooling down,
   neither `M` nor `T` routes any message to or from `M`, so the messages of
   both loops are retained in their senders' output queues.
12. Submit (and adopt) `UpdateConfigOfSubnet` NNS proposals setting the
   `halt_at_cup_height` flag of both `M` and `R`, and wait until each of their
   nodes reports in its journal that it is halted. Record the heights of the
   checkpoints they halted at.
13. Stop the replicas of both subnets and download the states they halted at.
   Assemble the merged state as a new checkpoint of `R`, at the next multiple of
   the DKG interval after the height `R` halted at, so that `R`'s own checkpoint
   is left untouched: the canisters and canister snapshots of `M` are added to
   those of `R`, and the result is marked as the product of a subnet merge. The
   ingress history of `M` is deliberately not merged in: the marker makes the
   replica re-register the ingress messages of the merged-in canisters that are
   still in progress. Compute the block time the merged state starts from, which
   must be larger than the times of both checkpoints, and the hash of its
   manifest.
14. Add the merged state to the checkpoints of `R`'s node, leaving its replica
   stopped.
15. Submit (and adopt) a `MergeSubnets` NNS proposal for `M` and `R`, which
   reroutes the canister ID ranges of `M` to `R`, and then a `RecoverSubnet` NNS
   proposal for `R`, which creates a recovery CUP for `R` at the merged state,
   running a fresh DKG for `R`'s membership. Recovering a subnet that was
   instructed to halt at its next CUP replaces that instruction with a plain
   halt, so `R` stays halted for now.
16. Start `R`'s replica and wait until it adopted the recovery CUP. Only now: a
   replica started before the recovery CUP exists resumes from the checkpoint
   `R` halted at, which does not hold the canisters of `M`. Then submit (and
   adopt) an `UpdateConfigOfSubnet` NNS proposal unhalting `R` and wait until it
   is healthy.
17. Check that `U8`, now served by `R`, kept the stable memory, the snapshot and
   (up to what an idle canister burns) the cycles balance of step 4, and that
   `UR`, which `R` hosted all along, is undisturbed and can call `U8` now that
   both are on the same subnet.
18. Set the global data of `U3`, `U5` and `U7` to `LOOP_BREAK_TRIGGER`, ending
   the three endless loops, and check that every ingress message that was in
   progress across the merge completed. `U3` and `U5` are reached through `R`,
   which serves the canisters of `M` after the merge.
19. Wait until every subnet other than `M` has reached the registry version the
   merge created, i.e. routes the canisters that used to be hosted by `M` to
   `R`. `M` itself is excluded: its replica was stopped for the merge and it is
   about to be deleted.
20. Submit (and adopt) a `DeleteSubnet` NNS proposal deleting `M`, which hosts no
   canister ID range anymore, and check that it is gone from the registry.

Success::
`M` becomes "merge ready", with `U2a` .. `U2e` installed, while both loops of
step 2 are stalled; the merge moves its canisters to `R`, where every ingress
message that was in progress across the merge completes; and `M` can then be
deleted.

end::catalog[] */

use anyhow::{Result, anyhow, bail};
use candid::{CandidType, Principal};
use ic_agent::{Agent, RequestId, agent::RequestStatusResponse};
use ic_management_canister_types::{SnapshotId, TakeCanisterSnapshotArgs};
use ic_nns_governance_api::NnsFunction;
use ic_recovery::registry_helper::RegistryPollingStrategy;
use ic_recovery::ssh_helper::SshHelper;
use ic_recovery::steps::Step;
use ic_recovery::util::SshUser;
use ic_recovery::{IC_STATE_DIR, Recovery, RecoveryArgs};
use ic_registry_subnet_type::SubnetType;
use ic_state_layout::{
    CANISTER_STATES_DIR, SNAPSHOTS_DIR, SUBNET_MERGED_FILE, StateLayout,
    UNVERIFIED_CHECKPOINT_MARKER,
};
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
    NnsInstallationBuilder, READY_WAIT_TIMEOUT, RETRY_BACKOFF, SshSession, SubnetSnapshot,
    TopologySnapshot, get_dependency_path_from_env,
};
use ic_system_test_driver::nns::{
    get_governance_canister, submit_external_proposal_with_test_id,
    vote_execute_proposal_assert_executed,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    JournalStreamer, MetricsFetcher, UniversalCanister, assert_create_agent, block_on,
    create_canister, runtime_from_url, set_controller,
};
use ic_types::{Height, SubnetId};
use ic_universal_canister::management::InstallMode;
use ic_universal_canister::{
    CallInterface, call_args, get_universal_canister_wasm, management, wasm,
};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;
use registry_canister::mutations::do_delete_subnet::DeleteSubnetPayload;
use registry_canister::mutations::do_recover_subnet::RecoverSubnetPayload;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use registry_canister::mutations::merge_subnets::MergeSubnetsPayload;
use slog::{Logger, info};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use url::Url;

/// Metrics making up the "merge readiness" condition.
const METRIC_REGISTRY_VERSION: &str = "mr_registry_version";
const METRIC_STREAM_MESSAGES: &str = "mr_stream_messages";
const METRIC_INGRESS_HISTORY_BY_STATE: &str = "replicated_state_ingress_history_length_by_state";
const METRIC_SUBNET_INPUT_QUEUE_MESSAGES: &str = "execution_subnet_input_queue_messages";
const METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES: &str = "execution_subnet_output_queue_messages";
const METRIC_SUBNET_CALL_CONTEXTS: &str = "replicated_state_subnet_call_contexts";
const METRIC_PENDING_REFUNDS_CYCLES: &str = "replicated_state_pending_refunds_cycles";
/// Timeout for a subnet to halt at its next CUP, which is up to a full DKG
/// interval away.
const HALT_TIMEOUT: Duration = Duration::from_secs(900);
/// Backoff between two searches of a node's journal for the halt message.
const HALT_BACKOFF: Duration = Duration::from_secs(10);

/// What a halted replica logs, once every few seconds, instead of delivering the
/// batches it would otherwise deliver (see `rs/consensus/src/consensus/batch_delivery.rs`).
const HALTED_LOG_PATTERN: &str = "is not delivered because replica is halted";

/// The label selecting the `install_code` call contexts of
/// `METRIC_SUBNET_CALL_CONTEXTS`.
const LABEL_INSTALL_CODE: &str = "type=\"install_code\"";

/// The dashboard's `R` in the readiness condition: the maximum total value in
/// cycles of the pending anonymous refunds of the cooling down subnet. (Not to
/// be confused with the subnet `R` of the runbook above.)
///
/// This test leaves no pending refunds behind, so it requires them to be worth
/// nothing at all. Making it hold non-zero ones would take a cycle bearing
/// message that is dropped from one of the subnet's queues while owed to a
/// canister of another subnet: the cycles of the best effort call of step 6 are
/// not it, as that call is picked up and its cycles are held by the open call
/// context of its callee rather than by a queued message. Which is just as well:
/// a cooling down subnet routes no refunds either (see `route_refunds` in
/// `rs/messaging/src/routing/stream_builder.rs`), so any refund it does hold
/// stays pending until it is merged, and is then lost -- the merged state takes
/// the refunds of the destination subnet, not those of the merged one.
const MAX_REFUND_VALUE_CYCLES: f64 = 0.0;

/// Number of loop iterations each universal canister must have completed before
/// the subnet is labeled "cooling down", so that the loops are known to be
/// making cross-subnet calls when the label takes effect.
const MIN_LOOP_ITERATIONS: u64 = 3;

/// One billion, the unit `INIT_INSTRUCTIONS` is expressed in.
const B: u64 = 1_000_000_000;

/// The names of the canisters `U1` installs code on.
const INSTALL_CODE_TARGETS: [&str; 5] = ["U2a", "U2b", "U2c", "U2d", "U2e"];

/// Instructions the `canister_init` of every canister installed by `U1` burns,
/// i.e. how long each of `U1`'s `install_code` calls runs. The point is to make
/// them as long-running as possible, so that the subnet has to drain
/// `install_code` calls that span hundreds of rounds before it can be merged.
///
/// An `install_code` message may consume at most
/// `MAX_INSTRUCTIONS_PER_INSTALL_CODE` = 300B instructions on an Application
/// subnet (`rs/config/src/subnet_config.rs`) and that budget also has to cover
/// compiling the module: 6_000 instructions per byte of the decompressed
/// (~350 KB) universal canister module, i.e. ~2.2B instructions, plus a 20M
/// base cost. The full compilation cost is charged whenever the module is not
/// in `expected_compiled_wasms`, which is cleared at every checkpoint, so an
/// `install_code` that is aborted at a checkpoint and restarted afterwards pays
/// it; hence the budget for `canister_init` has to leave room for it.
const INIT_INSTRUCTIONS: u64 = 295 * B;

/// Where in the stable memory of `U8` the blob that has to survive the merge is
/// stored, and the blob itself.
const STABLE_MEMORY_OFFSET: u32 = 0;
const STABLE_MEMORY_BLOB: &[u8] = b"this blob has to survive the subnet merge";

/// The cycles the best effort call of step 6 carries, and its timeout. The point
/// of the call is that a best effort message is in flight across the merge: its
/// callee never responds, so its deadline passes while `M` is cooling down, and
/// the cycles it carries are held by the callee's open call context, which the
/// merge has to carry over like any other canister state.
const BEST_EFFORT_CALL_CYCLES: u128 = 1_000_000_000;
const BEST_EFFORT_CALL_TIMEOUT_SECONDS: u32 = 60;

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

/// The global data value that would end the endless loops of `U3`, `U5` and
/// `U7`. The test never sets it, so those loops never end.
const LOOP_BREAK_TRIGGER: &[u8] = b"break";

/// The number of nodes of every subnet. More than one so that the merge has to
/// get the merged state to the other nodes of the destination subnet the way a
/// recovery does, i.e. by state sync from the one node it was uploaded to, and so
/// that the medians the merge readiness condition is made of are medians of more
/// than one value.
const SUBNET_SIZE: usize = 4;

/// The DKG interval length of the Application subnets, i.e. one less than the
/// distance between two consecutive checkpoints (and CUPs). The default is long
/// enough for an `install_code` burning `INIT_INSTRUCTIONS` to complete within
/// one interval, which matters because a paused `install_code` is aborted at
/// every checkpoint and has to start over afterwards.
const DKG_INTERVAL_LENGTH: u64 = 499;
/// The distance between two consecutive checkpoint (and CUP) heights.
const CHECKPOINT_INTERVAL: u64 = DKG_INTERVAL_LENGTH + 1;

/// How much later than the checkpoints it is assembled from the merged state
/// starts, i.e. the block time of the recovery CUP of `R` minus the larger of
/// the two checkpoint times.
const MERGED_STATE_TIME_MARGIN: Duration = Duration::from_secs(60);

/// Timeout for an ingress message that was in progress across the merge to
/// complete once the loop it is waiting for is broken. Generous because the
/// destination subnet has just resumed from the merged state and is busy
/// recomputing its manifest and draining the message loops of step 2 at the same
/// time: this has been observed to take up to four minutes.
const INGRESS_COMPLETION_TIMEOUT: Duration = Duration::from_secs(900);

/// Timeout for the subnet to become "merge ready". The binding terms are the
/// `install_code` calls of step 5, which take a couple of hundred rounds each
/// (and are executed one at a time, as at most one long-running `install_code`
/// makes progress per round), and the ingress history, which only becomes free
/// of terminal statuses once the entries of the ingress messages submitted
/// before the subnet started cooling down are pruned, i.e. at their (up to
/// `MAX_INGRESS_TTL` = 5 minutes away) expiry times.
const MERGE_READY_TIMEOUT: Duration = Duration::from_secs(2400);
/// Backoff between two evaluations of the readiness condition. Longer than the
/// default because every evaluation scrapes the metrics of all subnets.
const MERGE_READY_BACKOFF: Duration = Duration::from_secs(10);

/// How long the loops are observed to be stalled (step 11).
const STALL_OBSERVATION_PERIOD: Duration = Duration::from_secs(15);

/// Timeouts of the test itself: draining the `install_code` calls dominates,
/// the rest of the scenario takes a couple of minutes. The overall timeout
/// additionally covers the setup (booting the IC and installing the NNS).
const PER_TEST_TIMEOUT: Duration = Duration::from_secs(3300);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(3900);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TEST_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        // The merge stops and starts the replicas of the two subnets being merged,
        // so their nodes legitimately start the replica more than once. The
        // metrics to check have to stay prefix-free, so this updates the entry of
        // the default set rather than adding a more specific one.
        .update_orchestrator_metrics_to_check("orchestrator_processes_start_attempts_total", 2)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
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
}

pub fn test(env: TestEnv) {
    block_on(run(env));
}

async fn run(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    // The three Application subnets: `M` is the one that will be labeled
    // "cooling down" and merged away, `R` is the one it is merged into, and `T`
    // is the one `M` exchanges messages with in a loop and that holds the
    // canisters at the other end of the cross-subnet endless loops of step 6.
    let app_subnets: Vec<_> = topology
        .subnets()
        .filter(|subnet| subnet.subnet_type() == SubnetType::Application)
        .collect();
    assert_eq!(
        app_subnets.len(),
        3,
        "expected exactly 3 Application subnets"
    );
    let m_subnet = app_subnets[0].clone();
    let t_subnet = app_subnets[1].clone();
    let r_subnet = app_subnets[2].clone();
    let m_node = m_subnet.nodes().next().unwrap();
    let t_node = t_subnet.nodes().next().unwrap();
    let r_node = r_subnet.nodes().next().unwrap();
    let m_agent = assert_create_agent(m_node.get_public_url().as_str()).await;
    let t_agent = assert_create_agent(t_node.get_public_url().as_str()).await;
    let r_agent = assert_create_agent(r_node.get_public_url().as_str()).await;
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    info!(
        logger,
        "Subnets under test, with their (single) nodes:\n  \
         M={} on {}\n  \
         R={} on {}\n  \
         T={} on {}\n  \
         NNS={} on {}",
        m_subnet.subnet_id,
        m_node.node_id,
        r_subnet.subnet_id,
        r_node.node_id,
        t_subnet.subnet_id,
        t_node.node_id,
        topology.root_subnet_id(),
        nns_node.node_id,
    );

    // Step 1: Install a universal canister on each of `M` and `T`.
    info!(logger, "Step 1: Installing universal canisters US and UT");
    let us = UniversalCanister::new_with_retries(&m_agent, m_node.effective_canister_id(), &logger)
        .await;
    let ut = UniversalCanister::new_with_retries(&t_agent, t_node.effective_canister_id(), &logger)
        .await;
    info!(
        logger,
        "Step 1 done: US={}, UT={}",
        us.canister_id(),
        ut.canister_id(),
    );

    // Step 2: Start a loop of calls to the canister on the other subnet on both
    // universal canisters.
    info!(logger, "Step 2: Starting the US <-> UT call loops");
    start_call_loop(&us, ut.canister_id()).await;
    start_call_loop(&ut, us.canister_id()).await;
    info!(logger, "Step 2 done: both call loops started");

    // Step 3: Wait until both loops have completed a few iterations.
    info!(
        logger,
        "Step 3: Waiting for {MIN_LOOP_ITERATIONS} iterations of both call loops"
    );
    for (canister, name) in [(&us, "US"), (&ut, "UT")] {
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
    info!(logger, "Step 3 done: both call loops are making progress");

    // Step 4: Install all the canisters of the steps below. Every installation
    // has to happen before step 5 starts `U1`'s `install_code` calls: at most
    // one long-running `install_code` makes progress per round, and while one
    // is in progress no other `install_code` on the same subnet is executed at
    // all, so any installation attempted here later would be stuck behind
    // `U1`'s calls for as long as they run.
    info!(
        logger,
        "Step 4: Installing U1, U3, U5, U6 on M and U4, U7 on T, and creating {} canisters for U1 \
         to install code on",
        INSTALL_CODE_TARGETS.len(),
    );
    let m_id = m_node.effective_canister_id();
    let t_id = t_node.effective_canister_id();
    let r_id = r_node.effective_canister_id();
    let u1 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u3 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u4 = UniversalCanister::new_with_retries(&t_agent, t_id, &logger).await;
    let u5 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u6 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u7 = UniversalCanister::new_with_retries(&t_agent, t_id, &logger).await;
    // `U8` carries the state that has to survive the merge; `U9` on `T` and
    // `U10` on `M` are the two ends of the best effort call of step 6; and `UR`
    // is a canister of the destination subnet, which the merge must leave alone.
    let u8 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u9 = UniversalCanister::new_with_retries(&t_agent, t_id, &logger).await;
    let u10 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let ur = UniversalCanister::new_with_retries(&r_agent, r_id, &logger).await;
    info!(
        logger,
        "Step 4: U1={}, U3={}, U5={}, U6={}, U8={}, U10={} on M; U4={}, U7={}, U9={} on T; UR={} \
         on R",
        u1.canister_id(),
        u3.canister_id(),
        u5.canister_id(),
        u6.canister_id(),
        u8.canister_id(),
        u10.canister_id(),
        u4.canister_id(),
        u7.canister_id(),
        u9.canister_id(),
        ur.canister_id(),
    );
    let mut targets = Vec::new();
    for name in INSTALL_CODE_TARGETS {
        let target = create_canister(&m_agent, m_id).await;
        set_controller(&target, &u1.canister_id(), &m_agent).await;
        info!(logger, "Step 4: {name}={target} on M, controlled by U1");
        targets.push(target);
    }
    // The state of `U8` that the merge has to carry over: a blob in its stable
    // memory, a canister snapshot, and its cycles balance.
    u8.store_to_stable(STABLE_MEMORY_OFFSET, STABLE_MEMORY_BLOB)
        .await;
    let u8_snapshot = take_canister_snapshot(&m_agent, u8.canister_id()).await;
    let u8_cycles_before = cycles_balance(&u8).await.unwrap();
    info!(
        logger,
        "Step 4 done: all canisters installed; U8 holds {} bytes in its stable memory, snapshot \
         {} and {u8_cycles_before} cycles",
        STABLE_MEMORY_BLOB.len(),
        hex::encode(&u8_snapshot),
    );

    // Step 5: Have `U1` install code on the five canisters it controls.
    info!(
        logger,
        "Step 5: Executing the update call on U1 making the {} `install_code` calls",
        targets.len(),
    );
    u1.submit_update(install_code_payload(&targets))
        .await
        .expect("submitting U1's `install_code` calls should succeed");
    await_install_code_requests_inducted(&m_subnet, &logger).await;
    info!(
        logger,
        "Step 5 done: all of U1's `install_code` requests left its output queue"
    );

    // Step 6: Start the three endless loops, and the best effort call whose
    // cycles end up as a pending anonymous refund of `M`.
    info!(
        logger,
        "Step 6: Starting the three endless loops and U9's best effort call to U10"
    );
    // `U10` never responds, so the call is still in flight when `M` starts
    // cooling down, and its deadline passes while it is. Dropping it leaves `M`
    // owing its cycles to `U9`, which is on `T`: a refund `M` cannot route while
    // it is cooling down, and hence one that is still pending when it is merged.
    u9.submit_update(wasm().call_simple_with_cycles_and_best_effort_response(
        u10.canister_id(),
        "update",
        call_args().other_side(endless_loop()),
        BEST_EFFORT_CALL_CYCLES,
        BEST_EFFORT_CALL_TIMEOUT_SECONDS,
    ))
    .await
    .expect("submitting U9's best effort call should succeed");
    // The IDs of the ingress messages that stay in progress across the merge, so
    // that step 16 can check that all of them eventually completed. `U3` and
    // `U6` are on `M` and thus served by `R` after the merge; `U4` stays on `T`.
    let mut pending_ingress_messages: Vec<(String, Agent, Principal, RequestId)> = Vec::new();
    for (canister, name, agent) in [
        (&u3, "U3", &m_agent),
        (&u4, "U4", &t_agent),
        (&u6, "U6", &m_agent),
    ] {
        let payload = if name == "U3" {
            endless_loop()
        } else {
            let callee = if name == "U4" { &u5 } else { &u7 };
            endless_loop_call(callee.canister_id())
        };
        let request_id = canister
            .submit_update(payload)
            .await
            .unwrap_or_else(|e| panic!("submitting {name}'s update call should succeed: {e}"))
            .unwrap_or_else(|| panic!("{name}'s update call should not have completed already"));
        let agent = if name == "U4" {
            agent.clone()
        } else {
            r_agent.clone()
        };
        pending_ingress_messages.push((
            name.to_string(),
            agent,
            canister.canister_id(),
            request_id,
        ));
    }
    for (canister, name) in [(&u3, "U3"), (&u5, "U5"), (&u7, "U7")] {
        await_loop_started(canister, name, &logger).await;
    }
    info!(
        logger,
        "Step 6 done: U3 is looping, U5 is looping in a call from U4, and U7 is looping in a call \
         from U6"
    );

    // Step 7: Label `M` as "cooling down" in its subnet record.
    info!(
        logger,
        "Step 7: Labeling subnet M ({}) as \"cooling down\"", m_subnet.subnet_id,
    );
    let registry_version = set_subnet_cooling_down(&env, m_subnet.subnet_id, &logger).await;
    info!(
        logger,
        "Step 7 done: subnet M is labeled \"cooling down\" as of registry version \
         {registry_version} (V)",
    );

    // Step 8: Wait until the replicas of `M` observed the "cooling down" label,
    // i.e. until `M` rejects ingress messages.
    info!(
        logger,
        "Step 8: Waiting until subnet M rejects ingress messages"
    );
    retry_with_msg_async!(
        "waiting until subnet M rejects ingress messages",
        &logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            match us.update(wasm().reply_data(&[])).await {
                Ok(_) => bail!("ingress message to US was still accepted"),
                Err(err) => {
                    let err = err.to_string();
                    if !err.contains("cooling down") {
                        bail!("ingress message to US failed unexpectedly: {err}");
                    }
                    Ok(())
                }
            }
        }
    )
    .await
    .expect("subnet M did not start rejecting ingress messages");
    info!(
        logger,
        "Step 8 done: subnet M rejects ingress messages, so it is cooling down"
    );

    // Step 9: Check that `M` is *not* "merge ready" yet, so that the wait below
    // is known to be waiting for something: a readiness condition that held from
    // the start would be satisfied by a subnet that never had anything to drain.
    let terms = evaluate_merge_readiness(
        &topology,
        &m_subnet,
        registry_version,
        MAX_REFUND_VALUE_CYCLES,
    )
    .await
    .expect("failed to evaluate the merge readiness of subnet M");
    let unsatisfied: Vec<_> = terms
        .iter()
        .filter(|(_, satisfied)| !satisfied)
        .map(|(term, _)| term.as_str())
        .collect();
    assert!(
        !unsatisfied.is_empty(),
        "subnet M was already \"merge ready\" right after it started cooling down, so the wait \
         below would prove nothing",
    );
    info!(
        logger,
        "Step 9: subnet M is not \"merge ready\" yet: {}",
        unsatisfied.join("; "),
    );

    // Step 9 (continued): Wait until `M` is "merge ready".
    info!(
        logger,
        "Step 9: Waiting until subnet M is \"merge ready\" for V={registry_version} and at most \
         {MAX_REFUND_VALUE_CYCLES} cycles of pending refunds",
    );
    retry_with_msg_async!(
        format!(
            "waiting until subnet {} is \"merge ready\"",
            m_subnet.subnet_id
        ),
        &logger,
        MERGE_READY_TIMEOUT,
        MERGE_READY_BACKOFF,
        || async {
            let terms = evaluate_merge_readiness(
                &topology,
                &m_subnet,
                registry_version,
                MAX_REFUND_VALUE_CYCLES,
            )
            .await?;
            let unsatisfied: Vec<_> = terms
                .iter()
                .filter(|(_, satisfied)| !satisfied)
                .map(|(term, _)| term.as_str())
                .collect();
            if !unsatisfied.is_empty() {
                bail!("not merge ready: {}", unsatisfied.join("; "));
            }
            for (term, _) in &terms {
                info!(logger, "Step 9: merge readiness term holds: {term}");
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| panic!("subnet M did not become \"merge ready\": {e}"));
    info!(logger, "Step 9 done: subnet M is \"merge ready\"");

    // Step 10: Check that `U1`'s `install_code` calls did install the universal
    // canister module: a canister that has no module rejects every query.
    info!(
        logger,
        "Step 10: Checking that {} have been installed",
        INSTALL_CODE_TARGETS.join(", "),
    );
    for (&target, name) in targets.iter().zip(INSTALL_CODE_TARGETS) {
        let canister = UniversalCanister::from_canister_id(&m_agent, target);
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
        "Step 10 done: {} have been installed",
        INSTALL_CODE_TARGETS.join(", "),
    );

    // Step 11: Check that both call loops are stalled, i.e. that `M` became
    // "merge ready" because it is cooling down and not because the loops
    // stopped making calls.
    info!(
        logger,
        "Step 11: Checking that both call loops are stalled over {STALL_OBSERVATION_PERIOD:?}"
    );
    let before = [
        global_counter(&us).await.unwrap(),
        global_counter(&ut).await.unwrap(),
    ];
    tokio::time::sleep(STALL_OBSERVATION_PERIOD).await;
    for ((canister, name), before) in [(&us, "US"), (&ut, "UT")].into_iter().zip(before) {
        let after = global_counter(canister).await.unwrap();
        assert_eq!(
            before, after,
            "{name}'s call loop advanced from iteration {before} to {after} while subnet M was \
             cooling down",
        );
    }
    info!(
        logger,
        "Step 11 done: both call loops are stalled at iterations {before:?}"
    );

    // Step 12: Halt both `M` and `R` at their next CUP, i.e. at a checkpoint
    // whose state is certified, so that the merged state can be assembled from
    // states both subnets agree on.
    info!(
        logger,
        "Step 12: Halting subnets M and R at their next checkpoint"
    );
    for (subnet, name) in [(&m_subnet, "M"), (&r_subnet, "R")] {
        let version = halt_subnet_at_cup_height(&env, subnet.subnet_id, &logger).await;
        info!(
            logger,
            "Step 12: subnet {name} is set to halt at its next CUP as of registry version {version}"
        );
    }
    let m_height = await_halted_at_checkpoint(&m_node, "M", &logger).await;
    let r_height = await_halted_at_checkpoint(&r_node, "R", &logger).await;
    info!(
        logger,
        "Step 12 done: M halted at checkpoint {m_height}, R halted at checkpoint {r_height}"
    );

    // Step 13: Assemble the merged state: `R`'s state at the checkpoint it
    // halted at, with the canisters (and canister snapshots) of `M` added to it,
    // as a new checkpoint at the next multiple of the DKG interval, so that
    // `R`'s own checkpoint is left untouched.
    //
    // Taking `R`'s system metadata and subnet queues wholesale, i.e. dropping
    // `M`'s, is only sound because `M`'s were empty, which is what the merge
    // readiness of step 9 established. That they are *still* empty at the
    // checkpoint `M` halted at, minutes later, is due to `M` cooling down: no
    // message is routed out of any of its canisters' output queues, not even
    // into the loopback stream, so no management call can be inducted, no subnet
    // call context can be created and no `install_code` can start in between.
    let merged_height = r_height + CHECKPOINT_INTERVAL;
    info!(
        logger,
        "Step 13: Assembling the merged state as checkpoint {merged_height} of R"
    );

    // The replicas have to be stopped before their states are touched: the state
    // manager of a running replica owns its state directory, even while
    // consensus is halted.
    for (node, name) in [(&m_node, "M"), (&r_node, "R")] {
        node.block_on_bash_script_async("sudo systemctl stop ic-replica")
            .await
            .unwrap_or_else(|e| panic!("failed to stop the replica of subnet {name}: {e}"));
        info!(logger, "Step 13: stopped the replica of subnet {name}");
    }

    // `ic-recovery` is a synchronous library that blocks on its own runtime
    // internally (registry polling, rsync steps), which cannot be done from a
    // thread that is driving this runtime, so all of it runs on a blocking one.
    let merge = MergeStateArgs {
        logger: logger.clone(),
        admin_key_file: env
            .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
            .join(SSH_USERNAME),
        nns_url: topology
            .root_subnet()
            .nodes()
            .next()
            .unwrap()
            .get_public_url(),
        m_dir: env.get_path("recovery_m"),
        r_dir: env.get_path("recovery_r"),
        m_node_ip: m_node.get_ip_addr(),
        r_node_ip: r_node.get_ip_addr(),
        m_height,
        r_height,
        merged_height,
    };
    let (merged_time, state_hash) = tokio::task::spawn_blocking(move || merge.exec())
        .await
        .expect("the state merging task panicked");
    info!(
        logger,
        "Step 14 done: R holds the merged state, which hashes to {} and starts at {merged_time}",
        hex::encode(&state_hash),
    );

    // Step 15: Merge `M` into `R`: reroute `M`'s canister ID ranges to `R`, and
    // recover `R` at the merged state.
    info!(
        logger,
        "Step 15: Submitting the MergeSubnets proposal for M -> R"
    );
    let merge_registry_version =
        merge_subnets(&env, m_subnet.subnet_id, r_subnet.subnet_id, &logger).await;
    info!(
        logger,
        "Step 15: M is merged into R as of registry version {merge_registry_version}"
    );

    // `merge_subnets` only updates the routing table: making `R` resume from the
    // merged state is a subnet recovery like any other. The DKG of the recovery
    // CUP is handled by the NNS subnet, which is neither of the two subnets being
    // merged and stays available throughout.
    info!(
        logger,
        "Step 15: Submitting the RecoverSubnet proposal for R at height {merged_height}"
    );
    let recovery_registry_version = recover_subnet(
        &env,
        r_subnet.subnet_id,
        merged_height,
        merged_time,
        state_hash.clone(),
        &logger,
    )
    .await;
    info!(
        logger,
        "Step 15 done: R is recovered at the merged state as of registry version \
         {recovery_registry_version}"
    );

    // Step 16: Start `R`'s replica, now that the recovery CUP exists. Starting it
    // any earlier would have it resume from its own checkpoint, which does not
    // hold the canisters of `M`.
    info!(logger, "Step 16: Starting the replica of subnet R");
    r_node
        .block_on_bash_script_async("sudo systemctl start ic-replica")
        .await
        .expect("failed to start the replica of subnet R");
    // Whether `R` resumes from the merged state or from the checkpoint it halted
    // at is not something to leave to chance: a replica that started before its
    // node had synced the registry version holding the recovery CUP would come
    // up on the latter, silently serving a state without the canisters of `M`.
    // Wait for the node to report exactly the recovery CUP, so that this fails
    // loudly and promptly instead.
    {
        let logger = logger.clone();
        let node_ip = r_node.get_ip_addr();
        let state_hash = hex::encode(&state_hash);
        tokio::task::spawn_blocking(move || {
            Recovery::wait_for_recovery_cup(
                &logger,
                node_ip,
                Height::from(merged_height),
                state_hash,
            )
        })
        .await
        .expect("the recovery CUP waiting task panicked")
        .expect("subnet R did not adopt the recovery CUP holding the merged state");
    }
    info!(
        logger,
        "Step 16: subnet R adopted the recovery CUP at height {merged_height}"
    );

    // `recover_subnet` turned the "halt at the next CUP" instruction of step 12
    // into a plain halt, so that a recovered subnet does not resume before its
    // recovery has been checked. Lift it now that `R` came up on the merged
    // state: a halted subnet delivers no batches, so none of the ingress
    // messages of step 18 would complete.
    let unhalt_registry_version = unhalt_subnet(&env, r_subnet.subnet_id, &logger).await;
    info!(
        logger,
        "Step 16: R is unhalted as of registry version {unhalt_registry_version}"
    );
    // The `_async` variant, and not the blocking one: the latter drives its
    // request through `futures::executor::block_on`, which busy-polls a `reqwest`
    // future that needs the runtime this thread is driving, and livelocks as soon
    // as an attempt has to open a new connection -- which is exactly what happens
    // here, where `R` reports `WaitingForRootDelegation` for minutes before the
    // unhalting takes effect.
    // The `_async` variants of the driver's SSH and status helpers are what this
    // test uses throughout: the blocking ones drive their own future with
    // `futures::executor::block_on`, which busy-polls a `reqwest` request that
    // has to open a new connection instead of letting the runtime wait for it.
    r_node
        .await_status_is_healthy_async()
        .await
        .expect("subnet R did not become healthy after the merge");
    info!(logger, "Step 16 done: subnet R is healthy");

    // Step 17: Check that the merge carried the state of `M`'s canisters over and
    // left `R`'s own canister alone.
    info!(
        logger,
        "Step 17: Checking the state of U8 and UR after the merge"
    );
    let u8_on_r = UniversalCanister::from_canister_id(&r_agent, u8.canister_id());
    assert_eq!(
        u8_on_r
            .try_read_stable(
                STABLE_MEMORY_OFFSET,
                STABLE_MEMORY_BLOB.len().try_into().unwrap()
            )
            .await,
        STABLE_MEMORY_BLOB,
        "the stable memory of U8 did not survive the merge",
    );
    assert!(
        canister_snapshot_ids(&r_agent, u8.canister_id())
            .await
            .contains(&u8_snapshot),
        "the snapshot of U8 did not survive the merge",
    );
    let u8_cycles_after = cycles_balance(&u8_on_r)
        .await
        .expect("failed to read the cycles balance of U8 after the merge");
    assert!(
        u8_cycles_after <= u8_cycles_before
            && u8_cycles_before - u8_cycles_after <= u8_cycles_before / MAX_BURNED_CYCLES_FRACTION,
        "the cycles balance of U8 went from {u8_cycles_before} to {u8_cycles_after} across the \
         merge, a difference of more than the one in {MAX_BURNED_CYCLES_FRACTION} an idle canister \
         is expected to burn",
    );

    // `UR` was hosted by `R` all along: adding the canisters of `M` to `R`'s
    // state must not have disturbed it. And now that both are on `R`, they must
    // be able to call each other.
    let ur_reply = ur
        .update(wasm().call_simple(
            u8.canister_id(),
            "update",
            call_args().other_side(wasm().push_bytes(MERGED_CALL_REPLY).append_and_reply()),
        ))
        .await
        .expect("UR should be able to call a canister that was hosted by M");
    assert_eq!(
        ur_reply, MERGED_CALL_REPLY,
        "UR got an unexpected reply from U8",
    );
    info!(
        logger,
        "Step 17 done: U8 kept its stable memory, snapshot and cycles, and UR can call it"
    );

    // Step 18: Let the endless loops finish and check that every ingress message
    // that was still in progress when the merge happened completed.
    //
    // The canisters of `M` now live on `R`, which serves them under the same
    // canister IDs, so the agent for `R` is what reaches them. `U4` and `U7` did
    // not move: they are on `T`.
    info!(
        logger,
        "Step 18: Breaking the endless loops and waiting for the pending ingress messages"
    );
    let u3 = UniversalCanister::from_canister_id(&r_agent, u3.canister_id());
    let u5 = UniversalCanister::from_canister_id(&r_agent, u5.canister_id());
    for (canister, name) in [(&u3, "U3"), (&u5, "U5"), (&u7, "U7")] {
        retry_with_msg_async!(
            format!("setting the global data of {name} to {LOOP_BREAK_TRIGGER:?}"),
            &logger,
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
        info!(logger, "Step 18: broke {name}'s endless loop");
    }

    for (name, agent, canister_id, request_id) in pending_ingress_messages {
        await_ingress_message_replied(&agent, canister_id, &request_id, &name, &logger).await;
        info!(logger, "Step 18: {name}'s ingress message completed");
    }
    info!(
        logger,
        "Step 18 done: all the ingress messages that were pending across the merge completed"
    );

    // Step 18: Wait until every subnet observed the merge, i.e. routes the
    // canisters that used to be hosted by `M` to `R`. Only then may `M` be
    // deleted: a subnet still on an older registry version would keep routing
    // messages to a subnet that no longer exists.
    info!(
        logger,
        "Step 19: Waiting until all subnets reached registry version \
         {merge_registry_version}, which holds the merge"
    );
    await_registry_version_on_all_subnets(
        &topology,
        m_subnet.subnet_id,
        merge_registry_version,
        &logger,
    )
    .await;
    info!(logger, "Step 19 done: all subnets observed the merge");

    // Step 19: Delete the merged subnet, which hosts no canister ID range
    // anymore, and check that it is gone from the registry.
    info!(
        logger,
        "Step 20: Deleting subnet M ({})", m_subnet.subnet_id
    );
    let topology = delete_subnet(&env, m_subnet.subnet_id, &logger).await;
    let remaining: Vec<_> = topology.subnets().map(|subnet| subnet.subnet_id).collect();
    assert!(
        !remaining.contains(&m_subnet.subnet_id),
        "subnet M ({}) is still in the registry at version {}: {remaining:?}",
        m_subnet.subnet_id,
        topology.get_registry_version(),
    );
    info!(
        logger,
        "Step 20 done: subnet M is gone as of registry version {}; the remaining subnets are \
         {remaining:?}",
        topology.get_registry_version(),
    );
}

/// Everything the synchronous, `ic-recovery` driven part of the merge needs: it
/// downloads the states of both subnets, assembles the merged state as a new
/// checkpoint of the destination subnet, and puts it on the destination node.
///
/// This is a plain struct of owned data rather than a closure over the test's
/// state because it has to be moved onto a blocking thread: `ic-recovery` blocks
/// on its own runtime, which a thread driving the test's runtime cannot do.
struct MergeStateArgs {
    logger: Logger,
    admin_key_file: PathBuf,
    nns_url: Url,
    m_dir: PathBuf,
    r_dir: PathBuf,
    m_node_ip: IpAddr,
    r_node_ip: IpAddr,
    m_height: u64,
    r_height: u64,
    merged_height: u64,
}

impl MergeStateArgs {
    /// Returns the block time the recovered destination subnet should start from
    /// and the hash of the manifest of the merged state.
    fn exec(self) -> (u64, Vec<u8>) {
        let m_recovery = self.recovery(self.m_dir.clone());
        let r_recovery = self.recovery(self.r_dir.clone());

        for (recovery, node_ip, height, name) in [
            (&m_recovery, self.m_node_ip, self.m_height, "M"),
            (&r_recovery, self.r_node_ip, self.r_height, "R"),
        ] {
            info!(self.logger, "Downloading the state of subnet {name}");
            recovery
                .get_download_state_step(
                    node_ip,
                    SshUser::Admin,
                    Some(self.admin_key_file.clone()),
                    /* keep_downloaded_state= */ false,
                    Some(height),
                )
                .expect("failed to build the download step")
                .exec()
                .unwrap_or_else(|e| panic!("failed to download the state of subnet {name}: {e}"));
        }

        let m_checkpoints = m_recovery.work_dir.join(IC_STATE_DIR).join("checkpoints");
        let r_checkpoints = r_recovery.work_dir.join(IC_STATE_DIR).join("checkpoints");
        let m_checkpoint =
            m_checkpoints.join(StateLayout::checkpoint_name(Height::from(self.m_height)));
        let r_checkpoint =
            r_checkpoints.join(StateLayout::checkpoint_name(Height::from(self.r_height)));
        let merged_checkpoint = r_checkpoints.join(StateLayout::checkpoint_name(Height::from(
            self.merged_height,
        )));

        // The block time the recovered subnet starts from has to be larger than
        // the times of both checkpoints the merged state is assembled from.
        let m_time = checkpoint_time_nanos(&m_checkpoint);
        let r_time = checkpoint_time_nanos(&r_checkpoint);
        let merged_time = m_time.max(r_time) + MERGED_STATE_TIME_MARGIN.as_nanos() as u64;
        info!(
            self.logger,
            "M halted at time {m_time}, R at {r_time}; the merged state starts at {merged_time}"
        );

        assemble_merged_checkpoint(
            &r_checkpoint,
            &m_checkpoint,
            &merged_checkpoint,
            &self.logger,
        );
        let state_hash = manifest_root_hash(&merged_checkpoint);

        self.upload_merged_checkpoint(&merged_checkpoint);

        (merged_time, state_hash)
    }

    /// Adds `merged_checkpoint` to the checkpoints of the destination node,
    /// leaving its replica stopped.
    ///
    /// Not `Recovery::get_upload_state_and_restart_step`: that one replaces the
    /// whole state directory (and insists that it hold a single checkpoint),
    /// which would delete the checkpoint the destination subnet halted at. That
    /// checkpoint is meant to survive the merge untouched, so the merged state is
    /// added next to it instead.
    fn upload_merged_checkpoint(&self, merged_checkpoint: &Path) {
        let ssh_helper = SshHelper::new(
            self.logger.clone(),
            SshUser::Admin,
            self.r_node_ip,
            /* require_confirmation= */ false,
            Some(self.admin_key_file.clone()),
        );
        let staging = PathBuf::from("/var/lib/ic/data/merged_state");

        info!(
            self.logger,
            "Uploading the merged state to {}",
            staging.display()
        );
        // `/var/lib/ic/data` is not writable by the SSH user, so the staging
        // directory has to be created with `sudo` and then handed over to it, or
        // the `rsync` below (which runs as that user) cannot write into it.
        ssh_helper
            .ssh(format!(
                "set -e;
                 sudo rm -rf {staging};
                 sudo mkdir -p {staging};
                 sudo chown -R {ssh_user} {staging};",
                staging = staging.display(),
                ssh_user = SshUser::Admin,
            ))
            .expect("failed to prepare the staging directory on R");
        ssh_helper
            .rsync(
                format!("{}/", merged_checkpoint.display()),
                ssh_helper.remote_path(staging.join("")),
            )
            .expect("failed to rsync the merged state to R");

        info!(self.logger, "Installing the merged state on R");
        let name = StateLayout::checkpoint_name(Height::from(self.merged_height));
        ssh_helper
            .ssh(format!(
                "set -e;
                 CHECKPOINTS={NODE_IC_STATE_DIR}/checkpoints;
                 OWNER_UID=$(sudo stat -c '%u' $CHECKPOINTS);
                 GROUP_UID=$(sudo stat -c '%g' $CHECKPOINTS);
                 sudo mv {staging} $CHECKPOINTS/{name};
                 sudo chown -R \"$OWNER_UID:$GROUP_UID\" $CHECKPOINTS/{name};
                 sudo chmod -R a-w $CHECKPOINTS/{name};
                 sudo systemctl restart setup-permissions;",
                staging = staging.display(),
            ))
            .expect("failed to install the merged state on R");
    }

    fn recovery(&self, dir: PathBuf) -> Recovery {
        Recovery::new(
            self.logger.clone(),
            RecoveryArgs {
                dir,
                nns_url: self.nns_url.clone(),
                replica_version: None,
                admin_key_file: Some(self.admin_key_file.clone()),
                test_mode: true,
                skip_prompts: true,
            },
            /* neuron_args= */ None,
            self.nns_url.clone(),
            RegistryPollingStrategy::OnlyOnInit,
        )
        .expect("failed to init recovery")
    }
}

/// Copies the checkpoint at `base` to `merged`, replacing its canisters and
/// canister snapshots with the union of those of `base` and of `source`, and
/// marks the result as the product of a subnet merge.
///
/// Only the canisters and their snapshots are taken over from `source`: its
/// ingress history is not, as the `subnet_merged` marker makes the replica
/// re-register the ingress messages of the merged-in canisters that are still in
/// progress. Everything else (system metadata, subnet queues, ...) is `base`'s.
fn assemble_merged_checkpoint(base: &Path, source: &Path, merged: &Path, logger: &Logger) {
    // Checkpoints are read-only and `rsync` preserved that, so the downloaded
    // trees have to be made writable before anything can be assembled in them.
    for path in [base, source] {
        run_local(&format!(
            "chmod -R u+w {}",
            path.parent().expect("a checkpoint has a parent").display()
        ));
    }
    // `cp -al` hard links the file contents rather than copying them, which
    // keeps this cheap. The links are only ever read afterwards, except for the
    // marker written below, which is a fresh file.
    run_local(&format!("cp -al {} {}", base.display(), merged.display()));
    run_local(&format!("chmod -R u+w {}", merged.display()));
    for dir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
        let source_dir = source.join(dir);
        if !source_dir.exists() {
            info!(logger, "{} holds no {dir}", source.display());
            continue;
        }
        run_local(&format!(
            "mkdir -p {merged_dir} && cp -al {source_dir}/. {merged_dir}/",
            merged_dir = merged.join(dir).display(),
            source_dir = source_dir.display(),
        ));
    }
    // A `SubnetMerged` message with `merged` (field 1) set to `true`.
    std::fs::write(merged.join(SUBNET_MERGED_FILE), [0x08, 0x01])
        .expect("failed to write the subnet merged marker");
    // The uploaded checkpoint must not look unverified to the state manager.
    let _ = std::fs::remove_file(merged.join(UNVERIFIED_CHECKPOINT_MARKER));
}

/// Runs `script` locally, panicking with its output if it fails.
fn run_local(script: &str) {
    let output = Command::new("bash")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {script:?}: {e}"));
    assert!(
        output.status.success(),
        "{script:?} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Submits (and adopts) the `MergeSubnets` proposal rerouting the canister ID
/// ranges of `source_subnet` to `destination_subnet`, and returns the registry
/// version it created.
async fn merge_subnets(
    env: &TestEnv,
    source_subnet: SubnetId,
    destination_subnet: SubnetId,
    logger: &Logger,
) -> u64 {
    let payload = MergeSubnetsPayload {
        source_subnet,
        destination_subnet,
    };
    submit_and_adopt_proposal(env, NnsFunction::MergeSubnets, payload, logger).await
}

/// Submits (and adopts) the `RecoverSubnet` proposal creating a recovery CUP for
/// `subnet_id` at the given height, time and state hash, and returns the registry
/// version it created.
async fn recover_subnet(
    env: &TestEnv,
    subnet_id: SubnetId,
    height: u64,
    time_ns: u64,
    state_hash: Vec<u8>,
    logger: &Logger,
) -> u64 {
    let payload = RecoverSubnetPayload {
        subnet_id: subnet_id.get(),
        // The NNS subnet, which is neither of the two subnets being merged and
        // stays available throughout, handles the DKG of the recovery CUP.
        initial_dkg_subnet_id: None,
        height,
        time_ns,
        state_hash,
        // The subnet keeps its membership, holds no chain key and is not becoming
        // the NNS subnet, so there is nothing else to recover.
        replacement_nodes: None,
        registry_store_uri: None,
        chain_key_config: None,
    };
    submit_and_adopt_proposal(env, NnsFunction::RecoverSubnet, payload, logger).await
}

/// Submits (and adopts) the `DeleteSubnet` proposal deleting `subnet_id`, and
/// returns a topology snapshot taken after its mutations were applied.
async fn delete_subnet(env: &TestEnv, subnet_id: SubnetId, logger: &Logger) -> TopologySnapshot {
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = get_governance_canister(&nns_runtime);

    let payload = DeleteSubnetPayload {
        subnet_id: subnet_id.get().into(),
    };
    let proposal_id =
        submit_external_proposal_with_test_id(&governance, NnsFunction::DeleteSubnet, payload)
            .await;
    info!(logger, "Submitted {proposal_id}");
    vote_execute_proposal_assert_executed(&governance, proposal_id).await;

    topology
        .block_for_newer_registry_version()
        .await
        .expect("the registry should have a newer version after the proposal executed")
}

/// Waits until every subnet other than `stopped` has reached `registry_version`.
///
/// `stopped` is the merged subnet, whose replica this test stopped for the merge
/// and which therefore does not report metrics anymore. It is also the subnet
/// about to be deleted, so what matters is that every *other* subnet already
/// routes its canisters to the destination subnet.
async fn await_registry_version_on_all_subnets(
    topology: &TopologySnapshot,
    stopped: SubnetId,
    registry_version: u64,
    logger: &Logger,
) {
    retry_with_msg_async!(
        format!("waiting until all subnets reached registry version {registry_version}"),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            for subnet in topology.subnets().filter(|s| s.subnet_id != stopped) {
                let metrics = fetch_metrics(&subnet, &[METRIC_REGISTRY_VERSION]).await?;
                let version = median_across_replicas(&metrics, METRIC_REGISTRY_VERSION, |_| true)
                    .unwrap_or(0.0);
                if version < registry_version as f64 {
                    bail!(
                        "subnet {} is at registry version {version}",
                        subnet.subnet_id
                    );
                }
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| panic!("not all subnets reached registry version {registry_version}: {e}"));
}

/// Waits until the ingress message `request_id` sent to `canister_id` is
/// replied, i.e. until the update call it carries completed successfully.
async fn await_ingress_message_replied(
    agent: &Agent,
    canister_id: Principal,
    request_id: &RequestId,
    name: &str,
    logger: &Logger,
) {
    retry_with_msg_async!(
        format!("waiting for {name}'s ingress message to complete"),
        logger,
        INGRESS_COMPLETION_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let (status, _) = agent
                .request_status_raw(request_id, canister_id)
                .await
                .map_err(|e| anyhow!("failed to read the status of {name}'s message: {e}"))?;
            match status {
                RequestStatusResponse::Replied(_) => Ok(()),
                RequestStatusResponse::Rejected(reject) => {
                    panic!("{name}'s ingress message was rejected: {reject:?}")
                }
                other => bail!("{name}'s ingress message is {other:?}"),
            }
        }
    )
    .await
    .unwrap_or_else(|e| panic!("{name}'s ingress message did not complete: {e}"));
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
/// iteration consist of one loopback call plus one cross-subnet call.
async fn start_call_loop(canister: &UniversalCanister<'_>, peer: Principal) {
    // The continuation, executed by the reply and reject callbacks of the call
    // to `peer`: call `canister` itself with the loop body it holds in its
    // global data as the payload. Neither callback of this call may reply, as
    // the call context it is made in was already responded by the loop body.
    let continuation = wasm()
        .call_simple(
            canister.canister_id(),
            "update",
            call_args()
                .eval_other_side(wasm().get_global_data())
                .on_reply(wasm().noop())
                .on_reject(wasm().noop()),
        )
        .build();
    // The loop body: bump the iteration counter, fire a call to `peer` (which
    // merely replies) with the continuation as both callbacks, then reply.
    let loop_body = wasm()
        .inc_global_counter()
        .call_simple(
            peer,
            "update",
            call_args()
                .other_side(wasm().reply_data(&[]))
                .on_reply(continuation.clone())
                .on_reject(continuation),
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

/// The payload of the endless loops of `U3`, `U5` and `U7`: bump the global
/// counter, so that the test can observe (via a query) that the payload started
/// executing, and then loop until the global data is set to
/// `LOOP_BREAK_TRIGGER`, which this test never does.
///
/// Every iteration of the loop is a management canister `canister_status` call
/// for the executing canister itself, so the loop stalls as soon as the subnet
/// holding that canister stops routing messages out of its canisters' output
/// queues, i.e. as soon as it is cooling down. The canister never responds to
/// the call it is executing, so that call context stays open forever.
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
/// queue, i.e. are either enqueued in `subnet`'s subnet input queues or already
/// executing (and hence hold a call context in the subnet call context
/// manager).
///
/// Only then may `subnet` start cooling down: a request still sitting in `U1`'s
/// output queue would never be routed, not even into the loopback stream, and
/// the code would never be installed.
///
/// Every subnet message this test made before `U1`'s calls (creating and
/// installing canisters, setting their controller) was waited for, so the subnet
/// queues hold nothing but those calls by the time they are inducted.
async fn await_install_code_requests_inducted(subnet: &SubnetSnapshot, logger: &Logger) {
    let expected = INSTALL_CODE_TARGETS.len() as f64;
    // The number of requests enqueued plus executing only reaches `expected`
    // between the moment the last one is inducted and the moment the first one
    // completes, so waiting for the current value to reach it would be waiting
    // for a condition that stops holding. Remember the highest value seen
    // instead, which only grows.
    let highest = std::cell::Cell::new(0.0_f64);
    retry_with_msg_async!(
        format!(
            "waiting until all {} `install_code` requests are inducted on subnet {}",
            INSTALL_CODE_TARGETS.len(),
            subnet.subnet_id
        ),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let metrics = fetch_metrics(
                subnet,
                &[
                    METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
                    METRIC_SUBNET_CALL_CONTEXTS,
                ],
            )
            .await?;
            let enqueued = sum_of_medians(&metrics, METRIC_SUBNET_INPUT_QUEUE_MESSAGES, |_| true);
            let executing = sum_of_medians(&metrics, METRIC_SUBNET_CALL_CONTEXTS, |labels| {
                labels.contains(LABEL_INSTALL_CODE)
            });
            highest.set(highest.get().max(enqueued + executing));
            if highest.get() < expected {
                bail!(
                    "{enqueued} request(s) enqueued and {executing} executing, at most {} of them \
                     at once so far",
                    highest.get(),
                );
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| panic!("U1's `install_code` requests were not inducted: {e}"));
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
async fn take_canister_snapshot(agent: &Agent, canister_id: Principal) -> SnapshotId {
    let (snapshot,) = ManagementCanister::create(agent)
        .take_canister_snapshot(&TakeCanisterSnapshotArgs {
            canister_id,
            replace_snapshot: None,
            sender_canister_version: None,
            uninstall_code: None,
        })
        .call_and_wait()
        .await
        .expect("taking a canister snapshot should succeed");
    snapshot.id
}

/// The IDs of the snapshots `canister_id` holds.
async fn canister_snapshot_ids(agent: &Agent, canister_id: Principal) -> Vec<SnapshotId> {
    let (snapshots,) = ManagementCanister::create(agent)
        .list_canister_snapshots(&canister_id)
        .call_and_wait()
        .await
        .expect("listing the canister snapshots should succeed");
    snapshots.into_iter().map(|snapshot| snapshot.id).collect()
}

/// `canister`'s cycles balance, read via a query (an ingress message would be
/// rejected by a subnet that is cooling down).
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

/// Returns `canister`'s global counter, read via a query (an ingress message
/// would be rejected by a subnet that is cooling down).
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

/// Submits and adopts an `UpdateConfigOfSubnet` proposal labeling `subnet_id` as
/// "cooling down" in its subnet record. Returns the registry version created by
/// the proposal, i.e. `V` in the dashboard's readiness condition.
async fn set_subnet_cooling_down(env: &TestEnv, subnet_id: SubnetId, logger: &Logger) -> u64 {
    let payload = UpdateSubnetPayload {
        cooling_down: Some(true),
        ..empty_update_subnet_payload(subnet_id)
    };
    submit_and_adopt_update_subnet_proposal(env, payload, logger).await
}

/// An `UpdateSubnetPayload` for `subnet_id` that changes nothing, to be used as
/// the base of a payload changing a single field.
fn empty_update_subnet_payload(subnet_id: SubnetId) -> UpdateSubnetPayload {
    UpdateSubnetPayload {
        subnet_id,
        cooling_down: None,
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_ingress_bytes_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        features: None,
        resource_limits: None,
        chain_key_config: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        subnet_admins: None,
        // Deprecated/unused values follow
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: false,
    }
}

/// Submits (and adopts) `payload` as an `UpdateConfigOfSubnet` proposal, and
/// returns the registry version its mutation created.
async fn submit_and_adopt_update_subnet_proposal(
    env: &TestEnv,
    payload: UpdateSubnetPayload,
    logger: &Logger,
) -> u64 {
    submit_and_adopt_proposal(env, NnsFunction::UpdateConfigOfSubnet, payload, logger).await
}

/// Submits (and adopts) `payload` as a proposal calling `nns_function`, and
/// returns the registry version its mutations created.
async fn submit_and_adopt_proposal<T: CandidType>(
    env: &TestEnv,
    nns_function: NnsFunction,
    payload: T,
    logger: &Logger,
) -> u64 {
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = get_governance_canister(&nns_runtime);

    let proposal_id =
        submit_external_proposal_with_test_id(&governance, nns_function, payload).await;
    info!(logger, "Submitted proposal {proposal_id}");
    vote_execute_proposal_assert_executed(&governance, proposal_id).await;

    // The proposal's registry mutations are applied in a single registry version,
    // which is the newest one. The snapshot above was taken before the proposal
    // was submitted, so this cannot miss the version the mutations created.
    topology
        .block_for_newer_registry_version()
        .await
        .expect("the registry should have a newer version after the proposal executed")
        .get_registry_version()
        .get()
}

/// Evaluates the terms of the "merge readiness" condition of the `Subnet
/// merging` dashboard for `subnet` (the subnet that is cooling down),
/// `registry_version` (`V`) and `max_refund_value_cycles` (the dashboard's
/// `R`, not to be confused with the subnet `R`). Returns one
/// (description, satisfied) pair per term, in the order the terms appear in the
/// dashboard's readiness expression.
///
/// As in the dashboard, every term is evaluated on the median across the
/// replicas reporting the respective series, and missing data reads as zero
/// (the dashboard's `or vector(0)` fallback).
async fn evaluate_merge_readiness(
    topology: &TopologySnapshot,
    subnet: &SubnetSnapshot,
    registry_version: u64,
    max_refund_value_cycles: f64,
) -> Result<Vec<(String, bool)>> {
    let subnet_id = subnet.subnet_id;
    let own_metrics = fetch_metrics(
        subnet,
        &[
            METRIC_REGISTRY_VERSION,
            METRIC_STREAM_MESSAGES,
            METRIC_INGRESS_HISTORY_BY_STATE,
            METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
            METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES,
            METRIC_SUBNET_CALL_CONTEXTS,
            METRIC_PENDING_REFUNDS_CYCLES,
        ],
    )
    .await?;

    // Terms 1 and 2 range over all subnets: the registry version of every
    // subnet and the streams of all remote subnets towards this one.
    let remote_label = format!("remote=\"{subnet_id}\"");
    let mut min_registry_version = None;
    let mut incoming_stream_messages = 0.0;
    for other in topology.subnets() {
        let metrics = if other.subnet_id == subnet_id {
            own_metrics.clone()
        } else {
            fetch_metrics(&other, &[METRIC_REGISTRY_VERSION, METRIC_STREAM_MESSAGES]).await?
        };
        let version =
            median_across_replicas(&metrics, METRIC_REGISTRY_VERSION, |_| true).unwrap_or(0.0);
        min_registry_version = Some(min_registry_version.map_or(version, |v: f64| v.min(version)));
        if other.subnet_id != subnet_id {
            incoming_stream_messages +=
                sum_of_medians(&metrics, METRIC_STREAM_MESSAGES, |labels| {
                    labels.contains(&remote_label)
                });
        }
    }
    let min_registry_version = min_registry_version.unwrap_or(0.0);

    let outgoing_stream_messages = sum_of_medians(&own_metrics, METRIC_STREAM_MESSAGES, |_| true);
    let ingress_history_messages =
        sum_of_medians(&own_metrics, METRIC_INGRESS_HISTORY_BY_STATE, |labels| {
            !labels.contains("state=\"processing\"")
        });
    let subnet_input_queue_messages =
        sum_of_medians(&own_metrics, METRIC_SUBNET_INPUT_QUEUE_MESSAGES, |_| true);
    let subnet_output_queue_messages =
        median_across_replicas(&own_metrics, METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES, |_| true)
            .unwrap_or(0.0);
    let subnet_call_contexts = sum_of_medians(&own_metrics, METRIC_SUBNET_CALL_CONTEXTS, |_| true);
    let pending_refunds_cycles =
        median_across_replicas(&own_metrics, METRIC_PENDING_REFUNDS_CYCLES, |_| true)
            .unwrap_or(0.0);

    Ok(vec![
        (
            format!(
                "every subnet has reached registry version {registry_version} (the lowest one is \
                 at {min_registry_version})"
            ),
            min_registry_version >= registry_version as f64,
        ),
        (
            format!(
                "no remote subnet holds a message in its stream to subnet {subnet_id} \
                 ({incoming_stream_messages} messages)"
            ),
            incoming_stream_messages == 0.0,
        ),
        (
            format!(
                "subnet {subnet_id} holds no message in any of its streams, loopback included \
                 ({outgoing_stream_messages} messages)"
            ),
            outgoing_stream_messages == 0.0,
        ),
        (
            format!(
                "the ingress history holds nothing but `processing` entries \
                 ({ingress_history_messages} other entries)"
            ),
            ingress_history_messages == 0.0,
        ),
        (
            format!("the subnet input queues are empty ({subnet_input_queue_messages} messages)"),
            subnet_input_queue_messages == 0.0,
        ),
        (
            format!("the subnet output queues are empty ({subnet_output_queue_messages} messages)"),
            subnet_output_queue_messages == 0.0,
        ),
        (
            format!(
                "the subnet call context manager holds no call context ({subnet_call_contexts} \
                 call contexts)"
            ),
            subnet_call_contexts == 0.0,
        ),
        (
            format!(
                "the pending anonymous refunds are worth at most {max_refund_value_cycles} cycles \
                 ({pending_refunds_cycles} cycles)"
            ),
            pending_refunds_cycles <= max_refund_value_cycles,
        ),
    ])
}

/// Fetches the given metrics from all nodes of `subnet`, keyed by series (i.e.
/// metric name plus labels), with one value per node reporting the series.
async fn fetch_metrics(
    subnet: &SubnetSnapshot,
    metrics: &[&str],
) -> Result<BTreeMap<String, Vec<f64>>> {
    MetricsFetcher::new(
        subnet.nodes(),
        metrics.iter().map(|metric| metric.to_string()).collect(),
    )
    .fetch::<f64>()
    .await
    .map_err(|e| {
        anyhow!(
            "failed to fetch the metrics of subnet {}: {e}",
            subnet.subnet_id
        )
    })
}

/// The per-node values of every series of `metric` whose labels (`{...}`, or the
/// empty string for an unlabeled series) match `labels_match`.
///
/// `MetricsFetcher` matches metric names by prefix, so this also filters out
/// the series of any other metric that `metric` happens to be a prefix of.
fn matching_series<'a>(
    metrics: &'a BTreeMap<String, Vec<f64>>,
    metric: &str,
    labels_match: impl Fn(&str) -> bool,
) -> Vec<&'a Vec<f64>> {
    metrics
        .iter()
        .filter(|(series, _)| match series.strip_prefix(metric) {
            Some(labels) if labels.is_empty() || labels.starts_with('{') => labels_match(labels),
            _ => false,
        })
        .map(|(_, values)| values)
        .collect()
}

/// Prometheus' `quantile(0.5, ...)`: the median of `values`, interpolating
/// between the two middle values if there is an even number of them. `None` iff
/// `values` is empty.
fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut values = values.to_vec();
    values.sort_by(|a, b| a.partial_cmp(b).expect("metric value should not be NaN"));
    let middle = (values.len() - 1) as f64 / 2.0;
    Some((values[middle.floor() as usize] + values[middle.ceil() as usize]) / 2.0)
}

/// `sum(quantile by (<labels>) (0.5, <metric>{<filter>}))`: the median across
/// the replicas reporting each matching series, summed over those series.
fn sum_of_medians(
    metrics: &BTreeMap<String, Vec<f64>>,
    metric: &str,
    labels_match: impl Fn(&str) -> bool,
) -> f64 {
    matching_series(metrics, metric, labels_match)
        .into_iter()
        .filter_map(|values| median(values))
        .sum()
}

/// `quantile(0.5, <metric>{<filter>})`: the median across all replicas
/// reporting any matching series. `None` if there is no such series.
fn median_across_replicas(
    metrics: &BTreeMap<String, Vec<f64>>,
    metric: &str,
    labels_match: impl Fn(&str) -> bool,
) -> Option<f64> {
    let values: Vec<f64> = matching_series(metrics, metric, labels_match)
        .into_iter()
        .flatten()
        .copied()
        .collect();
    median(&values)
}

// ---------------------------------------------------------------------------
// Merging subnet M into subnet R.
// ---------------------------------------------------------------------------

/// The name of the directory the replica keeps its states in, on a node.
const NODE_IC_STATE_DIR: &str = "/var/lib/ic/data/ic_state";

/// Waits until `node`'s subnet is halted, and returns the height of the
/// checkpoint it halted at, i.e. of the state it stopped in.
///
/// Whether the subnet halted is read off the node's journal, which is where a
/// halted replica says that it stops delivering batches. Waiting for the
/// *checkpoint* height to stop advancing instead would not do: while the subnet
/// is running, its state runs ahead of its latest checkpoint by up to a whole DKG
/// interval, which is minutes of wall clock time, so the checkpoint height looks
/// stable long before the subnet halts. The state of that checkpoint is then
/// hundreds of rounds behind the state the merge readiness of step 9 was
/// established on, and may hold, say, an `install_code` that was aborted at the
/// checkpoint and only completed afterwards.
///
/// The batch heights of a subnet halting because of `halt_at_cup_height` stop at
/// a CUP height: the flag is read at the registry version of the summary block
/// active at a height, and that version only changes at a summary, so batch
/// delivery stops exactly when the summary carrying it becomes active. As
/// checkpoints are written at CUP heights, the latest checkpoint of a halted
/// subnet holds precisely the state it stopped in.
async fn await_halted_at_checkpoint(node: &IcNodeSnapshot, name: &str, logger: &Logger) -> u64 {
    info!(logger, "Waiting until subnet {name} is halted");
    // Polling the journal rather than following it: `follow()` blocks in
    // `journalctl --follow | grep -m 1` until the line shows up, with no timeout
    // of its own, so a line that never comes (because it was reworded, say)
    // would hang the test until the whole test times out. The cursor of
    // `from_now()` makes every poll search all entries since this point, so the
    // condition, once true, stays true.
    let journal = JournalStreamer::new(
        node.block_on_ssh_session_async()
            .await
            .unwrap_or_else(|e| panic!("failed to open an SSH session to subnet {name}: {e}")),
    )
    .from_now()
    .unwrap_or_else(|e| panic!("failed to create a journal streamer for subnet {name}: {e}"));
    retry_with_msg_async!(
        format!("waiting until subnet {name} reports that it is halted"),
        logger,
        HALT_TIMEOUT,
        HALT_BACKOFF,
        || async {
            // `contains` runs `journalctl | grep`, and `grep` exits non-zero when
            // it matches nothing, which the SSH helper in turn reports as an
            // error: an error here is indistinguishable from the line not being
            // there yet, so both mean "keep waiting". A journal that cannot be
            // searched at all therefore surfaces as the timeout below.
            match journal.contains(HALTED_LOG_PATTERN) {
                Ok(true) => Ok(()),
                Ok(false) => bail!("subnet {name} has not reported that it is halted yet"),
                Err(e) => bail!(
                    "subnet {name} has not reported that it is halted yet (or its journal could \
                     not be searched: {e})"
                ),
            }
        }
    )
    .await
    .unwrap_or_else(|e| panic!("subnet {name} did not report that it is halted: {e}"));

    let height = latest_checkpoint_height(node)
        .await
        .unwrap_or_else(|e| panic!("failed to read the checkpoint of subnet {name}: {e}"));
    assert_eq!(
        height % CHECKPOINT_INTERVAL,
        0,
        "subnet {name} halted at checkpoint {height}, which is not a CUP height",
    );
    height
}

/// The height of the highest checkpoint `node` holds. Checkpoint directories are
/// named after their height, in hexadecimal.
async fn latest_checkpoint_height(node: &IcNodeSnapshot) -> Result<u64> {
    let output = node
        .block_on_bash_script_async(&format!("sudo ls -1 {NODE_IC_STATE_DIR}/checkpoints"))
        .await
        .map_err(|e| anyhow!("failed to list the checkpoints: {e}"))?;
    output
        .split_whitespace()
        .map(|name| {
            u64::from_str_radix(name, 16)
                .map_err(|e| anyhow!("checkpoint name {name} is not a hex height: {e}"))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .ok_or_else(|| anyhow!("no checkpoint yet"))
}

/// Submits (and adopts) an `UpdateConfigOfSubnet` proposal setting the
/// `halt_at_cup_height` flag of `subnet_id`, so that the subnet halts once it
/// reaches its next CUP, i.e. at a checkpoint whose state is certified.
/// Returns the registry version the proposal created, which is the version at
/// which the subnet is instructed to halt.
async fn halt_subnet_at_cup_height(env: &TestEnv, subnet_id: SubnetId, logger: &Logger) -> u64 {
    let payload = UpdateSubnetPayload {
        halt_at_cup_height: Some(true),
        ..empty_update_subnet_payload(subnet_id)
    };
    submit_and_adopt_update_subnet_proposal(env, payload, logger).await
}

/// Submits (and adopts) an `UpdateConfigOfSubnet` proposal clearing the
/// `is_halted` flag of `subnet_id`, so that the subnet resumes delivering
/// batches. Returns the registry version the proposal created.
///
/// This is the flag `recover_subnet` sets in place of the `halt_at_cup_height`
/// flag it clears, so that a recovered subnet stays halted until its recovery
/// has been checked.
async fn unhalt_subnet(env: &TestEnv, subnet_id: SubnetId, logger: &Logger) -> u64 {
    let payload = UpdateSubnetPayload {
        is_halted: Some(false),
        ..empty_update_subnet_payload(subnet_id)
    };
    submit_and_adopt_update_subnet_proposal(env, payload, logger).await
}

/// Runs `state-tool` with the given arguments and returns its standard output.
fn state_tool(args: &[&str]) -> String {
    let binary = get_dependency_path_from_env("ENV_DEPS__STATE_TOOL");
    let output = Command::new(&binary)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", binary.display()));
    assert!(
        output.status.success(),
        "{} {args:?} failed: {}",
        binary.display(),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("state-tool output should be UTF-8")
}

/// The batch time of the checkpoint at `path`, in nanoseconds since the Epoch.
fn checkpoint_time_nanos(path: &Path) -> u64 {
    let output = state_tool(&["checkpoint_time", "--state", &path.display().to_string()]);
    output
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("failed to parse the checkpoint time {output:?}: {e}"))
}

/// The root hash of the manifest of the checkpoint at `path`.
fn manifest_root_hash(path: &Path) -> Vec<u8> {
    let output = state_tool(&["manifest", "--state", &path.display().to_string()]);
    let hash = output
        .lines()
        .find_map(|line| line.strip_prefix("ROOT HASH: "))
        .unwrap_or_else(|| panic!("no root hash in the manifest of {}", path.display()))
        .trim();
    hex::decode(hash).unwrap_or_else(|e| panic!("root hash {hash} is not hex: {e}"))
}
