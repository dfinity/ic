/* tag::catalog[]
Title:: Draining and merging a subnet that is "cooling down".

Goal:: Verify that a subnet labeled "cooling down" in its subnet record quiesces
while its canisters are busy making cross-subnet calls in a loop, installing
code on one another and waiting for responses that never arrive, i.e. that it
reaches the "merge readiness" condition of the `Subnet merging` dashboard (see
`bases/apps/ic-dashboards/core/subnet-merging.json` on branch
`mraszyk/subnet-merging-dashboard` of `dfinity/k8s`), and that the subnet
merging tool (`rs/recovery/subnet_merging`) then merges it into another subnet
without losing any of that state.

The subnet that is cooling down, i.e. the one that is merged away, is called `M`
and the Application subnet it is merged into is called `R`. A third Application
subnet `T` holds the canisters at the other end of `M`'s cross-subnet calls. The
NNS subnet is none of these: it has to stay available throughout, as it is where
the proposals of this test are executed, including the one recovering `R` at the
merged state.

Every proposal of the merge itself is submitted by the tool, through `ic-admin`
with the test neuron; this test submits none.

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
7. Hand over to the subnet merging tool, which runs one step at a time; the
   checks of the steps below are made in between its steps, at the points the
   step names give. The tool labels `M` as "cooling down" and reads back the
   registry version `V` this created (`CoolDownSourceSubnet`,
   `CheckRegistryForCoolingDownFlag`).
8. After `CheckRegistryForCoolingDownFlag`: wait until `M` rejects ingress
   messages, i.e. the replicas of `M` observed the "cooling down" label, and
   check that `M` is not "merge ready" yet, so that the tool's wait below is
   known to be waiting for something. Both use what the tool recorded: the
   readiness condition, evaluated by the tool's own code, and `V`, read from the
   tool's working directory.
9. The tool waits until `M` is "merge ready" according to the dashboard's
   condition for `V`: all subnets have reached registry version `V`, no stream
   in either direction holds a message (loopback included), the ingress history
   holds nothing but `processing` entries, `M`'s subnet input and output queues
   are empty, `M`'s subnet call context manager holds no call context, and its
   refund pool holds no pending anonymous refund (`CheckMergeReadiness`).
10. After `CheckMergeReadiness`: check that `M` answers no query call, which is
   the other half of what a cooling down subnet stops doing: it neither accepts
   ingress messages nor serves queries, and it executes no canister message.
   Whether the `install_code` calls of step 5 installed the code is therefore
   only observable after the merge, in step 17.
11. Also after `CheckMergeReadiness`: check that the two loops of step 2 are
   indeed stalled: while `M` is cooling down, it executes no canister message,
   and neither `M` nor `T` routes any message to or from `M`, so the messages of
   both loops are retained in their senders' output queues. `UT`'s iteration
   counter is read via a query to `T`; `US` sits on `M`, which answers no query,
   so `M`'s count of the rounds it skipped canister execution in stands in for
   it.
12. The tool sets the `halt_at_cup_height` flag of both `M` and `R` and waits
   until the node of each that the state is taken from holds the CUP its subnet
   halts at -- served at its public endpoint, written to its disk, and with the
   state it names certified (`Halt*SubnetAtCupHeight`,
   `WaitForHaltingCupOn*Subnet`).
13. The tool stops the replicas of both subnets, downloads the states they
   halted at, validates each against the CUP it was taken at and the subnet's
   public key in the NNS signed state tree, and assembles the merged state
   locally: the canisters and canister snapshots of `M` are added to those of
   `R`, and the result is marked as the product of a subnet merge. The ingress
   history of `M` is deliberately not merged in: the marker makes the replica
   re-register the ingress messages of the merged-in canisters that are still in
   progress. The tool also computes the block time the merged state starts from,
   which must be larger than the times of both checkpoints, and the hash of its
   manifest (`Stop*Replica`, `DownloadStateFrom*Subnet`, `Validate*SubnetCup`,
   `MergeStates`).
14. The tool submits a `MergeSubnets` proposal for `M` and `R`, which reroutes
   the canister ID ranges of `M` to `R`, and then a `RecoverSubnet` proposal for
   `R`, which creates a recovery CUP for `R` at the merged state, running a
   fresh DKG for `R`'s membership. Recovering a subnet that was instructed to
   halt at its next CUP replaces that instruction with a plain halt, so `R`
   stays halted for now (`MergeSubnets`,
   `CheckRegistryForRoutingTableEntry`, `ProposeCupForDestinationSubnet`).
15. The tool uploads the merged state to `R`'s node, replacing the state
   directory holding the checkpoint it halted at, and starts its replica back
   up. Deleting that checkpoint is what makes the recovery unambiguous: it does
   not hold the canisters of `M`, so a replica coming up on it would serve a
   state that silently lost them, and the merged state is now the only one `R`
   can resume from (`UploadStateToDestinationSubnet`).
16. The tool waits until `R` reports the recovery CUP, i.e. it did come up on
   the merged state, and then unhalts it
   (`WaitForCUPOnDestinationSubnet`, `UnhaltDestinationSubnet`).
17. After `UnhaltDestinationSubnet`: wait until `R` is healthy, then check that
   `U8`, now served by `R`, kept the stable memory, the snapshot and (up to what
   an idle canister burns) the cycles balance of step 4, and that `UR`, which
   `R` hosted all along, is undisturbed and can call `U8` now that both are on
   the same subnet. Check that `U2a` .. `U2e`, also served by `R` now, have been
   installed, i.e. that the `install_code` calls of step 5 ran to completion
   while `M` was cooling down rather than being lost or rejected.
18. Also after `UnhaltDestinationSubnet`: set the global data of `U3`, `U5` and
   `U7` to `LOOP_BREAK_TRIGGER`, ending the three endless loops, and check that
   every ingress message that was in progress across the merge completed. `U3`
   and `U5` are reached through `R`, which serves the canisters of `M` after the
   merge.
19. The tool waits until every subnet other than `M` has reached the registry
   version the merge created, i.e. routes the canisters that used to be hosted
   by `M` to `R`. `M` itself is excluded: its replica was stopped for the merge
   and it is about to be deleted (`CheckRegistryVersionOnAllSubnets`).
20. The tool deletes `M`, which hosts no canister ID range anymore
   (`DeleteSourceSubnet`); after that step, check that it is gone from the
   registry.

Success::
`M` becomes "merge ready", with `U2a` .. `U2e` installed, while both loops of
step 2 are stalled; the merge moves its canisters to `R`, where every ingress
message that was in progress across the merge completes; and `M` can then be
deleted.

end::catalog[] */

use anyhow::{Result, anyhow, bail};
use candid::Principal;
use ic_agent::{Agent, RequestId, agent::RequestStatusResponse};
use ic_management_canister_types::{SnapshotId, TakeCanisterSnapshotArgs};
use ic_recovery::{RecoveryArgs, file_sync_helper};
use ic_registry_subnet_type::SubnetType;
use ic_subnet_merging::{
    readiness::{SubnetNodeIps, evaluate_merge_readiness},
    subnet_merging::{StepType, SubnetMerging, SubnetMergingArgs},
    utils::read_cooling_down_registry_version,
};
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::{
    SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
    NnsInstallationBuilder, READY_WAIT_TIMEOUT, RETRY_BACKOFF, SubnetSnapshot, TopologySnapshot,
    get_guestos_img_version,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    MetricsFetcher, UniversalCanister, assert_create_agent, create_canister, set_controller,
};
use ic_types::{Height, SubnetId};
use ic_universal_canister::management::InstallMode;
use ic_universal_canister::{
    CallInterface, call_args, get_universal_canister_wasm, management, wasm,
};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;
use slog::{Logger, info};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Metrics this test reads itself; the ones making up the "merge readiness"
/// condition are read by the merging tool.
const METRIC_SUBNET_INPUT_QUEUE_MESSAGES: &str = "execution_subnet_input_queue_messages";
const METRIC_SUBNET_CALL_CONTEXTS: &str = "replicated_state_subnet_call_contexts";
const METRIC_ROUNDS_SKIPPED_CANISTER_EXECUTION: &str =
    "round_skipped_canister_execution_due_to_cooling_down";

/// The label selecting the `install_code` call contexts of
/// `METRIC_SUBNET_CALL_CONTEXTS`.
const LABEL_INSTALL_CODE: &str = "type=\"install_code\"";

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

/// The directory the merging tool works in, relative to the test environment.
const MERGING_DIR: &str = "subnet_merging";

/// How much later than the checkpoints it is assembled from the merged state
/// starts, i.e. the block time of the recovery CUP of `R` minus the larger of
/// the two checkpoint times.
const MERGED_STATE_TIME_MARGIN: Duration = Duration::from_secs(60);

/// Timeout for the subnet to become "merge ready". The binding terms are the
/// `install_code` calls of step 5, which take a couple of hundred rounds each
/// (and are executed one at a time, as at most one long-running `install_code`
/// makes progress per round), and the ingress history, which only becomes free
/// of terminal statuses once the entries of the ingress messages submitted
/// before the subnet started cooling down are pruned, i.e. at their (up to
/// `MAX_INGRESS_TTL` = 5 minutes away) expiry times.
const MERGE_READY_TIMEOUT: Duration = Duration::from_secs(2400);
/// Timeout for a subnet to reach the CUP it halts at, which is up to a full DKG
/// interval away.
const HALT_TIMEOUT: Duration = Duration::from_secs(900);
/// Timeout for the registry to reflect a proposal that `ic-admin` reported as
/// executed.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(300);
/// How long the merging tool waits between two evaluations of a condition it
/// waits for. Longer than a driver retry because every evaluation scrapes the
/// metrics of all subnets.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Timeout for an ingress message that was in progress across the merge to
/// complete once the loop it is waiting for is broken. Generous because the
/// destination subnet has just resumed from the merged state and is busy
/// recomputing its manifest and draining the message loops of step 2 at the same
/// time: this has been observed to take up to four minutes.
const INGRESS_COMPLETION_TIMEOUT: Duration = Duration::from_secs(900);

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

/// Everything the phases that run in between the steps of the merging tool need
/// from the phase that set the scenario up.
///
/// Canister ids and agents rather than `UniversalCanister`s, which borrow the
/// agent they were created with: the canisters of the subnet that is merged
/// away are reached through a different agent after the merge than before it.
struct Context {
    logger: Logger,
    m_subnet: SubnetSnapshot,
    r_subnet: SubnetSnapshot,
    m_node: IcNodeSnapshot,
    r_node: IcNodeSnapshot,
    m_agent: Agent,
    t_agent: Agent,
    r_agent: Agent,
    /// The two canisters calling each other in a loop across subnets, `US` on
    /// `M` and `UT` on `T`.
    us: Principal,
    ut: Principal,
    /// The canisters holding the endless loops of step 6, `U3` and `U5` on `M`
    /// and `U7` on `T`.
    u3: Principal,
    u5: Principal,
    u7: Principal,
    /// The canister on `M` whose state has to survive the merge, and that state.
    u8: Principal,
    u8_snapshot: SnapshotId,
    u8_cycles_before: u128,
    /// The canister `R` hosted all along, which the merge must leave alone.
    ur: Principal,
    /// The canisters `U1` installs code on while `M` is cooling down.
    targets: Vec<Principal>,
    /// The ingress messages that are in progress when the merge happens, with
    /// the agent each of them has to be read through afterwards.
    pending_ingress_messages: Vec<(String, Agent, Principal, RequestId)>,
}

impl Context {
    /// The nodes of every subnet, which is what the merge readiness condition
    /// is evaluated on.
    fn subnet_node_ips(topology: &TopologySnapshot) -> SubnetNodeIps {
        topology
            .subnets()
            .map(|subnet| {
                (
                    subnet.subnet_id,
                    subnet.nodes().map(|node| node.get_ip_addr()).collect(),
                )
            })
            .collect::<BTreeMap<SubnetId, _>>()
    }
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

/// Steps 0 to 6: set up the scenario the merge has to survive.
async fn prepare(env: &TestEnv) -> Context {
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
        "Subnets under test, with the nodes the merge works with:\n  \
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
    // cycles are held by the callee's call context across the merge.
    info!(
        logger,
        "Step 6: Starting the three endless loops and U9's best effort call to U10"
    );
    // `U10` never responds, so the call is still in flight when `M` starts
    // cooling down, and its deadline passes while it is.
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
    // that step 18 can check that all of them eventually completed. `U3` and
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

    Context {
        logger,
        m_subnet,
        r_subnet,
        m_node,
        r_node,
        us: us.canister_id(),
        ut: ut.canister_id(),
        u3: u3.canister_id(),
        u5: u5.canister_id(),
        u7: u7.canister_id(),
        u8: u8.canister_id(),
        u8_snapshot,
        u8_cycles_before,
        ur: ur.canister_id(),
        targets,
        pending_ingress_messages,
        m_agent,
        t_agent,
        r_agent,
    }
}

/// Steps 7 to 20: hand the scenario over to the subnet merging tool, and make
/// the checks of the steps in between its steps.
///
/// Plain synchronous code, like `rs/tests/consensus/subnet_splitting_test.rs`:
/// the tool's steps block on runtimes of their own, and the asynchronous checks
/// of this test are driven through `runtime`, which this thread is not inside.
fn merge(env: &TestEnv, context: &Context, runtime: &Runtime) {
    let logger = &context.logger;
    let topology = env.topology_snapshot();

    let ssh_priv_key_path = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(SSH_USERNAME);
    let readonly_pub_key =
        file_sync_helper::read_file(&env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR).join(SSH_USERNAME))
            .expect("Couldn't read public key");
    let merging_dir = env.get_path(MERGING_DIR);

    let recovery_args = RecoveryArgs {
        dir: merging_dir.clone(),
        nns_url: topology
            .root_subnet()
            .nodes()
            .next()
            .unwrap()
            .get_public_url(),
        replica_version: Some(get_guestos_img_version()),
        admin_key_file: Some(ssh_priv_key_path.clone()),
        test_mode: true,
        skip_prompts: true,
    };
    let merging_args = SubnetMergingArgs {
        source_subnet_id: context.m_subnet.subnet_id,
        destination_subnet_id: context.r_subnet.subnet_id,
        readonly_pub_key: Some(readonly_pub_key),
        readonly_key_file: Some(ssh_priv_key_path),
        keep_downloaded_state: Some(false),
        download_node_source: Some(context.m_node.get_ip_addr()),
        download_node_destination: Some(context.r_node.get_ip_addr()),
        upload_node_destination: Some(context.r_node.get_ip_addr()),
        time_margin_secs: MERGED_STATE_TIME_MARGIN.as_secs(),
        merge_ready_timeout_secs: MERGE_READY_TIMEOUT.as_secs(),
        halt_timeout_secs: HALT_TIMEOUT.as_secs(),
        registry_timeout_secs: REGISTRY_TIMEOUT.as_secs(),
        poll_interval_secs: POLL_INTERVAL.as_secs(),
        next_step: None,
    };

    info!(
        logger,
        "Step 7: Merging subnet M ({}) into subnet R ({})",
        context.m_subnet.subnet_id,
        context.r_subnet.subnet_id,
    );
    let merging = SubnetMerging::new(
        logger.clone(),
        recovery_args,
        /*neuron_args=*/ None,
        merging_args,
    );

    for (step_type, step) in merging {
        info!(logger, "Next step: {step_type:?}");
        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {step_type:?} failed: {e}"));

        match step_type {
            StepType::CheckRegistryForCoolingDownFlag => {
                runtime.block_on(check_ingress_rejected(context));
                check_not_merge_ready_yet(&topology, context, &merging_dir);
            }
            StepType::CheckMergeReadiness => {
                runtime.block_on(check_no_queries_and_stalled_loops(context))
            }
            StepType::UnhaltDestinationSubnet => runtime.block_on(verify_after_merge(context)),
            StepType::DeleteSourceSubnet => {
                runtime.block_on(check_source_subnet_deleted(&topology, context))
            }
            _ => {}
        }
    }

    info!(logger, "Subnet M has been merged into subnet R and deleted");
}

/// Step 8: wait until the replicas of `M` observed the "cooling down" label,
/// i.e. until `M` rejects ingress messages.
async fn check_ingress_rejected(context: &Context) {
    let logger = &context.logger;
    info!(
        logger,
        "Step 8: Waiting until subnet M rejects ingress messages"
    );
    let us = UniversalCanister::from_canister_id(&context.m_agent, context.us);
    retry_with_msg_async!(
        "waiting until subnet M rejects ingress messages",
        logger,
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
}

/// Step 9: check that `M` is *not* "merge ready" yet, so that the tool's wait
/// for the condition is known to be waiting for something: a readiness
/// condition that held from the start would be satisfied by a subnet that never
/// had anything to drain.
///
/// The very condition the tool waits for, evaluated by the tool's own code, at
/// the very registry version `V` the tool recorded when it labeled `M` as
/// cooling down.
fn check_not_merge_ready_yet(topology: &TopologySnapshot, context: &Context, merging_dir: &Path) {
    let logger = &context.logger;
    let registry_version = read_cooling_down_registry_version(merging_dir)
        .expect("the merging tool should have recorded the cooling down registry version");

    let terms = evaluate_merge_readiness(
        &Context::subnet_node_ips(topology),
        context.m_subnet.subnet_id,
        registry_version,
        logger,
    );
    let unsatisfied: Vec<&str> = terms
        .iter()
        .filter(|term| !term.satisfied)
        .map(|term| term.description.as_str())
        .collect();
    assert!(
        !unsatisfied.is_empty(),
        "subnet M was already \"merge ready\" right after it started cooling down, so the tool's \
         wait would prove nothing",
    );
    info!(
        logger,
        "Step 9: subnet M is not \"merge ready\" yet for V={registry_version}: {}",
        unsatisfied.join("; "),
    );
}

/// Steps 10 and 11: check that `M` answers no query call and that both call
/// loops of step 2 are stalled.
async fn check_no_queries_and_stalled_loops(context: &Context) {
    let logger = &context.logger;

    // Step 10: Step 8 saw `M` stop accepting ingress messages; refusing queries
    // is the other half of what a cooling down subnet stops doing, and the
    // reason the state of `M`'s canisters can only be inspected once `R` serves
    // them (step 17).
    info!(
        logger,
        "Step 10: Checking that subnet M rejects query calls"
    );
    let us = UniversalCanister::from_canister_id(&context.m_agent, context.us);
    let err = us
        .query(wasm().reply_data(&[]))
        .await
        .expect_err("query call to US was answered while subnet M was cooling down");
    let err = err.to_string();
    assert!(
        err.contains("cooling down"),
        "query call to US failed unexpectedly: {err}",
    );
    info!(logger, "Step 10 done: subnet M rejects query calls");

    // Step 11: `M` became "merge ready" because it is cooling down and not
    // because the loops stopped making calls.
    //
    // `UT` is on `T`, so its iteration counter can be read directly. `US` is on
    // `M`, which answers no query, so the number of rounds `M` skipped canister
    // execution in stands in for it: while that keeps growing, `M` executes no
    // canister message at all, the next iteration of `US`'s loop included.
    info!(
        logger,
        "Step 11: Checking that both call loops are stalled over {STALL_OBSERVATION_PERIOD:?}"
    );
    let ut = UniversalCanister::from_canister_id(&context.t_agent, context.ut);
    let ut_before = global_counter(&ut).await.unwrap();
    let skipped_before = rounds_with_skipped_canister_execution(&context.m_subnet).await;
    tokio::time::sleep(STALL_OBSERVATION_PERIOD).await;
    let ut_after = global_counter(&ut).await.unwrap();
    let skipped_after = rounds_with_skipped_canister_execution(&context.m_subnet).await;
    assert_eq!(
        ut_before, ut_after,
        "UT's call loop advanced from iteration {ut_before} to {ut_after} while subnet M was \
         cooling down",
    );
    assert!(
        skipped_after > skipped_before,
        "subnet M skipped canister execution in no round over {STALL_OBSERVATION_PERIOD:?} \
         ({skipped_before} rounds before, {skipped_after} after), so it was not cooling down and \
         US's loop was stalled for some other reason",
    );
    info!(
        logger,
        "Step 11 done: UT's call loop is stalled at iteration {ut_after} and subnet M skipped \
         canister execution in {} rounds while waiting",
        skipped_after - skipped_before,
    );
}

/// Steps 17 and 18: check that the merge carried the state of `M`'s canisters
/// over, left `R`'s own canister alone, and let every ingress message that was
/// in progress across it complete.
async fn verify_after_merge(context: &Context) {
    let logger = &context.logger;

    // The tool has unhalted `R`; a halted subnet delivers no batches, so none of
    // the calls below would be answered before it is healthy again.
    context
        .r_node
        .await_status_is_healthy_async()
        .await
        .expect("subnet R did not become healthy after the merge");
    info!(logger, "Step 16 done: subnet R is healthy");

    // Step 17: `U8` was hosted by `M` and is served by `R` now.
    info!(
        logger,
        "Step 17: Checking the state of U8 and UR after the merge"
    );
    let u8 = UniversalCanister::from_canister_id(&context.r_agent, context.u8);
    assert_eq!(
        u8.try_read_stable(
            STABLE_MEMORY_OFFSET,
            STABLE_MEMORY_BLOB.len().try_into().unwrap()
        )
        .await,
        STABLE_MEMORY_BLOB,
        "the stable memory of U8 did not survive the merge",
    );
    assert!(
        canister_snapshot_ids(&context.r_agent, context.u8)
            .await
            .contains(&context.u8_snapshot),
        "the snapshot of U8 did not survive the merge",
    );
    let u8_cycles_after = cycles_balance(&u8)
        .await
        .expect("failed to read the cycles balance of U8 after the merge");
    let u8_cycles_before = context.u8_cycles_before;
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
    let ur = UniversalCanister::from_canister_id(&context.r_agent, context.ur);
    let ur_reply = ur
        .update(wasm().call_simple(
            context.u8,
            "update",
            call_args().other_side(wasm().push_bytes(MERGED_CALL_REPLY).append_and_reply()),
        ))
        .await
        .expect("UR should be able to call a canister that was hosted by M");
    assert_eq!(
        ur_reply, MERGED_CALL_REPLY,
        "UR got an unexpected reply from U8",
    );
    // `U1`'s `install_code` calls ran while `M` was cooling down, and whether they
    // installed the universal canister module shows in a query: a canister that
    // has no module rejects every query. `R` has to be the one asked, as `M`
    // answered no query from the moment it started cooling down until it was
    // halted for the merge.
    info!(
        logger,
        "Step 17: Checking that {} have been installed",
        INSTALL_CODE_TARGETS.join(", "),
    );
    for (&target, name) in context.targets.iter().zip(INSTALL_CODE_TARGETS) {
        let canister = UniversalCanister::from_canister_id(&context.r_agent, target);
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
        "Step 17 done: U8 kept its stable memory, snapshot and cycles, UR can call it, and {} \
         have been installed",
        INSTALL_CODE_TARGETS.join(", "),
    );

    // Step 18: Let the endless loops finish and check that every ingress message
    // that was still in progress when the merge happened completed.
    //
    // The canisters of `M` now live on `R`, which serves them under the same
    // canister IDs, so the agent for `R` is what reaches them. `U7` did not
    // move: it is on `T`.
    info!(
        logger,
        "Step 18: Breaking the endless loops and waiting for the pending ingress messages"
    );
    for (agent, canister_id, name) in [
        (&context.r_agent, context.u3, "U3"),
        (&context.r_agent, context.u5, "U5"),
        (&context.t_agent, context.u7, "U7"),
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
        info!(logger, "Step 18: broke {name}'s endless loop");
    }

    for (name, agent, canister_id, request_id) in &context.pending_ingress_messages {
        await_ingress_message_replied(agent, *canister_id, request_id, name, logger).await;
        info!(logger, "Step 18: {name}'s ingress message completed");
    }
    info!(
        logger,
        "Step 18 done: all the ingress messages that were pending across the merge completed"
    );
}

/// Step 20: check that the subnet the tool deleted is gone from the registry.
async fn check_source_subnet_deleted(topology: &TopologySnapshot, context: &Context) {
    let logger = &context.logger;
    let m_subnet_id = context.m_subnet.subnet_id;

    let topology = topology
        .block_for_newer_registry_version()
        .await
        .expect("the registry should have a newer version after the subnet was deleted");
    let remaining: Vec<_> = topology.subnets().map(|subnet| subnet.subnet_id).collect();
    assert!(
        !remaining.contains(&m_subnet_id),
        "subnet M ({m_subnet_id}) is still in the registry at version {}: {remaining:?}",
        topology.get_registry_version(),
    );
    info!(
        logger,
        "Step 20 done: subnet M is gone as of registry version {}; the remaining subnets are \
         {remaining:?}",
        topology.get_registry_version(),
    );
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

/// The number of rounds `subnet` executed no canister message in because it is
/// cooling down, as the median across its replicas.
///
/// A subnet that is not cooling down never touches the counter, and a replica
/// that never touched it does not report it at all, which is a zero here.
async fn rounds_with_skipped_canister_execution(subnet: &SubnetSnapshot) -> f64 {
    let metrics = fetch_metrics(subnet, &[METRIC_ROUNDS_SKIPPED_CANISTER_EXECUTION])
        .await
        .unwrap_or_else(|e| {
            panic!(
                "failed to fetch the skipped canister execution metric of subnet {}: {e}",
                subnet.subnet_id
            )
        });
    median_across_replicas(&metrics, METRIC_ROUNDS_SKIPPED_CANISTER_EXECUTION, |_| true)
        .unwrap_or(0.0)
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
