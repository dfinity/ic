/* tag::catalog[]
Title:: Setting a subnet up to be "cooled down".

Goal:: Verify that a subnet holding what a subnet merge has to drain violates
the individual terms of the "merge readiness" condition, i.e. that the
condition a subnet merging tool waits for before merging such a subnet away is
one that the subnet does not satisfy to begin with. The subnet also holds calls
waiting for responses that never arrive: they are not drained, but make it
possible to assert that a subnet merge populates the ingress history properly.

The subnet that is set up to be cooled down, i.e. the one that would be merged
away, is called `M`; a second Application subnet `T` holds the canisters at the
other end of `M`'s cross-subnet calls.

"Executing" an update call below always means submitting it as an ingress
message without waiting for it to complete: most of the calls of this test are
never meant to complete.

Runbook::
0. Set up an IC with an NNS subnet (with the NNS canisters installed) and two
   Application subnets `M` and `T`, of `SUBNET_SIZE` nodes each.
1. Install a universal canister on each of `M` and `T`: `UM` on `M`, `UT` on
   `T`.
2. Make an ingress call to each of `UM` and `UT` with a payload that calls the
   universal canister on the other subnet in a loop.
3. Wait until both loops have completed a few iterations, i.e. messages are
   actually flowing between `M` and `T` in both directions.
4. Install the universal canisters of the steps below (`U1`, `U3`, `U5` and `U6`
   on `M`, `U4` and `U7` on `T`) and create five empty canisters `U2a` .. `U2e`
   on `M`, controlled by `U1`.
5. Execute an update call on `U1` that makes five calls to the management
   canister's `install_code` method, one per `U2x`, in mode `install`, with the
   universal canister module and an `arg` that makes `canister_init` burn
   `INIT_INSTRUCTIONS` instructions. Wait until all five requests have left
   `U1`'s output queue, i.e. until they are enqueued in `M`'s subnet input
   queues or already executing.
6. Start three endless loops, each of which calls the management canister's
   `canister_status` method for the looping canister over and over until the
   global data of that canister is set to `LOOP_BREAK_TRIGGER`, which this test
   never does:
   a. execute an update call on `U3` (on `M`) with the loop as its payload;
   b. execute an update call on `U4` (on `T`) that calls `U5` (on `M`) with the
      loop as its payload, so that `M` holds a canister looping in a call from
      another subnet that it can never respond to;
   c. execute an update call on `U6` (on `M`) that calls `U7` (on `T`) with the
      loop as its payload, so that `M` holds a canister waiting for a response
      from another subnet that never arrives.
   Wait until all three loops are running.
7. Evaluate the terms of the "merge readiness" condition for `M` and check that
   none of the `VIOLATED_CONDITIONS` holds: `T` holds messages in its stream to
   `M` and `M` holds messages in its own streams (the loops of step 2), the
   ingress history holds terminal entries (the calls of the steps above that
   did complete), `M`'s subnet input queues hold messages (`U1`'s `install_code`
   requests) and its subnet call context manager holds call contexts (the
   `install_code` calls that are executing). The remaining three terms are
   expected to hold and are only logged; `VIOLATED_CONDITIONS` says why.

Success::
Every term of the "merge readiness" condition that this scenario exercises is
violated.

end::catalog[] */

use anyhow::{Result, anyhow, bail};
use candid::Principal;
use ic_registry_subnet_type::SubnetType;
use ic_subnet_merging::metrics_helper::{fetch_metrics, sum_of_medians};
use ic_subnet_merging::readiness::{
    Condition, METRIC_SUBNET_CALL_CONTEXTS, METRIC_SUBNET_INPUT_QUEUE_MESSAGES, SubnetNodeIps,
    Term, evaluate_merge_readiness,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeContainer,
    NnsInstallationBuilder, READY_WAIT_TIMEOUT, RETRY_BACKOFF, SubnetSnapshot, TopologySnapshot,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    UniversalCanister, assert_create_agent, block_on, create_canister, set_controller,
};
use ic_types::Height;
use ic_universal_canister::management::InstallMode;
use ic_universal_canister::{
    CallInterface, call_args, get_universal_canister_wasm, management, wasm,
};
use slog::{Logger, info};
use std::time::Duration;

/// The label selecting the `install_code` call contexts of
/// `METRIC_SUBNET_CALL_CONTEXTS`.
const LABEL_INSTALL_CODE: &str = "type=\"install_code\"";

/// Number of loop iterations each universal canister must have completed before
/// the conditions are evaluated, so that the loops are known to be making
/// cross-subnet calls by then.
const MIN_LOOP_ITERATIONS: u64 = 3;

/// One billion, the unit `INIT_INSTRUCTIONS` is expressed in.
const B: u64 = 1_000_000_000;

/// The names of the canisters `U1` installs code on.
const INSTALL_CODE_TARGETS: [&str; 5] = ["U2a", "U2b", "U2c", "U2d", "U2e"];

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

/// The global data value that would end the endless loops of `U3`, `U5` and
/// `U7`. The test never sets it, so those loops never end.
const LOOP_BREAK_TRIGGER: &[u8] = b"break";

/// The number of nodes of every subnet. More than one so that the medians the
/// merge readiness condition is made of are medians of more than one value.
const SUBNET_SIZE: usize = 4;

/// The DKG interval length of the Application subnets, i.e. one less than the
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

/// Timeouts of the test itself: the whole scenario takes a couple of minutes,
/// the rest is headroom for the waits of the steps above. The overall timeout
/// additionally covers the setup (booting the IC and installing the NNS).
const PER_TEST_TIMEOUT: Duration = Duration::from_secs(900);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(1500);

/// The conditions this scenario violates, i.e. the ones step 7 checks. The
/// three that are missing are expected to hold:
///
/// * `RegistryVersion`, because this test creates no registry version: it
///   evaluates the condition at the version of its own topology snapshot, which
///   every subnet has long observed, rather than at the version a proposal
///   labeling `M` as "cooling down" would create.
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
const VIOLATED_CONDITIONS: [Condition; 5] = [
    Condition::IncomingStreams,
    Condition::OutgoingStreams,
    Condition::IngressHistory,
    Condition::SubnetInputQueues,
    Condition::SubnetCallContexts,
];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TEST_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
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

    // The two Application subnets: `M` is the one that is set up to be cooled
    // down and merged away, `T` is the one `M` exchanges messages with in a
    // loop and that holds the canisters at the other end of the cross-subnet
    // endless loops of step 6.
    let app_subnets: Vec<_> = topology
        .subnets()
        .filter(|subnet| subnet.subnet_type() == SubnetType::Application)
        .collect();
    assert_eq!(
        app_subnets.len(),
        2,
        "expected exactly 2 Application subnets"
    );
    let m_subnet = app_subnets[0].clone();
    let t_subnet = app_subnets[1].clone();
    let m_node = m_subnet.nodes().next().unwrap();
    let t_node = t_subnet.nodes().next().unwrap();
    let m_agent = assert_create_agent(m_node.get_public_url().as_str()).await;
    let t_agent = assert_create_agent(t_node.get_public_url().as_str()).await;
    info!(
        logger,
        "Subnets under test:\n  M={}\n  T={}\n  NNS={}",
        m_subnet.subnet_id,
        t_subnet.subnet_id,
        topology.root_subnet_id(),
    );

    // Step 1: Install a universal canister on each of `M` and `T`.
    info!(logger, "Step 1: Installing universal canisters UM and UT");
    let um = UniversalCanister::new_with_retries(&m_agent, m_node.effective_canister_id(), &logger)
        .await;
    let ut = UniversalCanister::new_with_retries(&t_agent, t_node.effective_canister_id(), &logger)
        .await;
    info!(
        logger,
        "Step 1 done: UM={}, UT={}",
        um.canister_id(),
        ut.canister_id(),
    );

    // Step 2: Start a loop of calls to the canister on the other subnet on both
    // universal canisters.
    info!(logger, "Step 2: Starting the UM <-> UT call loops");
    start_call_loop(&um, ut.canister_id()).await;
    start_call_loop(&ut, um.canister_id()).await;
    info!(logger, "Step 2 done: both call loops started");

    // Step 3: Wait until both loops have completed a few iterations.
    info!(
        logger,
        "Step 3: Waiting for {MIN_LOOP_ITERATIONS} iterations of both call loops"
    );
    for (canister, name) in [(&um, "UM"), (&ut, "UT")] {
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
    let u1 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u3 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u4 = UniversalCanister::new_with_retries(&t_agent, t_id, &logger).await;
    let u5 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u6 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u7 = UniversalCanister::new_with_retries(&t_agent, t_id, &logger).await;
    info!(
        logger,
        "Step 4: U1={}, U3={}, U5={}, U6={} on M; U4={}, U7={} on T",
        u1.canister_id(),
        u3.canister_id(),
        u5.canister_id(),
        u6.canister_id(),
        u4.canister_id(),
        u7.canister_id(),
    );
    let mut targets = Vec::new();
    for name in INSTALL_CODE_TARGETS {
        let target = create_canister(&m_agent, m_id).await;
        set_controller(&target, &u1.canister_id(), &m_agent).await;
        info!(logger, "Step 4: {name}={target} on M, controlled by U1");
        targets.push(target);
    }
    info!(logger, "Step 4 done: all canisters installed");

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

    // Step 6: Start the three endless loops.
    info!(logger, "Step 6: Starting the three endless loops");
    for (canister, name, callee) in [
        (&u3, "U3", None),
        (&u4, "U4", Some(&u5)),
        (&u6, "U6", Some(&u7)),
    ] {
        let payload = match callee {
            None => endless_loop(),
            Some(callee) => endless_loop_call(callee.canister_id()),
        };
        canister
            .submit_update(payload)
            .await
            .unwrap_or_else(|e| panic!("submitting {name}'s update call should succeed: {e}"))
            .unwrap_or_else(|| panic!("{name}'s update call should not have completed already"));
    }
    for (canister, name) in [(&u3, "U3"), (&u5, "U5"), (&u7, "U7")] {
        await_loop_started(canister, name, &logger).await;
    }
    info!(
        logger,
        "Step 6 done: U3 is looping, U5 is looping in a call from U4, and U7 is looping in a call \
         from U6"
    );

    // Step 7: Check that the scenario violates the individual conditions.
    check_conditions_violated(&topology, &m_subnet, &logger).await;
}

/// Step 7: check that none of the `VIOLATED_CONDITIONS` of the "merge
/// readiness" condition holds for `m_subnet`, i.e. that the condition a subnet
/// merging tool waits for is one this scenario does not satisfy.
///
/// The terms are evaluated by `ic_subnet_merging::readiness`, i.e. by the same
/// code a subnet merging tool evaluates them with. Every term is evaluated
/// repeatedly until all of `VIOLATED_CONDITIONS` are violated at the same
/// evaluation.
async fn check_conditions_violated(
    topology: &TopologySnapshot,
    m_subnet: &SubnetSnapshot,
    logger: &Logger,
) {
    // Not the registry version a proposal labeling `M` as "cooling down" would
    // create, which this test does not submit, but the one of the snapshot the
    // test works with: `Condition::RegistryVersion` holds for it, see
    // `VIOLATED_CONDITIONS`.
    let registry_version = topology.get_registry_version().get();
    info!(
        logger,
        "Step 7: Checking that subnet M violates the individual conditions for merging it away, \
         for V={registry_version}",
    );

    let terms = retry_with_msg_async!(
        format!(
            "waiting for subnet {} to violate the conditions {VIOLATED_CONDITIONS:?} all at once",
            m_subnet.subnet_id
        ),
        logger,
        CONDITIONS_TIMEOUT,
        CONDITIONS_BACKOFF,
        || async {
            let terms = evaluate_merge_readiness(
                &subnet_node_ips(topology),
                m_subnet.subnet_id,
                registry_version,
                logger,
            )
            .await;
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
            "subnet M satisfied conditions for merging it away that this scenario is meant to \
             violate: {e}"
        )
    });

    for term in &terms {
        let mark = if term.satisfied { "x" } else { " " };
        info!(logger, "  [{mark}] {}", term.description);
    }
    info!(
        logger,
        "Step 7 done: subnet M violates all of the conditions {VIOLATED_CONDITIONS:?}"
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
/// The canister never responds to the call it is executing, so that call
/// context stays open forever.
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
/// Every subnet message this test made before `U1`'s calls (creating and
/// installing canisters, setting their controller) was waited for, so the subnet
/// queues hold nothing but those calls by the time they are inducted.
async fn await_install_code_requests_inducted(subnet: &SubnetSnapshot, logger: &Logger) {
    let expected = INSTALL_CODE_TARGETS.len() as f64;
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
                logger,
                &node_ips,
                &[
                    METRIC_SUBNET_INPUT_QUEUE_MESSAGES,
                    METRIC_SUBNET_CALL_CONTEXTS,
                ],
            )
            .await;
            let enqueued = sum_of_medians(&metrics, METRIC_SUBNET_INPUT_QUEUE_MESSAGES, |_| true);
            let executing = sum_of_medians(&metrics, METRIC_SUBNET_CALL_CONTEXTS, |labels| {
                labels.contains(LABEL_INSTALL_CODE)
            });
            if enqueued + executing < expected {
                bail!("{enqueued} request(s) enqueued and {executing} executing");
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
