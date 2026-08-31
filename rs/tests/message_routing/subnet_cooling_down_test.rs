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

The subnet that is cooling down, i.e. the one that would be merged, is called
`M`; `R` is the root (NNS) subnet it would be merged into, which holds nothing
but the NNS canisters; `T` and `S` are two further Application subnets holding
the canisters at the other end of `M`'s cross-subnet calls.

"Executing" an update call below always means submitting it as an ingress
message without waiting for it to complete: most of the calls of this test are
never meant to complete.

Runbook::
0. Set up an IC with an NNS subnet `R` (with the NNS canisters installed) and
   three Application subnets `M`, `T` and `S`.
1. Install a universal canister on each of `M` and `T`: `US` on `M`, `UT` on `T`.
2. Make an ingress call to each of `US` and `UT` with a payload that calls the
   universal canister on the other subnet in a loop: the reply (or reject)
   callback of every call fires a new call.
3. Wait until both loops have completed a few iterations, i.e. messages are
   actually flowing between `M` and `T` in both directions.
4. Install the universal canisters of the steps below (`U1`, `U3`, `U5` and
   `U6` on `M`, `U4` and `U7` on `S`) and create five empty canisters
   `U2a` .. `U2e` on `M`, controlled by `U1`. All of this has to happen before
   step 5: a long-running `install_code` blocks every other `install_code` on
   the same subnet.
5. Execute an update call on `U1` that makes five calls to the management
   canister's `install_code` method, one per `U2x`, in mode `install`, with the
   universal canister module and an `arg` that makes `canister_init` burn
   `INIT_INSTRUCTIONS` instructions. Wait until all five requests have left
   `U1`'s output queue: a request still sitting there when `M` starts cooling
   down would never be routed, not even into the loopback stream, and the code
   would never be installed.
6. Start three endless loops, each of which runs until the global data of the
   looping canister is set to `LOOP_BREAK_TRIGGER`, which this test never does:
   a. execute an update call on `U3` that loops on `U3` itself;
   b. execute an update call on `U4` (on `S`) that calls `U5` (on `M`) with the
      loop as its payload, so that `M` holds a canister looping in a call from
      another subnet that it can never respond to;
   c. execute an update call on `U6` (on `M`) that calls `U7` (on `S`) with the
      loop as its payload, so that `M` holds a canister waiting for a response
      from another subnet that never arrives.
   Wait until all three loops are running.
7. Submit (and adopt) an `UpdateConfigOfSubnet` NNS proposal labeling `M` as
   "cooling down" in its subnet record, and record the registry version `V` it
   creates.
8. Wait until `M` rejects ingress messages, i.e. the replicas of `M` observed
   the "cooling down" label.
9. Wait until `M` is "merge ready" according to the dashboard's condition for
   `V` and 0 cycles of pending refunds: all subnets have reached registry
   version `V`, no stream in either direction holds a message (loopback
   included), the ingress history holds nothing but `processing` entries, `M`'s
   subnet input and output queues are empty, `M`'s subnet call context manager
   holds no call context, and the pending anonymous refunds are worth at most 0
   cycles.
10. Check that `U2a` .. `U2e` have been installed, i.e. that the `install_code`
   calls of step 5 ran to completion rather than being lost or rejected while
   `M` was cooling down.
11. Check that the two loops of step 2 are indeed stalled (their iteration
   counters, read via queries, no longer advance): while `M` is cooling down,
   neither `M` nor `T` routes any message to or from `M`, so the messages of
   both loops are retained in their senders' output queues.

Success::
`M` becomes "merge ready", with `U2a` .. `U2e` installed, while both loops of
step 2 are stalled.

end::catalog[] */

use anyhow::{Result, anyhow, bail};
use candid::Principal;
use ic_nns_governance_api::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeContainer,
    NnsInstallationBuilder, READY_WAIT_TIMEOUT, RETRY_BACKOFF, SubnetSnapshot, TopologySnapshot,
};
use ic_system_test_driver::nns::{
    get_governance_canister, submit_external_proposal_with_test_id,
    vote_execute_proposal_assert_executed,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    MetricsFetcher, UniversalCanister, assert_create_agent, block_on, create_canister,
    runtime_from_url, set_controller,
};
use ic_types::SubnetId;
use ic_universal_canister::management::InstallMode;
use ic_universal_canister::{
    CallInterface, call_args, get_universal_canister_wasm, management, wasm,
};
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::{Logger, info};
use std::collections::BTreeMap;
use std::time::Duration;

/// Metrics making up the "merge readiness" condition.
const METRIC_REGISTRY_VERSION: &str = "mr_registry_version";
const METRIC_STREAM_MESSAGES: &str = "mr_stream_messages";
const METRIC_INGRESS_HISTORY_BY_STATE: &str = "replicated_state_ingress_history_length_by_state";
const METRIC_SUBNET_INPUT_QUEUE_MESSAGES: &str = "execution_subnet_input_queue_messages";
const METRIC_SUBNET_OUTPUT_QUEUE_MESSAGES: &str = "execution_subnet_output_queue_messages";
const METRIC_SUBNET_CALL_CONTEXTS: &str = "replicated_state_subnet_call_contexts";
const METRIC_PENDING_REFUNDS_CYCLES: &str = "replicated_state_pending_refunds_cycles";

/// The label selecting the `install_code` call contexts of
/// `METRIC_SUBNET_CALL_CONTEXTS`.
const LABEL_INSTALL_CODE: &str = "type=\"install_code\"";

/// `R` in the dashboard's readiness condition: the maximum total value in
/// cycles of the pending anonymous refunds of the cooling down subnet. (Not to
/// be confused with the subnet `R` of the runbook above.)
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

/// The global data value that would end the endless loops of `U3`, `U5` and
/// `U7`. The test never sets it, so those loops never end.
const LOOP_BREAK_TRIGGER: &[u8] = b"break";

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
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
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
    // "cooling down", `T` is the one it exchanges messages with in a loop, and
    // `S` is the one holding the canisters at the other end of the cross-subnet
    // calls of the endless loops of step 6.
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
    let s_subnet = app_subnets[2].clone();
    let m_node = m_subnet.nodes().next().unwrap();
    let t_node = t_subnet.nodes().next().unwrap();
    let s_node = s_subnet.nodes().next().unwrap();
    let m_agent = assert_create_agent(m_node.get_public_url().as_str()).await;
    let t_agent = assert_create_agent(t_node.get_public_url().as_str()).await;
    let s_agent = assert_create_agent(s_node.get_public_url().as_str()).await;
    info!(
        logger,
        "Subnets under test: M={}, T={}, S={} (R={})",
        m_subnet.subnet_id,
        t_subnet.subnet_id,
        s_subnet.subnet_id,
        topology.root_subnet_id(),
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
        "Step 4: Installing U1, U3, U5, U6 on M and U4, U7 on S, and creating {} canisters for U1 \
         to install code on",
        INSTALL_CODE_TARGETS.len(),
    );
    let m_id = m_node.effective_canister_id();
    let s_id = s_node.effective_canister_id();
    let u1 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u3 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u4 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    let u5 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u6 = UniversalCanister::new_with_retries(&m_agent, m_id, &logger).await;
    let u7 = UniversalCanister::new_with_retries(&s_agent, s_id, &logger).await;
    info!(
        logger,
        "Step 4: U1={}, U3={}, U5={}, U6={} on M; U4={}, U7={} on S",
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
    u3.submit_update(endless_loop())
        .await
        .expect("submitting U3's endless loop should succeed");
    submit_endless_loop_call(&u4, u5.canister_id()).await;
    submit_endless_loop_call(&u6, u7.canister_id()).await;
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

    // Step 9: Wait until `M` is "merge ready".
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

/// Executes an update call on `caller` that calls `callee` with `endless_loop()`
/// as the payload for `callee` to execute. As `callee` never responds, neither
/// does `caller`, so its ingress message stays `processing` forever.
async fn submit_endless_loop_call(caller: &UniversalCanister<'_>, callee: Principal) {
    caller
        .submit_update(wasm().call_simple(callee, "update", call_args().other_side(endless_loop())))
        .await
        .expect("submitting the call starting the endless loop should succeed");
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
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = get_governance_canister(&nns_runtime);

    let payload = UpdateSubnetPayload {
        subnet_id,
        cooling_down: Some(true),
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
    };
    let proposal_id = submit_external_proposal_with_test_id(
        &governance,
        NnsFunction::UpdateConfigOfSubnet,
        payload,
    )
    .await;
    info!(logger, "Submitted proposal {proposal_id}");
    vote_execute_proposal_assert_executed(&governance, proposal_id).await;

    // The proposal's single registry mutation is the newest registry version.
    // The snapshot above was taken before the proposal was submitted, so this
    // cannot miss the version the mutation created.
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
