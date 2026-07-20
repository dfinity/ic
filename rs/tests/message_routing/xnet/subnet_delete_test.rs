/* tag::catalog[]
Title:: Subnet deletion with in-flight XNet messages.

Goal:: Verify that deleting a subnet correctly handles in-flight XNet messages:
requests towards the deleted subnet are rejected, responses towards the deleted
subnet are silently dropped (a response can never be rejected), and messages
from the deleted subnet that are still in its stream are not pulled after subnet
deletion. The scenario is run once per type of the deleted subnet (as two
separate tests sharing the same IC): it must behave the same whether the deleted
subnet is a CloudEngine subnet or a regular Application subnet (subnet deletion
is handled by the routing/topology layer, which is subnet-type agnostic).

Runbook::
0. Set up an IC with an NNS subnet, three Application subnets S, T and C_app,
   and one CloudEngine subnet C_cloud. Then, in each of the two tests, pick the
   subnet matching that test's deleted-subnet type as the deleted subnet C
   (C_cloud or C_app) and run the following scenario:
1. Install universal canisters US on S, UT on T, UC on C, plus two more
   canisters US2 and US3 on S (used for the response-dropping scenario).
2. Halt T.  Wait until T makes no progress.
3. From UC fire a bounded-wait call to UT that would set UT's global data to a
   fixed blob.  The call is fire-and-forget (UC replies to its ingress
   immediately) and remains stuck in the C -> T stream (T is halted).  Also from
   UC fire two bounded-wait calls to US2 and US3 (on the surviving subnet S).
   Each callee holds its reply back (looping on `canister_status` calls) until
   its global data is set.  Both calls are fire-and-forget; US2 and US3 start
   looping.
4. Halt C.  Wait until C makes no progress.
5. Set US2's global data, releasing its reply.  The reply is a response
   destined for UC on the halted subnet C; since C is halted it is not consumed
   and, as the S -> C stream is still empty, it is inducted into that stream.
   Wait until it shows up in the stream.
6. From US submit 10 bounded-wait calls to UC with 2 MB payload each
   (generated at runtime, ingress stays small).  Each call's on_reject handler
   replies with the reject code as a 4-byte LE integer.  The 2 MB payloads
   fill the S -> C stream, so some calls reach the stream while the rest stay
   in US's output queue.
7. Wait until the S -> C stream is full (its byte size reaches
   TARGET_STREAM_SIZE_BYTES); C is halted so the stream never drains.
8. Set US3's global data, releasing its reply.  As the stream is now full, this
   second response towards C cannot be inducted and stays in US3's output queue.
9. Delete C, unhalt T, verify T's registry version is the version at which C
   was deleted, check UT's global data is still empty (T must not pull messages
   from the deleted C's stream), and wait for all 10 calls from US to complete.
10. Assert at least one call from US was rejected with DestinationInvalid
   (call did not reach the stream: no route after deletion) and at least one
   with CanisterReject (call reached the stream, so its callback was still
   open when C was deleted; the destination subnet's disappearance triggers an
   immediate synthetic reject for it, rather than waiting for the bounded-wait
   callback to time out).
11. Assert (via the `mr_routed_message_count{type="response",
   status="canister_not_found"}` metric on S) that at least one response towards
   C was silently dropped: this is the response that sat in US3's output queue
   (Step 8), dropped by the stream builder when the route to C disappeared,
   without producing any reject.  The response that sat in the S -> C stream
   (Step 5) is dropped together with the whole stream on deletion, which is
   intentionally metric-silent; it is covered indirectly (any panic on S would
   fail the test via the unallowed "panicked" log pattern).

Note:: Bounded-wait (best-effort) calls with no cycles are used throughout
because they are the only cross-subnet calls allowed to/from a CloudEngine
subnet; they are equally valid for an Application subnet, which keeps the
scenario identical across both tests.

Success::
All assertions pass for both deleted-subnet types.

end::catalog[] */

use anyhow::{Result, bail};
use candid::{Decode, Encode};
use futures::future::join_all;
use ic_config::message_routing::TARGET_STREAM_SIZE_BYTES;
use ic_consensus_system_test_utils::rw_message::cert_state_makes_no_progress_with_retries;
use ic_management_canister_types_private::{
    IC_00, Method, Payload, SubnetInfoArgs, SubnetInfoResponse,
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
    READY_WAIT_TIMEOUT, RETRY_BACKOFF, SubnetSnapshot,
    install_registry_canister_with_testnet_topology,
};
use ic_system_test_driver::retry_with_msg_async;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    MetricsFetcher, UniversalCanister, assert_create_agent, block_on,
};
use ic_types::SubnetId;
use ic_universal_canister::{call_args, wasm};
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::do_delete_subnet::DeleteSubnetPayload;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use std::time::Duration;

const NUM_NODES: usize = 4;
const CALL_TIMEOUT_SECS: u32 = 300;
const FIXED_BLOB: &[u8] = b"cloud-engine-test-fixed-blob";
// Blobs used by the response-dropping scenario. A looping canister on S holds
// back its reply until its global data is set to `RESPONSE_TRIGGER_BLOB`, then
// replies with the given reply blob (the payload of the response that must be
// silently dropped once C is deleted). Two responses are produced: one that ends
// up in S's *stream* towards C, and one that stays in the sender canister's
// *output queue* (because the stream is already full).
const RESPONSE_TRIGGER_BLOB: &[u8] = b"subnet-delete-response-trigger";
const RESPONSE_STREAM_REPLY_BLOB: &[u8] = b"subnet-delete-response-in-stream";
const RESPONSE_QUEUE_REPLY_BLOB: &[u8] = b"subnet-delete-response-in-queue";
// The two tests run the scenario once each (per deleted-subnet type). A single
// run takes on the order of a couple of minutes in practice (halting subnets,
// filling the S->C stream and scraping metrics); the per-test timeout leaves
// ample headroom while staying below the bazel default `test_timeout` ("long" =
// 900s), so an in-test timeout fires with a clean error before bazel hard-kills
// the target. The overall timeout covers the shared setup plus both tests
// running sequentially.
const PER_TEST_TIMEOUT: Duration = Duration::from_secs(300);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(600);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_delete_cloud_engine_subnet))
        .add_test(systest!(test_delete_application_subnet))
        .with_timeout_per_test(PER_TEST_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        // Nodes on the deleted subnet panic when consensus can no longer find
        // their subnet record in the registry.
        .add_unallowed_log_pattern_except(
            "panicked",
            "rs/consensus/src/consensus/allowed_panics.rs",
        )
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    // Three Application subnets (S, T and the Application deletion candidate) and
    // one CloudEngine subnet (the CloudEngine deletion candidate), plus the NNS.
    InternetComputer::new()
        .with_api_boundary_nodes_playnet(1)
        .add_subnet(Subnet::fast(SubnetType::System, NUM_NODES))
        .add_subnet(Subnet::fast(SubnetType::Application, NUM_NODES))
        .add_subnet(Subnet::fast(SubnetType::Application, NUM_NODES))
        .add_subnet(Subnet::fast(SubnetType::Application, NUM_NODES))
        .add_subnet(Subnet::fast(SubnetType::CloudEngine, NUM_NODES))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    install_registry_canister_with_testnet_topology(
        &env,
        None::<fn(&mut RegistryCanisterInitPayloadBuilder)>,
    );
    // Install the governance universal canister used to submit registry changes.
    // The registry canister above is created at REGISTRY_CANISTER_ID (the first
    // canister id); the governance canister, created right after it, gets the
    // next canister id, which is GOVERNANCE_CANISTER_ID. Registry mutations from
    // that id are authorized, and both tests address it via that constant.
    block_on(install_governance_canister(&env));
}

async fn install_governance_canister(env: &TestEnv) {
    let logger = env.logger();
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    let nns_agent = assert_create_agent(nns_node.get_public_url().as_str()).await;
    let governance = UniversalCanister::new(&nns_agent, nns_node.effective_canister_id()).await;
    assert_eq!(
        governance.canister_id(),
        GOVERNANCE_CANISTER_ID.get().0,
        "governance universal canister must land at GOVERNANCE_CANISTER_ID; it \
         must be the first canister created after the registry canister",
    );
    slog::info!(logger, "governance={}", governance.canister_id());
}

/// Deletes the CloudEngine subnet.
pub fn test_delete_cloud_engine_subnet(env: TestEnv) {
    block_on(run_matrix_entry(env, SubnetType::CloudEngine));
}

/// Deletes an Application subnet. The scenario must behave the same as when
/// deleting a CloudEngine subnet (subnet deletion is handled by the
/// routing/topology layer, which is subnet-type agnostic).
pub fn test_delete_application_subnet(env: TestEnv) {
    block_on(run_matrix_entry(env, SubnetType::Application));
}

/// Reconstructs the governance canister handle (installed in `setup`), picks the
/// deleted subnet C matching `deleted_subnet_type` along with the sender subnet S
/// and the receiver subnet T (halted only temporarily during the scenario), and
/// runs the full subnet-deletion scenario.
async fn run_matrix_entry(env: TestEnv, deleted_subnet_type: SubnetType) {
    let logger = env.logger();
    let topology = env.topology_snapshot();

    let nns_subnet = topology.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let nns_agent = assert_create_agent(nns_node.get_public_url().as_str()).await;

    // Governance universal canister on the NNS subnet, used to submit registry
    // changes. It was installed at GOVERNANCE_CANISTER_ID during `setup`.
    let governance =
        UniversalCanister::from_canister_id(&nns_agent, GOVERNANCE_CANISTER_ID.get().0);

    // Application subnets: S is the sender and T is the receiver (halted only
    // temporarily during the scenario), while the third one is the Application
    // deletion candidate.
    let app_subnets: Vec<_> = topology
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .collect();
    assert!(
        app_subnets.len() >= 3,
        "expected at least 3 Application subnets, got {}",
        app_subnets.len()
    );
    let s_subnet = app_subnets[0].clone();
    let t_subnet = app_subnets[1].clone();
    let c_subnet = if deleted_subnet_type == SubnetType::CloudEngine {
        topology
            .subnets()
            .find(|s| s.subnet_type() == SubnetType::CloudEngine)
            .unwrap()
    } else {
        app_subnets[2].clone()
    };

    run_scenario(
        &env,
        &governance,
        &s_subnet,
        &t_subnet,
        &c_subnet,
        deleted_subnet_type,
        &logger,
    )
    .await;
}

/// Runs the full subnet-deletion scenario, deleting subnet `c_subnet` (whose
/// type is `deleted_subnet_type`). Subnets `s_subnet` and `t_subnet` play the
/// roles of the sender subnet S and the receiver subnet T (which is halted only
/// temporarily during the scenario).
#[allow(clippy::too_many_arguments)]
async fn run_scenario(
    env: &TestEnv,
    governance: &UniversalCanister<'_>,
    s_subnet: &SubnetSnapshot,
    t_subnet: &SubnetSnapshot,
    c_subnet: &SubnetSnapshot,
    deleted_subnet_type: SubnetType,
    logger: &slog::Logger,
) {
    slog::info!(
        logger,
        "=== Running scenario: deleting {:?} subnet C ({}) ===",
        deleted_subnet_type,
        c_subnet.subnet_id,
    );

    let s_node = s_subnet.nodes().next().unwrap();
    let t_node = t_subnet.nodes().next().unwrap();
    let c_node = c_subnet.nodes().next().unwrap();

    let s_agent = assert_create_agent(s_node.get_public_url().as_str()).await;
    let t_agent = assert_create_agent(t_node.get_public_url().as_str()).await;
    let c_agent = assert_create_agent(c_node.get_public_url().as_str()).await;

    // Step 1: Install universal canisters US on S, UT on T, UC on C, plus two
    // more canisters US2 and US3 on S dedicated to the response-dropping
    // scenario: US2 produces the response that ends up in S's stream towards C,
    // US3 the response that stays in US3's output queue.
    slog::info!(logger, "Step 1: Installing universal canisters on S, T, C");
    let us =
        UniversalCanister::new_with_retries(&s_agent, s_node.effective_canister_id(), logger).await;
    let us2 =
        UniversalCanister::new_with_retries(&s_agent, s_node.effective_canister_id(), logger).await;
    let us3 =
        UniversalCanister::new_with_retries(&s_agent, s_node.effective_canister_id(), logger).await;
    let ut =
        UniversalCanister::new_with_retries(&t_agent, t_node.effective_canister_id(), logger).await;
    let uc =
        UniversalCanister::new_with_retries(&c_agent, c_node.effective_canister_id(), logger).await;
    slog::info!(
        logger,
        "Step 1 done: US={}, US2={}, US3={}, UT={}, UC={}",
        us.canister_id(),
        us2.canister_id(),
        us3.canister_id(),
        ut.canister_id(),
        uc.canister_id(),
    );

    // Step 2: Halt subnet T and wait until T makes no progress.
    slog::info!(logger, "Step 2: Halting subnet T ({})", t_subnet.subnet_id);
    set_subnet_halted(governance, t_subnet.subnet_id, true).await;
    cert_state_makes_no_progress_with_retries(
        &t_node.get_public_url(),
        ut.canister_id().into(),
        logger,
        Duration::from_secs(120),
        Duration::from_secs(5),
    );
    slog::info!(logger, "Step 2 done: subnet T is halted");

    // Step 3: Fire a bounded-wait call from UC to UT that would set UT's global
    // data to FIXED_BLOB.  UC replies to its ingress immediately (fire-and-forget).
    slog::info!(
        logger,
        "Step 3: Firing bounded-wait UC->UT call (fire-and-forget)"
    );
    uc.update(
        wasm()
            .call_simple_with_cycles_and_best_effort_response(
                ut.canister_id(),
                "update",
                call_args()
                    .other_side(wasm().set_global_data(FIXED_BLOB).reply_data(&[]))
                    .on_reply(wasm().noop())
                    .on_reject(wasm().noop()),
                0_u128,
                CALL_TIMEOUT_SECS,
            )
            .reply_data(&[]),
    )
    .await
    .expect("UC fire-and-forget call to UT should succeed");

    // Also fire two bounded-wait calls from UC to US2 and US3 (on the surviving
    // sender subnet S). Each callee holds back its reply (by looping on
    // `canister_status` calls) until its global data is set to
    // RESPONSE_TRIGGER_BLOB. UC replies to its ingress immediately
    // (fire-and-forget). Both C and S are still running, so US2/US3 receive the
    // requests and start looping; their eventual replies will be *responses*
    // destined for UC on C (see Steps 5, 8, 9a).
    slog::info!(
        logger,
        "Step 3: Firing bounded-wait UC->US2 and UC->US3 looping calls (fire-and-forget)"
    );
    fire_looping_call(&uc, us2.canister_id(), RESPONSE_STREAM_REPLY_BLOB).await;
    fire_looping_call(&uc, us3.canister_id(), RESPONSE_QUEUE_REPLY_BLOB).await;
    slog::info!(
        logger,
        "Step 3 done: UC->UT, UC->US2 and UC->US3 fire-and-forget calls fired"
    );

    // Step 4: Halt subnet C and wait until C makes no progress.
    slog::info!(logger, "Step 4: Halting subnet C ({})", c_subnet.subnet_id);
    set_subnet_halted(governance, c_subnet.subnet_id, true).await;
    cert_state_makes_no_progress_with_retries(
        &c_node.get_public_url(),
        uc.canister_id().into(),
        logger,
        Duration::from_secs(120),
        Duration::from_secs(5),
    );
    slog::info!(logger, "Step 4 done: subnet C is halted");

    // Step 5: Now that C is halted, release US2's held-back reply by setting its
    // global data to RESPONSE_TRIGGER_BLOB. US2's loop then replies; that reply is
    // a *response* destined for UC on the (halted, soon to be deleted) subnet C.
    // Because C is halted it does not consume the response, and because the S->C
    // stream is still empty (Step 6 has not run yet) the response is inducted into
    // S's stream towards C. When C is deleted (Step 9a) this streamed response
    // must be silently dropped (its whole stream is discarded): unlike the
    // requests in Steps 6/10 (which are rejected), a response can never be
    // rejected.
    slog::info!(
        logger,
        "Step 5: Releasing US2's reply (response into the S->C stream)"
    );
    us2.update(
        wasm()
            .set_global_data(RESPONSE_TRIGGER_BLOB)
            .reply_data(&[]),
    )
    .await
    .expect("setting US2 global data should succeed");
    // Wait until the response is actually inducted into S's stream towards C
    // (before any of the large Step 6 payloads fill that stream).
    wait_for_stream_gauge_at_least(&s_node, "mr_stream_messages", c_subnet.subnet_id, 1, logger)
        .await;
    slog::info!(
        logger,
        "Step 5 done: US2 reply is in the S->C stream (>= 1 message)"
    );

    // Step 6: Submit 10 bounded-wait calls from US to UC each with 2 MB payload
    // (generated at runtime on S; the ingress itself is small).
    // The on_reject handler replies with the reject code as a 4-byte LE integer.
    // We submit all 10 calls before step 9 so they are in-flight in the S->C
    // stream before C is deleted.
    slog::info!(
        logger,
        "Step 6: Submitting 10 bounded-wait US->UC calls (2 MB payload each)"
    );
    let us_uc_wasm: Vec<u8> = wasm()
        .call_simple_with_cycles_and_best_effort_response(
            uc.canister_id(),
            "update",
            call_args()
                .eval_other_side(wasm().push_equal_bytes(0, 2 * 1000 * 1000).build())
                .on_reply(wasm().reply_data(&[]))
                .on_reject(
                    wasm()
                        .reject_code()
                        .int_to_blob()
                        .reply_data_append()
                        .reply(),
                ),
            0_u128,
            CALL_TIMEOUT_SECS,
        )
        .build();
    let us_canister_id = us.canister_id();
    let us_uc_request_ids: Vec<_> = join_all((0..10).map(|i| {
        let s_agent = s_agent.clone();
        let us_uc_wasm = us_uc_wasm.clone();
        async move {
            match s_agent
                .update(&us_canister_id, "update")
                .with_arg(us_uc_wasm)
                .call()
                .await
                .unwrap_or_else(|e| panic!("US->UC call {} submission failed: {e}", i + 1))
            {
                ic_agent::agent::CallResponse::Poll(id) => id,
                ic_agent::agent::CallResponse::Response(_) => {
                    panic!(
                        "US->UC call {} completed synchronously, expected Poll",
                        i + 1
                    )
                }
            }
        }
    }))
    .await;
    slog::info!(logger, "Step 6 done: {} pending", us_uc_request_ids.len());

    // Step 7: Wait until S's stream towards C is full. Each round the stream
    // builder moves queued messages into the S -> C stream, but stops adding to it
    // once its byte size reaches the soft limit TARGET_STREAM_SIZE_BYTES (the
    // check is `count_bytes() >= TARGET_STREAM_SIZE_BYTES`, evaluated before each
    // message, so the last one may push it slightly over). We detect this via the
    // `mr_stream_bytes` gauge. Once the stream is full the remaining large
    // requests stay in US's output queue, and any further message (the Step 8
    // response) will stay in its sender's output queue too. C is halted, so it
    // never garbage-collects the stream and the stream never drains below the
    // target.
    slog::info!(
        logger,
        "Step 7: Waiting for the S->C stream to fill ({} bytes)",
        TARGET_STREAM_SIZE_BYTES,
    );
    wait_for_stream_gauge_at_least(
        &s_node,
        "mr_stream_bytes",
        c_subnet.subnet_id,
        TARGET_STREAM_SIZE_BYTES as u64,
        logger,
    )
    .await;
    slog::info!(logger, "Step 7 done: S->C stream is full");

    // Step 8: Now that the stream is full, release US3's held-back reply. Its
    // response towards UC on C cannot be inducted into the full S->C stream, so it
    // stays in US3's output queue. When C is deleted (Step 9a) this queued
    // response must be silently dropped by the stream builder (route to C gone),
    // which — unlike the queued requests — happens without producing any reject.
    slog::info!(
        logger,
        "Step 8: Releasing US3's reply (response into US3's output queue)"
    );
    us3.update(
        wasm()
            .set_global_data(RESPONSE_TRIGGER_BLOB)
            .reply_data(&[]),
    )
    .await
    .expect("setting US3 global data should succeed");
    slog::info!(logger, "Step 8 done: US3 reply released");

    // Step 9a: Delete subnet C. Snapshot the topology right before the deletion:
    // `block_for_newer_registry_version` derives its target version from the
    // snapshot's registry version + 1, so the baseline must be captured before
    // the deletion, otherwise it could block forever waiting for a version that
    // only appears after the (later) unhalting of T.
    slog::info!(
        logger,
        "Step 9a: Deleting subnet C ({})",
        c_subnet.subnet_id
    );
    // Baseline for the cumulative "silently dropped response" counter, captured
    // before the deletion that triggers the drop. This counter carries over
    // between matrix entries (shared IC and sender subnet S), so Step 11 asserts
    // an increase relative to this baseline rather than an absolute threshold.
    let dropped_responses_before = read_dropped_response_count(&s_node)
        .await
        .expect("failed to read the dropped response counter before deletion");
    let topo_before_delete = env.topology_snapshot();
    let delete_arg = DeleteSubnetPayload {
        subnet_id: c_subnet.subnet_id.get().into(),
    };
    governance
        .forward_to(
            &REGISTRY_CANISTER_ID.get().0,
            "delete_subnet",
            Encode!(&delete_arg).unwrap(),
        )
        .await
        .expect("delete_subnet should succeed");

    // Record the registry version at which C was deleted.
    let topo_after_delete = topo_before_delete
        .block_for_newer_registry_version()
        .await
        .expect("registry should update after delete_subnet");
    let c_delete_registry_version = topo_after_delete.get_registry_version().get();
    slog::info!(
        logger,
        "Step 9a done: subnet C deleted at registry version {}",
        c_delete_registry_version,
    );

    // Step 9b: Unhalt subnet T.
    slog::info!(
        logger,
        "Step 9b: Unhalting subnet T ({})",
        t_subnet.subnet_id
    );
    set_subnet_halted(governance, t_subnet.subnet_id, false).await;
    slog::info!(logger, "Step 9b done: subnet T unhalted");

    // Step 9c: Wait for T to observe the registry version at which C was deleted.
    slog::info!(
        logger,
        "Step 9c: Waiting for subnet T to observe registry version {}",
        c_delete_registry_version,
    );
    wait_for_subnet_registry_version(&ut, t_subnet.subnet_id, c_delete_registry_version, logger)
        .await;
    slog::info!(
        logger,
        "Step 9c done: subnet T has observed registry version {}",
        c_delete_registry_version,
    );

    // Step 9d: Execute multiple update rounds on T, checking after each that UT's
    // global data is still empty (T must not pull messages from the deleted C's stream).
    slog::info!(
        logger,
        "Step 9d: Checking that UT global data remains empty over multiple rounds"
    );
    for i in 0..5_usize {
        let global_data = ut
            .update(wasm().get_global_data().reply_data_append().reply().build())
            .await
            .expect("update to UT should succeed");
        assert!(
            global_data.is_empty(),
            "UT global data should be empty at round {} but got {} bytes: {global_data:?}",
            i + 1,
            global_data.len()
        );
    }
    slog::info!(logger, "Step 9d done: UT global data is empty as expected");

    // Step 9e: Wait for all 10 calls from US to UC to complete.
    slog::info!(
        logger,
        "Step 9e: Waiting for all 10 US->UC calls to complete"
    );
    let us_uc_results = join_all(
        us_uc_request_ids
            .iter()
            .map(|req_id| s_agent.wait(req_id, us.canister_id())),
    )
    .await;
    slog::info!(logger, "Step 9e done: all 10 US->UC calls completed");

    // Step 10: Assert at least one call from US was rejected with DestinationInvalid
    // and at least one with CanisterReject.
    slog::info!(
        logger,
        "Step 10: Asserting rejection codes for 10 US->UC calls"
    );
    let mut dest_invalid_count = 0_usize;
    let mut canister_reject_count = 0_usize;
    for result in us_uc_results {
        let (bytes, _) = result.expect("US->UC call should have returned a reply with reject code");
        assert_eq!(
            bytes.len(),
            4,
            "Expected exactly 4 bytes (reject code), got {} bytes: {bytes:?}",
            bytes.len()
        );
        let code = u32::from_le_bytes(bytes.try_into().unwrap());
        slog::info!(logger, "Step 10: US->UC reject code {}", code);
        match code {
            3 => dest_invalid_count += 1,
            4 => canister_reject_count += 1,
            _ => panic!("Unexpected reject code {code} from US->UC call"),
        }
    }
    slog::info!(
        logger,
        "Step 10 done: DestinationInvalid={}, CanisterReject={}",
        dest_invalid_count,
        canister_reject_count,
    );
    assert!(
        dest_invalid_count >= 1,
        "Expected at least one DestinationInvalid rejection, got {dest_invalid_count} \
         (deleted subnet type: {deleted_subnet_type:?})"
    );
    assert!(
        canister_reject_count >= 1,
        "Expected at least one CanisterReject rejection, got {canister_reject_count} \
         (deleted subnet type: {deleted_subnet_type:?})"
    );
    // Step 11: Verify the two responses towards C were silently dropped.
    //
    // The response that was in US3's *output queue* (Step 8) is dropped by the
    // stream builder when it finds no route to C; this increments
    // `mr_routed_message_count{type="response",status="canister_not_found"}`, so
    // we can assert on it directly. (The queued requests from Step 6 increment the
    // same counter with `type="request"` and are additionally rejected, see Step
    // 10.)
    //
    // The response that was already in the S->C *stream* (Step 5) is dropped
    // together with the whole stream when C is deleted; that bulk discard is
    // intentionally metric-silent, so it cannot be asserted via a counter. It is
    // covered indirectly: a panic on S (e.g. from attempting to reject a response)
    // would fail the test via the unallowed "panicked" log pattern.
    slog::info!(
        logger,
        "Step 11: Verifying via metrics that the queued response towards C was dropped"
    );
    // Assert the cumulative counter grew by at least 1 relative to the baseline
    // captured before deletion (Step 9a): a bare `>= 1` check would spuriously
    // pass in the second matrix entry off the first entry's leftover count.
    let dropped_responses =
        wait_for_dropped_response_count_at_least(&s_node, dropped_responses_before + 1, logger)
            .await;
    slog::info!(
        logger,
        "Step 11 done: {} response(s) towards C dropped as no_route (canister_not_found) \
         (was {} before deletion)",
        dropped_responses,
        dropped_responses_before,
    );

    slog::info!(
        logger,
        "Scenario passed for deleted subnet type {:?}",
        deleted_subnet_type
    );
}

/// Fires a fire-and-forget, bounded-wait call from `uc` to `callee`'s `update`
/// method running the looping op: `callee` holds back its reply until its global
/// data equals `RESPONSE_TRIGGER_BLOB`, then replies with `reply_blob`. `uc`
/// replies to its own ingress immediately. Bounded-wait with no cycles is used
/// as elsewhere in the scenario (required to/from a CloudEngine subnet).
async fn fire_looping_call(
    uc: &UniversalCanister<'_>,
    callee: impl AsRef<[u8]>,
    reply_blob: &[u8],
) {
    uc.update(
        wasm()
            .call_simple_with_cycles_and_best_effort_response(
                callee,
                "update",
                call_args()
                    .other_side(
                        wasm().loop_until_global_data_set(RESPONSE_TRIGGER_BLOB, reply_blob),
                    )
                    .on_reply(wasm().noop())
                    .on_reject(wasm().noop()),
                0_u128,
                CALL_TIMEOUT_SECS,
            )
            .reply_data(&[]),
    )
    .await
    .expect("UC fire-and-forget looping call should succeed");
}

/// Reads the value of a per-stream gauge (e.g. `mr_stream_messages` or
/// `mr_stream_bytes`) for the stream towards `remote` on `node`, returning 0 if
/// the corresponding labelled series does not exist yet (no such stream).
async fn read_stream_gauge(
    node: &IcNodeSnapshot,
    metric: &str,
    remote: &str,
) -> anyhow::Result<u64> {
    let map = MetricsFetcher::new(std::iter::once(node.clone()), vec![metric.to_string()])
        .fetch::<u64>()
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch {metric}: {e}"))?;
    // The stream gauges are labelled with the destination subnet id (`remote`);
    // match on the full `remote="<id>"` label to avoid selecting a different
    // series whose subnet id happens to contain `remote` as a substring.
    let label_match = format!("remote=\"{remote}\"");
    Ok(map
        .iter()
        .find(|(key, _)| key.contains(&label_match))
        .and_then(|(_, values)| values.first().copied())
        .unwrap_or(0))
}

/// Waits until the per-stream gauge `metric` for the stream towards `remote` on
/// `node` reaches at least `at_least`.
async fn wait_for_stream_gauge_at_least(
    node: &IcNodeSnapshot,
    metric: &str,
    remote: SubnetId,
    at_least: u64,
    logger: &slog::Logger,
) {
    let remote = remote.to_string();
    retry_with_msg_async!(
        format!("waiting for {metric} towards {remote} to reach {at_least}"),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let value = read_stream_gauge(node, metric, &remote).await?;
            if value < at_least {
                bail!("{metric} towards {remote} is {value} (target {at_least})");
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| panic!("{metric} towards {remote} did not reach {at_least}: {e}"));
}

/// Reads the current value of the cumulative "silently dropped response" counter
/// on `node`, i.e. the sum of
/// `mr_routed_message_count{type="response",status="canister_not_found"}` across
/// all destination-subnet labels. Returns 0 if the counter is not present yet.
///
/// This counter is cumulative and, because all matrix entries share the same IC
/// and the same sender subnet S, it carries over between scenario runs. Callers
/// must therefore compare against a baseline captured before the deletion rather
/// than against an absolute threshold.
async fn read_dropped_response_count(node: &IcNodeSnapshot) -> anyhow::Result<u64> {
    let map = MetricsFetcher::new(
        std::iter::once(node.clone()),
        vec!["mr_routed_message_count".to_string()],
    )
    .fetch::<u64>()
    .await
    .map_err(|e| anyhow::anyhow!("failed to fetch mr_routed_message_count: {e}"))?;
    Ok(map
        .iter()
        .filter(|(key, _)| {
            key.contains("type=\"response\"") && key.contains("status=\"canister_not_found\"")
        })
        .filter_map(|(_, values)| values.first().copied())
        .sum())
}

/// Waits until the "silently dropped response" counter on `node` reaches at least
/// `at_least`, and returns the observed count. See [`read_dropped_response_count`]
/// for why callers pass a baseline-relative target rather than an absolute one.
async fn wait_for_dropped_response_count_at_least(
    node: &IcNodeSnapshot,
    at_least: u64,
    logger: &slog::Logger,
) -> u64 {
    retry_with_msg_async!(
        format!(
            "waiting for the silently dropped response counter (mr_routed_message_count \
             type=response status=canister_not_found) to reach {at_least}"
        ),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let dropped = read_dropped_response_count(node).await?;
            if dropped < at_least {
                bail!("dropped response counter is {dropped} (target {at_least})");
            }
            Ok(dropped)
        }
    )
    .await
    .unwrap_or_else(|e| panic!("silently dropped response counter did not reach {at_least}: {e}"))
}

async fn set_subnet_halted(
    governance: &UniversalCanister<'_>,
    subnet_id: ic_types::SubnetId,
    is_halted: bool,
) {
    let payload = UpdateSubnetPayload {
        subnet_id,
        is_halted: Some(is_halted),
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
    governance
        .forward_to(
            &REGISTRY_CANISTER_ID.get().0,
            "update_subnet",
            Encode!(&payload).unwrap(),
        )
        .await
        .expect("update_subnet should succeed");
}

async fn wait_for_subnet_registry_version(
    ut: &UniversalCanister<'_>,
    subnet_id: SubnetId,
    target_version: u64,
    logger: &slog::Logger,
) {
    retry_with_msg_async!(
        format!("waiting for subnet {subnet_id} to reach registry version {target_version}"),
        logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let reply = ut
                .update(
                    wasm()
                        .call_simple(
                            IC_00,
                            Method::SubnetInfo,
                            call_args().other_side(
                                SubnetInfoArgs {
                                    subnet_id: subnet_id.get(),
                                }
                                .encode(),
                            ),
                        )
                        .build(),
                )
                .await
                .map_err(|e| anyhow::anyhow!("subnet_info call failed: {e}"))?;
            let response = Decode!(&reply, SubnetInfoResponse)
                .map_err(|e| anyhow::anyhow!("failed to decode SubnetInfoResponse: {e}"))?;
            if response.registry_version < target_version {
                bail!(
                    "subnet {subnet_id} at registry version {} (target: {target_version})",
                    response.registry_version
                );
            }
            Ok(())
        }
    )
    .await
    .unwrap_or_else(|e| {
        panic!("subnet {subnet_id} did not reach registry version {target_version}: {e}")
    });
}
