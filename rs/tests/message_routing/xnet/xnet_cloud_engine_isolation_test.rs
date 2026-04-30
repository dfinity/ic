/* tag::catalog[]
Title:: CloudEngine subnets are isolated from XNet traffic.

Goal:: Verify that a CloudEngine subnet cannot exchange XNet messages with
other subnets (including other CloudEngine subnets), while intra-subnet
(loopback) calls still work. Additionally verify that the state tree only
exposes the expected subnets via /subnet and /canister_ranges.

Runbook::
0. Set up an IC with one System (NNS) subnet, one Application subnet, and
   two CloudEngine subnets. No NNS canisters are installed.
1. Install universal canisters on every subnet.
2. Verify that each CloudEngine canister can call itself (self-call).
3. Verify that two canisters on the same CloudEngine subnet can call each
   other (intra-subnet).
4. Verify that XNet calls between NNS and Application subnets succeed
   (both directions).
5. Verify that XNet calls involving any CloudEngine subnet are rejected:
   Application <-> CloudEngine, NNS <-> CloudEngine, and
   CloudEngine 1 <-> CloudEngine 2.
6. Via read_state, verify that /subnet/<id>/public_key and
   /canister_ranges/<id> are present only for the expected subnets:
   - NNS sees all four subnets (full topology).
   - Application sees NNS and itself.
   - Each CloudEngine sees only itself.

Success::
All assertions pass: loopback works, non-CloudEngine XNet works,
all cross-subnet directions involving CloudEngine are rejected, and
the state tree matches the expected visibility.

end::catalog[] */

use anyhow::Result;
use ic_agent::hash_tree::{Label, LookupResult, SubtreeLookupResult};
use ic_error_types::RejectCode;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{UniversalCanister, block_on};
use ic_universal_canister::{call_args, wasm};
use slog::info;
use std::time::Duration;

const PER_TASK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TASK_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .execute_from_args()?;
    Ok(())
}

fn setup(env: TestEnv) {
    InternetComputer::new()
        .with_api_boundary_nodes_playnet(1)
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .add_subnet(Subnet::fast_single_node(SubnetType::CloudEngine))
        .add_subnet(Subnet::fast_single_node(SubnetType::CloudEngine))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

/// Assert that the update call succeeded and the reply payload encodes the
/// given reject code as a little-endian u32 (as produced by the UC's
/// `reject_code().reply_int()` on_reject handler).
fn assert_xnet_rejected(res: Result<Vec<u8>, ic_agent::AgentError>, expected: RejectCode) {
    let reply = res.expect("Expected the update call to succeed (UC replies with reject code)");
    assert_eq!(
        reply.len(),
        4,
        "Expected 4-byte reject code blob, got {} bytes: {reply:?}",
        reply.len()
    );
    let code = u32::from_le_bytes(reply[..4].try_into().unwrap());
    let expected_code = expected as u32;
    assert_eq!(
        code, expected_code,
        "Expected reject code {expected:?} ({expected_code}), got {code}"
    );
}

fn test(env: TestEnv) {
    let logger = env.logger();
    block_on(async move {
        // Get one node from each subnet.
        let nns_node = env.get_first_healthy_nns_node_snapshot();
        let app_node = env.get_first_healthy_application_node_snapshot();
        let ce_node_1 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(
            |s| s.subnet_type() == SubnetType::CloudEngine,
            0,
        );
        let ce_node_2 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(
            |s| s.subnet_type() == SubnetType::CloudEngine,
            1,
        );

        let nns_agent = nns_node.build_default_agent_async().await;
        let app_agent = app_node.build_default_agent_async().await;
        let ce_agent_1 = ce_node_1.build_default_agent_async().await;
        let ce_agent_2 = ce_node_2.build_default_agent_async().await;

        info!(logger, "Installing universal canisters...");
        let uc_nns = UniversalCanister::new_with_retries(
            &nns_agent,
            nns_node.effective_canister_id(),
            &logger,
        )
        .await;
        let uc_app = UniversalCanister::new_with_retries(
            &app_agent,
            app_node.effective_canister_id(),
            &logger,
        )
        .await;
        let uc_ce_1a = UniversalCanister::new_with_retries(
            &ce_agent_1,
            ce_node_1.effective_canister_id(),
            &logger,
        )
        .await;
        let uc_ce_1b = UniversalCanister::new_with_retries(
            &ce_agent_1,
            ce_node_1.effective_canister_id(),
            &logger,
        )
        .await;
        let uc_ce_2a = UniversalCanister::new_with_retries(
            &ce_agent_2,
            ce_node_2.effective_canister_id(),
            &logger,
        )
        .await;
        let uc_ce_2b = UniversalCanister::new_with_retries(
            &ce_agent_2,
            ce_node_2.effective_canister_id(),
            &logger,
        )
        .await;

        let data = vec![42_u8];

        // ── Intra-subnet calls on CloudEngine subnets ───────────────────

        // 1. Each CloudEngine canister can call itself (self-call).
        info!(logger, "Testing self-call on CloudEngine subnet 1...");
        let res = uc_ce_1a
            .update(
                wasm().inter_update(
                    uc_ce_1a.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_message().reject()),
                ),
            )
            .await;
        assert_eq!(
            res.unwrap(),
            data,
            "Self-call on CloudEngine subnet 1 should succeed"
        );
        info!(logger, "Self-call on CloudEngine subnet 1 succeeded.");

        info!(logger, "Testing self-call on CloudEngine subnet 2...");
        let res = uc_ce_2a
            .update(
                wasm().inter_update(
                    uc_ce_2a.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_message().reject()),
                ),
            )
            .await;
        assert_eq!(
            res.unwrap(),
            data,
            "Self-call on CloudEngine subnet 2 should succeed"
        );
        info!(logger, "Self-call on CloudEngine subnet 2 succeeded.");

        // 2. Intra-subnet call between two different canisters on the same CloudEngine subnet.
        info!(
            logger,
            "Testing intra-subnet call on CloudEngine subnet 1..."
        );
        let res = uc_ce_1a
            .update(
                wasm().inter_update(
                    uc_ce_1b.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_message().reject()),
                ),
            )
            .await;
        assert_eq!(
            res.unwrap(),
            data,
            "Intra-subnet call on CloudEngine subnet 1 should succeed"
        );
        info!(
            logger,
            "Intra-subnet call on CloudEngine subnet 1 succeeded."
        );

        info!(
            logger,
            "Testing intra-subnet call on CloudEngine subnet 2..."
        );
        let res = uc_ce_2a
            .update(
                wasm().inter_update(
                    uc_ce_2b.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_message().reject()),
                ),
            )
            .await;
        assert_eq!(
            res.unwrap(),
            data,
            "Intra-subnet call on CloudEngine subnet 2 should succeed"
        );
        info!(
            logger,
            "Intra-subnet call on CloudEngine subnet 2 succeeded."
        );

        // ── XNet calls that should succeed (non-CloudEngine pairs) ──────

        // 3. NNS → Application should succeed.
        info!(
            logger,
            "Testing XNet call: NNS -> Application (should succeed)..."
        );
        let res = uc_nns
            .update(
                wasm().inter_update(
                    uc_app.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_message().reject()),
                ),
            )
            .await;
        assert_eq!(
            res.unwrap(),
            data,
            "NNS -> Application XNet call should succeed"
        );
        info!(logger, "NNS -> Application succeeded.");

        // 4. Application → NNS should succeed.
        info!(
            logger,
            "Testing XNet call: Application -> NNS (should succeed)..."
        );
        let res = uc_app
            .update(
                wasm().inter_update(
                    uc_nns.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_message().reject()),
                ),
            )
            .await;
        assert_eq!(
            res.unwrap(),
            data,
            "Application -> NNS XNet call should succeed"
        );
        info!(logger, "Application -> NNS succeeded.");

        // ── XNet calls that should be rejected (CloudEngine involved) ───

        // All cross-subnet calls involving a CloudEngine subnet must fail
        // with DestinationInvalid. The on_reject handler replies with the
        // reject code so we can verify the exact code.
        let rejected_pairs: &[(&str, &UniversalCanister<'_>, &str, &UniversalCanister<'_>)] = &[
            ("Application", &uc_app, "CloudEngine 1", &uc_ce_1a),
            ("CloudEngine 1", &uc_ce_1a, "Application", &uc_app),
            ("NNS", &uc_nns, "CloudEngine 1", &uc_ce_1a),
            ("CloudEngine 1", &uc_ce_1a, "NNS", &uc_nns),
            ("NNS", &uc_nns, "CloudEngine 2", &uc_ce_2a),
            ("CloudEngine 2", &uc_ce_2a, "NNS", &uc_nns),
            ("CloudEngine 1", &uc_ce_1a, "CloudEngine 2", &uc_ce_2a),
            ("CloudEngine 2", &uc_ce_2a, "CloudEngine 1", &uc_ce_1a),
        ];

        for (src_name, src_uc, dst_name, dst_uc) in rejected_pairs {
            info!(
                logger,
                "Testing XNet call: {src_name} -> {dst_name} (should fail)..."
            );
            let res = src_uc
                .update(
                    wasm().inter_update(
                        dst_uc.canister_id(),
                        call_args()
                            .other_side(wasm().reply_data(&data))
                            .on_reject(wasm().reject_code().reply_int()),
                    ),
                )
                .await;
            assert_xnet_rejected(res, RejectCode::DestinationInvalid);
            info!(logger, "{src_name} -> {dst_name} correctly rejected.");
        }

        // ── Verify /subnet and /canister_ranges via read_state ──────────
        //
        // For each subnet we query /subnet/<id>/public_key and
        // /canister_ranges/<id> for every known subnet ID and verify that
        // the expected ones are present and the rest absent.
        //
        // NNS sees all subnets (full topology for the state tree).
        // Application sees NNS and itself.
        // Each CloudEngine sees only itself.
        info!(
            logger,
            "Verifying /subnet and /canister_ranges via read_state..."
        );

        let nns_subnet_id = nns_node.subnet_id().unwrap();
        let app_subnet_id = app_node.subnet_id().unwrap();
        let ce_subnet_id_1 = ce_node_1.subnet_id().unwrap();
        let ce_subnet_id_2 = ce_node_2.subnet_id().unwrap();

        let all_subnets = [
            ("NNS", nns_subnet_id),
            ("Application", app_subnet_id),
            ("CloudEngine 1", ce_subnet_id_1),
            ("CloudEngine 2", ce_subnet_id_2),
        ];

        for (name, agent, own_subnet_id, expected_ids) in [
            (
                "NNS",
                &nns_agent,
                nns_subnet_id,
                vec![nns_subnet_id, app_subnet_id, ce_subnet_id_1, ce_subnet_id_2],
            ),
            (
                "Application",
                &app_agent,
                app_subnet_id,
                vec![nns_subnet_id, app_subnet_id],
            ),
            (
                "CloudEngine 1",
                &ce_agent_1,
                ce_subnet_id_1,
                vec![ce_subnet_id_1],
            ),
            (
                "CloudEngine 2",
                &ce_agent_2,
                ce_subnet_id_2,
                vec![ce_subnet_id_2],
            ),
        ] {
            info!(logger, "Checking /subnet and /canister_ranges on {name}...");

            // Query /subnet/<id>/public_key for all known subnet IDs in one
            // call (no restriction on mixing subnet IDs in /subnet paths).
            let subnet_paths: Vec<Vec<Label<Vec<u8>>>> = all_subnets
                .iter()
                .map(|(_target_name, id)| {
                    let id_label: Label<Vec<u8>> = id.get_ref().as_slice().into();
                    vec!["subnet".into(), id_label, "public_key".into()]
                })
                .collect();

            let cert = agent
                .read_subnet_state_raw(subnet_paths, own_subnet_id.get().into())
                .await
                .expect("read_state should succeed");

            for (target_name, id) in &all_subnets {
                let id_bytes = id.get_ref().as_slice();
                let should_be_visible = expected_ids.contains(id);

                // Check /subnet/<id>/public_key
                let subnet_result = cert.tree.lookup_path(&[
                    b"subnet".as_slice(),
                    id_bytes,
                    b"public_key".as_slice(),
                ]);
                assert_eq!(
                    matches!(subnet_result, LookupResult::Found(_)),
                    should_be_visible,
                    "{name}: /subnet/{target_name}/public_key visibility mismatch \
                     (expected visible={should_be_visible}, got {subnet_result:?})"
                );

                // Check /canister_ranges/<id> in separate calls per subnet ID
                // (the endpoint rejects requests with multiple distinct subnet IDs
                // in canister_ranges paths).
                let id_label: Label<Vec<u8>> = id.get_ref().as_slice().into();
                let cr_cert = agent
                    .read_subnet_state_raw(
                        vec![vec!["canister_ranges".into(), id_label]],
                        own_subnet_id.get().into(),
                    )
                    .await
                    .expect("read_state for canister_ranges should succeed");
                let cr_result = cr_cert
                    .tree
                    .lookup_subtree(&[b"canister_ranges".as_slice(), id_bytes]);
                assert_eq!(
                    matches!(cr_result, SubtreeLookupResult::Found(_)),
                    should_be_visible,
                    "{name}: /canister_ranges/{target_name} visibility mismatch \
                     (expected visible={should_be_visible}, got {cr_result:?})"
                );
            }

            info!(logger, "{name}: /subnet and /canister_ranges verified.");
        }

        info!(logger, "All assertions passed.");
    });
}
