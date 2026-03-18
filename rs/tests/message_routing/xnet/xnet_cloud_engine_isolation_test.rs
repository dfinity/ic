/* tag::catalog[]
Title:: CloudEngine subnets are isolated from XNet traffic.

Goal:: Verify that a CloudEngine subnet cannot exchange XNet messages with
other subnets (including other CloudEngine subnets), while intra-subnet
(loopback) calls still work.

Runbook::
0. Set up an IC with one Application subnet and two CloudEngine subnets.
1. Install universal canisters: one on the Application subnet, two on each
   CloudEngine subnet.
2. Verify that each CloudEngine canister can call itself (self-call).
3. Verify that two canisters on the same CloudEngine subnet can call each
   other (intra-subnet).
4. Attempt an XNet call from the Application canister to a CloudEngine
   canister and assert that it is rejected.
5. Attempt an XNet call from a CloudEngine canister to the Application
   canister and assert that it is rejected.
6. Attempt XNet calls between the two CloudEngine subnets (both directions)
   and assert that they are rejected.

Success::
All assertions pass: loopback works, all cross-subnet directions are rejected.

end::catalog[] */

use anyhow::Result;
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
        let app_node = env.get_first_healthy_application_node_snapshot();
        let ce_node_1 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(
            |s| s.subnet_type() == SubnetType::CloudEngine,
            0,
        );
        let ce_node_2 = env.get_first_healthy_node_snapshot_from_nth_subnet_where(
            |s| s.subnet_type() == SubnetType::CloudEngine,
            1,
        );

        let app_agent = app_node.build_default_agent_async().await;
        let ce_agent_1 = ce_node_1.build_default_agent_async().await;
        let ce_agent_2 = ce_node_2.build_default_agent_async().await;

        info!(logger, "Installing universal canisters...");
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

        let data = vec![42u8];

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

        // 3. Application → CloudEngine should be rejected.
        // The on_reject handler replies with the reject code so we can verify
        // the system produced DestinationInvalid (3) rather than some other code.
        info!(
            logger,
            "Testing XNet call: Application -> CloudEngine (should fail)..."
        );
        let res = uc_app
            .update(
                wasm().inter_update(
                    uc_ce_1a.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_code().reply_int()),
                ),
            )
            .await;
        assert_xnet_rejected(res, RejectCode::DestinationInvalid);
        info!(logger, "Application -> CloudEngine correctly rejected.");

        // 4. CloudEngine → Application should be rejected.
        info!(
            logger,
            "Testing XNet call: CloudEngine -> Application (should fail)..."
        );
        let res = uc_ce_1a
            .update(
                wasm().inter_update(
                    uc_app.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_code().reply_int()),
                ),
            )
            .await;
        assert_xnet_rejected(res, RejectCode::DestinationInvalid);
        info!(logger, "CloudEngine -> Application correctly rejected.");

        // 5. CloudEngine 1 → CloudEngine 2 should be rejected.
        info!(
            logger,
            "Testing XNet call: CloudEngine 1 -> CloudEngine 2 (should fail)..."
        );
        let res = uc_ce_1a
            .update(
                wasm().inter_update(
                    uc_ce_2a.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_code().reply_int()),
                ),
            )
            .await;
        assert_xnet_rejected(res, RejectCode::DestinationInvalid);
        info!(logger, "CloudEngine 1 -> CloudEngine 2 correctly rejected.");

        // 6. CloudEngine 2 → CloudEngine 1 should be rejected.
        info!(
            logger,
            "Testing XNet call: CloudEngine 2 -> CloudEngine 1 (should fail)..."
        );
        let res = uc_ce_2a
            .update(
                wasm().inter_update(
                    uc_ce_1a.canister_id(),
                    call_args()
                        .other_side(wasm().reply_data(&data))
                        .on_reject(wasm().reject_code().reply_int()),
                ),
            )
            .await;
        assert_xnet_rejected(res, RejectCode::DestinationInvalid);
        info!(logger, "CloudEngine 2 -> CloudEngine 1 correctly rejected.");

        info!(logger, "All assertions passed.");
    });
}
