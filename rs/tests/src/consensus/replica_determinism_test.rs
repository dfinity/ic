/* tag::catalog[]
Title:: Replica Determinism Test

Goal:: Ensure that a node restarts and catches up after realizing a divergence of state. It can contribute to consensus after restarting.

Runbook::
. Set up one subnet
. Make a node diverge
. Wait until we see the newly started node's PID finalizing a block.

Success:: The restarted node reports block finalizations.


end::catalog[] */

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    util::*,
};
use ic_types::{malicious_behaviour::MaliciousBehaviour, Height};
use ic_universal_canister::wasm;
use slog::info;

const DKG_INTERVAL: u64 = 9;
const FAULT_HEIGHT: u64 = DKG_INTERVAL + 1;

pub fn config(env: TestEnv) {
    let malicious_behaviour =
        MaliciousBehaviour::new(true).set_maliciously_corrupt_own_state_at_heights(FAULT_HEIGHT);
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(3)
                .add_malicious_nodes(1, malicious_behaviour),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// As the malicious behavior `CorruptOwnStateAtHeights` is enabled, this test
/// waits for the state to diverge and makes sure that the faulty replica is
/// restarted and that it can contribute to consensus afterwards.
pub fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    info!(log, "Checking readiness of all nodes after the IC setup...");
    topology.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(log, "All nodes are ready, IC setup succeeded.");
    let malicious_node = topology
        .root_subnet()
        .nodes()
        .find(|n| n.is_malicious())
        .expect("No malicious node found in the subnet.");
    let agent = malicious_node.with_default_agent(|agent| async move { agent });
    let rt = tokio::runtime::Runtime::new().expect("could not create tokio runtime");
    rt.block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                malicious_node.effective_canister_id(),
                &log,
            )
            .await;

            // After N update&query requests the height of a subnet is >= N.
            // Thus, if N = FAULT_HEIGHT, it's guaranteed that divergence happens along the
            // way.
            for n in 0..FAULT_HEIGHT {
                let mut result = agent
                    .update(&canister.canister_id(), "update")
                    .with_arg(wasm().set_global_data(&[n as u8]).reply())
                    .call_and_wait()
                    .await;
                // Error is expected after the malicious node panics due to divergence.
                if result.is_err() {
                    break;
                }
                result = canister
                    .query(wasm().get_global_data().append_and_reply())
                    .await;
                if result.is_err() {
                    break;
                }
                assert_eq!(result, Ok(vec![n as u8]));
            }

            info!(log, "Checking for malicious logs...");
            // Use unspecific allow_malicious_behaviour instead of specific maliciously_corrupt_own_state_at_heights
            assert_node_malicious(
                malicious_node.clone(),
                vec!["allow_malicious_behaviour: true"],
            )
            .await;
            info!(log, "Malicious log check succeeded.");

            // Wait until the malicious node restarts.
            malicious_node
                .await_status_is_healthy()
                .expect("Node didn't report healthy");

            // For the same reason as before, if N = DKG_INTERVAL + 1, it's guaranteed
            // that a catch up package is proposed by the faulty node.
            for n in 0..(DKG_INTERVAL + 1) {
                agent
                    .update(&canister.canister_id(), "update")
                    .with_arg(wasm().set_global_data(&[n as u8]).reply())
                    .call_and_wait()
                    .await
                    .expect("failed to update");
                let response = canister
                    .query(wasm().get_global_data().append_and_reply())
                    .await
                    .expect("failed to query");
                assert_eq!(response, vec![n as u8]);
            }
        }
    });
}
