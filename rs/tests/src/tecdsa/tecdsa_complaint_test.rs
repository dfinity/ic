/* tag::catalog[]
end::catalog[] */

use super::{enable_chain_key_signing, DKG_INTERVAL};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
};
use crate::tecdsa::{get_public_key_and_test_signature, make_key_ids_for_all_schemes};
use crate::util::{assert_malicious_from_topo, runtime_from_url, MessageCanister};
use canister_test::Canister;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::Height;
use slog::info;

pub fn config(env: TestEnv) {
    let malicious_behaviour =
        MaliciousBehaviour::new(true).set_maliciously_corrupt_ecdsa_dealings();
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

/// Tests whether a call to `sign_with_ecdsa`/`sign_with_schnorr` is responded with a signature
/// that is verifiable with the result from `ecdsa_public_key`/`schnorr_public_key`. This is done
/// in the presence of corrupted dealings/complaints.
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
    let nns_subnet = topology.root_subnet();
    let nns_honest_node = nns_subnet
        .nodes()
        .find(|n| !n.is_malicious())
        .expect("No honest node found in the subnet");
    let _ = nns_subnet
        .nodes()
        .find(|n| n.is_malicious())
        .expect("No malicious node found in the subnet");
    info!(&log, "Installing NNS canisters on the System subnet...");
    NnsInstallationBuilder::new()
        .install(&nns_honest_node, &env)
        .expect("Could not install NNS canisters.");
    info!(&log, "Successfully installed NNS canisters");
    let nns_agent = nns_honest_node.with_default_agent(|agent| async move { agent });
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    let logger = log.clone();
    rt.block_on(async move {
        let nns_runtime = runtime_from_url(
            nns_honest_node.get_public_url(),
            nns_honest_node.effective_canister_id(),
        );
        let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
        let key_ids = make_key_ids_for_all_schemes();
        enable_chain_key_signing(&governance, nns_subnet.subnet_id, key_ids.clone(), &log).await;

        let msg_can =
            MessageCanister::new(&nns_agent, nns_honest_node.effective_canister_id()).await;
        for key_id in &key_ids {
            let _public_key = get_public_key_and_test_signature(key_id, &msg_can, true, &log)
                .await
                .unwrap();
        }
    });

    info!(logger, "Checking for malicious logs...");
    assert_malicious_from_topo(&topology, vec!["maliciously_corrupt_ecdsa_dealings: true"]);
    info!(logger, "Malicious log check succeeded.");
}
