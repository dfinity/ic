/* tag::catalog[]
end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::{SshKeyGen, TestEnv};
use crate::driver::test_env_api::{
    HasGroupSetup, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationExt, ADMIN,
};
use crate::tecdsa::tecdsa_signature_test::{
    get_public_key_with_logger, get_signature_with_logger, make_key, verify_signature, KEY_ID1,
};
use crate::util::{runtime_from_url, MessageCanister};
use canister_test::{Canister, Cycles};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_types::malicious_behaviour::MaliciousBehaviour;
use ic_types::Height;
use slog::info;

use super::tecdsa_signature_test::{enable_ecdsa_signing, DKG_INTERVAL};

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    env.ssh_keygen(ADMIN).expect("ssh-keygen failed");
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

/// Tests whether a call to `sign_with_ecdsa` is responded with a signature
/// that is verifiable with the result from `ecdsa_public_key`. This is done
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
    nns_honest_node
        .install_nns_canisters()
        .expect("Could not install NNS canisters.");
    info!(&log, "Successfully installed NNS canisters");
    let nns_agent = nns_honest_node.with_default_agent(|agent| async move { agent });
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let nns_runtime = runtime_from_url(nns_honest_node.get_public_url());
        let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
        enable_ecdsa_signing(&governance, nns_subnet.subnet_id, make_key(KEY_ID1)).await;

        let msg_can =
            MessageCanister::new(&nns_agent, nns_honest_node.effective_canister_id()).await;
        let message_hash = [0xabu8; 32];
        let public_key = get_public_key_with_logger(make_key(KEY_ID1), &msg_can, &log)
            .await
            .unwrap();
        let signature = get_signature_with_logger(
            &message_hash,
            Cycles::zero(),
            make_key(KEY_ID1),
            &msg_can,
            &log,
        )
        .await
        .unwrap();
        verify_signature(&message_hash, &public_key, &signature);
    });
}
