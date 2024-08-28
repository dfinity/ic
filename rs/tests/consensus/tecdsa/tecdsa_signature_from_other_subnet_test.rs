use anyhow::Result;

use canister_test::Canister;
use ic_consensus_threshold_sig_system_test_utils::{
    enable_chain_key_signing, get_public_key_and_test_signature, make_key_ids_for_all_schemes,
    setup,
};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    systest,
    util::{block_on, runtime_from_url, MessageCanister},
};
use itertools::Itertools;

fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_subnet = topology.root_subnet();
    let (app_subnet_1, app_subnet_2) = topology
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .tuples()
        .next()
        .unwrap();
    let nns_node = nns_subnet.nodes().next().unwrap();
    let node_from_app_subnet_1 = app_subnet_1.nodes().next().unwrap();
    let agent_for_app_subnet_1 = node_from_app_subnet_1.build_default_agent();

    block_on(async move {
        let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
        let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
        let key_ids = make_key_ids_for_all_schemes();
        enable_chain_key_signing(&governance, app_subnet_2.subnet_id, key_ids.clone(), &log).await;
        let msg_can = MessageCanister::new(
            &agent_for_app_subnet_1,
            node_from_app_subnet_1.effective_canister_id(),
        )
        .await;

        for key_id in &key_ids {
            get_public_key_and_test_signature(key_id, &msg_can, false, &log)
                .await
                .expect("Should successfully create and verify the signature");
        }
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
