/* tag::catalog[]
Title:: Creating, fetching and deleting a vetkey on a subnet

Goal:: Test whether the local DKG mechanism for vetkeys works


Runbook::
. Setup::
    . System subnet comprising N nodes, necessary NNS canisters
. Wait one DKG interval
. Enable vetkey on subnet
. Wait two DKG intervals, check subnet health
. TODO(CON-1420): Fetch the public key from a canister

end::catalog[] */

use anyhow::Result;
use canister_test::Canister;
use ic_consensus_system_test_utils::node::await_node_certified_height;
use ic_consensus_threshold_sig_system_test_utils::{
    add_chain_keys_with_timeout_and_rotation_period, DKG_INTERVAL,
};
use ic_management_canister_types::{MasterPublicKeyId, VetKdCurve, VetKdKeyId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        },
    },
    systest,
    util::{block_on, runtime_from_url},
};
use ic_types::Height;
use slog::info;

const NODES_COUNT: usize = 4;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    // Check all subnet nodes are healthy.
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn test(env: TestEnv) {
    let log = env.logger();
    let topology_snapshot = env.topology_snapshot();

    let nns_subnet = topology_snapshot.root_subnet();
    let nns_node = nns_subnet.nodes().next().unwrap();

    info!(log, "Installing nns canisters.");
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters.");

    // TODO(CON-1420): Install message canister to fetch keys
    // TODO: Since installing these canisters takes some time, we should actually
    // take the hight at this moment as the base for the test and then wait relative to that.

    // Wait one DKG
    await_node_certified_height(&nns_node, Height::from(DKG_INTERVAL + 1), log.clone());

    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = Canister::new(&nns_runtime, GOVERNANCE_CANISTER_ID);
    let key_ids = vec![MasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: String::from("some_vetkd_key"),
    })];

    block_on(async {
        //enable_chain_key_signing(&governance, nns_subnet.subnet_id, key_ids.clone(), &log).await;
        add_chain_keys_with_timeout_and_rotation_period(
            &governance,
            nns_subnet.subnet_id,
            key_ids.clone(),
            None,
            None,
            &log,
        )
        .await;
    });

    // Wait two DKGs
    await_node_certified_height(&nns_node, Height::from((DKG_INTERVAL + 1) * 3), log.clone());
    // TODO(CON-1420): Fetch public key from subnet

    // Wait two more DKGs
    await_node_certified_height(&nns_node, Height::from((DKG_INTERVAL + 1) * 5), log.clone());
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
