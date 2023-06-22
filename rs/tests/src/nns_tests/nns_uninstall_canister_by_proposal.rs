/* tag::catalog[]
Title:: Uninstall a canister from a subnet via proposal

Goal:: Ensure that canisters can be uninstalled via proposals submitted to the governance canister.

Runbook::
. Setup:
   . System subnet comprising one node and a governance canister.
. Install a test canister.
. Assert that `update` call executes successfully on the test canister.
. Submit a proposal to the Governance Canister to uninstall the test canister.
. Assert that `update` call fails on the test canister.

Success::
. Update call executes successfully on the test canister after its installation.
. Update call fails on the test canister after being uninstalled.


end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
};
use crate::util::{runtime_from_url, UniversalCanister};
use crate::{
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    types::CanisterIdRecord,
    util::block_on,
};
use ic_agent::{export::Principal, Agent};
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_utils::{call::AsyncCall, interfaces::ManagementCanister};
use slog::info;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let log = env.logger();
    info!(log, "Installing NNS canisters on the root subnet...");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");
    info!(log, "NNS canisters installed successfully.");
    let nns_agent = nns_node.with_default_agent(|agent| async move { agent });
    // Install a test canister.
    let test_canister_id = block_on(UniversalCanister::new_with_retries(
        &nns_agent,
        nns_node.effective_canister_id(),
        &log,
    ))
    .canister_id();
    // Assert that `update` message can be sent to the test canister.
    block_on(assert_canister_update_call(
        true,
        &test_canister_id,
        &nns_agent,
    ));
    // Submit a proposal to the Governance Canister to uninstall the test canister.
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister =
        canister_test::Canister::new(&nns_runtime, ic_nns_constants::GOVERNANCE_CANISTER_ID);
    let proposal_payload = CanisterIdRecord {
        canister_id: test_canister_id,
    };
    let proposal_id = block_on(submit_external_proposal_with_test_id(
        &governance_canister,
        NnsFunction::UninstallCode,
        proposal_payload,
    ));
    block_on(vote_execute_proposal_assert_executed(
        &governance_canister,
        proposal_id,
    ));
    //Assert that `update` message can no longer be sent to the test canister.
    block_on(assert_canister_update_call(
        false,
        &test_canister_id,
        &nns_agent,
    ));
}

async fn assert_canister_update_call(
    expect_call_success: bool,
    canister_id: &Principal,
    agent: &Agent,
) {
    let has_module_hash = || async {
        ManagementCanister::create(agent)
            .canister_status(canister_id)
            .call_and_wait()
            .await
            .unwrap()
            .0
            .module_hash
            .is_some()
    };
    match expect_call_success {
        true => assert!(has_module_hash().await),
        false => assert!(!has_module_hash().await),
    }
}
