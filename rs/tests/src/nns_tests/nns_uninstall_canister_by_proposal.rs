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
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{HasTopologySnapshot, IcNodeContainer, NnsInstallationExt};
use crate::util::{assert_create_agent, delay, runtime_from_url, UniversalCanister};
use crate::{
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed},
    types::CanisterIdRecord,
    util::{assert_endpoints_health, block_on, EndpointsStatus},
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
}

pub fn test(env: TestEnv) {
    let logger = env.logger();

    info!(logger, "Installing NNS canisters on the root subnet...");
    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters");
    info!(&logger, "NNS canisters installed successfully.");

    let (handle, ref ctx) = get_ic_handle_and_ctx(env.clone());

    // Assert all nodes are reachable via http:://[IPv6]:8080/api/v2/status
    let mut rng = ctx.rng.clone();
    let endpoints: Vec<_> = handle.as_permutation(&mut rng).collect();
    block_on(async {
        assert_endpoints_health(endpoints.as_slice(), EndpointsStatus::AllHealthy).await
    });
    // Install a test canister.
    let agent = block_on(assert_create_agent(endpoints[0].url.as_str()));
    let test_canister_id = block_on(UniversalCanister::new_with_retries(
        &agent,
        endpoints[0].effective_canister_id(),
        &logger,
    ))
    .canister_id();
    // Assert that `update` message can be sent to the test canister.
    block_on(assert_canister_update_call(true, &test_canister_id, &agent));
    // Submit a proposal to the Governance Canister to uninstall the test canister.
    let nns_runtime = runtime_from_url(
        endpoints[0].url.clone(),
        endpoints[0].effective_canister_id(),
    );
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
        &agent,
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
            .call_and_wait(delay())
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
