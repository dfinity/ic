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

use crate::util::{assert_create_agent, delay, runtime_from_url, UniversalCanister};
use crate::{
    nns::{submit_external_proposal_with_test_id, vote_execute_proposal_assert_executed, NnsExt},
    types::CanisterIdRecord,
    util::{assert_endpoints_reachability, block_on, EndpointsStatus},
};
use ic_agent::{export::Principal, Agent};
use ic_fondue::{
    ic_instance::{InternetComputer, Subnet},
    ic_manager::IcHandle,
};
use ic_nns_governance::pb::v1::NnsFunction;
use ic_registry_subnet_type::SubnetType;
use ic_utils::{call::AsyncCall, interfaces::ManagementCanister};

pub fn config() -> InternetComputer {
    InternetComputer::new().add_subnet(Subnet::fast_single_node(SubnetType::System))
}

pub fn test(handle: IcHandle, ctx: &ic_fondue::pot::Context) {
    // Setup: install all necessary NNS canisters (including Governance).
    ctx.install_nns_canisters(&handle, true);
    // Assert all nodes are reachable via http:://[IPv6]:8080/api/v2/status
    let mut rng = ctx.rng.clone();
    let endpoints: Vec<_> = handle.as_permutation(&mut rng).collect();
    block_on(async {
        assert_endpoints_reachability(endpoints.as_slice(), EndpointsStatus::AllReachable).await
    });
    // Install a test canister.
    let agent = block_on(assert_create_agent(endpoints[0].url.as_str()));
    let test_canister_id = block_on(UniversalCanister::new(&agent)).canister_id();
    // Assert that `update` message can be sent to the test canister.
    block_on(assert_canister_update_call(true, &test_canister_id, &agent));
    // Submit a proposal to the Governance Canister to uninstall the test canister.
    let nns_runtime = runtime_from_url(endpoints[0].url.clone());
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
