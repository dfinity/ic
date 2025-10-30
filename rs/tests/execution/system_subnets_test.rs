#![allow(deprecated)]
use anyhow::Result;
use candid::{Decode, Encode, Principal};
use ic_agent::AgentError;
use ic_agent::agent::RejectCode;
use ic_cdk::api::management_canister::main::{CanisterIdRecord, CanisterStatusResponse};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::types::CreateCanisterResult;
use ic_system_test_driver::util::{UniversalCanister, assert_reject, block_on};
use ic_types::Cycles;
use ic_utils::interfaces::ManagementCanister;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(ingress_message_to_subnet_id_fails))
        .add_test(systest!(
            non_nns_canister_attempt_to_create_canister_on_another_subnet_fails
        ))
        .add_test(systest!(
            nns_canister_attempt_to_create_canister_on_another_subnet_succeeds
        ))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// Tests that an ingress message to a subnet ID fails.
pub fn ingress_message_to_subnet_id_fails(env: TestEnv) {
    let ver_app_node = env.get_first_healthy_verified_application_node_snapshot();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let sys_node = env.get_first_healthy_system_node_snapshot();
    let sys_no_nns_node = env.get_first_healthy_system_but_not_nns_node_snapshot();
    let ver_app_agent = ver_app_node.build_default_agent();
    let app_agent = app_node.build_default_agent();
    let sys_agent = sys_node.build_default_agent();
    let sys_no_nns_agent = sys_no_nns_node.build_default_agent();
    block_on(async move {
        // Check that an ingress message to a subnet ID fails
        // by successfully creating a canister using the provisional API (via an agent)
        // and then requesting `canister_status` for that canister
        // using the subnet ID as the callee (instead of the management canister ID).
        for (agent, node) in [
            (&ver_app_agent, &ver_app_node),
            (&app_agent, &app_node),
            (&sys_agent, &sys_node),
            (&sys_no_nns_agent, &sys_no_nns_node),
        ] {
            let mgr = ManagementCanister::create(agent);

            // Successfully create a canister on the corresponding subnet.
            let effective_canister_id = node.effective_canister_id();
            let canister_id: Principal = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(effective_canister_id)
                .call_and_wait()
                .await
                .unwrap()
                .0;

            let arg = CanisterIdRecord { canister_id };
            let subnet_id: Principal = node.subnet_id().unwrap().get().into();
            let agent_call = |callee: &Principal, effective_canister_id: &Principal| {
                agent
                    .update(callee, "canister_status")
                    .with_arg(Encode!(&arg).unwrap())
                    .with_effective_canister_id(*effective_canister_id)
                    .call_and_wait()
            };

            // Requesting `canister_status` using the subnet ID as the callee and as the effective canister ID fails
            // in the execution environment.
            let err = agent_call(&subnet_id, &subnet_id).await.unwrap_err();
            match err {
                AgentError::UncertifiedReject { reject, .. } => {
                    assert!(
                        reject
                            .reject_message
                            .contains(&format!("Canister {subnet_id} not found"))
                    );
                }
                _ => panic!("Unexpected error: {err:?}"),
            };

            // Requesting `canister_status` using the subnet ID as the callee and the canister ID as the effective canister ID fails
            // in the HTTP handler.
            let err = agent_call(&subnet_id, &canister_id).await.unwrap_err();
            match err {
                AgentError::HttpError(payload) => {
                    let error_message = String::from_utf8(payload.content).unwrap();
                    assert!(error_message.contains(&format!(
                        "Specified CanisterId {subnet_id} does not match effective canister id in URL {canister_id}"
                    )));
                }
                _ => panic!("Unexpected error: {err:?}"),
            };

            // The same call using the management canister ID as the callee and the canister ID as the effective canister ID succeeds
            // and returns a response of the corresponding type.
            let res = agent_call(&Principal::management_canister(), &canister_id)
                .await
                .unwrap();
            let _ = Decode!(&res, CanisterStatusResponse).unwrap();
        }
    });
}

/// Tests whether creating a canister on a subnet other than self fails when not
/// on the NNS subnet.
pub fn non_nns_canister_attempt_to_create_canister_on_another_subnet_fails(env: TestEnv) {
    let logger = env.logger();
    let ver_app_node = env.get_first_healthy_verified_application_node_snapshot();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let sys_node = env.get_first_healthy_system_node_snapshot();
    let sys_no_nns_node = env.get_first_healthy_system_but_not_nns_node_snapshot();
    let ver_app_agent = ver_app_node.build_default_agent();
    let app_agent = app_node.build_default_agent();
    let sys_no_nns_agent = sys_no_nns_node.build_default_agent();
    block_on(async move {
        // Check that canisters on non-NNS subnets cannot create canisters on other
        // subnets (including itself) by specifying their subnet ID as the callee.
        for (source_agent, source_node) in [
            (&ver_app_agent, &ver_app_node),
            (&app_agent, &app_node),
            (&sys_no_nns_agent, &sys_no_nns_node),
        ] {
            let uni_can = UniversalCanister::new_with_cycles_with_retries(
                source_agent,
                source_node.effective_canister_id(),
                900_000_000_000_000_u64,
                &logger,
            )
            .await;
            for other_subnet in [
                ver_app_node.subnet_id().unwrap(),
                app_node.subnet_id().unwrap(),
                sys_node.subnet_id().unwrap(),
                sys_no_nns_node.subnet_id().unwrap(),
            ] {
                let res = uni_can
                    .forward_with_cycles_to(
                        &other_subnet.get().into(),
                        "create_canister",
                        Encode!().unwrap(),
                        Cycles::from(100_000_000_000_000u64),
                    )
                    .await
                    .map(|res| {
                        Decode!(res.as_slice(), CreateCanisterResult)
                            .unwrap()
                            .canister_id
                    });
                assert_reject(res, RejectCode::CanisterReject);
            }
        }
    });
}

/// Tests whether creating a canister on another subnet (including itself) is possible from an NNS
/// canister.
pub fn nns_canister_attempt_to_create_canister_on_another_subnet_succeeds(env: TestEnv) {
    let logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let non_nns_node = env.get_first_healthy_non_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    block_on(async move {
        let uni_can = UniversalCanister::new_with_cycles_with_retries(
            &agent,
            nns_node.effective_canister_id(),
            900_000_000_000_000_u64,
            &logger,
        )
        .await;
        for other_subnet in [
            nns_node.subnet_id().unwrap(),
            non_nns_node.subnet_id().unwrap(),
        ] {
            uni_can
                .forward_with_cycles_to(
                    &other_subnet.get().into(),
                    "create_canister",
                    Encode!().unwrap(),
                    Cycles::from(100_000_000_000_000u64),
                )
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .unwrap();
        }
    });
}
