use anyhow::Result;
use candid::{Decode, Encode};
use ic_agent::agent::RejectCode;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::types::CreateCanisterResult;
use ic_system_test_driver::util::{assert_reject, block_on, UniversalCanister};
use ic_types::Cycles;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
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
