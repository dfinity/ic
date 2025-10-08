use anyhow::Result;
use ic_agent::{AgentError, agent::RejectCode, export::Principal};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{
    UniversalCanister, assert_http_submit_fails, assert_reject, block_on, set_controller,
};
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, management, wasm};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(controller_and_controllee_on_different_subnets))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::VerifiedApplication))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// A test to ensure that controller and controllee canisters can exist on
/// different subnets and they can still control each other.
pub fn controller_and_controllee_on_different_subnets(env: TestEnv) {
    let logger = env.logger();
    let ver_app_node = env.get_first_healthy_verified_application_node_snapshot();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let combinations = vec![
        (ver_app_node.clone(), app_node.clone()),
        (app_node, ver_app_node),
    ];
    block_on({
        async move {
            async fn install_via_cr(
                cr: &UniversalCanister<'_>,
                target: Principal,
            ) -> Result<Vec<u8>, AgentError> {
                cr.update(
                    wasm().call(
                        management::install_code(target, &*UNIVERSAL_CANISTER_WASM)
                            .with_mode(management::InstallMode::Reinstall),
                    ),
                )
                .await
            }

            for (cr_node, ce_node) in combinations {
                let controller_agent = cr_node.build_default_agent_async().await;
                let controllee_agent = ce_node.build_default_agent_async().await;

                let controller = UniversalCanister::new_with_retries(
                    &controller_agent,
                    cr_node.effective_canister_id(),
                    &logger,
                )
                .await;
                let controllee = UniversalCanister::new_with_retries(
                    &controllee_agent,
                    ce_node.effective_canister_id(),
                    &logger,
                )
                .await;

                // before setting the controller, this call must fail.
                assert_reject(
                    install_via_cr(&controller, controllee.canister_id()).await,
                    RejectCode::CanisterReject,
                );

                set_controller(
                    &controllee.canister_id(),
                    &controller.canister_id(),
                    &controllee_agent,
                )
                .await;

                let mgr = ManagementCanister::create(&controllee_agent);
                assert_http_submit_fails(
                    mgr.stop_canister(&controllee.canister_id()).call().await,
                    RejectCode::CanisterError,
                );

                install_via_cr(&controller, controllee.canister_id())
                    .await
                    .unwrap();

                controller
                    .update(wasm().call(management::stop_canister(controllee.canister_id())))
                    .await
                    .unwrap();

                controller
                    .update(wasm().call(management::delete_canister(controllee.canister_id())))
                    .await
                    .unwrap();
            }
        }
    })
}
