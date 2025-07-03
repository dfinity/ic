use anyhow::Result;
use ic_agent::agent::RejectCode;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::*;
use ic_types::Cycles;
use ic_universal_canister::{management, wasm};
use ic_utils::interfaces::ManagementCanister;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(
            creating_canisters_fails_if_limit_of_allowed_canisters_is_reached
        ))
        .execute_from_args()?;

    Ok(())
}

// A special configuration for testing the maximum number of canisters on a
// subnet. The value is set to 3 for the tests.
pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System).with_max_number_of_canisters(3))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// This test assumes it's being executed using
/// `config_max_number_of_canisters`, which limits the allowed canisters on the
/// subnet to be 3.
pub fn creating_canisters_fails_if_limit_of_allowed_canisters_is_reached(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);
            // Create 3 canisters when 3 are allowed, should succeed.
            mgr.create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(node.effective_canister_id())
                .call_and_wait()
                .await
                .unwrap();
            mgr.create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(node.effective_canister_id())
                .call_and_wait()
                .await
                .unwrap();
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            // Attempt to create a fourth canister when only 3 are allowed, should fail.
            let res = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(node.effective_canister_id())
                .call_and_wait()
                .await;
            assert_reject(res, RejectCode::SysFatal);

            // Creating a canister via another canister would also fail since we're at
            // limit.
            assert_reject(
                canister
                    .update(wasm().call(management::create_canister(Cycles::from(
                        100_000_000_000u64,
                    ))))
                    .await,
                RejectCode::CanisterReject,
            );
        }
    })
}
