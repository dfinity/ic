use anyhow::Result;
use ic_config::execution_environment::SUBNET_MEMORY_RESERVATION;
use ic_registry_resource_limits::ResourceLimits;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::*;
use ic_types::NumBytes;
use ic_universal_canister::wasm;

const MAXIMUM_CANISTER_STATE_SIZE: u64 = 1 << 30; // 1 GiB

fn maximum_state_size() -> NumBytes {
    SUBNET_MEMORY_RESERVATION + NumBytes::new(MAXIMUM_CANISTER_STATE_SIZE)
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(memory_grow_fails_beyond_maximum_state_size))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    let resource_limits = ResourceLimits {
        maximum_state_size: Some(maximum_state_size()),
        maximum_state_delta: None,
    };
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::Application).with_resource_limits(resource_limits),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn memory_grow_fails_beyond_maximum_state_size(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            let stable_grow = |pages: u64| {
                let canister = canister.clone(); // ensure owned inside async block
                async move {
                    canister
                        .update(
                            wasm()
                                .stable64_grow(pages)
                                .int64_to_blob()
                                .append_and_reply()
                                .build(),
                        )
                        .await
                        .unwrap()
                }
            };

            // sanity check: `ic0.stable64_grow` works for a small amount of pages
            // and returns the previous stable memory size in pages (1)
            let res = stable_grow(42).await;
            assert_eq!(res, 1_u64.to_le_bytes());

            // growing stable memory to `MAXIMUM_CANISTER_STATE_SIZE` should fail
            // because other pieces of the canister state already take some memory usage
            // and thus the total state size after the stable memory growth exceeds `MAXIMUM_CANISTER_STATE_SIZE`
            let maximum_canister_state_size_in_wasm_pages = MAXIMUM_CANISTER_STATE_SIZE >> 16;
            let res = stable_grow(maximum_canister_state_size_in_wasm_pages).await;
            // `ic0.stable64_grow` should return -1 upon failure
            assert_eq!(res, u64::MAX.to_le_bytes());
        }
    })
}
