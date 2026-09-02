use anyhow::Result;
use candid::Decode;
use ic_management_canister_types_private::{self as ic00, Method, Payload};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{UniversalCanister, block_on, create_and_install};
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(subnet_metrics_another_subnet_succeeds))
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

/// A canister on the application subnet calls `subnet_metrics` naming a
/// *different* subnet. Message routing delivers the call to that subnet, which
/// executes it and answers with **its own** metrics.
///
/// That a reply arrives at all already shows the call reached the named subnet,
/// since the handler rejects any `subnet_id` other than the executing subnet's
/// own. What the assertions below add is that the numbers in the reply are the
/// *remote* subnet's: the test perturbs only that subnet, by installing a
/// canister there, and pins how `num_canisters` moves. Were the reply carrying
/// the caller's own subnet's metrics, a canister created on the remote subnet
/// could not have moved it.
///
/// This test has an IC to itself and is the only test in its group, so nothing
/// else creates or deletes canisters on the remote subnet in the meantime and the
/// canister count can be pinned exactly.
///
/// Note also: unlike `node_metrics_history_another_subnet_succeeds` in
/// `general_execution_tests/api_tests.rs`, which calls
/// `get_first_healthy_application_node_snapshot()` twice and so ends up naming
/// its *own* subnet, this test names the verified-application subnet, so the call
/// really does cross a subnet boundary.
pub fn subnet_metrics_another_subnet_succeeds(env: TestEnv) {
    // Arrange.
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    let other_node = env.get_first_healthy_verified_application_node_snapshot();
    let other_agent = other_node.build_default_agent();
    let logger = env.logger();
    let other_subnet_id = other_node.subnet_id().unwrap().get();
    assert_ne!(other_subnet_id, app_node.subnet_id().unwrap().get());
    block_on({
        async move {
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;

            let read_remote = || async {
                let result = canister
                    .update(
                        wasm().call_simple(
                            ic00::IC_00,
                            Method::SubnetMetrics,
                            call_args().other_side(
                                ic00::SubnetMetricsArgs {
                                    subnet_id: other_subnet_id,
                                }
                                .encode(),
                            ),
                        ),
                    )
                    .await;
                let bytes = result.expect("cross-subnet subnet_metrics call failed");
                Decode!(&bytes, ic00::SubnetMetricsResponse).unwrap()
            };

            // Act.
            let before = read_remote().await;
            // Perturb only the remote subnet, by exactly one canister. Note the
            // retry-free helper: `UniversalCanister::new_with_retries` retries
            // creation *and* installation together, so a failed install would
            // leave a canister behind and the exact assertion below would fail
            // spuriously.
            let _remote_canister = create_and_install(
                &other_agent,
                other_node.effective_canister_id(),
                &UNIVERSAL_CANISTER_WASM,
            )
            .await;
            let after = read_remote().await;

            // Assert: the reply reports the *target* subnet's population, so
            // creating exactly one canister there moves it by exactly one.
            assert_eq!(
                after.num_canisters,
                before.num_canisters.clone() + candid::Nat::from(1_u64),
                "cross-subnet subnet_metrics did not report the target subnet's \
                 canister population: num_canisters was {} before and {} after \
                 creating a canister on subnet {other_subnet_id}",
                before.num_canisters,
                after.num_canisters,
            );
            // Sanity: the counters advance on the target subnet too. Both strict
            // comparisons also pin the fields non-zero, since `before` cannot be
            // negative.
            assert!(after.block_height > before.block_height);
            assert!(after.update_transactions_total > before.update_transactions_total);

            // `canister_state_bytes` is refreshed only on rounds whose batch number
            // is a multiple of 10 (`rs/messaging/src/message_routing.rs`), so it
            // legitimately reads 0 for the first rounds after the subnet is created.
            // Whether a given read lands before or after a refresh is a race, so
            // re-read until it is populated instead of assuming. Each read is an
            // update executing on the target subnet, so it advances at least one
            // round there; exhausting the bound means the field never refreshed,
            // which is a real failure.
            let mut canister_state_bytes = after.canister_state_bytes;
            for _ in 0..30 {
                if canister_state_bytes > 0_u64 {
                    break;
                }
                canister_state_bytes = read_remote().await.canister_state_bytes;
            }
            assert!(
                canister_state_bytes > 0_u64,
                "canister_state_bytes never refreshed off 0 across 30 rounds on \
                 subnet {other_subnet_id}; expected a multiple-of-10 batch to have \
                 refreshed it by now"
            );
        }
    })
}
