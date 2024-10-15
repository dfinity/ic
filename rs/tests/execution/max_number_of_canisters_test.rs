use anyhow::Result;
use candid::{Decode, Encode};
use futures::future::join_all;
use ic_agent::{agent::RejectCode, export::Principal, identity::Identity, AgentError};
use ic_management_canister_types::{
    CanisterSettingsArgs, CanisterSettingsArgsBuilder, CanisterStatusResultV2, CreateCanisterArgs,
    EmptyBlob, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::systest;
use ic_system_test_driver::types::*;
use ic_system_test_driver::util::*;
use ic_tests::execution::config_max_number_of_canisters;
use ic_types::{Cycles, PrincipalId};
use ic_universal_canister::{call_args, management, wasm, CallInterface, UNIVERSAL_CANISTER_WASM};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::{
    management_canister::{
        builders::{CanisterUpgradeOptions, InstallMode},
        UpdateCanisterBuilder,
    },
    ManagementCanister,
};
use slog::info;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(config_max_number_of_canisters)
        .add_test(systest!(
            creating_canisters_fails_if_limit_of_allowed_canisters_is_reached
        ))
        .execute_from_args()?;

    Ok(())
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
                    .update(wasm().call(management::create_canister(
                        Cycles::from(100_000_000_000u64).into_parts(),
                    )))
                    .await,
                RejectCode::CanisterReject,
            );
        }
    })
}
