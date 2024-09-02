/* tag::catalog[]

Title:: Canisters can be created, (un)installed and deleted.

Goal:: See title.

Runbook::

The test (module `execution::canister_lifecycle`) currently covers (at least) the following aspects:

. A canister cannot be created via a simple ingress message (unless the provisional API is used).
. A canister can be created via canother canister (that was created using the provisional API).
. Attempting to manage a canister with the wrong controller identity fails.
. A controller can delete a stopped canisters.
. A running canister cannot be deleted by the controller.
. Attempting to install a canister that exceeds the maximum memory allocation of the subnet fails.
. Attempting to grow the memory of an installed canister beyond the limits of the subnet fails.
. Attempting an installation of a large canister with (too) small memory allocation fails.
. Attempting an installation of a canister that reserved a large memory but with a (too) small memory allocation fails.
. A canister can install another canister and send messages to that canister.
. Attempting to install a canister on a subnet with an exhausted compute allocation fails.
. After deleting a canister, a new canister can be installed taking up the freed compute allocation.
. A controller can control (install/stop/delete) a controllee across different subnets.
. Changing settings of a frozen canister succeeds.

AKA:: Testcase 2.4


end::catalog[] */

use candid::{Decode, Encode};
use futures::future::join_all;
use ic_agent::{agent::RejectCode, export::Principal, identity::Identity, AgentError};
use ic_management_canister_types::{
    CanisterSettingsArgs, CanisterSettingsArgsBuilder, CanisterStatusResultV2, CreateCanisterArgs,
    EmptyBlob, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{GetFirstHealthyNodeSnapshot, HasPublicApiUrl};
use ic_system_test_driver::types::*;
use ic_system_test_driver::util::*;
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

pub fn create_canister_via_ingress_fails(env: TestEnv) {
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);
            assert_http_submit_fails(
                mgr.create_canister().call().await,
                RejectCode::CanisterReject,
            );
        }
    });
}

pub fn create_canister_via_canister_succeeds(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            // Create a canister for the user using the provisional API.
            // This universal canister acts as the user's wallet canister.
            let wallet_canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            // User requests from its wallet to create a new canister.
            let canister_id = create_canister_via_canister(&wallet_canister)
                .await
                .unwrap();

            // Check the status of the canister.
            wallet_canister
                .update(wasm().call(management::canister_status(canister_id)))
                .await
                .map(|res| {
                    let res = Decode!(res.as_slice(), CanisterStatusResult).unwrap();

                    // Verify that controllers are returned as expected.
                    assert_eq!(res.controller, wallet_canister.canister_id());
                    assert_eq!(
                        res.settings.controllers(),
                        vec![to_principal_id(&wallet_canister.canister_id())]
                    );
                })
                .unwrap()
        }
    });
}

pub fn update_settings_of_frozen_canister(env: TestEnv) {
    use ic_base_types::NumBytes;
    use ic_cdk::api::management_canister::main::{CanisterSettings, UpdateSettingsArgument};
    use ic_config::subnet_config::{CyclesAccountManagerConfig, SchedulerConfig};
    use ic_cycles_account_manager::CyclesAccountManager;

    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);
            let canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;

            // Construct large `UpdateSettings` argument.
            let mut controllers = mgr
                .canister_status(&canister.canister_id())
                .call_and_wait()
                .await
                .unwrap()
                .0
                .settings
                .controllers;
            for i in 0..9 {
                controllers.push(PrincipalId::new_derived(&controllers[0].into(), &[i]).into());
            }
            let low_freezing_threshold = 30u32 * 24 * 3600; // 30 days default
            let arg = UpdateSettingsArgument {
                canister_id: canister.canister_id(),
                settings: CanisterSettings {
                    controllers: Some(controllers),
                    compute_allocation: None,
                    memory_allocation: None,
                    freezing_threshold: Some(low_freezing_threshold.into()),
                    reserved_cycles_limit: None,
                },
            };
            let bytes = Encode!(&arg).unwrap();

            // Check that the canister is not frozen.
            canister
                .update(wasm().reply_data(&[]).build())
                .await
                .unwrap();

            // Update freezing threshold to a very high value to make the canister frozen.
            let high_freezing_threshold = 1_u64 << 62;
            UpdateCanisterBuilder::builder(&mgr, &canister.canister_id())
                .with_optional_freezing_threshold(Some(high_freezing_threshold))
                .call_and_wait()
                .await
                .expect("setting freezing threshold on unfrozen canister failed");

            // Check that the canister is indeed frozen.
            canister
                .update(wasm().reply_data(&[]).build())
                .await
                .unwrap_err();

            // Updating freezing threshold on a frozen canister back to a low value
            // fails if `UpdateSettings` argument is too large.
            mgr.update_("update_settings")
                .with_arg_raw(bytes.clone())
                .with_effective_canister_id(canister.canister_id())
                .build::<((),)>()
                .call_and_wait()
                .await
                .unwrap_err();

            // Update freezing threshold on a frozen canister back to a low value.
            let low_freezing_threshold = 30 * 24 * 3600; // 30 days default
            UpdateCanisterBuilder::builder(&mgr, &canister.canister_id())
                .with_optional_freezing_threshold(Some(low_freezing_threshold))
                .call_and_wait()
                .await
                .expect("setting freezing threshold on frozen canister failed");

            // Check that the canister is not frozen anymore.
            canister
                .update(wasm().reply_data(&[]).build())
                .await
                .unwrap();

            let balance_before = mgr
                .canister_status(&canister.canister_id())
                .call_and_wait()
                .await
                .unwrap()
                .0
                .cycles;

            // Updating freezing threshold on a not frozen canister to a low value
            // now succeeds also if `UpdateSettings` argument is too large
            // and charges the canister appropriately.
            mgr.update_("update_settings")
                .with_arg_raw(bytes.clone())
                .with_effective_canister_id(canister.canister_id())
                .build::<((),)>()
                .call_and_wait()
                .await
                .unwrap();

            let balance_after = mgr
                .canister_status(&canister.canister_id())
                .call_and_wait()
                .await
                .unwrap()
                .0
                .cycles;

            let cycles_account_manager = CyclesAccountManager::new(
                SchedulerConfig::application_subnet().max_instructions_per_message,
                SubnetType::Application,
                app_node.subnet_id().unwrap(),
                CyclesAccountManagerConfig::application_subnet(),
            );

            assert!(
                balance_after < balance_before
                    && balance_before - balance_after
                        > cycles_account_manager
                            .ingress_induction_cost_from_bytes(NumBytes::new(bytes.len() as u64), 1)
                            .get()
            );
        }
    });
}

pub fn create_canister_with_one_controller(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            let canister_b = canister_a
                .update(
                    wasm().call(
                        management::create_canister(
                            Cycles::from(2_000_000_000_000u64).into_parts(),
                        )
                        .with_controllers(vec![canister_a.canister_id()]),
                    ),
                )
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .unwrap();

            // Check that canister_a can ask for the status.
            canister_a
                .update(wasm().call(management::canister_status(canister_b)))
                .await
                .map(|res| {
                    let res = Decode!(res.as_slice(), CanisterStatusResult).unwrap();
                    // Verify that controllers are returned as expected.
                    assert_eq!(res.controller, canister_a.canister_id());
                    assert_eq!(
                        res.settings.controllers(),
                        vec![to_principal_id(&canister_a.canister_id())]
                    );
                })
                .unwrap()
        }
    });
}

pub fn update_settings_multiple_controllers(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    block_on({
        async move {
            let user = random_ed25519_identity();
            let user_principal = user.sender().unwrap();
            let agent = agent_with_identity(node.get_public_url().as_str(), user)
                .await
                .unwrap();
            let mgr = ManagementCanister::create(&agent);

            info!(logger, "Creating Canister A and canister B");
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let canister_b =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            // A creates C
            info!(logger, "Canister A attempts to create canister C.");
            let canister_c = canister_a
                .update(wasm().call(management::create_canister(
                    Cycles::from(2_000_000_000_000u64).into_parts(),
                )))
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .unwrap();

            // Check that canister_a can ask for the status.
            info!(
                logger,
                "Assert that canister A can ask for canister C's status."
            );
            canister_a
                .update(wasm().call(management::canister_status(canister_c)))
                .await
                .map(|res| {
                    let res = Decode!(res.as_slice(), CanisterStatusResult).unwrap();
                    // Verify that controllers are returned as expected.
                    assert_eq!(res.controller, canister_a.canister_id());
                    assert_eq!(
                        res.settings.controllers(),
                        vec![to_principal_id(&canister_a.canister_id())]
                    );
                })
                .unwrap();

            // B cannot access C's canister status
            info!(
                logger,
                "Assert that canister B cannot access canister C's status."
            );
            assert_reject(
                canister_b
                    .update(wasm().call(management::canister_status(canister_c)))
                    .await,
                RejectCode::CanisterReject,
            );

            // User also cannot fetch the status
            info!(
                logger,
                "Assert that the user cannot access canister C's status."
            );
            assert_http_submit_fails(
                mgr.canister_status(&canister_c).call().await,
                RejectCode::CanisterError,
            );

            // Update the controllers to B and `user`
            let controllers = vec![canister_b.canister_id(), user_principal];
            canister_a
                .update(wasm().call(
                    management::update_settings(canister_c).with_controllers(controllers.clone()),
                ))
                .await
                .unwrap();

            // Now A cannot access the canister's status.
            assert_reject(
                canister_a
                    .update(wasm().call(management::canister_status(canister_c)))
                    .await,
                RejectCode::CanisterReject,
            );

            // B and `user` should be able to access the canister status.
            canister_b
                .update(wasm().call(management::canister_status(canister_c)))
                .await
                .map(|res| {
                    let res = Decode!(res.as_slice(), CanisterStatusResult).unwrap();
                    // Verify that controllers are returned as expected.
                    assert_eq!(
                        res.controller,
                        Principal::from_text("ifxlm-aqaaa-multi-pleco-ntrol-lersa-h3ae").unwrap()
                    );

                    // Use a set to not worry about ordering.
                    let result = res.settings.controllers();
                    let expected = controllers
                        .iter()
                        .map(to_principal_id)
                        .collect::<Vec<PrincipalId>>();
                    assert_eq!(result, expected);
                })
                .unwrap();

            // `user` can now fetch the status too.
            mgr.canister_status(&canister_c)
                .call_and_wait()
                .await
                .unwrap();

            // B removes all controllers
            canister_b
                .update(
                    wasm().call(
                        management::update_settings(canister_c)
                            .with_controllers(Vec::<Principal>::new()), // No controllers
                    ),
                )
                .await
                .unwrap();

            // B and `user` can no longer access status.
            info!(
                logger,
                "Assert that the user can no longer access canister C's status."
            );
            assert_http_submit_fails(
                mgr.canister_status(&canister_c).call().await,
                RejectCode::CanisterError,
            );

            info!(
                logger,
                "Assert that canister B can no longer access canister C's status."
            );
            assert_reject(
                canister_b
                    .update(wasm().call(management::canister_status(canister_c)))
                    .await,
                RejectCode::CanisterReject,
            )
        }
    });
}

pub fn create_canister_with_no_controllers(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            let canister_b = canister_a
                .update(
                    wasm().call(
                        management::create_canister(
                            Cycles::from(2_000_000_000_000u64).into_parts(),
                        )
                        .with_controllers(Vec::<Principal>::new()), // No controllers
                    ),
                )
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .unwrap();

            // Canister A cannot ask for the status.
            assert_reject(
                canister_a
                    .update(wasm().call(management::canister_status(canister_b)))
                    .await,
                RejectCode::CanisterReject,
            );
        }
    });
}

pub fn create_canister_with_multiple_controllers(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let canister_b =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            let controllers = vec![canister_a.canister_id(), canister_b.canister_id()];

            // Canister A creates C with multiple controllers
            let canister_c = canister_a
                .update(
                    wasm().call(
                        management::create_canister(
                            Cycles::from(2_000_000_000_000u64).into_parts(),
                        )
                        .with_controllers(controllers.clone()),
                    ),
                )
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .unwrap();

            // Check that A can ask for the status.
            canister_a
                .update(wasm().call(management::canister_status(canister_c)))
                .await
                .map(|res| {
                    let res = Decode!(res.as_slice(), CanisterStatusResult).unwrap();
                    // Verify that controllers are returned as expected.
                    assert_eq!(
                        res.controller,
                        Principal::from_text("ifxlm-aqaaa-multi-pleco-ntrol-lersa-h3ae").unwrap()
                    );

                    // Check result matches the expected value.
                    let result = res.settings.controllers();
                    let expected = controllers
                        .iter()
                        .map(to_principal_id)
                        .collect::<Vec<PrincipalId>>();
                    assert_eq!(result, expected);
                })
                .unwrap();

            // Check that B can ask for the status.
            canister_b
                .update(wasm().call(management::canister_status(canister_c)))
                .await
                .map(|res| {
                    let res = Decode!(res.as_slice(), CanisterStatusResult).unwrap();
                    // Verify that controllers are returned as expected.
                    assert_eq!(
                        res.controller,
                        Principal::from_text("ifxlm-aqaaa-multi-pleco-ntrol-lersa-h3ae").unwrap()
                    );

                    // Use a set to not worry about ordering.
                    let result = res.settings.controllers();
                    let expected = controllers
                        .iter()
                        .map(to_principal_id)
                        .collect::<Vec<PrincipalId>>();
                    assert_eq!(result, expected);
                })
                .unwrap();
        }
    });
}

pub fn create_canister_with_too_many_controllers_fails(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;
            let mut controllers = vec![];

            // Setting more than maximum number of controllers allowed.
            for _ in 0..15 {
                controllers.push(
                    UniversalCanister::new_with_retries(
                        &agent,
                        node.effective_canister_id(),
                        &logger,
                    )
                    .await
                    .canister_id(),
                )
            }

            // Canister A creates C with multiple controllers
            let response = canister_a
                .update(
                    wasm().call(
                        management::create_canister(
                            Cycles::from(2_000_000_000_000u64).into_parts(),
                        )
                        .with_controllers(controllers),
                    ),
                )
                .await;
            assert_reject(response, RejectCode::CanisterReject);
        }
    });
}

pub fn managing_a_canister_with_wrong_controller_fails(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    block_on({
        async move {
            let user1 = random_ed25519_identity();
            let agent1 = agent_with_identity(node.get_public_url().as_str(), user1)
                .await
                .unwrap();

            // Create a canister for the user using the provisional API.
            let wallet_canister =
                UniversalCanister::new_with_retries(&agent1, node.effective_canister_id(), &logger)
                    .await;

            // User2 tries to manage the canister and fails.
            let user2 = random_ed25519_identity();
            let agent2 = agent_with_identity(node.get_public_url().as_str(), user2)
                .await
                .unwrap();
            let mgr = ManagementCanister::create(&agent2);

            // Try reinstalling code to it. Should fail.
            info!(
                logger,
                "Asserting that Reinstalling code on the canister fails."
            );
            assert_http_submit_fails(
                mgr.install_code(&wallet_canister.canister_id(), UNIVERSAL_CANISTER_WASM)
                    .with_mode(InstallMode::Reinstall)
                    .call()
                    .await,
                RejectCode::CanisterError,
            );

            // Upgrading it doesn't work either.
            info!(logger, "Asserting that upgrading the canister fails.");
            assert_http_submit_fails(
                mgr.install_code(&wallet_canister.canister_id(), UNIVERSAL_CANISTER_WASM)
                    .with_mode(InstallMode::Upgrade(Some(CanisterUpgradeOptions {
                        skip_pre_upgrade: Some(false),
                        wasm_memory_persistence: None,
                    })))
                    .call()
                    .await,
                RejectCode::CanisterError,
            );

            // Nor does stopping.
            info!(logger, "Asserting that stopping the canister fails.");
            assert_http_submit_fails(
                mgr.stop_canister(&wallet_canister.canister_id())
                    .call()
                    .await,
                RejectCode::CanisterError,
            );

            // Nor does fetching the status.
            info!(logger, "Asserting that fetching the canister status fails.");
            assert_http_submit_fails(
                mgr.canister_status(&wallet_canister.canister_id())
                    .call()
                    .await,
                RejectCode::CanisterError,
            );

            // Nor does deleting it.
            info!(logger, "Asserting that deleting the canister fails.");
            assert_http_submit_fails(
                mgr.delete_canister(&wallet_canister.canister_id())
                    .call()
                    .await,
                RejectCode::CanisterError,
            );
        }
    });
}

pub fn delete_stopped_canister_succeeds(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            // Create a canister for the user using the provisional API.
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            // Stop the canister
            mgr.stop_canister(&canister.canister_id())
                .call_and_wait()
                .await
                .expect("canister stopping failed");

            // Delete the canister.
            mgr.delete_canister(&canister.canister_id())
                .call_and_wait()
                .await
                .expect("canister deletion failed");

            // Querying the deleted canister fails.
            let res = agent
                .query(&canister.canister_id(), "query")
                .with_arg(vec![])
                .call()
                .await;
            assert_reject(res, RejectCode::DestinationInvalid);
        }
    })
}

pub fn delete_running_canister_fails(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            // Create a canister for the user using the provisional API.
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            // Delete the canister.
            let res = mgr
                .delete_canister(&canister.canister_id())
                .call_and_wait()
                .await;

            // This should really be a CanisterReject.
            assert_reject(res, RejectCode::CanisterError);
        }
    })
}

/// Try to install a canister with a large wasm but a small memory allocation.
/// It should be rejected.
pub fn canister_large_wasm_small_memory_allocation(env: TestEnv) {
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(app_node.effective_canister_id())
                .with_memory_allocation(1u64)
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;
            // Install a large wasm with a small memory allocation, it should fail.
            let res = mgr
                .install_code(&canister_id, UNIVERSAL_CANISTER_WASM)
                .call_and_wait()
                .await;
            assert_reject(res, RejectCode::CanisterReject);
        }
    })
}

/// Try to install a canister with a wasm that asks for a large memory but a
/// small memory allocation. It should be rejected.
pub fn canister_large_initial_memory_small_memory_allocation(env: TestEnv) {
    // A wasm module that asks for 2GiB of initial memory.
    let wasm = wat::parse_str(
        r#"(module
              (func $hi)
              (memory $memory 32768)
              (export "memory" (memory $memory))
              (export "canister_query hi" (func $hi)))"#,
    )
    .unwrap();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(app_node.effective_canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;

            // Install the wasm with no memory allocation, it should succeed.
            mgr.install_code(&canister_id, &wasm)
                .call_and_wait()
                .await
                .unwrap();

            // Attempt to set 1GB memory allocation for the canister, it should fail.
            let res = mgr
                .update_settings(&canister_id)
                .with_memory_allocation(1_u64 << 30)
                .call_and_wait()
                .await;
            assert_reject(res, RejectCode::CanisterReject);

            // Install the wasm with 3GiB memory allocation, it should succeed.
            mgr.update_settings(&canister_id)
                .with_memory_allocation(3_u64 << 30)
                .call_and_wait()
                .await
                .unwrap();
            mgr.install_code(&canister_id, &wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait()
                .await
                .unwrap();
        }
    })
}

/// Canister A creates canister B; installs wasm on it; and then executes some
/// code on it; Each of the above operations are done in distinct steps i.e. the
/// "user" initiates each step separately.
pub fn canister_can_manage_other_canister(env: TestEnv) {
    let logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let canister_a = UniversalCanister::new_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                &logger,
            )
            .await;

            let canister_b = canister_a
                .update(wasm().call(management::create_canister(
                    Cycles::from(2_000_000_000_000u64).into_parts(),
                )))
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .unwrap();

            canister_a
                .update(wasm().call(management::install_code(
                    canister_b,
                    UNIVERSAL_CANISTER_WASM,
                )))
                .await
                .unwrap();

            let arbitrary_bytes = b";ioapusdvzn,x";
            assert_eq!(
                canister_a
                    .update(wasm().inter_update(
                        canister_b,
                        call_args().other_side(wasm().reply_data(arbitrary_bytes)),
                    ))
                    .await
                    .unwrap(),
                arbitrary_bytes
            );
        }
    })
}

/// Canister A creates canister B; installs wasm on it; and then executes some
/// code on it; The creation is done in one step and the other two in a single
/// step.
pub fn canister_can_manage_other_canister_batched(env: TestEnv) {
    let logger = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    block_on({
        async move {
            let canister_a = UniversalCanister::new_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                &logger,
            )
            .await;
            let canister_b = canister_a
                .update(wasm().call(management::create_canister(
                    Cycles::from(2_000_000_000_000u64).into_parts(),
                )))
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .unwrap();

            let arbitrary_bytes = b";ioapusdvzn,x";
            let res = canister_a
                .update(wasm().call(
                    management::install_code(canister_b, UNIVERSAL_CANISTER_WASM).on_reply(
                        wasm().inter_update(
                            canister_b,
                            call_args().other_side(wasm().reply_data(arbitrary_bytes)),
                        ),
                    ),
                ))
                .await
                .unwrap();
            assert_eq!(res, arbitrary_bytes);
        }
    })
}

pub fn config_compute_allocation(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .add_subnet(Subnet::fast_single_node(SubnetType::Application))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

/// This tests expects to be run on a clean slate, i.e. requires it's own Pot
/// with one subnet of type Application.
/// Tests whether the compute allocation limits are enforced on an app subnet
/// both when creating canisters via the provisional API and via another
/// canister (which acts as the wallet canister).
pub fn total_compute_allocation_cannot_be_exceeded(env: TestEnv) {
    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    // See the corresponding field in the execution environment config.
    let allocatable_compute_capacity_in_percent = 50;
    // Note: the DTS scheduler requires at least 2 scheduler cores
    assert!(ic_config::subnet_config::SchedulerConfig::application_subnet().scheduler_cores >= 2);
    let app_sched_cores =
        (ic_config::subnet_config::SchedulerConfig::application_subnet().scheduler_cores - 1)
            * allocatable_compute_capacity_in_percent
            / 100;
    const MAX_COMP_ALLOC: Option<u64> = Some(99);
    block_on(async move {
        let mut canister_principals = Vec::new();
        let cans = join_all((0..app_sched_cores).map(|_| {
            UniversalCanister::new_with_params_with_retries(
                &agent,
                app_node.effective_canister_id(),
                MAX_COMP_ALLOC,
                Some(u64::MAX as u128),
                None,
                &logger,
            )
        }))
        .await;
        for can in cans {
            canister_principals.push(can.canister_id());
        }

        // Installing the app_sched_cores + 1st canister should fail.
        let can = UniversalCanister::new_with_params(
            &agent,
            app_node.effective_canister_id(),
            MAX_COMP_ALLOC,
            Some(u64::MAX as u128),
            None,
        )
        .await;
        assert!(can.is_err());

        let mgr = ManagementCanister::create(&agent);
        // Stop and delete all canisters.

        let res = join_all(
            canister_principals
                .iter()
                .map(|c_id| mgr.stop_canister(c_id).call_and_wait()),
        )
        .await;
        res.into_iter()
            .for_each(|x| x.expect("Could not stop canister."));

        let res = join_all(
            canister_principals
                .iter()
                .map(|c_id| mgr.delete_canister(c_id).call_and_wait()),
        )
        .await;
        res.into_iter()
            .for_each(|x| x.expect("Could not delete canister."));

        // Create universal canister with 'best effort' compute allocation of `0`.
        let uni_can = UniversalCanister::new_with_params_with_retries(
            &agent,
            app_node.effective_canister_id(),
            Some(0),
            Some(u64::MAX as u128),
            None,
            &logger,
        )
        .await;
        let arbitrary_bytes = b";ioapusdvzn,x";

        async fn install_canister(
            universal_canister: &UniversalCanister<'_>,
            reply_data: &[u8],
        ) -> Result<(Principal, Vec<u8>), AgentError> {
            let created_canister = universal_canister
                .update(wasm().call(management::create_canister(
                    Cycles::from(10_000_000_000_000_000u128).into_parts(),
                )))
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .expect("Could not create canister.");

            universal_canister
                .update(
                    wasm().call(
                        management::update_settings(created_canister)
                            .with_compute_allocation(MAX_COMP_ALLOC.unwrap()),
                    ),
                )
                .await?;

            let res = universal_canister
                .update(wasm().call(
                    management::install_code(created_canister, UNIVERSAL_CANISTER_WASM).on_reply(
                        wasm().inter_update(
                            created_canister,
                            call_args().other_side(wasm().reply_data(reply_data)),
                        ),
                    ),
                ))
                .await;
            res.map(|r| (created_canister, r))
        }

        let results =
            join_all((0..app_sched_cores).map(|_| install_canister(&uni_can, arbitrary_bytes)))
                .await;
        for r in results {
            assert_eq!(r.unwrap().1, arbitrary_bytes);
        }

        let res = install_canister(&uni_can, arbitrary_bytes).await;
        assert_reject(res, RejectCode::CanisterReject);
    })
}

// TODO(EXC-186): Enable this test.
pub fn canisters_with_low_balance_are_deallocated(env: TestEnv) {
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(Some(0))
                .with_effective_canister_id(app_node.effective_canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;

            // Install the universal canister.
            // NOTE: this call succeeds because `install_code` is free.
            mgr.install_code(&canister_id, UNIVERSAL_CANISTER_WASM)
                .with_raw_arg(wasm().noop().build())
                .call_and_wait()
                .await
                .expect("Couldn't install universal canister");

            let canister_status = mgr
                .canister_status(&canister_id)
                .call_and_wait()
                .await
                .unwrap()
                .0;

            // Canister has been emptied, memory freed.
            assert_eq!(canister_status.module_hash, None);
            assert_eq!(canister_status.memory_size, candid::Nat::from(0_u8));
        }
    })
}

// TODO(EXC-186): Enable this test.
pub fn canisters_are_deallocated_when_their_balance_falls(env: TestEnv) {
    #[derive(candid::CandidType)]
    struct Argument {
        canister_id: Principal,
    }
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            let mgr = ManagementCanister::create(&agent);

            let initial_cycles = 10_000_000_000_000u64;
            let create_canister_cycles = 2_000_000_000_000;
            let transfer_cycles = 8_000_000_000_000;

            let canister_a = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                app_node.effective_canister_id(),
                initial_cycles,
                &env.logger(),
            )
            .await;

            // Canister A created canister B with some cycles on it.
            let canister_b = create_canister_via_canister_with_cycles(
                &canister_a,
                Cycles::from(create_canister_cycles),
            )
            .await
            .unwrap();

            // Forward all the remaining cycles from A to B.
            assert_reject(
                canister_a
                    .forward_with_cycles_to(
                        &Principal::management_canister(),
                        "deposit_cycles",
                        Encode!(&Argument {
                            canister_id: canister_b,
                        })
                        .unwrap(),
                        Cycles::from(transfer_cycles),
                    )
                    .await,
                RejectCode::DestinationInvalid,
            );

            let canister_status = mgr
                .canister_status(&canister_a.canister_id())
                .call_and_wait()
                .await
                .unwrap()
                .0;

            // Canister A has been emptied, memory freed, but cycles remain.
            assert_eq!(canister_status.module_hash, None);
            assert_eq!(
                canister_status.cycles,
                candid::Nat::from(initial_cycles - create_canister_cycles - transfer_cycles - 1)
            );
            assert_eq!(canister_status.memory_size, candid::Nat::from(0_u8));
        }
    });
}

fn create_canister_test(env: TestEnv, payload: Vec<u8>) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister_a =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            canister_a
                .forward_with_cycles_to(
                    &Principal::management_canister(),
                    "create_canister",
                    payload,
                    Cycles::from(2_000_000_000_000u64),
                )
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CreateCanisterResult)
                        .unwrap()
                        .canister_id
                })
                .unwrap();
        }
    })
}

/// Sending no field
pub fn create_canister_with_no_settings_field(env: TestEnv) {
    let payload = EmptyBlob.encode();
    create_canister_test(env, payload);
}

/// Sending a field with value None
pub fn create_canister_with_none_settings_field(env: TestEnv) {
    let records = CreateCanisterArgs::default();
    let payload = records.encode();
    create_canister_test(env, payload);
}

/// Sending a field with settings empty (None)
pub fn create_canister_with_empty_settings(env: TestEnv) {
    let settings = CanisterSettingsArgs::default();
    let records = CreateCanisterArgs {
        settings: Some(settings),
        sender_canister_version: None,
    };
    let payload = records.encode();
    create_canister_test(env, payload);
}

/// Sending a field with some settings
pub fn create_canister_with_settings(env: TestEnv) {
    let settings = CanisterSettingsArgsBuilder::new()
        .with_compute_allocation(50)
        .build();
    let records = CreateCanisterArgs {
        settings: Some(settings),
        sender_canister_version: None,
    };
    let payload = records.encode();
    create_canister_test(env, payload);
}

/// Sending no `settings` field
pub fn provisional_create_canister_with_no_settings(env: TestEnv) {
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            // Create a canister for the user.
            let mgr = ManagementCanister::create(&agent);
            mgr.create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(node.effective_canister_id())
                .call_and_wait()
                .await
                .unwrap_or_else(|err| {
                    panic!("Couldn't create canister with provisional API: {}", err)
                });
        }
    })
}

pub fn create_canister_with_freezing_threshold(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            for valid_value in [u64::MAX, 0].iter() {
                // Create the canister with the freezing threshold set.
                let new_canister_id = canister
                    .forward_with_cycles_to(
                        &Principal::management_canister(),
                        "create_canister",
                        CreateCanisterArgs {
                            settings: Some(
                                CanisterSettingsArgsBuilder::new()
                                    .with_freezing_threshold(*valid_value)
                                    .build(),
                            ),
                            sender_canister_version: None,
                        }
                        .encode(),
                        Cycles::from(2_000_000_000_000u64),
                    )
                    .await
                    .map(|res| {
                        Decode!(res.as_slice(), CreateCanisterResult)
                            .unwrap()
                            .canister_id
                    })
                    .unwrap();

                // Check the status to verify that the freeze threshold is set.
                canister
                    .forward_to(
                        &Principal::management_canister(),
                        "canister_status",
                        Encode!(&CanisterIdRecord {
                            canister_id: new_canister_id,
                        })
                        .unwrap(),
                    )
                    .await
                    .map(|res| {
                        assert_eq!(
                            Decode!(res.as_slice(), CanisterStatusResultV2)
                                .unwrap()
                                .freezing_threshold(),
                            *valid_value
                        );
                    })
                    .unwrap()
            }
        }
    })
}

pub fn create_canister_with_invalid_freezing_threshold_fails(env: TestEnv) {
    let logger = env.logger();
    let node = env.get_first_healthy_node_snapshot();
    let agent = node.build_default_agent();
    block_on({
        async move {
            let canister =
                UniversalCanister::new_with_retries(&agent, node.effective_canister_id(), &logger)
                    .await;

            for invalid_value in [
                candid::Nat::from(u128::MAX),
                candid::Nat::from(2_u128 << 64_u128),
            ]
            .iter()
            {
                // Create the canister with an invalid freezing threshold. Should fail.
                assert_reject(
                    canister
                        .update(
                            wasm().call(
                                management::create_canister(
                                    Cycles::from(2_000_000_000_000u64).into_parts(),
                                )
                                .with_freezing_threshold(invalid_value.clone()),
                            ),
                        )
                        .await,
                    RejectCode::CanisterReject,
                );
            }
        }
    })
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
                        management::install_code(target, UNIVERSAL_CANISTER_WASM)
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

pub fn refunds_after_uninstall_are_refunded(env: TestEnv) {
    let logger = env.logger();
    // Choosing an NNS subnet since they aren't charged, so
    // testing cycle balances is easier.
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let agent = nns_node.build_default_agent();
    block_on({
        async move {
            let canister_a = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                100u64,
                &logger,
            )
            .await;
            let canister_b = UniversalCanister::new_with_cycles_with_retries(
                &agent,
                nns_node.effective_canister_id(),
                100u64,
                &logger,
            )
            .await;

            let a_balance = get_balance(&canister_a.canister_id(), &agent).await;
            let b_balance = get_balance(&canister_b.canister_id(), &agent).await;

            assert_eq!(a_balance, 100);
            assert_eq!(b_balance, 100);

            // Make B the controller of A
            set_controller(&canister_a.canister_id(), &canister_b.canister_id(), &agent).await;

            assert_reject(
                canister_a
                    .update(
                        // Canister A sends 50 cycles to B.
                        wasm().call_with_cycles(
                            canister_b.canister_id(),
                            "update",
                            call_args().other_side(
                                // B uninstalls A, then responds back without accepting
                                // the cycles. The cycles returned from B to A should
                                // be added back to A's balance.
                                wasm().call(
                                    management::uninstall_code(canister_a.canister_id())
                                        .on_reply(wasm().reply()),
                                ),
                            ),
                            Cycles::new(50),
                        ),
                    )
                    .await,
                // The call that A sent to B should have been rejected during the uninstall.
                RejectCode::CanisterReject,
            );

            // The balances of both A and B should've stayed the same.
            let b_balance = get_balance(&canister_b.canister_id(), &agent).await;
            let a_balance = canister_b
                .update(wasm().call(management::canister_status(canister_a.canister_id())))
                .await
                .map(|res| {
                    Decode!(res.as_slice(), CanisterStatusResultV2)
                        .unwrap()
                        .cycles()
                })
                .unwrap();

            assert_eq!(a_balance, 100);
            assert_eq!(b_balance, 100);
        }
    })
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
