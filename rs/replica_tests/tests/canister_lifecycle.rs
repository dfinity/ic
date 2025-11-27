use assert_matches::assert_matches;
use candid::Encode;
use ic_config::Config;
use ic_config::execution_environment::DEFAULT_WASM_MEMORY_LIMIT;
use ic_config::subnet_config::CyclesAccountManagerConfig;
use ic_error_types::{ErrorCode, RejectCode};
use ic_management_canister_types_private::{
    self as ic00, CanisterChange, CanisterIdRecord, CanisterInstallMode,
    CanisterSettingsArgsBuilder, CanisterStatusResultV2, CanisterStatusType, EmptyBlob, IC_00,
    InstallCodeArgs, LogVisibilityV2, Method, Payload, UpdateSettingsArgs,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_replica_tests as utils;
use ic_replica_tests::assert_reject;
use ic_test_utilities::assert_utils::assert_balance_equals;
use ic_test_utilities::universal_canister::management::CanisterUpgradeOptions;
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, management, wasm};
use ic_types::{CanisterId, ComputeAllocation, Cycles, NumBytes, PrincipalId, ingress::WasmResult};
use maplit::btreeset;
use std::{collections::BTreeSet, mem::size_of, str::FromStr};

const BALANCE_EPSILON: u64 = 1_000_000;
const NUM_CYCLES: u128 = 1_000_000_000;
const CANISTER_FREEZE_BALANCE_RESERVE: Cycles = Cycles::new(5_000_000_000_000);
const TEST_DEFAULT_LOG_MEMORY_LIMIT: u64 = 4_096;

#[test]
fn can_create_canister_from_another_canister() {
    utils::simple_canister_test(|canister| {
        // Canister ids are generated based on a counter within a subnet.
        // The universal canister was the first one to be created. The
        // canister we're about to create should be the second.
        let expected_canister_id = CanisterId::from(1);
        let expected_response_payload =
            Encode!(&CanisterIdRecord::from(expected_canister_id)).unwrap();
        let num_cycles = Cycles::new(1 << 70);
        // Call method "create_canister" on ic:00. This should create a canister
        // with the auto-generated id above.
        assert_eq!(
            canister.update(wasm().call(management::create_canister(num_cycles))),
            Ok(WasmResult::Reply(expected_response_payload))
        );
    });
}

#[test]
// Tests canister creation, stopping, starting, and checking the status.
fn full_canister_lifecycle_from_another_canister() {
    utils::simple_canister_test(|canister| {
        let expected_canister_id = CanisterId::from(1);
        let canister_id_record = Encode!(&CanisterIdRecord::from(expected_canister_id)).unwrap();
        let num_cycles = Cycles::new(1 << 70);

        // Create a new canister from within a canister.
        assert_eq!(
            canister.update(wasm().call(management::create_canister(num_cycles))),
            Ok(WasmResult::Reply(canister_id_record,)),
        );

        // Verify that the newly created canister is running.
        assert_matches!(
            canister.update(wasm().call(
                management::canister_status(expected_canister_id))
            ),
            Ok(WasmResult::Reply(res)) if CanisterStatusResultV2::decode(&res).unwrap().status() == CanisterStatusType::Running
        );

        // Let the canister stop the newly created canister.
        assert_eq!(
            canister.update(wasm().call(management::stop_canister(expected_canister_id))),
            Ok(WasmResult::Reply(EmptyBlob.encode())),
        );

        // Verify that the newly created canister is now stopped.
        assert_matches!(
            canister.update(wasm().call(
                management::canister_status(expected_canister_id))
            ),
            Ok(WasmResult::Reply(res)) if CanisterStatusResultV2::decode(&res).unwrap().status() == CanisterStatusType::Stopped
        );

        // Start the canister again.
        assert_eq!(
            canister.update(wasm().call(management::start_canister(expected_canister_id))),
            Ok(WasmResult::Reply(EmptyBlob.encode())),
        );

        // Verify that the canister is running again.
        assert_matches!(
            canister.update(wasm().call(
                    management::canister_status(expected_canister_id))
            ),
            Ok(WasmResult::Reply(res)) if CanisterStatusResultV2::decode(&res).unwrap().status() == CanisterStatusType::Running
        );
    });
}

#[test]
// Tests canister stopping, starting, and checking the status
// by sending ingress messages to ic:00.
fn full_canister_lifecycle_ingress() {
    utils::canister_test(|test| {
        let canister = test.create_universal_canister();
        // Create a new canister
        let expected_canister_id = CanisterId::from(1);
        let canister_id_record = Encode!(&CanisterIdRecord::from(expected_canister_id)).unwrap();
        let num_cycles = Cycles::new(1 << 70);

        // Create a new canister from within a canister.
        assert_eq!(
            test.ingress(
                canister,
                "update",
                wasm().call_with_cycles(
                    ic00::IC_00,
                    Method::CreateCanister,
                    call_args().other_side(EmptyBlob.encode()),
                    num_cycles,
                )
            ),
            Ok(WasmResult::Reply(canister_id_record.clone(),)),
        );

        // Set the controller to the anonymous user that's used in tests.
        test.ingress(
            canister,
            "update",
            wasm().call_with_cycles(
                ic00::IC_00,
                Method::UpdateSettings,
                call_args().other_side(
                    UpdateSettingsArgs::new(
                        expected_canister_id,
                        CanisterSettingsArgsBuilder::new()
                            .with_controllers(vec![PrincipalId::new_anonymous()])
                            .build(),
                    )
                    .encode(),
                ),
                num_cycles,
            ),
        )
        .unwrap();

        // Verify that the newly created canister is running.
        assert_matches!(
            test.ingress(IC_00, Method::CanisterStatus, canister_id_record.clone()),
            Ok(WasmResult::Reply(res)) if CanisterStatusResultV2::decode(&res).unwrap().status() == CanisterStatusType::Running
        );

        // Let ic:00 stop the newly created canister.
        assert_eq!(
            test.ingress(IC_00, Method::StopCanister, canister_id_record.clone()),
            Ok(WasmResult::Reply(EmptyBlob.encode()))
        );

        // Verify that the newly created canister is now stopped.
        assert_matches!(
            test.ingress(IC_00, Method::CanisterStatus, canister_id_record.clone()),
            Ok(WasmResult::Reply(res)) if CanisterStatusResultV2::decode(&res).unwrap().status() == CanisterStatusType::Stopped
        );

        // Start the canister again.
        assert_eq!(
            test.ingress(IC_00, Method::StartCanister, canister_id_record.clone()),
            Ok(WasmResult::Reply(EmptyBlob.encode()))
        );

        // Verify that the newly created canister is running.
        assert_matches!(
            test.ingress(IC_00, Method::CanisterStatus, canister_id_record),
            Ok(WasmResult::Reply(res)) if CanisterStatusResultV2::decode(&res).unwrap().status() == CanisterStatusType::Running
        );
    })
}

#[test]
fn delete_canister_with_incorrect_controller_fails() {
    utils::canister_test(|test| {
        let canister_a = test.create_universal_canister();
        let canister_b = test.create_universal_canister();

        // Canister A tries to delete canister B but it's not the controller.
        // Should fail.
        assert_reject(
            test.ingress(
                canister_a,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::DeleteCanister,
                    call_args().other_side(CanisterIdRecord::from(canister_b).encode()),
                ),
            ),
            RejectCode::CanisterError,
        );
    });
}

#[test]
fn delete_canister_delete_self_fails() {
    utils::canister_test(|test| {
        let canister_id = test.create_universal_canister();

        // Set the controller of the canister to be itself.
        assert_eq!(
            test.ingress(
                IC_00,
                Method::UpdateSettings,
                UpdateSettingsArgs::new(
                    canister_id,
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![canister_id.get()])
                        .build(),
                )
                .encode()
            ),
            Ok(WasmResult::Reply(EmptyBlob.encode()))
        );

        // Canister tries to delete itself. Should fail because a self-controlling
        // canister cannot be deleted.
        assert_reject(
            test.ingress(
                canister_id,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::DeleteCanister,
                    call_args().other_side(CanisterIdRecord::from(canister_id).encode()),
                ),
            ),
            RejectCode::CanisterError,
        );
    });
}

#[test]
fn delete_running_canister_fails() {
    utils::canister_test(|test| {
        // Create a new canister
        let canister_a = test.create_universal_canister();
        let canister_b = test.create_canister().unwrap();

        // Verify that the canister_b is running
        let canister_id_record = CanisterIdRecord::from(canister_b).encode();
        assert_matches!(
            test.ingress(IC_00, Method::CanisterStatus, canister_id_record),
            Ok(WasmResult::Reply(res)) if CanisterStatusResultV2::decode(&res).unwrap().status() == CanisterStatusType::Running
        );

        // Set the controller of canister_b to be canister_a
        assert_eq!(
            test.ingress(
                IC_00,
                Method::UpdateSettings,
                UpdateSettingsArgs::new(
                    canister_b,
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![canister_a.into()])
                        .build(),
                )
                .encode()
            ),
            Ok(WasmResult::Reply(EmptyBlob.encode()))
        );

        // Delete the canister. Should fail since it's running.
        assert_reject(
            test.ingress(
                canister_a,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::DeleteCanister,
                    call_args().other_side(CanisterIdRecord::from(canister_b).encode()),
                ),
            ),
            RejectCode::CanisterError,
        );
    });
}

#[test]
fn delete_stopped_canister_succeeds() {
    utils::canister_test(|test| {
        // Create a new canister
        let canister_a = test.create_universal_canister();
        let canister_b = test.create_canister().unwrap();

        // Let ic:00 stop canister_b
        let canister_id_record = CanisterIdRecord::from(canister_b).encode();
        assert_eq!(
            test.ingress(IC_00, "stop_canister", canister_id_record),
            Ok(WasmResult::Reply(EmptyBlob.encode()))
        );

        // Set the controller of canister_b to be canister_a
        test.ingress(
            IC_00,
            Method::UpdateSettings,
            UpdateSettingsArgs::new(
                canister_b,
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![canister_a.into()])
                    .build(),
            )
            .encode(),
        )
        .unwrap();

        // Ask canister_a to delete canister_b. Should succeed.
        test.ingress(
            canister_a,
            "update",
            wasm().call_simple(
                ic00::IC_00,
                Method::DeleteCanister,
                call_args().other_side(CanisterIdRecord::from(canister_b).encode()),
            ),
        )
        .unwrap();

        // Canister calls can not even be made to this canister.
    });
}

#[test]
fn provisional_create_canister_with_cycles_respects_whitelist() {
    {
        let (config, _tmpdir) = Config::temp_config();
        // By default all principals are allowed. This call should succeed.
        utils::canister_test_with_config(config, |test| {
            test.ingress(
                IC_00,
                Method::ProvisionalCreateCanisterWithCycles,
                ic00::ProvisionalCreateCanisterWithCyclesArgs::new(Some(NUM_CYCLES), None).encode(),
            )
            .unwrap();
        });
    }

    {
        let (config, _tmpdir) = Config::temp_config();
        let mut ic_config = utils::get_ic_config();
        let provisional_whitelist = ProvisionalWhitelist::Set(BTreeSet::new());
        ic_config.set_provisional_whitelist(provisional_whitelist);

        // No sender IDs allowed. This call should fail.
        utils::canister_test_with_ic_config(config, ic_config, |test| {
            assert_matches!(
                test.ingress(
                    IC_00,
                    Method::ProvisionalCreateCanisterWithCycles,
                    ic00::ProvisionalCreateCanisterWithCyclesArgs::new(Some(NUM_CYCLES), None).encode(),
                ),
                Err(err) if err.code() == ErrorCode::CanisterMethodNotFound
            );
        });
    }

    let (config, _tmpdir) = Config::temp_config();
    let mut ic_config = utils::get_ic_config();
    let canister_id_1 = CanisterId::from(0);
    let provisional_whitelist =
        ProvisionalWhitelist::Set(btreeset! {PrincipalId::new_anonymous(), canister_id_1.get()});
    ic_config.set_provisional_whitelist(provisional_whitelist);

    utils::canister_test_with_ic_config(config, ic_config, |test| {
        // Creating universal canisters. These succeed because the user is in the
        // whitelist.
        let canister_id_1 = test.create_universal_canister();
        let canister_id_2 = test.create_universal_canister();

        // canister_id_1 is in the whitelist.
        assert_matches!(
            test.ingress(
                canister_id_1,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::ProvisionalCreateCanisterWithCycles,
                    call_args().other_side(
                        ic00::ProvisionalCreateCanisterWithCyclesArgs::new(Some(NUM_CYCLES), None)
                            .encode(),
                    ),
                ),
            ),
            Ok(WasmResult::Reply(_))
        );

        // canister_id_2 isn't in the whitelist.
        assert_reject(
            test.ingress(
                canister_id_2,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::ProvisionalCreateCanisterWithCycles,
                    call_args().other_side(
                        ic00::ProvisionalCreateCanisterWithCyclesArgs::new(Some(NUM_CYCLES), None)
                            .encode(),
                    ),
                ),
            ),
            RejectCode::CanisterError,
        );
    });
}

#[test]
fn provisional_top_up_canister_does_not_exist() {
    {
        let (config, _tmpdir) = Config::temp_config();
        utils::canister_test_with_config(config, |test| {
            assert_matches!(
                test.ingress(
                    IC_00,
                    Method::ProvisionalTopUpCanister,
                    ic00::ProvisionalTopUpCanisterArgs::new(IC_00 /* any principal */, NUM_CYCLES).encode(),
                ),
                Err(err) if err.code() == ErrorCode::CanisterNotFound
            );
        });
    }
}

#[test]
fn provisional_top_up_canister_respects_whitelist() {
    {
        let (config, _tmpdir) = Config::temp_config();
        // By default all principals are allowed. This call should succeed.
        utils::canister_test_with_config(config, |test| {
            let canister_id = test.create_universal_canister();
            test.ingress(
                IC_00,
                Method::ProvisionalTopUpCanister,
                ic00::ProvisionalTopUpCanisterArgs::new(canister_id, NUM_CYCLES).encode(),
            )
            .unwrap();
        });
    }

    let (config, _tmpdir) = Config::temp_config();
    let mut ic_config = utils::get_ic_config();
    let canister_id_1 = CanisterId::from(0);
    let provisional_whitelist =
        ProvisionalWhitelist::Set(btreeset! {PrincipalId::new_anonymous(), canister_id_1.get()});
    ic_config.set_provisional_whitelist(provisional_whitelist);

    utils::canister_test_with_ic_config(config, ic_config, |test| {
        // Creating universal canisters. These succeed because the user is in the
        // whitelist.
        let canister_id_1 = test.create_universal_canister();
        let canister_id_2 = test.create_universal_canister();

        // canister_id_1 is in the whitelist.
        assert_matches!(
            test.ingress(
                canister_id_1,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::ProvisionalTopUpCanister,
                    call_args().other_side(
                        ic00::ProvisionalTopUpCanisterArgs::new(canister_id_1, NUM_CYCLES).encode()
                    ),
                ),
            ),
            Ok(WasmResult::Reply(_))
        );

        // canister_id_2 isn't in the whitelist.
        assert_reject(
            test.ingress(
                canister_id_2,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::ProvisionalTopUpCanister,
                    call_args().other_side(
                        ic00::ProvisionalTopUpCanisterArgs::new(canister_id_1, NUM_CYCLES).encode(),
                    ),
                ),
            ),
            RejectCode::CanisterError,
        );
    });
}

#[test]
fn can_create_canister_with_cycles_from_another_canister() {
    utils::canister_test(|test| {
        let num_cycles = CANISTER_FREEZE_BALANCE_RESERVE + Cycles::new(5_000_000_000_000);

        // Create a universal canister.
        let canister_id = test.create_universal_canister_with_args(vec![], num_cycles.get());

        let old_canister_cycles_balance_before =
            test.canister_state(&canister_id).system_state.balance();

        // Create another canister with some cycles.
        let config = CyclesAccountManagerConfig::application_subnet();
        let cycles_for_new_canister = config.canister_creation_fee + Cycles::new(100_000_000);
        let new_canister_id_payload = test
            .ingress(
                canister_id,
                "update",
                wasm().call_with_cycles(
                    IC_00,
                    Method::CreateCanister,
                    call_args().other_side(EmptyBlob.encode()),
                    cycles_for_new_canister,
                ),
            )
            .unwrap()
            .bytes();

        let new_canister_id = CanisterIdRecord::decode(new_canister_id_payload.as_slice())
            .unwrap()
            .get_canister_id();

        let old_canister_cycles_balance_after =
            test.canister_state(&canister_id).system_state.balance();
        println!("old canister balance after: {old_canister_cycles_balance_after}");
        let new_canister_cycles_balance =
            test.canister_state(&new_canister_id).system_state.balance();

        // Check that the balance of the sending canister after creating a new canister
        // is at most its previous balance minus the cycles transferred.
        assert!(
            old_canister_cycles_balance_after
                <= old_canister_cycles_balance_before - cycles_for_new_canister,
            "Cycle balance of the creating canister should decrease by at least {cycles_for_new_canister}"
        );

        // Check that the balance of the created canister is at most the cycles
        // transferred.
        assert!(
            new_canister_cycles_balance <= cycles_for_new_canister,
            "Cycle balance of the newly created canister is larger than the cycles transferred to it"
        );
    });
}

#[test]
fn provisional_create_canister_with_cycles_and_top_up() {
    let (config, _tmpdir) = Config::temp_config();
    let mut ic_config = utils::get_ic_config();
    let provisional_whitelist = ProvisionalWhitelist::Set(btreeset!(
        // PrincipalId of CanisterA that is created below.  This code assumes
        // that we can predict the canister Ids that are generated in
        // CanisterManager and may need updating if that is no longer the case.
        PrincipalId::from_str("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap(),
        PrincipalId::new_anonymous(),
    ));
    ic_config.set_provisional_whitelist(provisional_whitelist);

    utils::canister_test_with_ic_config(config, ic_config, |test| {
        // Create a canister
        let canister_a_id = test.create_universal_canister();
        let canister_a_cycles_before: u128 = test
            .canister_state(&canister_a_id)
            .system_state
            .balance()
            .get();
        let canister_b_cycles_init = canister_a_cycles_before / 2; // Create with 1/2 * cycles of canister_a
        let canister_b_cycles_top_up = canister_b_cycles_init; // Top-Up with just as many cycles

        // From `canister_a` call `IC_00` to create a canister with cycles.
        let canister_b_id = test
            .ingress(
                canister_a_id,
                "update",
                wasm().call_simple(
                    IC_00,
                    Method::ProvisionalCreateCanisterWithCycles,
                    call_args().other_side(
                        ic00::ProvisionalCreateCanisterWithCyclesArgs::new(
                            Some(canister_b_cycles_init),
                            None,
                        )
                        .encode(),
                    ),
                ),
            )
            .unwrap()
            .bytes();

        let canister_b_id = CanisterIdRecord::decode(canister_b_id.as_slice())
            .unwrap()
            .get_canister_id();

        let canister_b_cycles: u128 = test
            .canister_state(&canister_b_id)
            .system_state
            .balance()
            .get();

        assert_eq!(canister_b_cycles, canister_b_cycles_init);

        // From `canister_a` call `IC_00` to top-up `canister_b`.
        test.ingress(
            canister_a_id,
            "update",
            wasm().call_simple(
                IC_00,
                Method::ProvisionalTopUpCanister,
                call_args().other_side(
                    ic00::ProvisionalTopUpCanisterArgs::new(
                        canister_b_id,
                        canister_b_cycles_top_up,
                    )
                    .encode(),
                ),
            ),
        )
        .unwrap()
        .bytes();

        let canister_b_cycles_after_top_up: u128 = test
            .canister_state(&canister_b_id)
            .system_state
            .balance()
            .get();

        // Canister B now has (init + top-up) cycles
        assert_eq!(
            canister_b_cycles_after_top_up,
            canister_b_cycles_init + canister_b_cycles_top_up
        );

        // From `canister_a` call `IC_00` to create a canister without cycles argument.
        // The default value is `config.hypervisor.default_provisional_cycles_balance`.
        let canister_c_id = test
            .ingress(
                canister_a_id,
                "update",
                wasm().call_simple(
                    IC_00,
                    Method::ProvisionalCreateCanisterWithCycles,
                    call_args().other_side(
                        ic00::ProvisionalCreateCanisterWithCyclesArgs::new(None, None).encode(),
                    ),
                ),
            )
            .unwrap()
            .bytes();

        let canister_c_id = CanisterIdRecord::decode(canister_c_id.as_slice())
            .unwrap()
            .get_canister_id();

        let canister_c_cycles = test.canister_state(&canister_c_id).system_state.balance();

        assert_eq!(
            canister_c_cycles,
            Config::temp_config()
                .0
                .hypervisor
                .default_provisional_cycles_balance
        );
    });
}

#[test]
fn can_get_canister_information() {
    utils::canister_test(|test| {
        // Create a new canister
        let canister_a = test.create_universal_canister();
        let num_cycles = Cycles::new(1 << 70);
        let canister_b = test.create_canister_with_cycles(num_cycles.get()).unwrap();

        // Set the controller of canister_b to be canister_a
        assert_eq!(
            test.ingress(
                IC_00,
                Method::UpdateSettings,
                UpdateSettingsArgs::new(
                    canister_b,
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![canister_a.into()])
                        .build(),
                )
                .encode()
            ),
            Ok(WasmResult::Reply(EmptyBlob.encode()))
        );

        let canister_history_size =
            NumBytes::from((2 * size_of::<CanisterChange>() + 2 * size_of::<PrincipalId>()) as u64);
        // Request the status of canister_b.
        assert_matches!(
            test.ingress(
                canister_a,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::CanisterStatus,
                    call_args().other_side(CanisterIdRecord::from(canister_b).encode()),
                ),
            ),
            // We can check exact equality because no costs are incurred for a
            // canister that's created but has no code installed on it.
            Ok(WasmResult::Reply(res)) if CanisterStatusResultV2::decode(&res).unwrap() == CanisterStatusResultV2::new(
                CanisterStatusType::Running,
                false,
                1,
                None,
                canister_a.get(),
                vec![canister_a.get()],
                canister_history_size,
                NumBytes::from(0),
                NumBytes::from(0),
                NumBytes::from(0),
                NumBytes::from(0),
                NumBytes::from(0),
                canister_history_size,
                NumBytes::from(0),
                NumBytes::from(0),
                num_cycles.get(),
                ComputeAllocation::default().as_percent(),
                None,
                2592000,
                Some(5_000_000_000_000u128),
                LogVisibilityV2::default(),
                TEST_DEFAULT_LOG_MEMORY_LIMIT,
                0u128,
                0u128,
                0u128,
                0u128,
                0u128,
                0u128,
                Some(DEFAULT_WASM_MEMORY_LIMIT.get()),
                0u64,
                Default::default(),
            )
        );

        // Install code to canister_b.
        test.ingress(
            canister_a,
            "update",
            wasm().call_simple(
                ic00::IC_00,
                Method::InstallCode,
                call_args().other_side(
                    InstallCodeArgs::new(
                        CanisterInstallMode::Install,
                        canister_b,
                        UNIVERSAL_CANISTER_WASM.to_vec(),
                        vec![],
                    )
                    .encode(),
                ),
            ),
        )
        .unwrap();

        // Request the status of canister_b.
        assert_matches!(
            test.ingress(
                canister_a,
                "update",
                wasm().call_simple(
                    ic00::IC_00,
                    Method::CanisterStatus,
                    call_args().other_side(CanisterIdRecord::from(canister_b).encode()),
                ),
            ),
            Ok(WasmResult::Reply(res)) => assert_canister_status_result_equals(
                CanisterStatusResultV2::new(
                    CanisterStatusType::Running,
                    false,
                    0,
                    Some(ic_crypto_sha2::Sha256::hash(&UNIVERSAL_CANISTER_WASM).to_vec()),
                    canister_a.get(),
                    vec![canister_a.get()],
                    // We don't assert a specific memory size since the universal canister's
                    // size changes between updates.
                    NumBytes::from(0),
                    NumBytes::from(0),
                    NumBytes::from(0),
                    NumBytes::from(0),
                    NumBytes::from(0),
                    NumBytes::from(0),
                    NumBytes::from(0),
                    NumBytes::from(0),
                    NumBytes::from(0),
                    num_cycles.get(),
                    ComputeAllocation::default().as_percent(),
                    None,
                    259200,
                    None,
                    LogVisibilityV2::default(),
                    TEST_DEFAULT_LOG_MEMORY_LIMIT,
                    0u128,
                    0u128,
                    0u128,
                    0u128,
                    0u128,
                    0u128,
                    Some(DEFAULT_WASM_MEMORY_LIMIT.get()),
                    0u64,
                    Default::default(),
                ),
                CanisterStatusResultV2::decode(&res).unwrap(),
                2 * BALANCE_EPSILON,
            )
        );
    });
}

#[test]
fn cannot_run_method_on_empty_canister() {
    utils::canister_test(|test| {
        let canister = test.create_canister().unwrap();
        match test.ingress(canister, "hello", vec![]) {
            Err(err) => {
                err.assert_contains(
                    ErrorCode::CanisterWasmModuleNotFound,
                    "Error from Canister rwlgt-iiaaa-aaaaa-aaaaa-cai: Attempted \
                    to execute a message, but the canister contains no Wasm module.",
                );
            }
            rest => panic!("Unexpected behaviour {rest:?}"),
        }
    })
}

// Asserts that two `CanisterStatusResult`s are almost equal. Because
// `CanisterStatusResult` contains cycles balances, we can't assert on actual
// equality, so use the helper method that asserts two cycles balances are equal
// within some accuracy. Additionally, we ignore the memory size.
fn assert_canister_status_result_equals(
    expected: CanisterStatusResultV2,
    actual: CanisterStatusResultV2,
    epsilon: u64,
) {
    assert_eq!(expected.status(), actual.status());
    assert_eq!(expected.module_hash(), actual.module_hash());
    assert_eq!(expected.controller(), actual.controller());
    assert_balance_equals(
        Cycles::from(expected.cycles()),
        Cycles::from(actual.cycles()),
        Cycles::from(epsilon),
    );
}

#[test]
// Tests canister Upgrade with skipping pre_upgrade hook, using CanisterInstallModeV2.
fn test_canister_skip_upgrade() {
    utils::simple_canister_test(|canister| {
        let num_cycles = Cycles::new(1 << 70);

        // Create a new canister from within a canister.
        let reply = match canister
            .update(wasm().call(management::create_canister(num_cycles)))
            .unwrap()
        {
            WasmResult::Reply(reply) => reply,
            _ => panic!("Unexpected result"),
        };

        let canister_id = CanisterIdRecord::decode(&reply).unwrap().get_canister_id();

        // Install canister code.
        assert_matches!(
            canister.update(wasm().call(management::install_code(
                canister_id,
                &*UNIVERSAL_CANISTER_WASM
            ))),
            Ok(WasmResult::Reply(_))
        );

        let set_trap_pre_upgrade = wasm().set_pre_upgrade(wasm().trap()).reply().build();

        // Set pre_upgrade to trap.
        assert_matches!(
            canister.update(
                wasm().inter_update(canister_id, call_args().other_side(set_trap_pre_upgrade),)
            ),
            Ok(WasmResult::Reply(_))
        );

        // Upgrade without skipping pre_upgrade should fail.
        assert_matches!(
            canister.update(wasm().call(
                management::install_code(canister_id, &*UNIVERSAL_CANISTER_WASM).with_mode(
                    management::InstallMode::Upgrade(Some(CanisterUpgradeOptions {
                        skip_pre_upgrade: Some(false),
                        wasm_memory_persistence: None,
                    })),
                ),
            )),
            Ok(WasmResult::Reject(_))
        );

        // Upgrade with skipping pre upgrade should succeed.
        assert_matches!(
            canister.update(wasm().call(
                management::install_code(canister_id, &*UNIVERSAL_CANISTER_WASM).with_mode(
                    management::InstallMode::Upgrade(Some(CanisterUpgradeOptions {
                        skip_pre_upgrade: Some(true),
                        wasm_memory_persistence: None,
                    }))
                ),
            )),
            Ok(WasmResult::Reply(_))
        );

        // Check that canister is upgraded. We try to execute another upgrade without skipping pre_upgrade,
        // and it should succeed since there's a no-op pre_ugprade method after the upgrade.
        assert_matches!(
            canister.update(wasm().call(
                management::install_code(canister_id, &*UNIVERSAL_CANISTER_WASM).with_mode(
                    management::InstallMode::Upgrade(Some(CanisterUpgradeOptions {
                        skip_pre_upgrade: Some(false),
                        wasm_memory_persistence: None,
                    })),
                ),
            )),
            Ok(WasmResult::Reply(_))
        );
    });
}
