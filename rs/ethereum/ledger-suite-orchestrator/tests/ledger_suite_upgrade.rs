use candid::{Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_ledger_suite_orchestrator::candid::{InstalledCanister, InstalledLedgerSuite};
use ic_ledger_suite_orchestrator::candid::{LedgerSuiteVersion, UpgradeArg};
use ic_ledger_suite_orchestrator::state::WasmHash;
use ic_ledger_suite_orchestrator_test_utils::universal_canister::{
    CanisterChangeDetails, CanisterInfoResponse, CanisterInstallMode, UniversalCanister,
};
use ic_ledger_suite_orchestrator_test_utils::{
    default_init_arg, ledger_suite_orchestrator_wasm, ledger_wasm, new_state_machine,
    tweak_ledger_suite_wasms, usdc, usdc_erc20_contract, usdt, usdt_erc20_contract,
    LedgerSuiteOrchestrator, GIT_COMMIT_HASH_UPGRADE, MINTER_PRINCIPAL, NNS_ROOT_PRINCIPAL,
};
use ic_state_machine_tests::{CanisterSettingsArgsBuilder, CanisterStatusType};
use icrc_ledger_types::icrc1::transfer::TransferArg;
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use proptest::prelude::Rng;
use std::sync::Arc;

#[test]
fn should_not_change_ledger_suite_version_when_registering_embedded_wasms_a_second_time() {
    let env = Arc::new(new_state_machine());
    let orchestrator_v1 = LedgerSuiteOrchestrator::new_with_ledger_get_blocks_disabled(
        env.clone(),
        default_init_arg(),
    )
    .register_embedded_wasms();
    let embedded_ledger_suite_v1 = orchestrator_v1.embedded_ledger_suite_version();

    assert_eq!(
        orchestrator_v1.get_orchestrator_info().ledger_suite_version,
        Some(embedded_ledger_suite_v1.clone().into())
    );

    let orchestrator_v2 = orchestrator_v1.upgrade_ledger_suite_orchestrator(
        ledger_suite_orchestrator_wasm(),
        UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH_UPGRADE.to_string()),
            ledger_compressed_wasm_hash: None,
            index_compressed_wasm_hash: None,
            archive_compressed_wasm_hash: None,
            cycles_management: None,
            manage_ledger_suites: None,
        },
    );

    assert_eq!(
        orchestrator_v2.get_orchestrator_info().ledger_suite_version,
        Some(embedded_ledger_suite_v1.into())
    );
}

#[test]
fn should_have_two_different_orchestrator_versions_embedding_two_different_ledgers() {
    let env = Arc::new(new_state_machine());

    let orchestrator_v1 = LedgerSuiteOrchestrator::new_with_ledger_get_blocks_disabled(
        env.clone(),
        default_init_arg(),
    );
    let embedded_ledger_wasm_hash_v1 = orchestrator_v1.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash_v1 = orchestrator_v1.embedded_index_wasm_hash.clone();

    let orchestrator_v2 = LedgerSuiteOrchestrator::new(env.clone(), default_init_arg());
    let embedded_ledger_wasm_hash_v2 = orchestrator_v2.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash_v2 = orchestrator_v2.embedded_index_wasm_hash.clone();

    assert_ne!(embedded_ledger_wasm_hash_v1, embedded_ledger_wasm_hash_v2);
    assert_eq!(embedded_index_wasm_hash_v1, embedded_index_wasm_hash_v2);

    orchestrator_v1
        .register_embedded_wasms()
        .add_erc20_token(usdc())
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v1);

    orchestrator_v2
        .register_embedded_wasms()
        .add_erc20_token(usdc())
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v2);
}

#[test]
fn should_upgrade_managed_ledgers_to_new_version() {
    let env = Arc::new(new_state_machine());
    let orchestrator_v1 = LedgerSuiteOrchestrator::new_with_ledger_get_blocks_disabled(
        env.clone(),
        default_init_arg(),
    );
    let embedded_ledger_wasm_hash_v1 = orchestrator_v1.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash_v1 = orchestrator_v1.embedded_index_wasm_hash.clone();
    let embedded_archive_wasm_hash_v1 = orchestrator_v1.embedded_archive_wasm_hash.clone();

    let orchestrator_v1 = orchestrator_v1
        .register_embedded_wasms()
        .add_erc20_token(usdc())
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v1)
        .setup
        .add_erc20_token(usdt())
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v1)
        .setup;

    let ckusdc_ledger = orchestrator_v1
        .call_orchestrator_canister_ids(&usdc_erc20_contract())
        .unwrap()
        .ledger
        .unwrap();
    let ckusdt_ledger = orchestrator_v1
        .call_orchestrator_canister_ids(&usdt_erc20_contract())
        .unwrap()
        .ledger
        .unwrap();

    assert_eq!(
        orchestrator_v1.get_orchestrator_info().ledger_suite_version,
        Some(LedgerSuiteVersion {
            ledger_compressed_wasm_hash: embedded_ledger_wasm_hash_v1.to_string(),
            index_compressed_wasm_hash: embedded_index_wasm_hash_v1.to_string(),
            archive_compressed_wasm_hash: embedded_archive_wasm_hash_v1.to_string(),
        })
    );

    let embedded_ledger_wasm_v2 = ledger_wasm();
    assert_ne!(
        &embedded_ledger_wasm_hash_v1,
        embedded_ledger_wasm_v2.hash()
    );
    let orchestrator_v2 = orchestrator_v1.upgrade_ledger_suite_orchestrator(
        ledger_suite_orchestrator_wasm(),
        UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH_UPGRADE.to_string()),
            ledger_compressed_wasm_hash: Some(embedded_ledger_wasm_v2.hash().to_string()),
            index_compressed_wasm_hash: None,
            archive_compressed_wasm_hash: None,
            cycles_management: None,
            manage_ledger_suites: None,
        },
    );

    assert_eq!(
        orchestrator_v2.get_orchestrator_info().ledger_suite_version,
        Some(LedgerSuiteVersion {
            ledger_compressed_wasm_hash: embedded_ledger_wasm_v2.hash().to_string(),
            index_compressed_wasm_hash: embedded_index_wasm_hash_v1.to_string(),
            archive_compressed_wasm_hash: embedded_archive_wasm_hash_v1.to_string(),
        })
    );

    orchestrator_v2.advance_time_for_upgrade();

    for ledger in [ckusdc_ledger, ckusdt_ledger] {
        let status =
            orchestrator_v2.canister_status_of(CanisterId::unchecked_from_principal(ledger.into()));
        assert_eq!(
            status.module_hash(),
            Some(embedded_ledger_wasm_v2.hash().as_ref().to_vec())
        );
        assert_eq!(status.status(), CanisterStatusType::Running);
    }
}

#[test]
fn should_upgrade_all_managed_canisters_with_different_versions_to_same_version() {
    let env = Arc::new(new_state_machine());
    let orchestrator =
        LedgerSuiteOrchestrator::new(env.clone(), default_init_arg()).register_embedded_wasms();
    let universal_canister = UniversalCanister::new(env.clone());
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let embedded_archive_wasm_hash = orchestrator.embedded_archive_wasm_hash.clone();

    let (tweak_ledger_wasm, tweak_index_wasm, _) = tweak_ledger_suite_wasms();
    let tweak_ledger_wasm_hash = tweak_ledger_wasm.hash().clone();
    assert_ne!(tweak_ledger_wasm_hash, embedded_ledger_wasm_hash);
    let tweak_index_wasm_hash = tweak_index_wasm.hash().clone();
    assert_ne!(tweak_index_wasm_hash, embedded_index_wasm_hash);

    let has_last_been_upgraded_to = |canister_info: &CanisterInfoResponse, wasm_hash: &WasmHash| {
        let changes: Vec<_> = canister_info
            .changes()
            .into_iter()
            .map(|c| c.details().clone())
            .collect();
        let expected_change = CanisterChangeDetails::code_deployment(
            CanisterInstallMode::Upgrade,
            wasm_hash.clone().into(),
        );
        changes.last() == Some(&expected_change)
    };

    let orchestrator = orchestrator
        .add_erc20_token(usdc())
        .expect_new_ledger_and_index_canisters()
        .trigger_creation_of_archive()
        .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash)
        .ledger_out_of_band_upgrade(NNS_ROOT_PRINCIPAL, tweak_ledger_wasm)
        .assert_ledger_has_wasm_hash(&tweak_ledger_wasm_hash)
        .setup
        .add_erc20_token(usdt())
        .expect_new_ledger_and_index_canisters()
        .trigger_creation_of_archive()
        .assert_index_has_wasm_hash(&embedded_index_wasm_hash)
        .index_out_of_band_upgrade(NNS_ROOT_PRINCIPAL, tweak_index_wasm)
        .assert_index_has_wasm_hash(&tweak_index_wasm_hash)
        .setup;

    let orchestrator = orchestrator.upgrade_ledger_suite_orchestrator(
        ledger_suite_orchestrator_wasm(),
        UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH_UPGRADE.to_string()),
            ledger_compressed_wasm_hash: Some(embedded_ledger_wasm_hash.to_string()),
            index_compressed_wasm_hash: Some(embedded_index_wasm_hash.to_string()),
            archive_compressed_wasm_hash: Some(embedded_archive_wasm_hash.to_string()),
            cycles_management: None,
            manage_ledger_suites: None,
        },
    );
    orchestrator.advance_time_for_upgrade();
    orchestrator.advance_time_for_upgrade();

    let mut orchestrator = orchestrator;
    for erc20_contract in [usdc_erc20_contract(), usdt_erc20_contract()] {
        orchestrator = orchestrator
            .assert_managed_canisters(&erc20_contract)
            .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash)
            .assert_ledger_canister_info_satisfy(&universal_canister, |t| {
                has_last_been_upgraded_to(t, &embedded_ledger_wasm_hash)
            })
            .assert_index_has_wasm_hash(&embedded_index_wasm_hash)
            .assert_index_canister_info_satisfy(&universal_canister, |t| {
                has_last_been_upgraded_to(t, &embedded_index_wasm_hash)
            })
            .assert_all_archive_canister_info_satisfy(&universal_canister, |t| {
                has_last_been_upgraded_to(t, &embedded_archive_wasm_hash)
            })
            .setup
    }
}

#[test]
fn should_upgrade_all_managed_canisters_to_same_already_installed_version() {
    let env = Arc::new(new_state_machine());
    let orchestrator =
        LedgerSuiteOrchestrator::new(env.clone(), default_init_arg()).register_embedded_wasms();
    let universal_canister = UniversalCanister::new(env.clone());
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let embedded_archive_wasm_hash = orchestrator.embedded_archive_wasm_hash.clone();

    let has_only_install_change = |canister_info: &CanisterInfoResponse, wasm_hash: &WasmHash| {
        let changes: Vec<_> = canister_info
            .changes()
            .into_iter()
            .map(|c| c.details().clone())
            .collect();
        matches!(
            changes.first(),
            Some(CanisterChangeDetails::CanisterCreation(_))
        ) && matches!(changes.get(1), Some(x) if x == &CanisterChangeDetails::code_deployment(
            CanisterInstallMode::Install,
            wasm_hash.clone().into(),
        )) && matches!(
            changes.get(2), //ledger will change controller of spawned off archive
            None | Some(CanisterChangeDetails::CanisterControllersChange(_))
        ) && changes.len() <= 3
    };

    let has_been_upgraded_to = |canister_info: &CanisterInfoResponse, wasm_hash: &WasmHash| {
        let changes: Vec<_> = canister_info
            .changes()
            .into_iter()
            .map(|c| c.details().clone())
            .collect();
        let expected_change = CanisterChangeDetails::code_deployment(
            CanisterInstallMode::Upgrade,
            wasm_hash.clone().into(),
        );
        (matches!(changes.get(2), Some(c) if c == &expected_change)
            || matches!(changes.get(3), Some(c) if c == &expected_change))
            && changes.len() <= 4
    };

    let mut orchestrator = orchestrator;
    for add_erc20 in [usdc(), usdt()] {
        orchestrator = orchestrator
            .add_erc20_token(add_erc20)
            .expect_new_ledger_and_index_canisters()
            .assert_ledger_canister_info_satisfy(&universal_canister, |t| {
                has_only_install_change(t, &embedded_ledger_wasm_hash)
            })
            .assert_index_canister_info_satisfy(&universal_canister, |t| {
                has_only_install_change(t, &embedded_index_wasm_hash)
            })
            .trigger_creation_of_archive()
            .assert_all_archive_canister_info_satisfy(&universal_canister, |t| {
                has_only_install_change(t, &embedded_archive_wasm_hash)
            })
            .setup
    }

    let orchestrator = orchestrator.upgrade_ledger_suite_orchestrator(
        ledger_suite_orchestrator_wasm(),
        UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH_UPGRADE.to_string()),
            ledger_compressed_wasm_hash: Some(embedded_ledger_wasm_hash.to_string()),
            index_compressed_wasm_hash: Some(embedded_index_wasm_hash.to_string()),
            archive_compressed_wasm_hash: Some(embedded_archive_wasm_hash.to_string()),
            cycles_management: None,
            manage_ledger_suites: None,
        },
    );

    orchestrator.advance_time_for_upgrade();
    orchestrator.advance_time_for_upgrade();

    let mut orchestrator = orchestrator;
    for erc20_contract in [usdc_erc20_contract(), usdt_erc20_contract()] {
        orchestrator = orchestrator
            .assert_managed_canisters(&erc20_contract)
            .assert_index_canister_info_satisfy(&universal_canister, |t| {
                has_been_upgraded_to(t, &embedded_index_wasm_hash)
            })
            .assert_ledger_canister_info_satisfy(&universal_canister, |t| {
                has_been_upgraded_to(t, &embedded_ledger_wasm_hash)
            })
            .assert_all_archive_canister_info_satisfy(&universal_canister, |t| {
                has_been_upgraded_to(t, &embedded_archive_wasm_hash)
            })
            .setup
    }
}

#[test]
fn should_upgrade_without_reinstalling() {
    let env = Arc::new(new_state_machine());
    let orchestrator_v1 = LedgerSuiteOrchestrator::new_with_ledger_get_blocks_disabled(
        env.clone(),
        default_init_arg(),
    );
    let embedded_ledger_wasm_hash_v1 = orchestrator_v1.embedded_ledger_wasm_hash.clone();

    let orchestrator_v1 = orchestrator_v1
        .register_embedded_wasms()
        .add_erc20_token(usdc())
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v1);
    let mint_index = orchestrator_v1
        .call_ledger_icrc1_transfer(
            MINTER_PRINCIPAL,
            &TransferArg {
                from_subaccount: None,
                to: Principal::management_canister().into(),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(1_000_000u32),
            },
        )
        .expect("failed to mint 1 ckUSDC");
    let blocks_before_upgrade =
        orchestrator_v1.call_ledger_icrc3_get_blocks(&vec![GetBlocksRequest {
            start: mint_index.clone(),
            length: Nat::from(1_u8),
        }]);
    assert_eq!(blocks_before_upgrade.blocks.len(), 1);

    let embedded_ledger_wasm_v2 = ledger_wasm();
    assert_ne!(
        &embedded_ledger_wasm_hash_v1,
        embedded_ledger_wasm_v2.hash()
    );
    let orchestrator_v2 = orchestrator_v1.setup.upgrade_ledger_suite_orchestrator(
        ledger_suite_orchestrator_wasm(),
        UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH_UPGRADE.to_string()),
            ledger_compressed_wasm_hash: Some(embedded_ledger_wasm_v2.hash().to_string()),
            index_compressed_wasm_hash: None,
            archive_compressed_wasm_hash: None,
            cycles_management: None,
            manage_ledger_suites: None,
        },
    );

    orchestrator_v2.advance_time_for_upgrade();

    let orchestrator_v2 = orchestrator_v2
        .assert_managed_canisters(&usdc_erc20_contract())
        .assert_ledger_has_wasm_hash(embedded_ledger_wasm_v2.hash());

    let blocks_after_upgrade =
        orchestrator_v2.call_ledger_icrc3_get_blocks(&vec![GetBlocksRequest {
            start: mint_index,
            length: Nat::from(1_u8),
        }]);
    assert_eq!(blocks_before_upgrade, blocks_after_upgrade);
}

#[test]
fn should_upgrade_when_some_canister_are_stopped_to_simulate_previous_upgrade_failure() {
    let rng = &mut reproducible_rng();
    let [stop_ledger, stop_index] = rng.gen::<[bool; 2]>();
    test_when_canisters_stopped(stop_ledger, stop_index);

    fn test_when_canisters_stopped(stop_ledger: bool, stop_index: bool) {
        let orchestrator = LedgerSuiteOrchestrator::default();
        let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
        let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();

        let (tweak_ledger_wasm, tweak_index_wasm, _) = tweak_ledger_suite_wasms();
        let tweak_ledger_wasm_hash = tweak_ledger_wasm.hash().clone();
        assert_ne!(tweak_ledger_wasm_hash, embedded_ledger_wasm_hash);
        let tweak_index_wasm_hash = tweak_index_wasm.hash().clone();
        assert_ne!(tweak_index_wasm_hash, embedded_index_wasm_hash);

        let orchestrator = orchestrator
            .add_erc20_token(usdc())
            .expect_new_ledger_and_index_canisters()
            .trigger_creation_of_archive()
            .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash)
            .ledger_out_of_band_upgrade(NNS_ROOT_PRINCIPAL, tweak_ledger_wasm)
            .assert_ledger_has_wasm_hash(&tweak_ledger_wasm_hash)
            .assert_index_has_wasm_hash(&embedded_index_wasm_hash)
            .index_out_of_band_upgrade(NNS_ROOT_PRINCIPAL, tweak_index_wasm)
            .assert_index_has_wasm_hash(&tweak_index_wasm_hash);

        let orchestrator = match (stop_ledger, stop_index) {
            (true, true) => orchestrator.stop_ledger().stop_index(),
            (true, false) => orchestrator.stop_ledger(),
            (false, true) => orchestrator.stop_index(),
            (false, false) => orchestrator,
        }
        .setup;

        let orchestrator = orchestrator.upgrade_ledger_suite_orchestrator(
            ledger_suite_orchestrator_wasm(),
            UpgradeArg {
                git_commit_hash: Some(GIT_COMMIT_HASH_UPGRADE.to_string()),
                ledger_compressed_wasm_hash: Some(embedded_ledger_wasm_hash.to_string()),
                index_compressed_wasm_hash: Some(embedded_index_wasm_hash.to_string()),
                archive_compressed_wasm_hash: None,
                cycles_management: None,
                manage_ledger_suites: None,
            },
        );

        orchestrator.advance_time_for_upgrade();
        orchestrator.advance_time_for_upgrade();

        orchestrator
            .assert_managed_canisters(&usdc_erc20_contract())
            .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash)
            .assert_index_has_wasm_hash(&embedded_index_wasm_hash);
    }
}

// Upgrading the ledger is not an atomic operation and so the ledger could spawn a new archive:
// 1) before the upgrade: this case is potentially problematic since the new archive is spawned off from the not yet upgraded version of the ledger
// and upgrading the ledger afterwards won't automatically upgrade previously spawned archives.
// 2) after the upgrade: this case is typically fine since the new archive is spawned off from the upgraded version of the ledger,
// which typically corresponds to the new version of the archive that one wants to upgrade to.
#[test]
fn should_upgrade_archive_created_just_before_ledger_upgrade() {
    let env = Arc::new(new_state_machine());
    let orchestrator =
        LedgerSuiteOrchestrator::new(env.clone(), default_init_arg()).register_embedded_wasms();
    let universal_canister = UniversalCanister::new(env.clone());
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let embedded_archive_wasm_hash = orchestrator.embedded_archive_wasm_hash.clone();

    let has_been_upgraded_to = |canister_info: &CanisterInfoResponse, wasm_hash: &WasmHash| {
        let changes: Vec<_> = canister_info
            .changes()
            .into_iter()
            .map(|c| c.details().clone())
            .collect();
        let expected_change = CanisterChangeDetails::code_deployment(
            CanisterInstallMode::Upgrade,
            wasm_hash.clone().into(),
        );
        (matches!(changes.get(2), Some(c) if c == &expected_change)
            || matches!(changes.get(3), Some(c) if c == &expected_change))
            && changes.len() <= 4
    };

    let managed_canisters = orchestrator
        .add_erc20_token(usdc())
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_wasm_hash(embedded_ledger_wasm_hash.clone())
        .assert_index_has_wasm_hash(embedded_index_wasm_hash.clone())
        .check_metrics()
        .assert_contains_metric("ledger_suite_orchestrator_managed_archives 0");

    // Run task DiscoverArchives pre-emptively to ensure it's not run during upgrade
    // so that we can test the case where the orchestrator doesn't know about the archive
    managed_canisters.setup.advance_time_for_periodic_tasks();

    let managed_canisters = managed_canisters
        .check_metrics()
        .assert_contains_metric("ledger_suite_orchestrator_managed_archives 0")
        .trigger_creation_of_archive()
        .check_metrics()
        // the orchestrator is not yet aware of the archive
        .assert_contains_metric("ledger_suite_orchestrator_managed_archives 0");

    let orchestrator = managed_canisters.setup.upgrade_ledger_suite_orchestrator(
        ledger_suite_orchestrator_wasm(),
        UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH_UPGRADE.to_string()),
            ledger_compressed_wasm_hash: Some(embedded_ledger_wasm_hash.to_string()),
            index_compressed_wasm_hash: None,
            archive_compressed_wasm_hash: Some(embedded_archive_wasm_hash.to_string()),
            cycles_management: None,
            manage_ledger_suites: None,
        },
    );

    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator.env.tick();
    let orchestrator = orchestrator
        .assert_managed_canisters(&usdc_erc20_contract())
        .assert_ledger_canister_info_satisfy(&universal_canister, |t| {
            has_been_upgraded_to(t, &embedded_ledger_wasm_hash)
        })
        .check_metrics()
        // the orchestrator is not yet aware of the archive
        .assert_contains_metric("ledger_suite_orchestrator_managed_archives 0")
        .setup;

    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator
        .assert_managed_canisters(&usdc_erc20_contract())
        .assert_all_archive_canister_info_satisfy(&universal_canister, |t| {
            has_been_upgraded_to(t, &embedded_archive_wasm_hash)
        })
        .check_metrics()
        .assert_contains_metric("ledger_suite_orchestrator_managed_archives 1");
}

#[test]
fn should_upgrade_canisters_managed_but_not_installed_by_orchestrator() {
    let env = Arc::new(new_state_machine());
    let orchestrator =
        LedgerSuiteOrchestrator::new(env.clone(), default_init_arg()).register_embedded_wasms();
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let embedded_archive_wasm_hash = orchestrator.embedded_archive_wasm_hash.clone();
    let [ledger, index] = {
        // Temporary orchestrator is used as helper to spawn-off a new ledger suite.
        let orchestrator_v1 = LedgerSuiteOrchestrator::new_with_ledger_get_blocks_disabled(
            env.clone(),
            default_init_arg(),
        );
        let embedded_ledger_wasm_hash_v1 = orchestrator_v1.embedded_ledger_wasm_hash.clone();
        let embedded_index_wasm_hash_v1 = orchestrator_v1.embedded_index_wasm_hash.clone();
        assert_ne!(embedded_ledger_wasm_hash, embedded_ledger_wasm_hash_v1);
        let canisters = orchestrator_v1
            .register_embedded_wasms()
            .add_erc20_token(usdc())
            .expect_new_ledger_and_index_canisters()
            .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v1)
            .canister_ids;
        [
            InstalledCanister {
                canister_id: canisters.ledger.unwrap(),
                installed_wasm_hash: embedded_ledger_wasm_hash_v1.to_string(),
            },
            InstalledCanister {
                canister_id: canisters.index.unwrap(),
                installed_wasm_hash: embedded_index_wasm_hash_v1.to_string(),
            },
        ]
    };
    let universal_canister = UniversalCanister::new(env.clone());
    for canister_id in [ledger.canister_id, index.canister_id] {
        env.update_settings(
            &CanisterId::try_from(PrincipalId(canister_id)).unwrap(),
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![orchestrator.ledger_suite_orchestrator_id.into()])
                .build(),
        )
        .unwrap();
    }

    let orchestrator = orchestrator.upgrade_ledger_suite_orchestrator(
        ledger_suite_orchestrator_wasm(),
        UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH_UPGRADE.to_string()),
            ledger_compressed_wasm_hash: Some(embedded_ledger_wasm_hash.to_string()),
            index_compressed_wasm_hash: Some(embedded_index_wasm_hash.to_string()),
            archive_compressed_wasm_hash: Some(embedded_archive_wasm_hash.to_string()),
            cycles_management: None,
            manage_ledger_suites: Some(vec![InstalledLedgerSuite {
                token_symbol: "ckETH".to_string(),
                ledger: ledger.clone(),
                index: index.clone(),
                archives: None,
            }]),
        },
    );

    orchestrator.advance_time_for_upgrade();
    orchestrator.advance_time_for_upgrade();

    assert_eq!(
        universal_canister
            .canister_info(CanisterId::try_from(PrincipalId(index.canister_id)).unwrap())
            .module_hash()
            .unwrap()
            .as_slice(),
        embedded_index_wasm_hash.as_ref()
    );
    assert_eq!(
        universal_canister
            .canister_info(CanisterId::try_from(PrincipalId(ledger.canister_id)).unwrap())
            .module_hash()
            .unwrap()
            .as_slice(),
        embedded_ledger_wasm_hash.as_ref()
    );
}
