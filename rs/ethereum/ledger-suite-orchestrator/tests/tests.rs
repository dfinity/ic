use assert_matches::assert_matches;
use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_icrc1_ledger::FeatureFlags as LedgerFeatureFlags;
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, CyclesManagement, LedgerInitArg, ManagedCanisterStatus, ManagedCanisters,
    OrchestratorArg, OrchestratorInfo, UpdateCyclesManagement, UpgradeArg,
};
use ic_ledger_suite_orchestrator_test_utils::arbitrary::arb_init_arg;
use ic_ledger_suite_orchestrator_test_utils::{
    assert_reply, new_state_machine, supported_erc20_tokens, usdc, usdc_erc20_contract, usdt,
    LedgerSuiteOrchestrator, NNS_ROOT_PRINCIPAL,
};
use ic_state_machine_tests::ErrorCode;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue as LedgerMetadataValue;
use icrc_ledger_types::icrc1::account::Account as LedgerAccount;
use proptest::prelude::ProptestConfig;
use proptest::proptest;
use std::str::FromStr;
use std::sync::Arc;

const MAX_TICKS: usize = 10;
const GIT_COMMIT_HASH: &str = "6a8e5fca2c6b4e12966638c444e994e204b42989";

pub const TEN_TRILLIONS: u64 = 10_000_000_000_000; // 10 TC

proptest! {
    #![proptest_config(ProptestConfig {
            cases: 10,
            .. ProptestConfig::default()
        })]
    #[test]
    fn should_install_orchestrator_and_add_supported_erc20_tokens(init_arg in arb_init_arg()) {
        let more_controllers = init_arg.more_controller_ids.clone();
        let mut orchestrator = LedgerSuiteOrchestrator::new(Arc::new(new_state_machine()), init_arg);
        let orchestrator_principal: Principal = orchestrator.ledger_suite_orchestrator_id.get().into();
        let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
        let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
        let controllers: Vec<_> = std::iter::once(orchestrator_principal).chain(more_controllers.into_iter()).collect();

        for token in supported_erc20_tokens(Principal::anonymous(), embedded_ledger_wasm_hash, embedded_index_wasm_hash) {
            orchestrator = orchestrator
                .add_erc20_token(token)
                .expect_new_ledger_and_index_canisters()
                .assert_all_controlled_by(&controllers)
                .assert_ledger_icrc1_total_supply(0_u8)
                .assert_index_has_correct_ledger_id()
                .setup;
        }
    }
}

#[test]
fn should_spawn_ledger_with_correct_init_args() {
    const CKETH_TOKEN_LOGO: &str = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IiMzQjAwQjkiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNi4zODM3IDc3LjIwNTJDMTguNDM0IDEwNS4yMDYgNDAuNzk0IDEyNy41NjYgNjguNzk0OSAxMjkuNjE2VjEzNS45NEMzNy4zMDg3IDEzMy44NjcgMTIuMTMzIDEwOC42OTEgMTAuMDYwNSA3Ny4yMDUySDE2LjM4MzdaIiBmaWxsPSJ1cmwoI3BhaW50MF9saW5lYXJfMTEwXzU4NikiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik02OC43NjQ2IDE2LjM1MzRDNDAuNzYzOCAxOC40MDM2IDE4LjQwMzcgNDAuNzYzNyAxNi4zNTM1IDY4Ljc2NDZMMTAuMDMwMyA2OC43NjQ2QzEyLjEwMjcgMzcuMjc4NCAzNy4yNzg1IDEyLjEwMjYgNjguNzY0NiAxMC4wMzAyTDY4Ljc2NDYgMTYuMzUzNFoiIGZpbGw9IiMyOUFCRTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMjkuNjE2IDY4LjczNDNDMTI3LjU2NiA0MC43MzM0IDEwNS4yMDYgMTguMzczMyA3Ny4yMDUxIDE2LjMyMzFMNzcuMjA1MSA5Ljk5OTk4QzEwOC42OTEgMTIuMDcyNCAxMzMuODY3IDM3LjI0ODEgMTM1LjkzOSA2OC43MzQzTDEyOS42MTYgNjguNzM0M1oiIGZpbGw9InVybCgjcGFpbnQxX2xpbmVhcl8xMTBfNTg2KSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc3LjIzNTQgMTI5LjU4NkMxMDUuMjM2IDEyNy41MzYgMTI3LjU5NiAxMDUuMTc2IDEyOS42NDcgNzcuMTc0OUwxMzUuOTcgNzcuMTc0OUMxMzMuODk3IDEwOC42NjEgMTA4LjcyMiAxMzMuODM3IDc3LjIzNTQgMTM1LjkwOUw3Ny4yMzU0IDEyOS41ODZaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGQ9Ik03My4xOTA0IDMxVjYxLjY4MThMOTkuMTIzIDczLjI2OTZMNzMuMTkwNCAzMVoiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAzMUw0Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA2MS42ODE4VjMxWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTczLjE5MDQgOTMuMTUyM1YxMTRMOTkuMTQwMyA3OC4wOTg0TDczLjE5MDQgOTMuMTUyM1oiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAxMTRWOTMuMTQ4OEw0Ny4yNTQ0IDc4LjA5ODRMNzMuMTkwNCAxMTRaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNNzMuMTkwNCA4OC4zMjY5TDk5LjEyMyA3My4yNjk2TDczLjE5MDQgNjEuNjg4N1Y4OC4zMjY5WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC4yIi8+CjxwYXRoIGQ9Ik00Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA4OC4zMjY5VjYxLjY4ODdMNDcuMjU0NCA3My4yNjk2WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC42Ii8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMTEwXzU4NiIgeDE9IjUzLjQ3MzYiIHkxPSIxMjIuNzkiIHgyPSIxNC4wMzYyIiB5Mj0iODkuNTc4NiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBvZmZzZXQ9IjAuMjEiIHN0b3AtY29sb3I9IiNFRDFFNzkiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjNTIyNzg1Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQxX2xpbmVhcl8xMTBfNTg2IiB4MT0iMTIwLjY1IiB5MT0iNTUuNjAyMSIgeDI9IjgxLjIxMyIgeTI9IjIyLjM5MTQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agb2Zmc2V0PSIwLjIxIiBzdG9wLWNvbG9yPSIjRjE1QTI0Ii8+CjxzdG9wIG9mZnNldD0iMC42ODQxIiBzdG9wLWNvbG9yPSIjRkJCMDNCIi8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg==";

    // Adapted from ckETH ledger init args https://dashboard.internetcomputer.org/proposal/126309
    let realistic_usdc_ledger_init_arg = LedgerInitArg {
        minting_account: LedgerAccount {
            owner: Principal::from_str("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap(),
            subaccount: None,
        },
        fee_collector_account: Some(LedgerAccount {
            owner: Principal::from_str("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap(),
            subaccount: Some([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0xf, 0xe, 0xe,
            ]),
        }),
        initial_balances: vec![],
        transfer_fee: 2_000_000_000_000_u64.into(),
        decimals: Some(6),
        token_name: "USD Coin".to_string(),
        token_symbol: "USDC".to_string(),
        token_logo: CKETH_TOKEN_LOGO.to_string(),
        max_memo_length: Some(80),
        feature_flags: Some(LedgerFeatureFlags { icrc2: true }),
        maximum_number_of_accounts: None,
        accounts_overflow_trim_quantity: None,
    };

    let orchestrator = LedgerSuiteOrchestrator::default();
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    orchestrator
        .add_erc20_token(AddErc20Arg {
            contract: usdc_erc20_contract(),
            ledger_init_arg: realistic_usdc_ledger_init_arg,
            git_commit_hash: GIT_COMMIT_HASH.to_string(),
            ledger_compressed_wasm_hash: embedded_ledger_wasm_hash.to_string(),
            index_compressed_wasm_hash: embedded_index_wasm_hash.to_string(),
        })
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_icrc1_fee(2_000_000_000_000_u64)
        .assert_ledger_icrc1_decimals(6_u8)
        .assert_ledger_icrc1_name("USD Coin")
        .assert_ledger_icrc1_symbol("USDC")
        .assert_ledger_icrc1_total_supply(0_u8)
        .assert_ledger_icrc1_minting_account(LedgerAccount {
            owner: Principal::from_str("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap(),
            subaccount: None,
        })
        .assert_ledger_icrc1_metadata(vec![
            (
                "icrc1:logo".to_string(),
                LedgerMetadataValue::from(CKETH_TOKEN_LOGO),
            ),
            (
                "icrc1:decimals".to_string(),
                LedgerMetadataValue::from(6_u64),
            ),
            (
                "icrc1:name".to_string(),
                LedgerMetadataValue::from("USD Coin"),
            ),
            (
                "icrc1:symbol".to_string(),
                LedgerMetadataValue::from("USDC"),
            ),
            (
                "icrc1:fee".to_string(),
                LedgerMetadataValue::from(2_000_000_000_000_u64),
            ),
            (
                "icrc1:max_memo_length".to_string(),
                LedgerMetadataValue::from(80_u64),
            ),
        ]);
}

#[test]
fn should_change_cycles_for_canister_creation() {
    let orchestrator = LedgerSuiteOrchestrator::default();
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();

    let orchestrator = orchestrator
        .add_erc20_token(usdc(
            Principal::anonymous(),
            embedded_ledger_wasm_hash.clone(),
            embedded_index_wasm_hash.clone(),
        ))
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_cycles(200_000_000_000_000_u128)
        .assert_index_has_cycles(100_000_000_000_000_u128)
        .setup;

    orchestrator
        .upgrade_ledger_suite_orchestrator_with_same_wasm(&OrchestratorArg::UpgradeArg(
            UpgradeArg {
                git_commit_hash: None,
                ledger_compressed_wasm_hash: None,
                index_compressed_wasm_hash: None,
                archive_compressed_wasm_hash: None,
                cycles_management: Some(UpdateCyclesManagement {
                    cycles_for_ledger_creation: Some(300_000_000_000_000_u128.into()),
                    cycles_for_index_creation: Some(50_000_000_000_000_u128.into()),
                    ..Default::default()
                }),
            },
        ))
        .unwrap();

    orchestrator
        .add_erc20_token(usdt(
            Principal::anonymous(),
            embedded_ledger_wasm_hash.clone(),
            embedded_index_wasm_hash,
        ))
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_cycles(300_000_000_000_000_u128)
        .assert_index_has_cycles(50_000_000_000_000_u128);
}

#[test]
fn should_spawn_archive_from_ledger_with_correct_controllers() {
    let orchestrator = LedgerSuiteOrchestrator::default();
    let expected_controllers = vec![
        orchestrator.ledger_suite_orchestrator_id.get().into(),
        NNS_ROOT_PRINCIPAL,
    ];
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let usdc = usdc(
        Principal::anonymous(),
        embedded_ledger_wasm_hash,
        embedded_index_wasm_hash,
    );

    orchestrator
        .add_erc20_token(usdc.clone())
        .expect_new_ledger_and_index_canisters()
        .trigger_creation_of_archive()
        .assert_all_controlled_by(&expected_controllers);
}

#[test]
fn should_discover_new_archive_and_top_up() {
    let orchestrator = LedgerSuiteOrchestrator::default();

    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let usdc = usdc(
        Principal::anonymous(),
        embedded_ledger_wasm_hash,
        embedded_index_wasm_hash,
    );

    let managed_canisters = orchestrator
        .add_erc20_token(usdc.clone())
        .expect_new_ledger_and_index_canisters()
        .assert_ledger_has_cycles(200_000_000_000_000_u128)
        .check_metrics()
        .assert_contains_metric("ledger_suite_orchestrator_managed_archives 0")
        .trigger_creation_of_archive()
        .assert_ledger_has_cycles(100_000_000_000_000_u128)
        .assert_all_archives_have_cycles(100_000_000_000_000_u128);

    managed_canisters.setup.advance_time_for_cycles_top_up();

    //[maybe_top_up] task started before archive discovery, so no top-up is expected.
    let managed_canisters = managed_canisters
        .assert_all_archives_have_cycles(100_000_000_000_000_u128)
        .check_metrics()
        .assert_contains_metric("ledger_suite_orchestrator_managed_archives 1");

    managed_canisters.setup.advance_time_for_cycles_top_up();

    managed_canisters
        .assert_all_archives_have_cycles(110_000_000_000_000_u128)
        .check_metrics()
        .assert_contains_metric("ledger_suite_orchestrator_managed_archives 1");
}

#[test]
fn should_reject_adding_an_already_managed_erc20_token() {
    let orchestrator = LedgerSuiteOrchestrator::default();
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let usdc = usdc(
        Principal::anonymous(),
        embedded_ledger_wasm_hash,
        embedded_index_wasm_hash,
    );
    let orchestrator = orchestrator
        .add_erc20_token(usdc.clone())
        .expect_new_ledger_and_index_canisters()
        .setup;

    let result = orchestrator
        .upgrade_ledger_suite_orchestrator_with_same_wasm(&OrchestratorArg::AddErc20Arg(usdc));

    assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("Erc20ContractAlreadyManaged"));
}

#[test]
fn should_top_up_spawned_canisters() {
    let orchestrator = LedgerSuiteOrchestrator::with_cycles_management(CyclesManagement {
        cycles_for_ledger_creation: 100_000_000_000_000_u128.into(),
        ..Default::default()
    });
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let usdc = usdc(
        Principal::anonymous(),
        embedded_ledger_wasm_hash,
        embedded_index_wasm_hash,
    );
    let orchestrator = orchestrator
        .add_erc20_token(usdc.clone())
        .expect_new_ledger_and_index_canisters()
        .setup;

    let canisters = orchestrator
        .call_orchestrator_canister_ids(&usdc_erc20_contract())
        .unwrap();

    let ledger_canister_id =
        CanisterId::unchecked_from_principal(PrincipalId::from(canisters.ledger.unwrap()));

    let index_canister_id =
        CanisterId::unchecked_from_principal(PrincipalId::from(canisters.index.unwrap()));

    let pre_top_up_balance_ledger = orchestrator.canister_status_of(ledger_canister_id).cycles();
    let pre_top_up_balance_index = orchestrator.canister_status_of(index_canister_id).cycles();

    orchestrator.advance_time_for_cycles_top_up();
    let balance_ledger_after_first_top_up =
        orchestrator.canister_status_of(ledger_canister_id).cycles();
    let balance_index_after_first_top_up =
        orchestrator.canister_status_of(index_canister_id).cycles();
    assert_eq!(
        balance_index_after_first_top_up - pre_top_up_balance_index,
        TEN_TRILLIONS as u128
    );
    assert_eq!(
        balance_ledger_after_first_top_up - pre_top_up_balance_ledger,
        TEN_TRILLIONS as u128
    );

    orchestrator.advance_time_for_cycles_top_up();
    let balance_ledger_after_second_top_up =
        orchestrator.canister_status_of(ledger_canister_id).cycles();
    let balance_index_after_second_top_up =
        orchestrator.canister_status_of(index_canister_id).cycles();
    assert_eq!(
        balance_index_after_second_top_up - balance_index_after_first_top_up,
        TEN_TRILLIONS as u128
    );
    assert_eq!(
        balance_ledger_after_second_top_up - balance_ledger_after_first_top_up,
        TEN_TRILLIONS as u128
    );
}

#[test]
fn should_reject_upgrade_with_invalid_args() {
    const UNKNOWN_WASM_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const INVALID_GIT_COMMIT_HASH: &str = "0000";
    fn test_upgrade_with_invalid_args(
        orchestrator: &LedgerSuiteOrchestrator,
        upgrade_arg_with_wrong_hash: &OrchestratorArg,
    ) {
        let result = orchestrator
            .upgrade_ledger_suite_orchestrator_with_same_wasm(upgrade_arg_with_wrong_hash);
        assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("ERROR: "));
    }

    let orchestrator = LedgerSuiteOrchestrator::default();
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let usdc = usdc(
        Principal::anonymous(),
        embedded_ledger_wasm_hash.clone(),
        embedded_index_wasm_hash,
    );

    test_upgrade_with_invalid_args(
        &orchestrator,
        &OrchestratorArg::AddErc20Arg(AddErc20Arg {
            ledger_compressed_wasm_hash: UNKNOWN_WASM_HASH.to_string(),
            ..usdc.clone()
        }),
    );

    test_upgrade_with_invalid_args(
        &orchestrator,
        &OrchestratorArg::AddErc20Arg(AddErc20Arg {
            index_compressed_wasm_hash: UNKNOWN_WASM_HASH.to_string(),
            ..usdc.clone()
        }),
    );

    test_upgrade_with_invalid_args(
        &orchestrator,
        &OrchestratorArg::AddErc20Arg(AddErc20Arg {
            git_commit_hash: INVALID_GIT_COMMIT_HASH.to_string(),
            ..usdc.clone()
        }),
    );

    let valid_upgrade_arg = UpgradeArg {
        git_commit_hash: None,
        ledger_compressed_wasm_hash: None,
        index_compressed_wasm_hash: None,
        archive_compressed_wasm_hash: None,
        cycles_management: None,
    };

    test_upgrade_with_invalid_args(
        &orchestrator,
        &OrchestratorArg::UpgradeArg(UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH.to_string()),
            ledger_compressed_wasm_hash: Some(UNKNOWN_WASM_HASH.to_string()),
            ..valid_upgrade_arg.clone()
        }),
    );

    test_upgrade_with_invalid_args(
        &orchestrator,
        &OrchestratorArg::UpgradeArg(UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH.to_string()),
            index_compressed_wasm_hash: Some(UNKNOWN_WASM_HASH.to_string()),
            ..valid_upgrade_arg.clone()
        }),
    );

    test_upgrade_with_invalid_args(
        &orchestrator,
        &OrchestratorArg::UpgradeArg(UpgradeArg {
            git_commit_hash: Some(GIT_COMMIT_HASH.to_string()),
            archive_compressed_wasm_hash: Some(UNKNOWN_WASM_HASH.to_string()),
            ..valid_upgrade_arg.clone()
        }),
    );

    test_upgrade_with_invalid_args(
        &orchestrator,
        &OrchestratorArg::UpgradeArg(UpgradeArg {
            git_commit_hash: None,
            ledger_compressed_wasm_hash: Some(embedded_ledger_wasm_hash.to_string()),
            ..valid_upgrade_arg.clone()
        }),
    );
}

#[test]
fn should_reject_update_calls_to_http_request() {
    let orchestrator = LedgerSuiteOrchestrator::default();
    let request = HttpRequest {
        method: "GET".to_string(),
        url: "/dashboard".to_string(),
        headers: Default::default(),
        body: Default::default(),
    };

    let message_id = orchestrator.env.send_ingress(
        PrincipalId::new_user_test_id(1),
        orchestrator.ledger_suite_orchestrator_id,
        "http_request",
        Encode!(&request).expect("failed to encode HTTP request"),
    );

    assert_matches!(
        orchestrator
            .env
            .await_ingress(message_id.clone(), MAX_TICKS),
        Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("update call rejected")
    );
}

#[test]
fn should_retrieve_orchestrator_info() {
    let orchestrator = LedgerSuiteOrchestrator::default();
    let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
    let usdc = usdc(
        Principal::anonymous(),
        embedded_ledger_wasm_hash.clone(),
        embedded_index_wasm_hash.clone(),
    );
    let usdt = usdt(
        Principal::anonymous(),
        embedded_ledger_wasm_hash,
        embedded_index_wasm_hash,
    );

    let canisters = orchestrator
        .add_erc20_token(usdc.clone())
        .expect_new_ledger_and_index_canisters();
    let usdc_ledger_id = canisters.ledger_canister_id();
    let usdc_index_id = canisters.index_canister_id();

    let orchestrator = canisters.setup;
    let canisters = orchestrator
        .add_erc20_token(usdt.clone())
        .expect_new_ledger_and_index_canisters();
    let usdt_ledger_id = canisters.ledger_canister_id();
    let usdt_index_id = canisters.index_canister_id();

    let info = canisters.setup.get_orchestrator_info();
    assert_eq!(
        info,
        OrchestratorInfo {
            managed_canisters: vec![
                ManagedCanisters {
                    erc20_contract: usdc.contract.clone(),
                    ckerc20_token_symbol: "ckUSDC".to_string(),
                    ledger: Some(ManagedCanisterStatus::Installed {
                        canister_id: usdc_ledger_id.into(),
                        installed_wasm_hash: usdc.ledger_compressed_wasm_hash,
                    }),
                    index: Some(ManagedCanisterStatus::Installed {
                        canister_id: usdc_index_id.into(),
                        installed_wasm_hash: usdc.index_compressed_wasm_hash,
                    }),
                    archives: vec![]
                },
                ManagedCanisters {
                    erc20_contract: usdt.contract.clone(),
                    ckerc20_token_symbol: "ckUSDT".to_string(),
                    ledger: Some(ManagedCanisterStatus::Installed {
                        canister_id: usdt_ledger_id.into(),
                        installed_wasm_hash: usdt.ledger_compressed_wasm_hash,
                    }),
                    index: Some(ManagedCanisterStatus::Installed {
                        canister_id: usdt_index_id.into(),
                        installed_wasm_hash: usdt.index_compressed_wasm_hash,
                    }),
                    archives: vec![]
                }
            ],
            cycles_management: CyclesManagement {
                cycles_for_ledger_creation: Nat::from(200_000_000_000_000_u64),
                cycles_for_archive_creation: Nat::from(100000000000000_u64),
                cycles_for_index_creation: Nat::from(100000000000000_u64),
                cycles_top_up_increment: Nat::from(10000000000000_u64),
            },
            more_controller_ids: vec![NNS_ROOT_PRINCIPAL],
            minter_id: None
        }
    );
}

#[test]
fn should_query_logs_and_metrics() {
    let orchestrator = LedgerSuiteOrchestrator::default();
    test_http_query(&orchestrator, "/metrics");
    test_http_query(&orchestrator, "/logs");

    fn test_http_query<U: Into<String>>(orchestrator: &LedgerSuiteOrchestrator, url: U) {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: url.into(),
            headers: Default::default(),
            body: Default::default(),
        };

        let response = Decode!(
            &assert_reply(
                orchestrator
                    .env
                    .query(
                        orchestrator.ledger_suite_orchestrator_id,
                        "http_request",
                        Encode!(&request).expect("failed to encode HTTP request"),
                    )
                    .expect("failed to query get_transactions on the ledger")
            ),
            HttpResponse
        )
        .unwrap();

        assert_eq!(response.status_code, 200_u16);
    }
}

#[test]
fn should_get_canister_status_smoke_test() {
    let orchestrator = LedgerSuiteOrchestrator::default();
    let get_canister_status = orchestrator.get_canister_status();
    assert_eq!(format!("{:?}", get_canister_status.status), "Running");
}

mod upgrade {
    use super::*;
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use ic_ledger_suite_orchestrator::state::WasmHash;
    use ic_ledger_suite_orchestrator_test_utils::universal_canister::{
        CanisterChangeDetails, CanisterInfoResponse, CanisterInstallMode, UniversalCanister,
    };
    use ic_ledger_suite_orchestrator_test_utils::{
        default_init_arg, ledger_suite_orchestrator_wasm, ledger_wasm, tweak_ledger_suite_wasms,
        usdt_erc20_contract, GIT_COMMIT_HASH_UPGRADE,
    };
    use ic_state_machine_tests::CanisterStatusType;
    use icrc_ledger_types::icrc1::transfer::TransferArg;
    use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
    use proptest::prelude::Rng;

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
            .add_erc20_token(usdc(
                Principal::anonymous(),
                embedded_ledger_wasm_hash_v1.clone(),
                embedded_index_wasm_hash_v1.clone(),
            ))
            .expect_new_ledger_and_index_canisters()
            .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v1);

        orchestrator_v2
            .add_erc20_token(usdc(
                Principal::anonymous(),
                embedded_ledger_wasm_hash_v2.clone(),
                embedded_index_wasm_hash_v2.clone(),
            ))
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

        let orchestrator_v1 = orchestrator_v1
            .add_erc20_token(usdc(
                Principal::anonymous(),
                embedded_ledger_wasm_hash_v1.clone(),
                embedded_index_wasm_hash_v1.clone(),
            ))
            .expect_new_ledger_and_index_canisters()
            .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v1)
            .setup
            .add_erc20_token(usdt(
                Principal::anonymous(),
                embedded_ledger_wasm_hash_v1.clone(),
                embedded_index_wasm_hash_v1.clone(),
            ))
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
            },
        );

        orchestrator_v2.advance_time_for_upgrade();

        for ledger in [ckusdc_ledger, ckusdt_ledger] {
            let status = orchestrator_v2
                .canister_status_of(CanisterId::unchecked_from_principal(ledger.into()));
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
        let orchestrator = LedgerSuiteOrchestrator::new(env.clone(), default_init_arg());
        let universal_canister = UniversalCanister::new(env.clone());
        let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
        let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
        let embedded_archive_wasm_hash = orchestrator.embedded_archive_wasm_hash.clone();

        let (tweak_ledger_wasm, tweak_index_wasm, _) = tweak_ledger_suite_wasms();
        let tweak_ledger_wasm_hash = tweak_ledger_wasm.hash().clone();
        assert_ne!(tweak_ledger_wasm_hash, embedded_ledger_wasm_hash);
        let tweak_index_wasm_hash = tweak_index_wasm.hash().clone();
        assert_ne!(tweak_index_wasm_hash, embedded_index_wasm_hash);

        let has_last_been_upgraded_to =
            |canister_info: &CanisterInfoResponse, wasm_hash: &WasmHash| {
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
            .add_erc20_token(usdc(
                Principal::anonymous(),
                embedded_ledger_wasm_hash.clone(),
                embedded_index_wasm_hash.clone(),
            ))
            .expect_new_ledger_and_index_canisters()
            .trigger_creation_of_archive()
            .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash)
            .ledger_out_of_band_upgrade(NNS_ROOT_PRINCIPAL, tweak_ledger_wasm)
            .assert_ledger_has_wasm_hash(&tweak_ledger_wasm_hash)
            .setup
            .add_erc20_token(usdt(
                Principal::anonymous(),
                embedded_ledger_wasm_hash.clone(),
                embedded_index_wasm_hash.clone(),
            ))
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
        let orchestrator = LedgerSuiteOrchestrator::new(env.clone(), default_init_arg());
        let universal_canister = UniversalCanister::new(env.clone());
        let embedded_ledger_wasm_hash = orchestrator.embedded_ledger_wasm_hash.clone();
        let embedded_index_wasm_hash = orchestrator.embedded_index_wasm_hash.clone();
        let embedded_archive_wasm_hash = orchestrator.embedded_archive_wasm_hash.clone();

        let has_only_install_change = |canister_info: &CanisterInfoResponse,
                                       wasm_hash: &WasmHash| {
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
        for add_erc20 in [
            usdc(
                Principal::anonymous(),
                embedded_ledger_wasm_hash.clone(),
                embedded_index_wasm_hash.clone(),
            ),
            usdt(
                Principal::anonymous(),
                embedded_ledger_wasm_hash.clone(),
                embedded_index_wasm_hash.clone(),
            ),
        ] {
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
        let embedded_index_wasm_hash_v1 = orchestrator_v1.embedded_index_wasm_hash.clone();

        let orchestrator_v1 = orchestrator_v1
            .add_erc20_token(usdc(
                Principal::anonymous(),
                embedded_ledger_wasm_hash_v1.clone(),
                embedded_index_wasm_hash_v1.clone(),
            ))
            .expect_new_ledger_and_index_canisters()
            .assert_ledger_has_wasm_hash(&embedded_ledger_wasm_hash_v1);
        let mint_index = orchestrator_v1
            .call_ledger_icrc1_transfer(
                Principal::anonymous(),
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
                .add_erc20_token(usdc(
                    Principal::anonymous(),
                    embedded_ledger_wasm_hash.clone(),
                    embedded_index_wasm_hash.clone(),
                ))
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
}
