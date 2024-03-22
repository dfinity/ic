use assert_matches::assert_matches;
use candid::{Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canisters_http_types::HttpRequest;
use ic_icrc1_ledger::FeatureFlags as LedgerFeatureFlags;
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, LedgerInitArg, OrchestratorArg, UpgradeArg,
};
use ic_ledger_suite_orchestrator::scheduler::TEN_TRILLIONS;
use ic_ledger_suite_orchestrator_test_utils::arbitrary::arb_init_arg;
use ic_ledger_suite_orchestrator_test_utils::{
    new_state_machine, supported_erc20_tokens, usdc, usdc_erc20_contract, LedgerSuiteOrchestrator,
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

    let result =
        orchestrator.upgrade_ledger_suite_orchestrator(&OrchestratorArg::AddErc20Arg(usdc));

    assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("Erc20ContractAlreadyManaged"));
}

#[test]
fn should_top_up_spawned_canisters() {
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

    let canisters = orchestrator
        .call_orchestrator_canister_ids(&usdc_erc20_contract())
        .unwrap();

    let ledger_canister_id =
        CanisterId::unchecked_from_principal(PrincipalId::from(canisters.ledger.unwrap()));

    let index_canister_id =
        CanisterId::unchecked_from_principal(PrincipalId::from(canisters.index.unwrap()));

    let pre_top_up_balance_ledger = orchestrator.canister_status_of(ledger_canister_id).cycles();
    let pre_top_up_balance_index = orchestrator.canister_status_of(index_canister_id).cycles();

    orchestrator
        .env
        .advance_time(std::time::Duration::from_secs(60 * 60 + 1));
    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator.env.tick();

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

    orchestrator
        .env
        .advance_time(std::time::Duration::from_secs(60 * 60 + 1));
    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator.env.tick();
    orchestrator.env.tick();

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
        let result = orchestrator.upgrade_ledger_suite_orchestrator(upgrade_arg_with_wrong_hash);
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
