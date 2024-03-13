use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_cketh_minter::endpoints::events::EventPayload;
use ic_cketh_minter::endpoints::AddCkErc20Token;
use ic_cketh_test_utils::ckerc20::CkErc20Setup;
use ic_cketh_test_utils::flow::DepositParams;
use ic_cketh_test_utils::{format_ethereum_address_to_eip_55, CkEthSetup};
use ic_ledger_suite_orchestrator_test_utils::supported_erc20_tokens;
use ic_state_machine_tests::ErrorCode;

#[test]
fn should_refuse_to_add_ckerc20_token_from_unauthorized_principal() {
    let cketh = CkEthSetup::default();
    let result = cketh.add_ckerc20_token(Principal::anonymous(), &ckusdc());
    assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("ERROR: ERC-20"));

    let orchestrator_id: Principal = "nbsys-saaaa-aaaar-qaaga-cai".parse().unwrap();
    let result = cketh
        .upgrade_minter_to_add_orchestrator_id(orchestrator_id)
        .add_ckerc20_token(Principal::anonymous(), &ckusdc());
    assert_matches!(result, Err(e) if e.code() == ErrorCode::CanisterCalledTrap && e.description().contains("ERROR: only the orchestrator"));

    fn ckusdc() -> AddCkErc20Token {
        AddCkErc20Token {
            chain_id: Nat::from(1_u8),
            address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            ckerc20_token_symbol: "ckUSDC".to_string(),
            ckerc20_ledger_id: "mxzaz-hqaaa-aaaar-qaada-cai".parse().unwrap(),
        }
    }
}

#[test]
fn should_add_ckusdc_and_ckusdt_to_minter_via_orchestrator() {
    let mut ckerc20 = CkErc20Setup::default();
    let embedded_ledger_wasm_hash = ckerc20.orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = ckerc20.orchestrator.embedded_index_wasm_hash.clone();

    for token in supported_erc20_tokens(embedded_ledger_wasm_hash, embedded_index_wasm_hash) {
        ckerc20.orchestrator = ckerc20
            .orchestrator
            .add_erc20_token(token.clone())
            .expect_new_ledger_and_index_canisters()
            .setup;
        let new_ledger_id = ckerc20
            .orchestrator
            .call_orchestrator_canister_ids(&token.contract)
            .unwrap()
            .ledger
            .unwrap();

        ckerc20.cketh = ckerc20.cketh.assert_has_unique_events_in_order(&vec![
            EventPayload::AddedCkErc20Token {
                chain_id: token.contract.chain_id,
                address: format_ethereum_address_to_eip_55(&token.contract.address),
                ckerc20_token_symbol: token.ledger_init_arg.token_symbol,
                ckerc20_ledger_id: new_ledger_id,
            },
        ]);
    }
}

#[test]
fn should_mint_with_ckerc20_setup() {
    CkErc20Setup::default()
        .cketh
        .deposit(DepositParams::default())
        .expect_mint();
}

mod withdraw_erc20 {
    use super::*;
    use ic_cketh_minter::endpoints::ckerc20::WithdrawErc20Error;
    use ic_cketh_test_utils::ckerc20::{DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS, ONE_USDC};
    use ic_cketh_test_utils::flow::DepositParams;
    use ic_cketh_test_utils::CKETH_TRANSFER_FEE;
    use ic_ledger_suite_orchestrator_test_utils::{new_state_machine, usdc_erc20_contract};
    use num_bigint::BigUint;
    use std::sync::Arc;

    #[test]
    fn should_trap_when_ckerc20_feature_not_active() {
        CkErc20Setup::new_without_ckerc20_active(Arc::new(new_state_machine()))
            .call_minter_withdraw_erc20(
                Principal::anonymous(),
                0_u8,
                "ckUSDC",
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_trap("disabled");
    }

    #[test]
    fn should_trap_when_called_from_anonymous_principal() {
        CkErc20Setup::default()
            .call_minter_withdraw_erc20(
                Principal::anonymous(),
                0_u8,
                "ckUSDC",
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_trap("anonymous");
    }

    #[test]
    fn should_trap_when_destination_invalid() {
        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        ckerc20
            .call_minter_withdraw_erc20(caller, 0_u8, "ckUSDC", "0xinvalid-address")
            .expect_trap("address");
    }

    #[test]
    fn should_error_when_address_blocked() {
        let blocked_address = "0x01e2919679362dFBC9ee1644Ba9C6da6D6245BB1";
        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        ckerc20
            .call_minter_withdraw_erc20(caller, 0_u8, "ckUSDC", blocked_address)
            .expect_error(WithdrawErc20Error::RecipientAddressBlocked {
                address: blocked_address.to_string(),
            });
    }

    #[test]
    fn should_trap_when_amount_overflow_u256() {
        let ridiculously_large_amount = Nat(BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF1",
            16,
        )
        .unwrap());

        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        ckerc20
            .call_minter_withdraw_erc20(
                caller,
                ridiculously_large_amount,
                "ckUSDC",
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_trap("u256");
    }

    #[test]
    fn should_trap_when_token_invalid() {
        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        ckerc20
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                "USDC",
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_trap("token symbol");
    }

    #[test]
    fn should_error_when_token_unknown() {
        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        ckerc20
            .add_supported_erc20_tokens()
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                "ckusdc",
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_error(WithdrawErc20Error::TokenNotSupported {
                supported_tokens: vec!["ckUSDC".to_string(), "ckUSDT".to_string()],
            });
    }

    #[test]
    fn should_error_when_minter_not_allowed_to_burn_cketh() {
        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        let cketh_ledger = ckerc20.cketh_ledger_id();
        ckerc20
            .add_supported_erc20_tokens()
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                "ckUSDC",
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_error(WithdrawErc20Error::InsufficientAllowance {
                allowance: Nat::from(0_u8),
                failed_burn_amount: Nat::from(CKETH_TRANSFER_FEE),
                token_symbol: "ckETH".to_string(),
                ledger_id: cketh_ledger,
            });
    }

    #[test]
    fn should_error_when_not_enough_cketh() {
        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        let cketh_ledger = ckerc20.cketh_ledger_id();
        ckerc20
            .add_supported_erc20_tokens()
            .deposit_cketh(DepositParams {
                amount: 10,
                ..DepositParams::default()
            })
            .call_cketh_ledger_approve_minter(caller, 100, None)
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                "ckUSDC",
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_error(WithdrawErc20Error::InsufficientFunds {
                balance: Nat::from(0_u8),
                failed_burn_amount: Nat::from(CKETH_TRANSFER_FEE),
                token_symbol: "ckETH".to_string(),
                ledger_id: cketh_ledger,
            });
    }

    #[test]
    fn should_error_when_minter_not_allowed_to_burn_ckerc20() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let caller = ckerc20.caller();
        let ckusdc_ledger = ckerc20
            .orchestrator
            .call_orchestrator_canister_ids(&usdc_erc20_contract())
            .expect("BUG: missing ckUSDC ledger suite")
            .ledger
            .unwrap();
        ckerc20
            .deposit_cketh(DepositParams::default())
            .call_cketh_ledger_approve_minter(caller, 100, None)
            .call_minter_withdraw_erc20(
                caller,
                ONE_USDC,
                "ckUSDC",
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_error(WithdrawErc20Error::InsufficientAllowance {
                allowance: Nat::from(0_u8),
                failed_burn_amount: ONE_USDC.into(),
                token_symbol: "ckUSDC".to_string(),
                ledger_id: ckusdc_ledger,
            });
    }
}
