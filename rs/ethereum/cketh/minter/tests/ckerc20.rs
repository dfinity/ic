use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_cketh_minter::endpoints::events::{EventPayload, EventSource};
use ic_cketh_minter::endpoints::CandidBlockTag::Finalized;
use ic_cketh_minter::endpoints::{AddCkErc20Token, CkErc20Token, Erc20Balance, MinterInfo};
use ic_cketh_minter::memo::MintMemo;
use ic_cketh_minter::numeric::BlockNumber;
use ic_cketh_minter::SCRAPPING_ETH_LOGS_INTERVAL;
use ic_cketh_test_utils::ckerc20::{CkErc20DepositParams, CkErc20Setup, Erc20Token, ONE_USDC};
use ic_cketh_test_utils::flow::DepositParams;
use ic_cketh_test_utils::mock::{JsonRpcMethod, MockJsonRpcProviders};
use ic_cketh_test_utils::response::{block_response, empty_logs, Erc20LogEntry};
use ic_cketh_test_utils::{
    format_ethereum_address_to_eip_55, CkEthSetup, CKETH_MINIMUM_WITHDRAWAL_AMOUNT,
    DEFAULT_DEPOSIT_FROM_ADDRESS, DEFAULT_DEPOSIT_LOG_INDEX, DEFAULT_DEPOSIT_TRANSACTION_HASH,
    DEFAULT_ERC20_DEPOSIT_LOG_INDEX, DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH,
    ERC20_HELPER_CONTRACT_ADDRESS, ETH_HELPER_CONTRACT_ADDRESS,
    LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL, MAX_ETH_LOGS_BLOCK_RANGE, MINTER_ADDRESS,
    RECEIVED_ERC20_EVENT_TOPIC, RECEIVED_ETH_EVENT_TOPIC,
};
use ic_ethereum_types::Address;
use ic_ledger_suite_orchestrator_test_utils::{supported_erc20_tokens, usdc};
use ic_state_machine_tests::ErrorCode;
use ic_state_machine_tests::{CanisterStatusType, WasmResult};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Mint;
use serde_json::json;
use std::time::Duration;

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

    for token in supported_erc20_tokens(
        ckerc20.cketh.minter_id.into(),
        embedded_ledger_wasm_hash,
        embedded_index_wasm_hash,
    ) {
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

        ckerc20 = ckerc20
            .check_events()
            .assert_has_unique_events_in_order(&vec![EventPayload::AddedCkErc20Token {
                chain_id: token.contract.chain_id,
                address: format_ethereum_address_to_eip_55(&token.contract.address),
                ckerc20_token_symbol: token.ledger_init_arg.token_symbol,
                ckerc20_ledger_id: new_ledger_id,
            }]);
    }
}

#[test]
fn should_retry_to_add_usdc_when_minter_stopped() {
    const RETRY_FREQUENCY: Duration = Duration::from_secs(5);

    let mut ckerc20 = CkErc20Setup::default();
    let embedded_ledger_wasm_hash = ckerc20.orchestrator.embedded_ledger_wasm_hash.clone();
    let embedded_index_wasm_hash = ckerc20.orchestrator.embedded_index_wasm_hash.clone();
    let usdc = usdc(
        Principal::anonymous(),
        embedded_ledger_wasm_hash,
        embedded_index_wasm_hash,
    );
    let stop_msg_id = ckerc20
        .env
        .stop_canister_non_blocking(ckerc20.cketh.minter_id);
    assert_eq!(ckerc20.cketh.minter_status(), CanisterStatusType::Stopping);

    ckerc20.orchestrator = ckerc20
        .orchestrator
        .add_erc20_token(usdc.clone())
        .expect_new_ledger_and_index_canisters()
        .setup;
    let new_ledger_id = ckerc20
        .orchestrator
        .call_orchestrator_canister_ids(&usdc.contract)
        .unwrap()
        .ledger
        .unwrap();

    ckerc20.cketh.stop_ongoing_https_outcalls();
    let stop_res = ckerc20.env.await_ingress(stop_msg_id, 100);
    assert_matches!(stop_res, Ok(WasmResult::Reply(_)));
    assert_eq!(ckerc20.cketh.minter_status(), CanisterStatusType::Stopped);
    ckerc20.env.advance_time(RETRY_FREQUENCY);
    ckerc20.env.tick();

    ckerc20.cketh.start_minter();
    assert_eq!(ckerc20.cketh.minter_status(), CanisterStatusType::Running);
    ckerc20.env.advance_time(RETRY_FREQUENCY);
    ckerc20.env.tick();

    ckerc20
        .cketh
        .assert_has_unique_events_in_order(&vec![EventPayload::AddedCkErc20Token {
            chain_id: usdc.contract.chain_id,
            address: format_ethereum_address_to_eip_55(&usdc.contract.address),
            ckerc20_token_symbol: usdc.ledger_init_arg.token_symbol,
            ckerc20_ledger_id: new_ledger_id,
        }]);
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
    use ic_base_types::PrincipalId;
    use ic_cketh_minter::endpoints::ckerc20::{
        LedgerError, RetrieveErc20Request, WithdrawErc20Error,
    };
    use ic_cketh_minter::endpoints::events::{
        TransactionReceipt, TransactionStatus, UnsignedTransaction,
    };
    use ic_cketh_minter::endpoints::{EthTransaction, RetrieveEthStatus, TxFinalizedStatus};
    use ic_cketh_minter::memo::BurnMemo;
    use ic_cketh_minter::PROCESS_REIMBURSEMENT;
    use ic_cketh_test_utils::ckerc20::{
        erc20_transfer_data, Erc20WithdrawalFlow, RefreshGasFeeEstimate,
        DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS, ONE_USDC, TWO_USDC,
    };
    use ic_cketh_test_utils::flow::{
        increment_max_priority_fee_per_gas, DepositParams, ProcessWithdrawalParams,
    };
    use ic_cketh_test_utils::mock::JsonRpcProvider;
    use ic_cketh_test_utils::response::{
        decode_transaction, default_erc20_signed_eip_1559_transaction, hash_transaction,
    };
    use ic_cketh_test_utils::{
        CKETH_TRANSFER_FEE, DEFAULT_BLOCK_HASH, DEFAULT_BLOCK_NUMBER,
        DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION, DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE,
        DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH, DEFAULT_PRINCIPAL_ID, EXPECTED_BALANCE,
    };
    use ic_ledger_suite_orchestrator_test_utils::{new_state_machine, CKERC20_TRANSFER_FEE};
    use icrc_ledger_types::icrc3::transactions::Burn;
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;
    use serde_bytes::ByteBuf;
    use std::convert::identity;
    use std::sync::Arc;

    const NOT_SUPPORTED_CKERC20_LEDGER_ID: Principal = Principal::management_canister();

    #[test]
    fn should_trap_when_ckerc20_feature_not_active() {
        CkErc20Setup::new_without_ckerc20_active(Arc::new(new_state_machine()))
            .call_minter_withdraw_erc20(
                Principal::anonymous(),
                0_u8,
                NOT_SUPPORTED_CKERC20_LEDGER_ID,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_no_refresh_gas_fee_estimate()
            .expect_trap("disabled");
    }

    #[test]
    fn should_trap_when_called_from_anonymous_principal() {
        CkErc20Setup::default()
            .call_minter_withdraw_erc20(
                Principal::anonymous(),
                0_u8,
                NOT_SUPPORTED_CKERC20_LEDGER_ID,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_no_refresh_gas_fee_estimate()
            .expect_trap("anonymous");
    }

    #[test]
    fn should_trap_when_destination_invalid() {
        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        ckerc20
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                NOT_SUPPORTED_CKERC20_LEDGER_ID,
                "0xinvalid-address",
            )
            .expect_no_refresh_gas_fee_estimate()
            .expect_trap("address");
    }

    #[test]
    fn should_error_when_address_blocked() {
        let blocked_address = "0x01e2919679362dFBC9ee1644Ba9C6da6D6245BB1";
        let ckerc20 = CkErc20Setup::default();
        let caller = ckerc20.caller();
        ckerc20
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                NOT_SUPPORTED_CKERC20_LEDGER_ID,
                blocked_address,
            )
            .expect_no_refresh_gas_fee_estimate()
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
                NOT_SUPPORTED_CKERC20_LEDGER_ID,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_no_refresh_gas_fee_estimate()
            .expect_trap("u256");
    }

    #[test]
    fn should_error_when_token_unknown() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let caller = ckerc20.caller();
        let supported_tokens = ckerc20
            .cketh
            .get_minter_info()
            .supported_ckerc20_tokens
            .unwrap();

        ckerc20
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                NOT_SUPPORTED_CKERC20_LEDGER_ID,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_no_refresh_gas_fee_estimate()
            .expect_error(WithdrawErc20Error::TokenNotSupported { supported_tokens });
    }

    #[test]
    fn should_error_when_minter_not_allowed_to_burn_cketh() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let caller = ckerc20.caller();
        let cketh_ledger = ckerc20.cketh_ledger_id();
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");

        ckerc20
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_refresh_gas_fee_estimate(identity)
            .expect_error(WithdrawErc20Error::CkEthLedgerError {
                error: LedgerError::InsufficientAllowance {
                    allowance: Nat::from(0_u8),
                    failed_burn_amount: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE.into(),
                    token_symbol: "ckETH".to_string(),
                    ledger_id: cketh_ledger,
                },
            });
    }

    #[test]
    fn should_error_when_not_enough_cketh() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let caller = ckerc20.caller();
        let cketh_ledger = ckerc20.cketh_ledger_id();
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");

        ckerc20
            .deposit_cketh(DepositParams {
                amount: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE + CKETH_TRANSFER_FEE - 1,
                ..DepositParams::default()
            })
            .call_cketh_ledger_approve_minter(
                caller,
                DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE,
                None,
            )
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_refresh_gas_fee_estimate(identity)
            .expect_error(WithdrawErc20Error::CkEthLedgerError {
                error: LedgerError::InsufficientFunds {
                    balance: Nat::from(DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE - 1),
                    failed_burn_amount: Nat::from(DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE),
                    token_symbol: "ckETH".to_string(),
                    ledger_id: cketh_ledger,
                },
            });
    }

    #[test]
    fn should_error_when_minter_fails_to_burn_ckerc20_and_reimburse_cketh() {
        let transaction_fee = DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE;
        let cketh_burn_index = 2_u8;
        let mut tests = vec![];

        let (setup_without_ckerc20_approval, ckerc20_token) = {
            let mut ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
            let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
            let caller = ckerc20.caller();
            ckerc20 = ckerc20
                .deposit_cketh(DepositParams::default())
                .call_cketh_ledger_approve_minter(caller, transaction_fee, None);
            (ckerc20, ckusdc)
        };
        tests.push(ParameterizedTest {
            setup: setup_without_ckerc20_approval,
            expected_withdrawal_error: WithdrawErc20Error::CkErc20LedgerError {
                cketh_block_index: cketh_burn_index.into(),
                error: LedgerError::InsufficientAllowance {
                    allowance: Nat::from(0_u8),
                    failed_burn_amount: TWO_USDC.into(),
                    token_symbol: "ckUSDC".to_string(),
                    ledger_id: ckerc20_token.ledger_canister_id,
                },
            },
        });

        let (setup_with_insufficient_ckerc20_funds, ckerc20_token) = {
            let mut ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
            let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
            let caller = ckerc20.caller();
            ckerc20 = ckerc20
                .deposit_cketh_and_ckerc20(EXPECTED_BALANCE, ONE_USDC, ckusdc.clone(), caller)
                .expect_mint()
                .call_cketh_ledger_approve_minter(caller, transaction_fee, None)
                .call_ckerc20_ledger_approve_minter(
                    ckusdc.ledger_canister_id,
                    caller,
                    TWO_USDC,
                    None,
                );
            (ckerc20, ckusdc)
        };
        tests.push(ParameterizedTest {
            setup: setup_with_insufficient_ckerc20_funds,
            expected_withdrawal_error: WithdrawErc20Error::CkErc20LedgerError {
                cketh_block_index: cketh_burn_index.into(),
                error: LedgerError::InsufficientFunds {
                    balance: Nat::from(ONE_USDC - CKERC20_TRANSFER_FEE),
                    failed_burn_amount: Nat::from(TWO_USDC),
                    token_symbol: "ckUSDC".to_string(),
                    ledger_id: ckerc20_token.ledger_canister_id,
                },
            },
        });

        for test in tests {
            let mut ckerc20 = test.setup;
            let caller = ckerc20.caller();
            let balance_before_withdrawal = ckerc20.cketh.balance_of(caller);
            assert!(balance_before_withdrawal >= transaction_fee);
            let minter = ckerc20.cketh.minter_id;
            let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");

            ckerc20 = ckerc20
                .call_minter_withdraw_erc20(
                    caller,
                    TWO_USDC,
                    ckusdc.ledger_canister_id,
                    DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
                )
                .expect_refresh_gas_fee_estimate(identity)
                .expect_error(test.expected_withdrawal_error)
                .call_cketh_ledger_get_transaction(cketh_burn_index)
                .expect_burn(Burn {
                    amount: Nat::from(transaction_fee),
                    from: Account {
                        owner: caller,
                        subaccount: None,
                    },
                    spender: Some(Account {
                        owner: minter.into(),
                        subaccount: None,
                    }),
                    memo: Some(Memo::from(BurnMemo::Erc20GasFee {
                        ckerc20_token_symbol: "ckUSDC".parse().unwrap(),
                        ckerc20_withdrawal_amount: TWO_USDC.into(),
                        to_address: DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS
                            .parse()
                            .unwrap(),
                    })),
                    created_at_time: None,
                });

            let balance_after_withdrawal = ckerc20.cketh.balance_of(caller);
            assert_eq!(
                balance_after_withdrawal,
                balance_before_withdrawal - Nat::from(transaction_fee),
            );
            let reimbursed_amount = Nat::from(transaction_fee - CKETH_TRANSFER_FEE);
            ckerc20 = ckerc20
                .check_events()
                .assert_has_unique_events_in_order(&vec![
                    EventPayload::FailedErc20WithdrawalRequest {
                        withdrawal_id: cketh_burn_index.into(),
                        reimbursed_amount: reimbursed_amount.clone(),
                        to: caller,
                        to_subaccount: None,
                    },
                ]);

            ckerc20.env.advance_time(PROCESS_REIMBURSEMENT);
            ckerc20.env.tick();
            let balance_after_reimbursement = ckerc20.cketh.balance_of(caller);
            assert_eq!(
                balance_after_reimbursement,
                balance_after_withdrawal + reimbursed_amount.clone(),
            );
            ckerc20
                .check_events()
                .assert_has_unique_events_in_order(&vec![EventPayload::ReimbursedEthWithdrawal {
                    withdrawal_id: cketh_burn_index.into(),
                    reimbursed_in_block: Nat::from(cketh_burn_index) + 1_u8,
                    reimbursed_amount: reimbursed_amount.clone(),
                    transaction_hash: None,
                }])
                .call_cketh_ledger_get_transaction(3_u8)
                .expect_mint(Mint {
                    amount: reimbursed_amount,
                    to: Account {
                        owner: caller,
                        subaccount: None,
                    },
                    memo: Some(Memo::from(MintMemo::ReimburseWithdrawal {
                        withdrawal_id: cketh_burn_index.into(),
                    })),
                    created_at_time: None,
                });
        }

        struct ParameterizedTest {
            setup: CkErc20Setup,
            expected_withdrawal_error: WithdrawErc20Error,
        }
    }

    #[test]
    fn should_refresh_gas_fee_estimate_only_once_within_a_minute() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
        let cketh_ledger = ckerc20.cketh_ledger_id();
        let user_1 = ckerc20.caller();
        let user_2: Principal = PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID + 1).into();
        assert_ne!(user_1, user_2);
        let insufficient_allowance_error = WithdrawErc20Error::CkEthLedgerError {
            error: LedgerError::InsufficientAllowance {
                allowance: Nat::from(0_u8),
                failed_burn_amount: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE.into(),
                token_symbol: "ckETH".to_string(),
                ledger_id: cketh_ledger,
            },
        };

        let ckerc20 = ckerc20
            .call_minter_withdraw_erc20(
                user_1,
                0_u8,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_refresh_gas_fee_estimate(identity)
            .expect_error(insufficient_allowance_error.clone());

        ckerc20.env.advance_time(Duration::from_secs(59));

        let ckerc20 = ckerc20
            .call_minter_withdraw_erc20(
                user_2,
                0_u8,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_no_refresh_gas_fee_estimate()
            .expect_error(insufficient_allowance_error.clone());

        ckerc20.env.advance_time(Duration::from_millis(1_001));

        ckerc20
            .call_minter_withdraw_erc20(
                user_2,
                0_u8,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_refresh_gas_fee_estimate(identity)
            .expect_error(insufficient_allowance_error);
    }

    #[test]
    fn should_prevent_parallel_refresh_of_gas_fee_estimate() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
        let cketh_ledger = ckerc20.cketh_ledger_id();
        let user_1 = ckerc20.caller();
        let user_2: Principal = PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID + 1).into();
        assert_ne!(user_1, user_2);
        let insufficient_allowance_error = WithdrawErc20Error::CkEthLedgerError {
            error: LedgerError::InsufficientAllowance {
                allowance: Nat::from(0_u8),
                failed_burn_amount: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE.into(),
                token_symbol: "ckETH".to_string(),
                ledger_id: cketh_ledger,
            },
        };

        let RefreshGasFeeEstimate {
            setup: ckerc20,
            message_id: first_withdrawal_msg_id,
        } = ckerc20.call_minter_withdraw_erc20(
            user_1,
            0_u8,
            ckusdc.ledger_canister_id,
            DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
        );

        let RefreshGasFeeEstimate {
            setup: ckerc20,
            message_id: second_withdrawal_msg_id,
        } = ckerc20.call_minter_withdraw_erc20(
            user_2,
            0_u8,
            ckusdc.ledger_canister_id,
            DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
        );
        let ckerc20 = Erc20WithdrawalFlow {
            setup: ckerc20,
            message_id: second_withdrawal_msg_id,
        }
        .expect_error(WithdrawErc20Error::TemporarilyUnavailable(
            "Failed to retrieve current gas fee".to_string(),
        ));

        RefreshGasFeeEstimate {
            setup: ckerc20,
            message_id: first_withdrawal_msg_id,
        }
        .expect_refresh_gas_fee_estimate(identity)
        .expect_error(insufficient_allowance_error);
    }

    #[test]
    fn should_withdraw_ckusdc() {
        fn test(transaction_status: TransactionStatus) {
            let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
            let minter = ckerc20.cketh.minter_id;
            let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
            let caller = ckerc20.caller();
            let ckerc20_tx_fee = DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE;

            let ckerc20 = ckerc20
                .deposit_cketh_and_ckerc20(
                    EXPECTED_BALANCE,
                    TWO_USDC + CKERC20_TRANSFER_FEE,
                    ckusdc.clone(),
                    caller,
                )
                .expect_mint()
                .call_cketh_ledger_approve_minter(caller, ckerc20_tx_fee, None)
                .call_ckerc20_ledger_approve_minter(
                    ckusdc.ledger_canister_id,
                    caller,
                    TWO_USDC,
                    None,
                )
                .call_minter_withdraw_erc20(
                    caller,
                    TWO_USDC,
                    ckusdc.ledger_canister_id,
                    DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
                )
                .expect_refresh_gas_fee_estimate(identity)
                .expect_withdrawal_request_accepted();

            assert_eq!(
                ckerc20
                    .setup
                    .erc20_balance_from_get_minter_info(&ckusdc.erc20_contract_address),
                TWO_USDC + CKERC20_TRANSFER_FEE
            );
            let time = ckerc20.setup.env.get_time().as_nanos_since_unix_epoch();

            let RetrieveErc20Request {
                cketh_block_index,
                ckerc20_block_index,
            } = ckerc20.withdrawal_request.clone();

            let ckerc20 = match transaction_status {
                TransactionStatus::Success => ckerc20
                    .wait_and_validate_withdrawal(ProcessWithdrawalParams::default())
                    .expect_finalized_status(TxFinalizedStatus::Success(EthTransaction {
                        transaction_hash: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH.to_string(),
                    })),
                TransactionStatus::Failure => ckerc20
                    .wait_and_validate_withdrawal(
                        ProcessWithdrawalParams::default().with_failed_transaction_receipt(),
                    )
                    .expect_finalized_status(TxFinalizedStatus::PendingReimbursement(
                        EthTransaction {
                            transaction_hash: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH
                                .to_string(),
                        },
                    )),
            }
            .call_cketh_ledger_get_transaction(cketh_block_index.clone())
            .expect_burn(Burn {
                amount: ckerc20_tx_fee.into(),
                from: Account {
                    owner: caller,
                    subaccount: None,
                },
                spender: Some(Account {
                    owner: minter.into(),
                    subaccount: None,
                }),
                memo: Some(Memo::from(BurnMemo::Erc20GasFee {
                    ckerc20_token_symbol: "ckUSDC".parse().unwrap(),
                    ckerc20_withdrawal_amount: TWO_USDC.into(),
                    to_address: DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS
                        .parse()
                        .unwrap(),
                })),
                created_at_time: None,
            })
            .call_ckerc20_ledger_get_transaction(
                ckusdc.ledger_canister_id,
                ckerc20_block_index.clone(),
            )
            .expect_burn(Burn {
                amount: TWO_USDC.into(),
                from: Account {
                    owner: caller,
                    subaccount: None,
                },
                spender: Some(Account {
                    owner: minter.into(),
                    subaccount: None,
                }),
                memo: Some(Memo::from(BurnMemo::Erc20Convert {
                    ckerc20_withdrawal_id: cketh_block_index.0.to_u64().unwrap(),
                    to_address: DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS
                        .parse()
                        .unwrap(),
                })),
                created_at_time: None,
            });

            let expected_cketh_balance_after_withdrawal =
                Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE - ckerc20_tx_fee);
            assert_eq!(
                ckerc20.cketh.balance_of(caller),
                expected_cketh_balance_after_withdrawal
            );
            let expected_ckerc20_balance_after_withdrawal = Nat::from(0_u8);
            assert_eq!(
                ckerc20.balance_of_ledger(ckusdc.ledger_canister_id, caller),
                expected_ckerc20_balance_after_withdrawal
            );
            assert_eq!(
                ckerc20.erc20_balance_from_get_minter_info(&ckusdc.erc20_contract_address),
                match transaction_status {
                    TransactionStatus::Success => CKERC20_TRANSFER_FEE,
                    TransactionStatus::Failure => TWO_USDC + CKERC20_TRANSFER_FEE,
                }
            );

            let estimated_max_fee_per_gas = Nat::from(33_003_708_258_u64);
            let estimated_gas_limit = Nat::from(65_000_u64);
            let ckerc20 = ckerc20
                .check_events()
                .assert_has_unique_events_in_order(&vec![
                    EventPayload::AcceptedErc20WithdrawalRequest {
                        max_transaction_fee: ckerc20_tx_fee.into(),
                        withdrawal_amount: TWO_USDC.into(),
                        erc20_contract_address: ckusdc.erc20_contract_address.clone(),
                        destination: DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
                        cketh_ledger_burn_index: cketh_block_index.clone(),
                        ckerc20_ledger_id: ckusdc.ledger_canister_id,
                        ckerc20_ledger_burn_index: ckerc20_block_index.clone(),
                        from: caller,
                        from_subaccount: None,
                        created_at: time,
                    },
                    EventPayload::CreatedTransaction {
                        withdrawal_id: cketh_block_index.clone(),
                        transaction: UnsignedTransaction {
                            chain_id: Nat::from(1_u8),
                            nonce: Nat::from(0_u8),
                            max_priority_fee_per_gas: 1_500_000_000_u64.into(),
                            max_fee_per_gas: estimated_max_fee_per_gas.clone(),
                            gas_limit: estimated_gas_limit.clone(),
                            destination: ckusdc.erc20_contract_address,
                            value: 0_u8.into(),
                            data: ByteBuf::from(erc20_transfer_data(
                                &DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS
                                    .parse()
                                    .unwrap(),
                                &TWO_USDC.into(),
                            )),
                            access_list: vec![],
                        },
                    },
                    EventPayload::SignedTransaction {
                        withdrawal_id: cketh_block_index.clone(),
                        raw_transaction: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION.to_string(),
                    },
                    EventPayload::FinalizedTransaction {
                        withdrawal_id: cketh_block_index.clone(),
                        transaction_receipt: TransactionReceipt {
                            block_hash: DEFAULT_BLOCK_HASH.to_string(),
                            block_number: Nat::from(DEFAULT_BLOCK_NUMBER),
                            effective_gas_price: Nat::from(4_277_923_390_u64),
                            gas_used: Nat::from(21_000_u64),
                            status: transaction_status.clone(),
                            transaction_hash: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH
                                .to_string(),
                        },
                    },
                ]);

            ckerc20.env.advance_time(PROCESS_REIMBURSEMENT);
            let cketh_balance_after_reimbursement = ckerc20.wait_for_updated_ledger_balance(
                ckerc20.cketh_ledger_id(),
                caller,
                &expected_cketh_balance_after_withdrawal,
            );
            assert_eq!(
                cketh_balance_after_reimbursement,
                expected_cketh_balance_after_withdrawal
            );

            if transaction_status == TransactionStatus::Failure {
                let ckerc20_balance_after_reimbursement = ckerc20.wait_for_updated_ledger_balance(
                    ckusdc.ledger_canister_id,
                    caller,
                    &expected_ckerc20_balance_after_withdrawal,
                );
                assert_eq!(ckerc20_balance_after_reimbursement, Nat::from(TWO_USDC));
                ckerc20
                    .check_events()
                    .assert_has_unique_events_in_order(&vec![
                        EventPayload::ReimbursedErc20Withdrawal {
                            withdrawal_id: cketh_block_index.clone(),
                            burn_in_block: ckerc20_block_index.clone(),
                            reimbursed_in_block: Nat::from(3_u8),
                            ledger_id: ckusdc.ledger_canister_id,
                            reimbursed_amount: TWO_USDC.into(),
                            transaction_hash: Some(
                                DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH.to_string(),
                            ),
                        },
                    ])
                    .call_ckerc20_ledger_get_transaction(ckusdc.ledger_canister_id, 3_u8)
                    .expect_mint(Mint {
                        amount: TWO_USDC.into(),
                        to: Account {
                            owner: caller,
                            subaccount: None,
                        },
                        memo: Some(Memo::from(MintMemo::ReimburseTransaction {
                            withdrawal_id: ckerc20_block_index.0.to_u64().unwrap(),
                            tx_hash: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH.parse().unwrap(),
                        })),
                        created_at_time: None,
                    });
            }
        }

        test(TransactionStatus::Success);
        test(TransactionStatus::Failure);
    }

    #[test]
    fn should_resubmit_transaction_as_is_when_price_still_actual() {
        let (expected_tx, expected_sig) = default_erc20_signed_eip_1559_transaction();
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
        let caller = ckerc20.caller();
        let ckerc20_tx_fee = CKETH_MINIMUM_WITHDRAWAL_AMOUNT;

        ckerc20
            .deposit_cketh_and_ckerc20(
                EXPECTED_BALANCE,
                TWO_USDC + CKERC20_TRANSFER_FEE,
                ckusdc.clone(),
                caller,
            )
            .expect_mint()
            .call_cketh_ledger_approve_minter(caller, ckerc20_tx_fee, None)
            .call_ckerc20_ledger_approve_minter(ckusdc.ledger_canister_id, caller, TWO_USDC, None)
            .call_minter_withdraw_erc20(
                caller,
                TWO_USDC,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_refresh_gas_fee_estimate(identity)
            .expect_withdrawal_request_accepted()
            .process_withdrawal_with_resubmission_and_same_price(expected_tx, expected_sig)
            .check_events()
            .assert_has_no_event_satisfying(|event| {
                matches!(event, EventPayload::ReplacedTransaction { .. })
            });
    }

    #[test]
    fn should_resubmit_new_transaction_with_same_max_fee_per_gas_when_price_increased() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
        let caller = ckerc20.caller();
        let ckerc20_tx_fee = DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE;
        let (first_tx, first_tx_sig) = default_erc20_signed_eip_1559_transaction();
        let first_tx_hash = hash_transaction(first_tx.clone(), first_tx_sig);
        let resubmitted_sent_tx = "0x02f8b0018084625900808507af2c9f6282fde894a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb000000000000000000000000221e931fbfcb9bd54ddd26ce6f5e29e98add01c000000000000000000000000000000000000000000000000000000000001e8480c001a03acbc792d2f821acaab8da81517f1905e30cd3acd2f85d7995c68c0ad1fd8817a0793a076f2163658c833ccddd37ee0a762a18adb423f689db5ffcf528ae667bf0";
        let (resubmitted_tx, resubmitted_tx_sig) = decode_transaction(resubmitted_sent_tx);
        let resubmitted_tx_hash = hash_transaction(resubmitted_tx.clone(), resubmitted_tx_sig);
        assert_eq!(
            resubmitted_tx,
            first_tx.clone().max_priority_fee_per_gas(1_650_000_000_u64)
        );
        assert_ne!(first_tx_hash, resubmitted_tx_hash);

        let ckerc20 = ckerc20
            .deposit_cketh_and_ckerc20(
                EXPECTED_BALANCE,
                TWO_USDC + CKERC20_TRANSFER_FEE,
                ckusdc.clone(),
                caller,
            )
            .expect_mint()
            .call_cketh_ledger_approve_minter(caller, ckerc20_tx_fee, None)
            .call_ckerc20_ledger_approve_minter(ckusdc.ledger_canister_id, caller, TWO_USDC, None)
            .call_minter_withdraw_erc20(
                caller,
                TWO_USDC,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_refresh_gas_fee_estimate(identity)
            .expect_withdrawal_request_accepted();

        let RetrieveErc20Request {
            cketh_block_index,
            ckerc20_block_index: _,
        } = ckerc20.withdrawal_request.clone();

        ckerc20
            .process_withdrawal_with_resubmission_and_increased_price(
                first_tx.clone(),
                first_tx_sig,
                &mut increment_max_priority_fee_per_gas,
                resubmitted_tx,
                resubmitted_tx_sig,
            )
            .check_events()
            .assert_has_unique_events_in_order(&vec![
                EventPayload::ReplacedTransaction {
                    withdrawal_id: cketh_block_index.clone(),
                    transaction: UnsignedTransaction {
                        chain_id: Nat::from(1_u8),
                        nonce: Nat::from(0_u8),
                        max_priority_fee_per_gas: Nat::from(1_650_000_000_u64),
                        max_fee_per_gas: Nat::from(first_tx.max_fee_per_gas.unwrap().as_u64()),
                        gas_limit: Nat::from(65_000_u64),
                        destination: ckusdc.erc20_contract_address,
                        value: 0_u8.into(),
                        data: ByteBuf::from(erc20_transfer_data(
                            &DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS
                                .parse()
                                .unwrap(),
                            &TWO_USDC.into(),
                        )),
                        access_list: vec![],
                    },
                },
                EventPayload::SignedTransaction {
                    withdrawal_id: cketh_block_index.clone(),
                    raw_transaction: resubmitted_sent_tx.to_string(),
                },
                EventPayload::FinalizedTransaction {
                    withdrawal_id: cketh_block_index,
                    transaction_receipt: TransactionReceipt {
                        block_hash: DEFAULT_BLOCK_HASH.to_string(),
                        block_number: Nat::from(DEFAULT_BLOCK_NUMBER),
                        effective_gas_price: Nat::from(4_277_923_390_u64),
                        gas_used: Nat::from(21_000_u64),
                        status: TransactionStatus::Success,
                        transaction_hash: format!("{:?}", resubmitted_tx_hash),
                    },
                },
            ]);
    }
    #[test]
    fn should_not_finalize_transaction_when_receipts_do_not_match() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
        let caller = ckerc20.caller();
        let ckerc20_tx_fee = CKETH_MINIMUM_WITHDRAWAL_AMOUNT;

        ckerc20
            .deposit_cketh_and_ckerc20(
                EXPECTED_BALANCE,
                TWO_USDC + CKERC20_TRANSFER_FEE,
                ckusdc.clone(),
                caller,
            )
            .expect_mint()
            .call_cketh_ledger_approve_minter(caller, ckerc20_tx_fee, None)
            .call_ckerc20_ledger_approve_minter(ckusdc.ledger_canister_id, caller, TWO_USDC, None)
            .call_minter_withdraw_erc20(
                caller,
                TWO_USDC,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_refresh_gas_fee_estimate(identity)
            .expect_withdrawal_request_accepted()
            .wait_and_validate_withdrawal(
                ProcessWithdrawalParams::default().with_inconsistent_transaction_receipt(),
            )
            .expect_status(RetrieveEthStatus::TxSent(EthTransaction {
                transaction_hash: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH.to_string(),
            }));
    }

    #[test]
    fn should_not_send_eth_transaction_when_fee_history_inconsistent() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
        let caller = ckerc20.caller();
        let ckerc20_tx_fee = CKETH_MINIMUM_WITHDRAWAL_AMOUNT;

        ckerc20
            .deposit_cketh_and_ckerc20(
                EXPECTED_BALANCE,
                TWO_USDC + CKERC20_TRANSFER_FEE,
                ckusdc.clone(),
                caller,
            )
            .expect_mint()
            .call_cketh_ledger_approve_minter(caller, ckerc20_tx_fee, None)
            .call_ckerc20_ledger_approve_minter(ckusdc.ledger_canister_id, caller, TWO_USDC, None)
            .call_minter_withdraw_erc20(
                caller,
                TWO_USDC,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_refresh_gas_fee_estimate(identity)
            .expect_withdrawal_request_accepted()
            .start_processing_withdrawals()
            .retrieve_fee_history(move |mock| {
                mock.modify_response(
                    JsonRpcProvider::Ankr,
                    &mut |response: &mut ethers_core::types::FeeHistory| {
                        response.oldest_block = 0x17740742_u64.into()
                    },
                )
                .modify_response(
                    JsonRpcProvider::PublicNode,
                    &mut |response: &mut ethers_core::types::FeeHistory| {
                        response.oldest_block = 0x17740743_u64.into()
                    },
                )
                .modify_response(
                    JsonRpcProvider::LlamaNodes,
                    &mut |response: &mut ethers_core::types::FeeHistory| {
                        response.oldest_block = 0x17740744_u64.into()
                    },
                )
            })
            .expect_status(RetrieveEthStatus::Pending);
    }
}

#[test]
fn should_deposit_ckerc20() {
    let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
    let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
    let caller: Principal = ckerc20.caller();

    ckerc20
        .deposit_ckerc20(ONE_USDC, ckusdc.clone(), caller)
        .expect_mint()
        .call_ckerc20_ledger_get_transaction(ckusdc.ledger_canister_id, 0_u8)
        .expect_mint(Mint {
            amount: Nat::from(ONE_USDC),
            to: Account {
                owner: caller,
                subaccount: None,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_ERC20_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        });
}

#[test]
fn should_deposit_cketh_and_ckerc20() {
    let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
    let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
    let caller = ckerc20.caller();

    ckerc20
        .deposit_cketh_and_ckerc20(
            CKETH_MINIMUM_WITHDRAWAL_AMOUNT,
            ONE_USDC,
            ckusdc.clone(),
            caller,
        )
        .expect_mint()
        .call_cketh_ledger_get_transaction(0_u8)
        .expect_mint(Mint {
            amount: CKETH_MINIMUM_WITHDRAWAL_AMOUNT.into(),
            to: Account {
                owner: caller,
                subaccount: None,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        })
        .call_ckerc20_ledger_get_transaction(ckusdc.ledger_canister_id, 0_u8)
        .expect_mint(Mint {
            amount: ONE_USDC.into(),
            to: Account {
                owner: caller,
                subaccount: None,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_ERC20_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        });
}

#[test]
fn should_block_deposit_from_blocked_address() {
    let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
    let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
    let from_address_blocked: Address = "0x01e2919679362dFBC9ee1644Ba9C6da6D6245BB1"
        .parse()
        .unwrap();

    ckerc20
        .deposit(CkErc20DepositParams {
            from_address: from_address_blocked,
            ..CkErc20DepositParams::for_token(ONE_USDC, ckusdc)
        })
        .expect_no_mint()
        .check_events()
        .assert_has_unique_events_in_order(&vec![EventPayload::InvalidDeposit {
            event_source: EventSource {
                transaction_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.to_string(),
                log_index: Nat::from(DEFAULT_ERC20_DEPOSIT_LOG_INDEX),
            },
            reason: format!("blocked address {from_address_blocked}"),
        }]);
}

#[test]
fn should_block_deposit_from_corrupted_principal() {
    let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
    let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
    let invalid_principal = "0x0a01f79d0000000000fe01000000000000000000000000000000000000000001";

    ckerc20
        .deposit(CkErc20DepositParams {
            override_erc20_log_entry: Box::new(|mut entry: Erc20LogEntry| {
                entry.encoded_principal = invalid_principal.to_string();
                entry
            }),
            ..CkErc20DepositParams::for_token(ONE_USDC, ckusdc)
        })
        .expect_no_mint()
        .check_events()
        .assert_has_unique_events_in_order(&vec![EventPayload::InvalidDeposit {
            event_source: EventSource {
                transaction_hash: DEFAULT_ERC20_DEPOSIT_TRANSACTION_HASH.to_string(),
                log_index: Nat::from(DEFAULT_ERC20_DEPOSIT_LOG_INDEX),
            },
            reason: format!("failed to decode principal from bytes {invalid_principal}"),
        }]);
}

#[test]
fn should_fail_to_mint_from_unsupported_erc20_contract_address() {
    let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
    let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
    let unsupported_erc20_address: Address = "0x6b175474e89094c44da98b954eedeac495271d0f"
        .parse()
        .unwrap();
    assert!(!ckerc20
        .supported_erc20_contract_addresses()
        .contains(&unsupported_erc20_address));

    ckerc20
        .deposit(CkErc20DepositParams {
            override_erc20_log_entry: Box::new(move |mut entry: Erc20LogEntry| {
                entry.erc20_contract_address = unsupported_erc20_address;
                entry
            }),
            ..CkErc20DepositParams::for_token(ONE_USDC, ckusdc)
        })
        .expect_no_mint()
        .check_events()
        .assert_has_no_event_satisfying(|event| {
            matches!(event, EventPayload::AcceptedErc20Deposit { .. })
        });
}

#[test]
fn should_retrieve_minter_info() {
    let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
    let supported_ckerc20_tokens = ckerc20
        .supported_erc20_tokens
        .iter()
        .map(|token: &Erc20Token| CkErc20Token {
            ckerc20_token_symbol: token.ledger_init_arg.token_symbol.clone(),
            erc20_contract_address: format_ethereum_address_to_eip_55(&token.contract.address),
            ledger_canister_id: ckerc20
                .orchestrator
                .call_orchestrator_canister_ids(&token.contract)
                .unwrap()
                .ledger
                .unwrap(),
        })
        .collect::<Vec<_>>();
    assert!(!supported_ckerc20_tokens.is_empty());

    let erc20_balances = supported_ckerc20_tokens
        .iter()
        .map(|token| Erc20Balance {
            erc20_contract_address: token.erc20_contract_address.clone(),
            balance: Nat::from(0_u8),
        })
        .collect();

    let info_at_start = ckerc20.cketh.get_minter_info();
    assert_eq!(
        info_at_start,
        MinterInfo {
            minter_address: Some(format_ethereum_address_to_eip_55(MINTER_ADDRESS)),
            eth_helper_contract_address: Some(format_ethereum_address_to_eip_55(
                ETH_HELPER_CONTRACT_ADDRESS
            )),
            erc20_helper_contract_address: Some(format_ethereum_address_to_eip_55(
                ERC20_HELPER_CONTRACT_ADDRESS
            )),
            supported_ckerc20_tokens: Some(supported_ckerc20_tokens),
            minimum_withdrawal_amount: Some(Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT)),
            ethereum_block_height: Some(Finalized),
            last_observed_block_number: None,
            eth_balance: Some(Nat::from(0_u8)),
            last_gas_fee_estimate: None,
            erc20_balances: Some(erc20_balances),
        }
    );
}

#[test]
fn should_scrape_from_last_scraped_after_upgrade() {
    let mut ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();

    // Set latest_finalized_block so that we scrapped twice each time.
    let latest_finalized_block =
        LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + MAX_ETH_LOGS_BLOCK_RANGE * 2;
    ckerc20.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(latest_finalized_block))
        .build()
        .expect_rpc_calls(&ckerc20);
    let erc20_topics = ckerc20.supported_erc20_contract_address_topics();

    // ckETH event logs
    let first_from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let first_to_block = first_from_block
        .checked_add(BlockNumber::from(MAX_ETH_LOGS_BLOCK_RANGE))
        .unwrap();
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": first_from_block,
            "toBlock": first_to_block,
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&ckerc20);

    let second_from_block = first_to_block
        .checked_add(BlockNumber::from(1_u64))
        .unwrap();
    let second_to_block = BlockNumber::from(latest_finalized_block);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": second_from_block,
            "toBlock": second_to_block,
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&ckerc20);

    // ckERC20 event logs
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": first_from_block,
            "toBlock": first_to_block,
            "address": [ERC20_HELPER_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ERC20_EVENT_TOPIC, erc20_topics.clone()]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&ckerc20);

    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": second_from_block,
            "toBlock": second_to_block,
            "address": [ERC20_HELPER_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ERC20_EVENT_TOPIC, erc20_topics]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&ckerc20);

    // Upgrade to see if everything works
    ckerc20
        .cketh
        .check_audit_logs_and_upgrade_as_ref(Default::default());
    ckerc20 = ckerc20
        .check_events()
        .assert_has_unique_events_in_order(&vec![
            EventPayload::SyncedToBlock {
                block_number: latest_finalized_block.into(),
            },
            EventPayload::SyncedErc20ToBlock {
                block_number: latest_finalized_block.into(),
            },
        ]);

    // Advance block height and scrape again
    let latest_finalized_block =
        u64::try_from(second_to_block.into_inner()).unwrap() + MAX_ETH_LOGS_BLOCK_RANGE;
    ckerc20.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(latest_finalized_block))
        .build()
        .expect_rpc_calls(&ckerc20);

    // ckETH event logs
    let first_from_block = second_to_block
        .checked_add(BlockNumber::from(1_u64))
        .unwrap();
    let first_to_block = BlockNumber::from(latest_finalized_block);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": first_from_block,
            "toBlock": first_to_block,
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&ckerc20);

    // ckERC20 event logs
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": first_from_block,
            "toBlock": first_to_block,
            "address": [ERC20_HELPER_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ERC20_EVENT_TOPIC, erc20_topics]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&ckerc20);
}
