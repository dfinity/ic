use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_cketh_minter::endpoints::events::{EventPayload, EventSource};
use ic_cketh_minter::endpoints::CandidBlockTag::Finalized;
use ic_cketh_minter::endpoints::{AddCkErc20Token, CkErc20Token, MinterInfo};
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
use ic_ledger_suite_orchestrator_test_utils::supported_erc20_tokens;
use ic_state_machine_tests::ErrorCode;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Mint;
use serde_json::json;

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
fn should_mint_with_ckerc20_setup() {
    CkErc20Setup::default()
        .cketh
        .deposit(DepositParams::default())
        .expect_mint();
}

mod withdraw_erc20 {
    use super::*;
    use ic_cketh_minter::endpoints::ckerc20::{
        LedgerError, RetrieveErc20Request, WithdrawErc20Error,
    };
    use ic_cketh_minter::endpoints::events::{
        TransactionReceipt, TransactionStatus, UnsignedTransaction,
    };
    use ic_cketh_minter::endpoints::{EthTransaction, TxFinalizedStatus};
    use ic_cketh_minter::memo::BurnMemo;
    use ic_cketh_minter::PROCESS_REIMBURSEMENT;
    use ic_cketh_test_utils::ckerc20::{
        erc20_transfer_data, DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS, ONE_USDC, TWO_USDC,
    };
    use ic_cketh_test_utils::flow::{DepositParams, ProcessWithdrawalParams};
    use ic_cketh_test_utils::{
        CKETH_TRANSFER_FEE, DEFAULT_BLOCK_HASH, DEFAULT_BLOCK_NUMBER,
        DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION, DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH,
        EXPECTED_BALANCE,
    };
    use ic_ledger_suite_orchestrator_test_utils::{new_state_machine, CKERC20_TRANSFER_FEE};
    use icrc_ledger_types::icrc3::transactions::Burn;
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;
    use serde_bytes::ByteBuf;
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
            .expect_error(WithdrawErc20Error::CkEthLedgerError {
                error: LedgerError::InsufficientAllowance {
                    allowance: Nat::from(0_u8),
                    failed_burn_amount: Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT),
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
                amount: CKETH_MINIMUM_WITHDRAWAL_AMOUNT,
                ..DepositParams::default()
            })
            .call_cketh_ledger_approve_minter(caller, CKETH_MINIMUM_WITHDRAWAL_AMOUNT, None)
            .call_minter_withdraw_erc20(
                caller,
                0_u8,
                ckusdc.ledger_canister_id,
                DEFAULT_ERC20_WITHDRAWAL_DESTINATION_ADDRESS,
            )
            .expect_error(WithdrawErc20Error::CkEthLedgerError {
                error: LedgerError::InsufficientFunds {
                    balance: Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT - CKETH_TRANSFER_FEE),
                    failed_burn_amount: Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT),
                    token_symbol: "ckETH".to_string(),
                    ledger_id: cketh_ledger,
                },
            });
    }

    #[test]
    fn should_error_when_minter_fails_to_burn_ckerc20_and_reimburse_cketh() {
        let transaction_fee = CKETH_MINIMUM_WITHDRAWAL_AMOUNT;
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
    fn should_withdraw_ckusdc_and_reimburse_unused_transaction_fees() {
        let ckerc20 = CkErc20Setup::default().add_supported_erc20_tokens();
        let minter = ckerc20.cketh.minter_id;
        let ckusdc = ckerc20.find_ckerc20_token("ckUSDC");
        let caller = ckerc20.caller();
        let ckerc20_tx_fee = CKETH_MINIMUM_WITHDRAWAL_AMOUNT;

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
            .expect_withdrawal_request_accepted();

        let time = ckerc20.setup.env.get_time().as_nanos_since_unix_epoch();

        let RetrieveErc20Request {
            cketh_block_index,
            ckerc20_block_index,
        } = ckerc20.withdrawal_request.clone();

        let ckerc20 = ckerc20
            .wait_and_validate_withdrawal(ProcessWithdrawalParams::default())
            .expect_finalized_status(TxFinalizedStatus::Success(EthTransaction {
                transaction_hash: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH.to_string(),
            }))
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

        let expected_balance_after_withdrawal =
            Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE - CKETH_MINIMUM_WITHDRAWAL_AMOUNT);
        assert_eq!(
            ckerc20.cketh.balance_of(caller),
            expected_balance_after_withdrawal
        );
        assert_eq!(
            ckerc20.balance_of_ledger(ckusdc.ledger_canister_id, caller),
            Nat::from(0_u8)
        );

        let effective_gas_price = Nat::from(4_277_923_390_u64);
        let gas_used = Nat::from(21_000_u64);
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
                    ckerc20_ledger_burn_index: ckerc20_block_index,
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
                        max_fee_per_gas: 33_003_708_258_u64.into(),
                        gas_limit: 65_000_u64.into(),
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
                        effective_gas_price: effective_gas_price.clone(),
                        gas_used: gas_used.clone(),
                        status: TransactionStatus::Success,
                        transaction_hash: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH.to_string(),
                    },
                },
            ]);

        let effective_tx_fee = effective_gas_price * gas_used;
        assert!(effective_tx_fee < ckerc20_tx_fee);
        let reimbursed_amount = ckerc20_tx_fee - effective_tx_fee;
        ckerc20.env.advance_time(PROCESS_REIMBURSEMENT);
        let balance_after_reimbursement = ckerc20.wait_for_updated_ledger_balance(
            ckerc20.cketh_ledger_id(),
            caller,
            &expected_balance_after_withdrawal,
        );
        assert_eq!(
            balance_after_reimbursement - expected_balance_after_withdrawal,
            reimbursed_amount.clone(),
        );

        ckerc20
            .check_events()
            .assert_has_unique_events_in_order(&vec![EventPayload::ReimbursedEthWithdrawal {
                withdrawal_id: cketh_block_index.clone(),
                reimbursed_in_block: Nat::from(3_u8),
                reimbursed_amount: reimbursed_amount.clone(),
                transaction_hash: Some(DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH.to_string()),
            }])
            .call_cketh_ledger_get_transaction(3_u8)
            .expect_mint(Mint {
                amount: reimbursed_amount,
                to: Account {
                    owner: caller,
                    subaccount: None,
                },
                memo: Some(Memo::from(MintMemo::ReimburseTransaction {
                    withdrawal_id: cketh_block_index.0.to_u64().unwrap(),
                    tx_hash: DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH.parse().unwrap(),
                })),
                created_at_time: None,
            });
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
    let supported_ckerc20_tokens = Some(
        ckerc20
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
            .collect::<Vec<_>>(),
    );

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
            supported_ckerc20_tokens,
            minimum_withdrawal_amount: Some(Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT)),
            ethereum_block_height: Some(Finalized),
            last_observed_block_number: None,
            eth_balance: Some(Nat::from(0_u8)),
            last_gas_fee_estimate: None,
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
