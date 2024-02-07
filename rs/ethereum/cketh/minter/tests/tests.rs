use crate::mock::{
    JsonRpcMethod, JsonRpcProvider, MockJsonRpcProviders, MockJsonRpcProvidersBuilder,
};
use candid::{Decode, Encode, Nat, Principal};
use ethers_core::abi::AbiDecode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_cketh_minter::address::Address;
use ic_cketh_minter::endpoints::events::{
    Event, EventPayload, EventSource, GetEventsResult, TransactionReceipt, TransactionStatus,
    UnsignedTransaction,
};
use ic_cketh_minter::endpoints::RetrieveEthStatus::Pending;
use ic_cketh_minter::endpoints::{
    CandidBlockTag, EthTransaction, RetrieveEthRequest, RetrieveEthStatus, TxFinalizedStatus,
    WithdrawalArg, WithdrawalError,
};
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::lifecycle::{init::InitArg as MinterInitArgs, EthereumNetwork, MinterArg};
use ic_cketh_minter::logs::Log;
use ic_cketh_minter::memo::{BurnMemo, MintMemo};
use ic_cketh_minter::numeric::BlockNumber;
use ic_cketh_minter::{
    PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL, PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL,
    PROCESS_REIMBURSEMENT, SCRAPPING_ETH_LOGS_INTERVAL,
};
use ic_icrc1_ledger::{InitArgsBuilder as LedgerInitArgsBuilder, LedgerArgument};
use ic_state_machine_tests::{Cycles, MessageId, StateMachine, StateMachineBuilder, WasmResult};
use ic_test_utilities_load_wasm::load_wasm;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc3::transactions::Transaction as LedgerTransaction;
use icrc_ledger_types::icrc3::transactions::{Burn, Mint};
use num_traits::cast::ToPrimitive;
use serde_json::json;
use std::collections::BTreeMap;
use std::convert::identity;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

const CKETH_TRANSFER_FEE: u64 = 10;
const MAX_TICKS: usize = 10;
const DEFAULT_PRINCIPAL_ID: u64 = 10352385;
const DEFAULT_DEPOSIT_BLOCK_NUMBER: u64 = 0x9;
const DEFAULT_DEPOSIT_FROM_ADDRESS: &str = "0x55654e7405fcb336386ea8f36954a211b2cda764";
const DEFAULT_DEPOSIT_TRANSACTION_HASH: &str =
    "0xcfa48c44dc89d18a898a42b4a5b02b6847a3c2019507d5571a481751c7a2f353";
const DEFAULT_DEPOSIT_LOG_INDEX: u64 = 0x24;
const DEFAULT_BLOCK_HASH: &str =
    "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4";

const LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL: u64 = 3_956_206;
const DEFAULT_BLOCK_NUMBER: u64 = 0x4132ec;
const EXPECTED_BALANCE: u64 = 100_000_000_000_000_000;
const EFFECTIVE_GAS_PRICE: u64 = 4_277_923_390;

const DEFAULT_WITHDRAWAL_TRANSACTION_HASH: &str =
    "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5";
const DEFAULT_WITHDRAWAL_TRANSACTION: &str = "0x02f87301808459682f008507af2c9f6282520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c0880160cf1e9917a0e680c001a0b27af25a08e87836a778ac2858fdfcff1f6f3a0d43313782c81d05ca34b80271a078026b399a32d3d7abab625388a3c57f651c66a182eb7f8b1a58d9aef7547256";
const MINTER_ADDRESS: &str = "0xfd644a761079369962386f8e4259217c2a10b8d0";
const DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS: &str = "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0";

const HELPER_SMART_CONTRACT_ADDRESS: &str = "0x907b6efc1a398fd88a8161b3ca02eec8eaf72ca1";
const RECEIVED_ETH_EVENT_TOPIC: &str =
    "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435";
const HEADER_SIZE_LIMIT: u64 = 2 * 1024;

const MAX_ETH_LOGS_BLOCK_RANGE: u64 = 799;

#[test]
fn should_deposit_and_withdraw() {
    let cketh = CkEthSetup::new();
    let minter: Principal = cketh.minter_id.into();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);
    let destination = DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string();

    let cketh = cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_get_transaction(0)
        .expect_mint(Mint {
            amount: EXPECTED_BALANCE.into(),
            to: Account {
                owner: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
                subaccount: None,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        })
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), destination.clone())
        .expect_withdrawal_request_accepted();

    let withdrawal_id = cketh.withdrawal_id().clone();
    let time = cketh.setup.env.get_time().as_nanos_since_unix_epoch();
    let cketh = cketh
        .wait_and_validate_withdrawal(ProcessWithdrawalParams::default())
        .expect_finalized_status(TxFinalizedStatus::Success(EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        }))
        .call_ledger_get_transaction(withdrawal_id.clone())
        .expect_burn(Burn {
            amount: withdrawal_amount.clone(),
            from: Account {
                owner: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
                subaccount: None,
            },
            spender: Some(Account {
                owner: minter,
                subaccount: None,
            }),
            memo: Some(Memo::from(BurnMemo::Convert {
                to_address: destination.parse().unwrap(),
            })),
            created_at_time: None,
        });
    assert_eq!(cketh.balance_of(caller), Nat::from(0));

    let max_fee_per_gas = Nat::from(33003708258u64);
    let gas_limit = Nat::from(21_000);

    cketh.assert_has_unique_events_in_order(&vec![
        EventPayload::AcceptedEthWithdrawalRequest {
            withdrawal_amount: withdrawal_amount.clone(),
            destination: destination.clone(),
            ledger_burn_index: withdrawal_id.clone(),
            from: caller,
            from_subaccount: None,
            created_at: Some(time),
        },
        EventPayload::CreatedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            transaction: UnsignedTransaction {
                chain_id: Nat::from(1),
                nonce: Nat::from(0),
                max_priority_fee_per_gas: Nat::from(1_500_000_000),
                max_fee_per_gas: max_fee_per_gas.clone(),
                gas_limit: gas_limit.clone(),
                destination,
                value: withdrawal_amount - max_fee_per_gas * gas_limit,
                data: Default::default(),
                access_list: vec![],
            },
        },
        EventPayload::SignedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            raw_transaction: "0x02f87301808459682f008507af2c9f6282520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c0880160cf1e9917a0e680c001a0b27af25a08e87836a778ac2858fdfcff1f6f3a0d43313782c81d05ca34b80271a078026b399a32d3d7abab625388a3c57f651c66a182eb7f8b1a58d9aef7547256".to_string(),
        },
        EventPayload::FinalizedTransaction {
            withdrawal_id,
            transaction_receipt: TransactionReceipt {
                block_hash: DEFAULT_BLOCK_HASH.to_string(),
                block_number: Nat::from(DEFAULT_BLOCK_NUMBER),
                effective_gas_price: Nat::from(4277923390u64),
                gas_used: Nat::from(21_000),
                status: TransactionStatus::Success,
                transaction_hash:
                "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string(),
            },
        },
    ]);
}

#[test]
fn should_block_deposit_from_blocked_address() {
    let cketh = CkEthSetup::new();
    let from_address_blocked: Address = "0x01e2919679362dFBC9ee1644Ba9C6da6D6245BB1"
        .parse()
        .unwrap();

    cketh
        .deposit(DepositParams {
            from_address: from_address_blocked,
            ..Default::default()
        })
        .expect_no_mint()
        .assert_has_unique_events_in_order(&vec![EventPayload::InvalidDeposit {
            event_source: EventSource {
                transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
            },
            reason: format!("blocked address {from_address_blocked}"),
        }]);
}

#[test]
fn should_not_mint_when_logs_inconsistent() {
    let deposit_params = DepositParams::default();
    let (ankr_logs, public_node_logs) = {
        let ankr_log_entry = deposit_params.eth_log_entry();
        let mut cloudflare_log_entry = ankr_log_entry.clone();
        cloudflare_log_entry.amount += 1;
        (
            vec![ethers_core::types::Log::from(ankr_log_entry)],
            vec![ethers_core::types::Log::from(cloudflare_log_entry)],
        )
    };
    assert_ne!(ankr_logs, public_node_logs);

    CkEthSetup::new()
        .deposit(deposit_params.with_mock_eth_get_logs(move |mock| {
            mock.respond_with(JsonRpcProvider::Ankr, ankr_logs.clone())
                .respond_with(JsonRpcProvider::PublicNode, public_node_logs.clone())
                .respond_with(JsonRpcProvider::Cloudflare, ankr_logs.clone())
        }))
        .expect_no_mint();
}

#[test]
fn should_block_withdrawal_to_blocked_address() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);
    let blocked_address = "0x01e2919679362dFBC9ee1644Ba9C6da6D6245BB1".to_string();

    cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), blocked_address.clone())
        .expect_error(WithdrawalError::RecipientAddressBlocked {
            address: blocked_address,
        });
}

#[test]
fn should_fail_to_withdraw_without_approval() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();

    cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_minter_withdraw_eth(
            caller,
            Nat::from(10),
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
        .expect_error(WithdrawalError::InsufficientAllowance {
            allowance: Nat::from(0_u64),
        });
}

#[test]
fn should_fail_to_withdraw_when_insufficient_funds() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let deposit_amount = 10_000_000_000_000_000_u64;
    let amount_after_approval = deposit_amount - CKETH_TRANSFER_FEE;
    assert!(deposit_amount > amount_after_approval);

    cketh
        .deposit(DepositParams {
            amount: deposit_amount,
            ..Default::default()
        })
        .expect_mint()
        .call_ledger_approve_minter(caller, deposit_amount, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(
            caller,
            Nat::from(deposit_amount),
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
        .expect_error(WithdrawalError::InsufficientFunds {
            balance: Nat::from(amount_after_approval),
        });
}

#[test]
fn should_fail_to_withdraw_too_small_amount() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, 10_000, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(
            caller,
            Nat::from(CKETH_TRANSFER_FEE - 1),
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
        .expect_error(WithdrawalError::AmountTooLow {
            min_withdrawal_amount: CKETH_TRANSFER_FEE.into(),
        });
}

#[test]
fn should_not_finalize_transaction_when_receipts_do_not_match() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);

    cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(
            caller,
            withdrawal_amount,
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
        .expect_withdrawal_request_accepted()
        .wait_and_validate_withdrawal(
            ProcessWithdrawalParams::default().with_mock_eth_get_transaction_receipt(move |mock| {
                mock.modify_response(
                    JsonRpcProvider::Ankr,
                    &mut |response: &mut ethers_core::types::TransactionReceipt| {
                        response.status = Some(0.into())
                    },
                )
                .modify_response(
                    JsonRpcProvider::PublicNode,
                    &mut |response: &mut ethers_core::types::TransactionReceipt| {
                        response.status = Some(1.into())
                    },
                )
            }),
        )
        .expect_status(RetrieveEthStatus::TxSent(EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        }));
}

#[test]
fn should_not_send_eth_transaction_when_fee_history_inconsistent() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);

    cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(
            caller,
            withdrawal_amount,
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
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
                JsonRpcProvider::Cloudflare,
                &mut |response: &mut ethers_core::types::FeeHistory| {
                    response.oldest_block = 0x17740744_u64.into()
                },
            )
        })
        .expect_status(RetrieveEthStatus::Pending);
}

#[test]
fn should_reimburse() {
    let cketh = CkEthSetup::new();
    let minter: Principal = cketh.minter_id.into();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);
    let destination = "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0".to_string();

    let cketh = cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_get_transaction(0)
        .expect_mint(Mint {
            amount: EXPECTED_BALANCE.into(),
            to: Account {
                owner: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
                subaccount: None,
            },
            memo: Some(Memo::from(MintMemo::Convert {
                from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                log_index: DEFAULT_DEPOSIT_LOG_INDEX.into(),
            })),
            created_at_time: None,
        })
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1);

    let balance_before_withdrawal = cketh.balance_of(caller);
    assert_eq!(balance_before_withdrawal, withdrawal_amount);

    let time_before_withdrawal = cketh.env.get_time().as_nanos_since_unix_epoch();

    let cketh = cketh
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), destination.clone())
        .expect_withdrawal_request_accepted();

    let withdrawal_id = cketh.withdrawal_id().clone();
    let (tx, _sig) = default_signed_eip_1559_transaction();
    let cketh = cketh
        .wait_and_validate_withdrawal(
            ProcessWithdrawalParams::default().with_mock_eth_get_transaction_receipt(move |mock| {
                mock.modify_response_for_all(
                    &mut |receipt: &mut ethers_core::types::TransactionReceipt| {
                        receipt.status = Some(0_u64.into())
                    },
                )
            }),
        )
        .expect_finalized_status(TxFinalizedStatus::PendingReimbursement(EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        }))
        .call_ledger_get_transaction(withdrawal_id.clone())
        .expect_burn(Burn {
            amount: withdrawal_amount.clone(),
            from: Account {
                owner: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
                subaccount: None,
            },
            spender: Some(Account {
                owner: minter,
                subaccount: None,
            }),
            memo: Some(Memo::from(BurnMemo::Convert {
                to_address: destination.parse().unwrap(),
            })),
            created_at_time: None,
        });

    assert_eq!(cketh.balance_of(caller), Nat::from(0));

    cketh.env.advance_time(PROCESS_REIMBURSEMENT);
    cketh.env.tick();

    let cost_of_failed_transaction = withdrawal_amount
        .0
        .to_u128()
        .unwrap()
        .checked_sub(tx.value.unwrap().as_u128())
        .unwrap();
    assert_eq!(cost_of_failed_transaction, 693_077_873_418_000);

    let balance_after_withdrawal = cketh.balance_of(caller);
    assert_eq!(
        balance_after_withdrawal,
        balance_before_withdrawal.clone() - cost_of_failed_transaction
    );

    let reimbursed_amount = Nat::from(tx.value.unwrap().as_u128());
    let reimbursed_in_block = withdrawal_id.clone() + Nat::from(1);
    let failed_tx_hash =
        "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string();
    assert_eq!(
        cketh.retrieve_eth_status(&withdrawal_id),
        RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Reimbursed {
            reimbursed_amount: reimbursed_amount.clone(),
            reimbursed_in_block: reimbursed_in_block.clone(),
            transaction_hash: failed_tx_hash.clone()
        })
    );

    let max_fee_per_gas = Nat::from(33003708258u64);
    let gas_limit = Nat::from(21_000);

    cketh
        .call_ledger_get_transaction(reimbursed_in_block)
        .expect_mint(Mint {
            amount: reimbursed_amount.clone(),
            to: Account {
                owner: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
                subaccount: None,
            },
            memo: Some(Memo::from(MintMemo::Reimburse {
                withdrawal_id: withdrawal_id.0.to_u64().unwrap(),
                tx_hash:  failed_tx_hash.parse().unwrap(),
            })),
            created_at_time: None,
        })
        .assert_has_unique_events_in_order(&vec![
        EventPayload::AcceptedEthWithdrawalRequest {
            withdrawal_amount: withdrawal_amount.clone(),
            destination: destination.clone(),
            ledger_burn_index: withdrawal_id.clone(),
            from: caller,
            from_subaccount: None,
            created_at: Some(time_before_withdrawal),
        },
        EventPayload::CreatedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            transaction: UnsignedTransaction {
                chain_id: Nat::from(1),
                nonce: Nat::from(0),
                max_priority_fee_per_gas: Nat::from(1_500_000_000),
                max_fee_per_gas: max_fee_per_gas.clone(),
                gas_limit: gas_limit.clone(),
                destination,
                value: withdrawal_amount - max_fee_per_gas * gas_limit,
                data: Default::default(),
                access_list: vec![],
            },
        },
        EventPayload::SignedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            raw_transaction: "0x02f87301808459682f008507af2c9f6282520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c0880160cf1e9917a0e680c001a0b27af25a08e87836a778ac2858fdfcff1f6f3a0d43313782c81d05ca34b80271a078026b399a32d3d7abab625388a3c57f651c66a182eb7f8b1a58d9aef7547256".to_string(),
        },
        EventPayload::FinalizedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            transaction_receipt: TransactionReceipt {
                block_hash: DEFAULT_BLOCK_HASH.to_string(),
                block_number: Nat::from(DEFAULT_BLOCK_NUMBER),
                effective_gas_price: Nat::from(4277923390u64),
                gas_used: Nat::from(21_000),
                status: TransactionStatus::Failure,
                transaction_hash:
                "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string(),
            }},
        EventPayload::ReimbursedEthWithdrawal {
            transaction_hash: Some("0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string()),
            reimbursed_amount,
            withdrawal_id: withdrawal_id.clone(),
            reimbursed_in_block: withdrawal_id + 1,
        },
    ]);
}

#[test]
fn should_resubmit_transaction_as_is_when_price_still_actual() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);
    let (expected_tx, expected_sig) = default_signed_eip_1559_transaction();
    let expected_sent_tx = encode_transaction(expected_tx, expected_sig);

    let cketh = cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(
            caller,
            withdrawal_amount,
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
        .expect_withdrawal_request_accepted()
        .start_processing_withdrawals()
        .retrieve_fee_history(identity)
        .expect_status(RetrieveEthStatus::Pending)
        .retrieve_latest_transaction_count(identity)
        .expect_status(RetrieveEthStatus::TxCreated)
        .send_raw_transaction_expecting(&expected_sent_tx)
        .expect_status_sent()
        .retrieve_finalized_transaction_count(|mock| {
            mock.modify_response_for_all(&mut |count: &mut String| {
                *count = transaction_count_response(0)
            })
        })
        .expect_pending_transaction()
        .retry_processing_withdrawals()
        .retrieve_fee_history(identity)
        .expect_status(RetrieveEthStatus::TxSent(EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        }))
        .retrieve_latest_transaction_count(|mock| {
            mock.modify_response_for_all(&mut |count: &mut String| {
                *count = transaction_count_response(0)
            })
        })
        .expect_status(RetrieveEthStatus::TxSent(EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        }))
        .send_raw_transaction_expecting(&expected_sent_tx)
        .expect_status_sent()
        .retrieve_finalized_transaction_count(|mock| {
            mock.modify_response_for_all(&mut |count: &mut String| {
                *count = transaction_count_response(1)
            })
        })
        .expect_finalized_transaction()
        .retrieve_transaction_receipt(identity)
        .expect_finalized_status(TxFinalizedStatus::Success(EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        }));

    cketh.assert_has_no_event_satisfying(|event| {
        matches!(event, EventPayload::ReplacedTransaction { .. })
    });
}

#[test]
fn should_resubmit_new_transaction_when_price_increased() {
    let cketh = CkEthSetup::new();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(EXPECTED_BALANCE - CKETH_TRANSFER_FEE);
    let (expected_tx, expected_sig) = default_signed_eip_1559_transaction();
    let first_tx_hash = hash_transaction(expected_tx.clone(), expected_sig);
    let expected_sent_tx = encode_transaction(expected_tx.clone(), expected_sig);
    let resubmitted_sent_tx = "0x02f87301808462590080850873e448ec82520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c088016090159f0c209680c080a0b43ed9d22ba0731a5cb30ca6e8e171982ab0edc5040dfe0aeee2c77e1b89bd9ea01dfb601f4125243a81ce4d2bfe10c60d519f92a3a4eff8b6dc3da69e19382238";
    let (resubmitted_tx, resubmitted_tx_sig) = decode_transaction(resubmitted_sent_tx);
    let resubmitted_tx_hash = hash_transaction(resubmitted_tx.clone(), resubmitted_tx_sig);
    assert_eq!(
        resubmitted_tx,
        expected_tx
            .clone()
            .value(99_237_614_339_235_990_u64)
            .max_priority_fee_per_gas(1_650_000_000_u64)
            .max_fee_per_gas(36_304_079_084_u64)
    );
    assert_ne!(first_tx_hash, resubmitted_tx_hash);

    let cketh = cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(
            caller,
            withdrawal_amount,
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
        .expect_withdrawal_request_accepted();

    let withdrawal_id = cketh.withdrawal_id().clone();

    let cketh = cketh
        .start_processing_withdrawals()
        .retrieve_fee_history(identity)
        .expect_status(RetrieveEthStatus::Pending)
        .retrieve_latest_transaction_count(identity)
        .expect_status(RetrieveEthStatus::TxCreated)
        .send_raw_transaction_expecting(&expected_sent_tx)
        .expect_status_sent()
        .retrieve_finalized_transaction_count(|mock| {
            mock.modify_response_for_all(&mut |count: &mut String| {
                *count = transaction_count_response(0)
            })
        })
        .expect_pending_transaction()
        .retry_processing_withdrawals()
        .retrieve_fee_history(|mock| {
            mock.modify_response_for_all(&mut |fee_history| increment_base_fee_per_gas(fee_history))
        })
        .expect_status(RetrieveEthStatus::TxSent(EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        }))
        .retrieve_latest_transaction_count(|mock| {
            mock.modify_response_for_all(&mut |count: &mut String| {
                *count = transaction_count_response(0)
            })
        })
        .expect_status(RetrieveEthStatus::TxCreated)
        .send_raw_transaction_expecting(&encode_transaction(resubmitted_tx, resubmitted_tx_sig))
        .expect_status_sent()
        .retrieve_finalized_transaction_count(|mock| {
            mock.modify_response_for_all(&mut |count: &mut String| {
                *count = transaction_count_response(1)
            })
        })
        .expect_finalized_transaction()
        .retrieve_transaction_receipt(|mock| {
            mock.with_request_params(json!([first_tx_hash]))
                .respond_for_all_with(serde_json::Value::Null)
        })
        .retrieve_transaction_receipt(|mock| {
            mock.with_request_params(json!([resubmitted_tx_hash]))
                .respond_for_all_with(transaction_receipt(format!("{:?}", resubmitted_tx_hash)))
        })
        .expect_finalized_status(TxFinalizedStatus::Success(EthTransaction {
            transaction_hash: format!("{:?}", resubmitted_tx_hash),
        }));

    cketh.assert_has_unique_events_in_order(&vec![
        EventPayload::ReplacedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            transaction: UnsignedTransaction {
                chain_id: Nat::from(1),
                nonce: Nat::from(0),
                max_priority_fee_per_gas: Nat::from(1_650_000_000_u64),
                max_fee_per_gas: Nat::from(36_304_079_084_u64),
                gas_limit: Nat::from(21_000),
                destination: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
                value: Nat::from(99_237_614_339_235_990_u64),
                data: Default::default(),
                access_list: vec![],
            },
        },
        EventPayload::SignedTransaction {
            withdrawal_id: withdrawal_id.clone(),
            raw_transaction: resubmitted_sent_tx.to_string(),
        },
        EventPayload::FinalizedTransaction {
            withdrawal_id,
            transaction_receipt: TransactionReceipt {
                block_hash: DEFAULT_BLOCK_HASH.to_string(),
                block_number: Nat::from(DEFAULT_BLOCK_NUMBER),
                effective_gas_price: Nat::from(4277923390u64),
                gas_used: Nat::from(21_000),
                status: TransactionStatus::Success,
                transaction_hash: format!("{:?}", resubmitted_tx_hash),
            },
        },
    ]);
}

#[test]
fn should_not_overlap_when_scrapping_logs() {
    let cketh = CkEthSetup::new();

    cketh.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER))
        .build()
        .expect_rpc_calls(&cketh);

    let first_from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let first_to_block = first_from_block
        .checked_add(BlockNumber::from(MAX_ETH_LOGS_BLOCK_RANGE))
        .unwrap();
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": first_from_block,
            "toBlock": first_to_block,
            "address": [HELPER_SMART_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);

    let second_from_block = first_to_block
        .checked_add(BlockNumber::from(1_u64))
        .unwrap();
    let second_to_block = second_from_block
        .checked_add(BlockNumber::from(MAX_ETH_LOGS_BLOCK_RANGE))
        .unwrap();
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": second_from_block,
            "toBlock": second_to_block,
            "address": [HELPER_SMART_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);

    cketh
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: second_to_block.into(),
        }]);
}

#[test]
fn should_retry_from_same_block_when_scrapping_fails() {
    let cketh = CkEthSetup::new();

    cketh.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER))
        .build()
        .expect_rpc_calls(&cketh);
    let from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let to_block = from_block
        .checked_add(BlockNumber::from(MAX_ETH_LOGS_BLOCK_RANGE))
        .unwrap();
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": [HELPER_SMART_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .respond_with(JsonRpcProvider::PublicNode, json!({"error":{"code":-32000,"message":"max message response size exceed"},"id":74,"jsonrpc":"2.0"}))
        .build()
        .expect_rpc_calls(&cketh);

    let cketh = cketh
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into(),
        }]);

    cketh.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER))
        .build()
        .expect_rpc_calls(&cketh);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": [HELPER_SMART_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);

    cketh
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: Nat::from(to_block),
        }]);
}

#[test]
fn should_scrap_one_block_when_at_boundary_with_last_finalized_block() {
    let cketh = CkEthSetup::new();

    cketh.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1))
        .build()
        .expect_rpc_calls(&cketh);
    let from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": from_block,
            "toBlock": from_block,
            "address": [HELPER_SMART_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);
}

#[test]
fn should_panic_when_last_finalized_block_in_the_past() {
    let cketh = CkEthSetup::new();

    cketh.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL - 1))
        .build()
        .expect_rpc_calls(&cketh);

    let cketh = cketh
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into(),
        }]);

    let last_finalized_block = LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 10;
    cketh.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(last_finalized_block))
        .build()
        .expect_rpc_calls(&cketh);

    let first_from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let first_to_block = BlockNumber::from(last_finalized_block);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": first_from_block,
            "toBlock": first_to_block,
            "address": [HELPER_SMART_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);

    cketh
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: last_finalized_block.into(),
        }]);
}

#[test]
fn should_skip_scrapping_when_last_seen_block_newer_than_current_height() {
    let safe_block_number = LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 100;
    let finalized_block_number = safe_block_number - 32;
    let cketh = CkEthSetup::new().check_audit_logs_and_upgrade(UpgradeArg {
        ethereum_block_height: Some(CandidBlockTag::Safe),
        ..Default::default()
    });
    cketh.env.tick();

    let cketh = cketh
        .deposit(
            DepositParams::default()
                .with_mock_eth_get_block_by_number(move |mock| {
                    mock.with_request_params(json!(["safe", false]))
                        .respond_for_all_with(block_response(safe_block_number))
                })
                .with_mock_eth_get_logs(move |mock| {
                    mock.with_request_params(json!([{
                        "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                        "toBlock": BlockNumber::from(safe_block_number),
                        "address": [HELPER_SMART_CONTRACT_ADDRESS],
                        "topics": [RECEIVED_ETH_EVENT_TOPIC]
                    }]))
                }),
        )
        .expect_mint();

    let cketh = cketh
        .check_audit_logs_and_upgrade(UpgradeArg {
            ethereum_block_height: Some(CandidBlockTag::Finalized),
            ..Default::default()
        })
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: safe_block_number.into(),
        }]);
    cketh.env.tick();

    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .with_request_params(json!(["finalized", false]))
        .respond_for_all_with(block_response(finalized_block_number))
        .build()
        .expect_rpc_calls(&cketh);

    cketh
        .assert_has_no_rpc_call(&JsonRpcMethod::EthGetLogs)
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_no_event_satisfying(|event| {
            matches!(event, EventPayload::SyncedToBlock { block_number }
                if block_number != &Nat::from(safe_block_number) && block_number != &Nat::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL))
        });
}

#[test]
fn should_half_range_of_scrapped_logs_when_response_over_two_mega_bytes() {
    let cketh = CkEthSetup::new();
    let deposit = DepositParams::default().eth_log_entry();
    // around 600 bytes per log
    // we need at least 3334 logs to reach the 2MB limit
    let large_amount_of_logs = multi_logs_for_single_transaction(deposit.clone(), 3_500);
    assert!(serde_json::to_vec(&large_amount_of_logs).unwrap().len() > 2_000_000);

    let from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let to_block = from_block
        .checked_add(BlockNumber::from(MAX_ETH_LOGS_BLOCK_RANGE))
        .unwrap();
    let half_to_block = from_block
        .checked_add(BlockNumber::from(MAX_ETH_LOGS_BLOCK_RANGE / 2))
        .unwrap();

    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER))
        .build()
        .expect_rpc_calls(&cketh);

    for max_response_bytes in all_eth_get_logs_response_size_estimates() {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": [HELPER_SMART_CONTRACT_ADDRESS],
                "topics": [RECEIVED_ETH_EVENT_TOPIC]
            }]))
            .with_max_response_bytes(max_response_bytes)
            .respond_for_all_with(large_amount_of_logs.clone())
            .build()
            .expect_rpc_calls(&cketh);
    }

    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": from_block,
            "toBlock": half_to_block,
            "address": [HELPER_SMART_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .with_max_response_bytes(all_eth_get_logs_response_size_estimates()[0])
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);

    cketh
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: half_to_block.into(),
        }])
        .assert_has_no_event_satisfying(|event| matches!(event, EventPayload::SkippedBlock { .. }));
}

#[test]
fn should_skip_single_block_containing_too_many_events() {
    let cketh = CkEthSetup::new();
    let deposit = DepositParams::default().eth_log_entry();
    // around 600 bytes per log
    // we need at least 3334 logs to reach the 2MB limit
    let large_amount_of_logs = multi_logs_for_single_transaction(deposit.clone(), 3_500);
    assert!(serde_json::to_vec(&large_amount_of_logs).unwrap().len() > 2_000_000);

    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 3))
        .build()
        .expect_rpc_calls(&cketh);

    for max_response_bytes in all_eth_get_logs_response_size_estimates() {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "toBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 3),
                "address": [HELPER_SMART_CONTRACT_ADDRESS],
                "topics": [RECEIVED_ETH_EVENT_TOPIC]
            }]))
            .with_max_response_bytes(max_response_bytes)
            .respond_for_all_with(large_amount_of_logs.clone())
            .build()
            .expect_rpc_calls(&cketh);
    }

    for max_response_bytes in all_eth_get_logs_response_size_estimates() {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "toBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 2),
                "address": [HELPER_SMART_CONTRACT_ADDRESS],
                "topics": [RECEIVED_ETH_EVENT_TOPIC]
            }]))
            .with_max_response_bytes(max_response_bytes)
            .respond_for_all_with(large_amount_of_logs.clone())
            .build()
            .expect_rpc_calls(&cketh);
    }

    for max_response_bytes in all_eth_get_logs_response_size_estimates() {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "toBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "address": [HELPER_SMART_CONTRACT_ADDRESS],
                "topics": [RECEIVED_ETH_EVENT_TOPIC]
            }]))
            .with_max_response_bytes(max_response_bytes)
            .respond_for_all_with(large_amount_of_logs.clone())
            .build()
            .expect_rpc_calls(&cketh);
    }

    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 2),
            "toBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 3),
            "address": [HELPER_SMART_CONTRACT_ADDRESS],
            "topics": [RECEIVED_ETH_EVENT_TOPIC]
        }]))
        .with_max_response_bytes(all_eth_get_logs_response_size_estimates()[0])
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);

    cketh
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_unique_events_in_order(&vec![
            EventPayload::SkippedBlock {
                block_number: (LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1).into(),
            },
            EventPayload::SyncedToBlock {
                block_number: (LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 3).into(),
            },
        ]);
}

fn assert_contains_unique_event(events: &[Event], payload: EventPayload) {
    match events.iter().filter(|e| e.payload == payload).count() {
        0 => panic!("missing the event payload {payload:#?} in audit log {events:#?}"),
        1 => (),
        n => panic!("event payload {payload:#?} appears {n} times in audit log {events:#?}"),
    }
}

fn assert_reply(result: WasmResult) -> Vec<u8> {
    match result {
        WasmResult::Reply(bytes) => bytes,
        WasmResult::Reject(reject) => {
            panic!("Expected a successful reply, got a reject: {}", reject)
        }
    }
}

fn ledger_wasm() -> Vec<u8> {
    let path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rosetta-api")
        .join("icrc1")
        .join("ledger");
    load_wasm(path, "ic-icrc1-ledger", &[])
}

fn minter_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "cketh_minter",
        &[],
    )
}

fn install_minter(env: &StateMachine, ledger_id: CanisterId, minter_id: CanisterId) -> CanisterId {
    let args = MinterInitArgs {
        ecdsa_key_name: "master_ecdsa_public_key".parse().unwrap(),
        ethereum_network: EthereumNetwork::MAINNET,
        ledger_id: ledger_id.get().0,
        next_transaction_nonce: 0.into(),
        ethereum_block_height: CandidBlockTag::Finalized,
        ethereum_contract_address: Some(HELPER_SMART_CONTRACT_ADDRESS.to_string()),
        minimum_withdrawal_amount: CKETH_TRANSFER_FEE.into(),
        last_scraped_block_number: LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into(),
    };
    let minter_arg = MinterArg::InitArg(args);
    env.install_existing_canister(minter_id, minter_wasm(), Encode!(&minter_arg).unwrap())
        .unwrap();
    minter_id
}

fn default_deposit_from_address() -> Address {
    DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap()
}

#[derive(Clone)]
pub struct EthLogEntry {
    pub encoded_principal: String,
    pub amount: u64,
    pub from_address: Address,
    pub transaction_hash: String,
}

impl From<EthLogEntry> for ethers_core::types::Log {
    fn from(log_entry: EthLogEntry) -> Self {
        let amount_hex = format!("0x{:0>64x}", log_entry.amount);
        let json_value = json!({
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": "0x79cfe76d69337dae199e32c2b6b3d7c2668bfe71a05f303f95385e70031b9ef8",
            "blockNumber": format!("0x{:x}", DEFAULT_DEPOSIT_BLOCK_NUMBER),
            "data": amount_hex,
            "logIndex": format!("0x{:x}", DEFAULT_DEPOSIT_LOG_INDEX),
            "removed": false,
            "topics": [
                RECEIVED_ETH_EVENT_TOPIC,
                format!("0x000000000000000000000000{}", hex::encode(log_entry.from_address.as_ref())),
                log_entry.encoded_principal
            ],
            "transactionHash": log_entry.transaction_hash,
            "transactionIndex": "0x33"
        });
        serde_json::from_value(json_value).expect("BUG: invalid log entry")
    }
}

fn empty_logs() -> Vec<ethers_core::types::Log> {
    vec![]
}

fn multi_logs_for_single_transaction(
    log_entry: EthLogEntry,
    num_logs: usize,
) -> Vec<ethers_core::types::Log> {
    let mut logs = Vec::with_capacity(num_logs);
    for log_index in 0..num_logs {
        let mut log = ethers_core::types::Log::from(log_entry.clone());
        log.log_index = Some(log_index.into());
        logs.push(log);
    }
    logs
}

fn all_eth_get_logs_response_size_estimates() -> Vec<u64> {
    vec![
        100 + HEADER_SIZE_LIMIT,
        2048 + HEADER_SIZE_LIMIT,
        4096 + HEADER_SIZE_LIMIT,
        8192 + HEADER_SIZE_LIMIT,
        16_384 + HEADER_SIZE_LIMIT,
        32_768 + HEADER_SIZE_LIMIT,
        65_536 + HEADER_SIZE_LIMIT,
        131_072 + HEADER_SIZE_LIMIT,
        262_144 + HEADER_SIZE_LIMIT,
        524_288 + HEADER_SIZE_LIMIT,
        1_048_576 + HEADER_SIZE_LIMIT,
        2_000_000,
    ]
}

fn fee_history() -> ethers_core::types::FeeHistory {
    let json_value = json!({
        "oldestBlock": "0x1134b57",
        "reward": [
            ["0x25ed41c"],
            ["0x0"],
            ["0x0"],
            ["0x479ace"],
            ["0x0"]
        ],
        "baseFeePerGas": [
            "0x39fc781e8",
            "0x3ab9a6343",
            "0x3a07c507e",
            "0x39814c872",
            "0x391ea51f7",
            "0x3aae23831"
        ],
        "gasUsedRatio": [
            0,
            0.22033613333333332,
            0.8598215666666666,
            0.5756615333333334,
            0.3254294
        ]
    });
    serde_json::from_value(json_value).expect("BUG: invalid fee history")
}

fn increment_base_fee_per_gas(fee_history: &mut ethers_core::types::FeeHistory) {
    for base_fee_per_gas in fee_history.base_fee_per_gas.iter_mut() {
        *base_fee_per_gas = base_fee_per_gas.checked_add(1_u64.into()).unwrap();
    }
}

fn send_raw_transaction_response() -> ethers_core::types::TxHash {
    ethers_core::types::TxHash::decode_hex(
        "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d",
    )
    .unwrap()
}

fn block_response(block_number: u64) -> ethers_core::types::Block<ethers_core::types::TxHash> {
    ethers_core::types::Block::<ethers_core::types::TxHash> {
        number: Some(block_number.into()),
        base_fee_per_gas: Some(0x3e4f64de7_u64.into()),
        ..Default::default()
    }
}

fn transaction_receipt(transaction_hash: String) -> ethers_core::types::TransactionReceipt {
    let json_value = json!({
        "blockHash": DEFAULT_BLOCK_HASH,
        "blockNumber": format!("{:#x}", DEFAULT_BLOCK_NUMBER),
        "contractAddress": null,
        "cumulativeGasUsed": "0x8b2e10",
        "effectiveGasPrice": format!("{:#x}", EFFECTIVE_GAS_PRICE),
        "from": "0x1789f79e95324a47c5fd6693071188e82e9a3558",
        "gasUsed": "0x5208",
        "logs": [],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status": format!("{:#x}", 1_u8),
        "to": "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0",
        "transactionHash": transaction_hash,
        "transactionIndex": "0x32",
        "type": "0x2"
    });
    serde_json::from_value(json_value).expect("BUG: invalid transaction receipt")
}

fn transaction_count_response(count: u32) -> String {
    format!("{:#x}", count)
}

fn encode_principal(principal: Principal) -> String {
    let n = principal.as_slice().len();
    assert!(n <= 29);
    let mut fixed_bytes = [0u8; 32];
    fixed_bytes[0] = n as u8;
    fixed_bytes[1..=n].copy_from_slice(principal.as_slice());
    format!("0x{}", hex::encode(fixed_bytes))
}

fn minter_address() -> [u8; 20] {
    ethers_core::types::Bytes::from_str(MINTER_ADDRESS)
        .unwrap()
        .to_vec()
        .try_into()
        .unwrap()
}

fn default_signed_eip_1559_transaction() -> (
    ethers_core::types::Eip1559TransactionRequest,
    ethers_core::types::Signature,
) {
    let tx = ethers_core::types::Eip1559TransactionRequest::new()
        .from(minter_address())
        .to(DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS
            .parse::<ethers_core::types::NameOrAddress>()
            .unwrap())
        .nonce(0_u64)
        .value(99_306_922_126_581_990_u64)
        .gas(21_000_u64)
        .max_priority_fee_per_gas(1_500_000_000_u64)
        .max_fee_per_gas(33_003_708_258_u64)
        .chain_id(1_u64);
    let sig = ethers_core::types::Signature {
        r: ethers_core::types::U256::from_dec_str(
            "80728915039673634151963281987194499535727562641034879173530654129915839382129",
        )
        .unwrap(),
        s: ethers_core::types::U256::from_dec_str(
            "54281815563936592133007646348951747532427232100340298742740287107883437683286",
        )
        .unwrap(),
        v: 1,
    };
    (tx, sig)
}

fn encode_transaction(
    tx: ethers_core::types::Eip1559TransactionRequest,
    sig: ethers_core::types::Signature,
) -> String {
    ethers_core::types::transaction::eip2718::TypedTransaction::Eip1559(tx)
        .rlp_signed(&sig)
        .to_string()
}

fn decode_transaction(
    tx: &str,
) -> (
    ethers_core::types::Eip1559TransactionRequest,
    ethers_core::types::Signature,
) {
    use ethers_core::types::transaction::eip2718::TypedTransaction;

    TypedTransaction::decode_signed(&rlp::Rlp::new(
        &ethers_core::types::Bytes::from_str(tx).unwrap(),
    ))
    .map(|(tx, sig)| match tx {
        TypedTransaction::Eip1559(eip1559_tx) => (eip1559_tx, sig),
        _ => panic!("BUG: unexpected sent ETH transaction type {:?}", tx),
    })
    .expect("BUG: failed to deserialize sent ETH transaction")
}

fn hash_transaction(
    tx: ethers_core::types::Eip1559TransactionRequest,
    sig: ethers_core::types::Signature,
) -> ethers_core::types::TxHash {
    ethers_core::types::transaction::eip2718::TypedTransaction::Eip1559(tx).hash(&sig)
}

pub struct CkEthSetup {
    pub env: StateMachine,
    pub caller: PrincipalId,
    pub ledger_id: CanisterId,
    pub minter_id: CanisterId,
}

impl Default for CkEthSetup {
    fn default() -> Self {
        Self::new()
    }
}

impl CkEthSetup {
    pub fn new() -> Self {
        let env = StateMachineBuilder::new()
            .with_default_canister_range()
            .build();
        let minter_id =
            env.create_canister_with_cycles(None, Cycles::new(100_000_000_000_000), None);
        let ledger_id = env.create_canister(None);

        env.install_existing_canister(
            ledger_id,
            ledger_wasm(),
            Encode!(&LedgerArgument::Init(
                LedgerInitArgsBuilder::with_symbol_and_name("ckETH", "ckETH")
                    .with_minting_account(minter_id.get().0)
                    .with_transfer_fee(CKETH_TRANSFER_FEE)
                    .with_max_memo_length(80)
                    .with_decimals(18)
                    .with_feature_flags(ic_icrc1_ledger::FeatureFlags { icrc2: true })
                    .build(),
            ))
            .unwrap(),
        )
        .unwrap();
        let minter_id = install_minter(&env, ledger_id, minter_id);
        let caller = PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID);

        let cketh = Self {
            env,
            caller,
            ledger_id,
            minter_id,
        };

        assert_eq!(
            Address::from_str(MINTER_ADDRESS).unwrap(),
            Address::from_str(&cketh.minter_address()).unwrap()
        );
        cketh
    }

    pub fn deposit(self, params: DepositParams) -> DepositFlow {
        DepositFlow {
            setup: self,
            params,
        }
    }

    pub fn minter_address(&self) -> String {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "minter_address",
                        Encode!().unwrap(),
                    )
                    .expect("failed to get eth address")
            ),
            String
        )
        .unwrap()
    }

    pub fn retrieve_eth_status(&self, block_index: &Nat) -> RetrieveEthStatus {
        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress_as(
                        self.caller,
                        self.minter_id,
                        "retrieve_eth_status",
                        Encode!(&block_index.0.to_u64().unwrap()).unwrap(),
                    )
                    .expect("failed to get eth address")
            ),
            RetrieveEthStatus
        )
        .unwrap()
    }

    pub fn balance_of(&self, account: impl Into<Account>) -> Nat {
        Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.ledger_id,
                        "icrc1_balance_of",
                        Encode!(&account.into()).unwrap()
                    )
                    .expect("failed to query balance on the ledger")
            ),
            Nat
        )
        .unwrap()
    }

    pub fn call_ledger_approve_minter(
        self,
        from: Principal,
        amount: u64,
        from_subaccount: Option<[u8; 32]>,
    ) -> ApprovalFlow {
        let approval_response = Decode!(&assert_reply(self.env.execute_ingress_as(
            PrincipalId::from(from),
            self.ledger_id,
            "icrc2_approve",
            Encode!(&ApproveArgs {
                from_subaccount,
                spender: Account {
                    owner: self.minter_id.into(),
                    subaccount: None
                },
                amount: Nat::from(amount),
                expected_allowance: None,
                expires_at: None,
                fee: None,
                memo: None,
                created_at_time: None,
            }).unwrap()
            ).expect("failed to execute token transfer")),
            Result<Nat, ApproveError>
        )
        .unwrap();
        ApprovalFlow {
            setup: self,
            approval_response,
        }
    }

    pub fn call_ledger_get_transaction<T: Into<Nat>>(
        self,
        ledger_index: T,
    ) -> LedgerTransactionAssert {
        use icrc_ledger_types::icrc3::transactions::{
            GetTransactionsRequest, GetTransactionsResponse,
        };

        let request = GetTransactionsRequest {
            start: ledger_index.into(),
            length: 1.into(),
        };
        let mut response = Decode!(
            &assert_reply(
                self.env
                    .query(
                        self.ledger_id,
                        "get_transactions",
                        Encode!(&request).unwrap()
                    )
                    .expect("failed to query get_transactions on the ledger")
            ),
            GetTransactionsResponse
        )
        .unwrap();
        assert_eq!(
            response.transactions.len(),
            1,
            "Expected exactly one transaction but got {:?}",
            response.transactions
        );
        LedgerTransactionAssert {
            setup: self,
            ledger_transaction: response.transactions.pop().unwrap(),
        }
    }

    pub fn call_minter_withdraw_eth(
        self,
        from: Principal,
        amount: Nat,
        recipient: String,
    ) -> WithdrawalFlow {
        let arg = WithdrawalArg { amount, recipient };
        let message_id = self.env.send_ingress(
            PrincipalId::from(from),
            self.minter_id,
            "withdraw_eth",
            Encode!(&arg).expect("failed to encode withdraw args"),
        );
        WithdrawalFlow {
            setup: self,
            message_id,
        }
    }

    pub fn _get_logs(&self, priority: &str) -> Log {
        let request = HttpRequest {
            method: "".to_string(),
            url: format!("/logs?priority={priority}"),
            headers: vec![],
            body: serde_bytes::ByteBuf::new(),
        };
        let response = Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "http_request", Encode!(&request).unwrap(),)
                    .expect("failed to get minter info")
            ),
            HttpResponse
        )
        .unwrap();
        serde_json::from_slice(&response.body).expect("failed to parse ckbtc minter log")
    }

    pub fn assert_has_unique_events_in_order(self, expected_events: &[EventPayload]) -> Self {
        let audit_events = self.get_all_events();
        let mut found_event_indexes = BTreeMap::new();
        for (index_expected_event, expected_event) in expected_events.iter().enumerate() {
            for (index_audit_event, audit_event) in audit_events.iter().enumerate() {
                if &audit_event.payload == expected_event {
                    assert_eq!(
                        found_event_indexes.insert(index_expected_event, index_audit_event),
                        None,
                        "Event {:?} occurs multiple times",
                        expected_event
                    );
                }
            }
            assert!(
                found_event_indexes.contains_key(&index_expected_event),
                "Missing event {:?}",
                expected_event
            )
        }
        let audit_event_indexes = found_event_indexes.into_values().collect::<Vec<_>>();
        let sorted_audit_event_indexes = {
            let mut indexes = audit_event_indexes.clone();
            indexes.sort_unstable();
            indexes
        };
        assert_eq!(
            audit_event_indexes, sorted_audit_event_indexes,
            "Events were found in unexpected order"
        );
        self
    }

    pub fn assert_has_no_event_satisfying<P: Fn(&EventPayload) -> bool>(
        self,
        predicate: P,
    ) -> Self {
        if let Some(unexpected_event) = self
            .get_all_events()
            .into_iter()
            .find(|event| predicate(&event.payload))
        {
            panic!(
                "Found an event satisfying the predicate: {:?}",
                unexpected_event
            )
        }
        self
    }

    fn get_events(&self, start: u64, length: u64) -> GetEventsResult {
        use ic_cketh_minter::endpoints::events::GetEventsArg;

        Decode!(
            &assert_reply(
                self.env
                    .execute_ingress(
                        self.minter_id,
                        "get_events",
                        Encode!(&GetEventsArg { start, length }).unwrap(),
                    )
                    .expect("failed to get minter info")
            ),
            GetEventsResult
        )
        .unwrap()
    }

    pub fn get_all_events(&self) -> Vec<Event> {
        const FIRST_BATCH_SIZE: u64 = 100;
        let GetEventsResult {
            mut events,
            total_event_count,
        } = self.get_events(0, FIRST_BATCH_SIZE);
        while events.len() < total_event_count as usize {
            let mut next_batch =
                self.get_events(events.len() as u64, total_event_count - events.len() as u64);
            events.append(&mut next_batch.events);
        }
        events
    }

    fn check_audit_log(&self) {
        Decode!(
            &assert_reply(
                self.env
                    .query(self.minter_id, "check_audit_log", Encode!().unwrap())
                    .unwrap(),
            ),
            ()
        )
        .unwrap()
    }

    fn upgrade_minter(&self, upgrade_arg: UpgradeArg) {
        self.env
            .upgrade_canister(
                self.minter_id,
                minter_wasm(),
                Encode!(&MinterArg::UpgradeArg(upgrade_arg)).unwrap(),
            )
            .unwrap();
    }

    fn check_audit_logs_and_upgrade(self, upgrade_arg: UpgradeArg) -> Self {
        self.check_audit_log();
        self.env.tick(); //tick before upgrade to finish current timers which are reset afterwards
        self.upgrade_minter(upgrade_arg);
        self
    }

    fn assert_has_no_rpc_call(self, method: &JsonRpcMethod) -> Self {
        for _ in 0..MAX_TICKS {
            if let Some(unexpected_request) = self
                .env
                .canister_http_request_contexts()
                .values()
                .map(|context| {
                    crate::mock::JsonRpcRequest::from_str(
                        std::str::from_utf8(&context.body.clone().unwrap()).unwrap(),
                    )
                    .expect("BUG: invalid JSON RPC method")
                })
                .find(|rpc_request| rpc_request.method.to_string() == method.to_string())
            {
                panic!("Unexpected RPC call: {:?}", unexpected_request);
            }
            self.env.tick();
            self.env.advance_time(Duration::from_nanos(1));
        }
        self
    }
}

pub struct DepositParams {
    pub from_address: Address,
    pub recipient: Principal,
    pub amount: u64,
    pub override_rpc_eth_get_block_by_number:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_eth_get_logs:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
}

impl Default for DepositParams {
    fn default() -> Self {
        Self {
            from_address: default_deposit_from_address(),
            recipient: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
            amount: EXPECTED_BALANCE,
            override_rpc_eth_get_block_by_number: Box::new(identity),
            override_rpc_eth_get_logs: Box::new(identity),
        }
    }
}

impl DepositParams {
    fn eth_log(&self) -> ethers_core::types::Log {
        ethers_core::types::Log::from(self.eth_log_entry())
    }

    fn eth_log_entry(&self) -> EthLogEntry {
        EthLogEntry {
            encoded_principal: encode_principal(self.recipient),
            amount: self.amount,
            from_address: self.from_address,
            transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
        }
    }

    pub fn with_mock_eth_get_block_by_number<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_eth_get_block_by_number = Box::new(override_mock);
        self
    }

    pub fn with_mock_eth_get_logs<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_eth_get_logs = Box::new(override_mock);
        self
    }
}

pub struct DepositFlow {
    setup: CkEthSetup,
    params: DepositParams,
}

impl DepositFlow {
    pub fn expect_mint(mut self) -> CkEthSetup {
        let balance_before = self.setup.balance_of(self.params.recipient);
        self.handle_deposit();
        let balance_after: Nat = self.updated_balance(&balance_before);
        assert_eq!(balance_after - balance_before, self.params.amount);

        self.setup.check_audit_log();

        let events = self.setup.get_all_events();
        assert_contains_unique_event(
            &events,
            EventPayload::AcceptedDeposit {
                transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                block_number: Nat::from(DEFAULT_DEPOSIT_BLOCK_NUMBER),
                log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                from_address: self.params.from_address.to_string(),
                value: Nat::from(self.params.amount),
                principal: self.params.recipient,
            },
        );
        assert_contains_unique_event(
            &events,
            EventPayload::MintedCkEth {
                event_source: EventSource {
                    transaction_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
                    log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
                },
                mint_block_index: Nat::from(0),
            },
        );
        self.setup
    }

    fn updated_balance(&self, balance_before: &Nat) -> Nat {
        let mut current_balance = balance_before.clone();
        for _ in 0..10 {
            self.setup.env.advance_time(Duration::from_secs(1));
            self.setup.env.tick();
            current_balance = self.setup.balance_of(self.params.recipient);
            if &current_balance != balance_before {
                break;
            }
        }
        current_balance
    }

    pub fn expect_no_mint(mut self) -> CkEthSetup {
        let balance_before = self.setup.balance_of(self.params.recipient);
        self.handle_deposit();
        let balance_after: Nat = self.updated_balance(&balance_before);
        assert_eq!(balance_before, balance_after);
        self.setup
    }

    fn handle_deposit(&mut self) {
        self.setup.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);

        let default_get_block_by_number =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
                .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER));
        (self.params.override_rpc_eth_get_block_by_number)(default_get_block_by_number)
            .build()
            .expect_rpc_calls(&self.setup);

        self.setup.env.advance_time(SCRAPPING_ETH_LOGS_INTERVAL);

        let default_eth_get_logs = MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .respond_for_all_with(vec![self.params.eth_log()]);
        (self.params.override_rpc_eth_get_logs)(default_eth_get_logs)
            .build()
            .expect_rpc_calls(&self.setup);
    }
}

pub struct LedgerTransactionAssert {
    setup: CkEthSetup,
    ledger_transaction: LedgerTransaction,
}

impl LedgerTransactionAssert {
    pub fn expect_mint(self, expected: Mint) -> CkEthSetup {
        assert_eq!(self.ledger_transaction.kind, "mint");
        assert_eq!(self.ledger_transaction.mint, Some(expected));
        assert_eq!(self.ledger_transaction.burn, None);
        assert_eq!(self.ledger_transaction.transfer, None);
        assert_eq!(self.ledger_transaction.approve, None);
        // we ignore timestamp
        self.setup
    }

    pub fn expect_burn(self, expected: Burn) -> CkEthSetup {
        assert_eq!(self.ledger_transaction.kind, "burn");
        assert_eq!(self.ledger_transaction.mint, None);
        assert_eq!(self.ledger_transaction.burn, Some(expected));
        assert_eq!(self.ledger_transaction.transfer, None);
        assert_eq!(self.ledger_transaction.approve, None);
        // we ignore timestamp
        self.setup
    }
}

pub struct ApprovalFlow {
    setup: CkEthSetup,
    approval_response: Result<Nat, ApproveError>,
}

impl ApprovalFlow {
    pub fn expect_error(self, error: ApproveError) -> CkEthSetup {
        assert_eq!(
            self.approval_response,
            Err(error),
            "BUG: unexpected result during approval"
        );
        self.setup
    }

    pub fn expect_ok(self, ledger_approval_id: u64) -> CkEthSetup {
        assert_eq!(
            self.approval_response,
            Ok(Nat::from(ledger_approval_id)),
            "BUG: unexpected result during approval"
        );
        self.setup
    }
}

pub struct WithdrawalFlow {
    setup: CkEthSetup,
    message_id: MessageId,
}

impl WithdrawalFlow {
    pub fn expect_withdrawal_request_accepted(self) -> ProcessWithdrawal {
        let response = self
            .minter_response()
            .expect("BUG: unexpected error from minter during withdrawal");
        ProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: response,
        }
    }

    pub fn expect_error(self, error: WithdrawalError) -> CkEthSetup {
        assert_eq!(
            self.minter_response(),
            Err(error),
            "BUG: unexpected result during withdrawal"
        );
        self.setup
    }

    fn minter_response(&self) -> Result<RetrieveEthRequest, WithdrawalError> {
        Decode!(&assert_reply(
        self.setup.env
            .await_ingress(self.message_id.clone(), MAX_TICKS)
            .expect("failed to resolve message with id: {message_id}"),
    ), Result<RetrieveEthRequest, WithdrawalError>)
        .unwrap()
    }
}

pub struct ProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
}

pub struct ProcessWithdrawalParams {
    pub override_rpc_eth_fee_history:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_latest_eth_get_transaction_count:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_eth_send_raw_transaction:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_finalized_eth_get_transaction_count:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
    pub override_rpc_eth_get_transaction_receipt:
        Box<dyn FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder>,
}

impl Default for ProcessWithdrawalParams {
    fn default() -> Self {
        Self {
            override_rpc_eth_fee_history: Box::new(identity),
            override_rpc_latest_eth_get_transaction_count: Box::new(identity),
            override_rpc_eth_send_raw_transaction: Box::new(identity),
            override_rpc_finalized_eth_get_transaction_count: Box::new(identity),
            override_rpc_eth_get_transaction_receipt: Box::new(identity),
        }
    }
}

impl ProcessWithdrawalParams {
    pub fn with_mock_eth_get_transaction_receipt<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_eth_get_transaction_receipt = Box::new(override_mock);
        self
    }

    pub fn with_mock_eth_fee_history<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder + 'static,
    >(
        mut self,
        override_mock: F,
    ) -> Self {
        self.override_rpc_eth_fee_history = Box::new(override_mock);
        self
    }
}

impl ProcessWithdrawal {
    pub fn withdrawal_id(&self) -> &Nat {
        &self.withdrawal_request.block_index
    }

    pub fn start_processing_withdrawals(self) -> FeeHistoryProcessWithdrawal {
        assert_eq!(
            self.setup.retrieve_eth_status(self.withdrawal_id()),
            Pending
        );
        self.setup
            .env
            .advance_time(PROCESS_ETH_RETRIEVE_TRANSACTIONS_INTERVAL);
        FeeHistoryProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }

    pub fn retry_processing_withdrawals(self) -> FeeHistoryProcessWithdrawal {
        self.setup
            .env
            .advance_time(PROCESS_ETH_RETRIEVE_TRANSACTIONS_RETRY_INTERVAL);
        FeeHistoryProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }

    pub fn wait_and_validate_withdrawal(
        self,
        params: ProcessWithdrawalParams,
    ) -> TransactionReceiptProcessWithdrawal {
        self.start_processing_withdrawals()
            .retrieve_fee_history(params.override_rpc_eth_fee_history)
            .expect_status(RetrieveEthStatus::Pending)
            .retrieve_latest_transaction_count(params.override_rpc_latest_eth_get_transaction_count)
            .expect_status(RetrieveEthStatus::TxCreated)
            .send_raw_transaction(params.override_rpc_eth_send_raw_transaction)
            .expect_status_sent()
            .retrieve_finalized_transaction_count(
                params.override_rpc_finalized_eth_get_transaction_count,
            )
            .expect_finalized_transaction()
            .retrieve_transaction_receipt(params.override_rpc_eth_get_transaction_receipt)
    }
}

pub struct FeeHistoryProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
}

impl FeeHistoryProcessWithdrawal {
    pub fn retrieve_fee_history<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_fee_history = MockJsonRpcProviders::when(JsonRpcMethod::EthFeeHistory)
            .respond_for_all_with(fee_history());
        (override_mock)(default_eth_fee_history)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    pub fn expect_status(
        self,
        status: RetrieveEthStatus,
    ) -> LatestTransactionCountProcessWithdrawal {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            status,
            "BUG: unexpected status while processing withdrawal"
        );
        LatestTransactionCountProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }
}

pub struct LatestTransactionCountProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
}

impl LatestTransactionCountProcessWithdrawal {
    pub fn retrieve_latest_transaction_count<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_get_latest_transaction_count =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetTransactionCount)
                .respond_for_all_with(transaction_count_response(0))
                .with_request_params(json!([MINTER_ADDRESS, "latest"]));
        (override_mock)(default_eth_get_latest_transaction_count)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    pub fn expect_status(self, status: RetrieveEthStatus) -> SendRawTransactionProcessWithdrawal {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            status,
            "BUG: unexpected status while processing withdrawal"
        );
        SendRawTransactionProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }
}

pub struct SendRawTransactionProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
}

impl SendRawTransactionProcessWithdrawal {
    pub fn send_raw_transaction<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_send_raw_transaction =
            MockJsonRpcProviders::when(JsonRpcMethod::EthSendRawTransaction)
                .respond_with(JsonRpcProvider::Ankr, send_raw_transaction_response());
        (override_mock)(default_eth_send_raw_transaction)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    pub fn send_raw_transaction_expecting(self, expected_sent_tx: &str) -> Self {
        use ethers_core::types::transaction::eip2718::TypedTransaction;

        let (tx, sig) = decode_transaction(expected_sent_tx);
        sig.verify(
            TypedTransaction::Eip1559(tx.clone()).sighash(),
            tx.from.unwrap(),
        )
        .expect("BUG: cannot verify signature of minter's ETH transaction");

        let tx_hash = hash_transaction(tx, sig);
        self.send_raw_transaction(|mock| {
            mock.with_request_params(json!([expected_sent_tx]))
                .respond_with(JsonRpcProvider::Ankr, tx_hash)
        })
    }

    pub fn expect_status_sent(self) -> FinalizedTransactionCountProcessWithdrawal {
        let tx_hash = match self
            .setup
            .retrieve_eth_status(&self.withdrawal_request.block_index)
        {
            RetrieveEthStatus::TxSent(tx) => tx.transaction_hash,
            other => panic!("BUG: unexpected transactions status {:?}", other),
        };
        FinalizedTransactionCountProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
            sent_transaction_hash: tx_hash,
        }
    }
}

pub struct FinalizedTransactionCountProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
    sent_transaction_hash: String,
}

impl FinalizedTransactionCountProcessWithdrawal {
    pub fn retrieve_finalized_transaction_count<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_get_latest_transaction_count =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetTransactionCount)
                .respond_for_all_with(transaction_count_response(1))
                .with_request_params(json!([MINTER_ADDRESS, "finalized"]));
        (override_mock)(default_eth_get_latest_transaction_count)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    pub fn expect_finalized_transaction(self) -> TransactionReceiptProcessWithdrawal {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            RetrieveEthStatus::TxSent(EthTransaction {
                transaction_hash: self.sent_transaction_hash.clone()
            }),
            "BUG: unexpected status while processing withdrawal"
        );
        TransactionReceiptProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
            sent_transaction_hash: self.sent_transaction_hash,
        }
    }

    pub fn expect_pending_transaction(self) -> ProcessWithdrawal {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            RetrieveEthStatus::TxSent(EthTransaction {
                transaction_hash: self.sent_transaction_hash.clone()
            }),
            "BUG: unexpected status while processing withdrawal"
        );
        ProcessWithdrawal {
            setup: self.setup,
            withdrawal_request: self.withdrawal_request,
        }
    }
}

pub struct TransactionReceiptProcessWithdrawal {
    setup: CkEthSetup,
    withdrawal_request: RetrieveEthRequest,
    sent_transaction_hash: String,
}

impl TransactionReceiptProcessWithdrawal {
    pub fn retrieve_transaction_receipt<
        F: FnMut(MockJsonRpcProvidersBuilder) -> MockJsonRpcProvidersBuilder,
    >(
        self,
        mut override_mock: F,
    ) -> Self {
        let default_eth_get_transaction_receipt =
            MockJsonRpcProviders::when(JsonRpcMethod::EthGetTransactionReceipt)
                .respond_for_all_with(transaction_receipt(self.sent_transaction_hash.clone()));
        (override_mock)(default_eth_get_transaction_receipt)
            .build()
            .expect_rpc_calls(&self.setup);
        self
    }

    fn check_audit_logs_and_upgrade(mut self) -> Self {
        self.setup = self.setup.check_audit_logs_and_upgrade(Default::default());
        self
    }

    pub fn expect_status(self, status: RetrieveEthStatus) -> Self {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            status,
            "BUG: unexpected status while processing withdrawal"
        );
        self
    }

    pub fn expect_finalized_status(self, status: TxFinalizedStatus) -> CkEthSetup {
        assert_eq!(
            self.setup
                .retrieve_eth_status(&self.withdrawal_request.block_index),
            RetrieveEthStatus::TxFinalized(status),
            "BUG: unexpected finalized status while processing withdrawal"
        );
        self.check_audit_logs_and_upgrade().setup
    }
}

mod mock {
    use crate::{assert_reply, CkEthSetup, MAX_TICKS};
    use candid::{Decode, Encode};
    use ic_base_types::CanisterId;
    use ic_cdk::api::management_canister::http_request::{
        HttpResponse as OutCallHttpResponse, TransformArgs,
    };
    use ic_state_machine_tests::{
        CanisterHttpMethod, CanisterHttpRequestContext, CanisterHttpResponsePayload,
        PayloadBuilder, RejectCode, StateMachine,
    };
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::str::FromStr;
    use std::time::Duration;
    use strum::IntoEnumIterator;

    trait Matcher {
        fn matches(&self, context: &CanisterHttpRequestContext) -> bool;
    }
    pub struct MockJsonRpcProviders {
        stubs: Vec<StubOnce>,
    }

    //variants are prefixed by Eth because it's the names of those methods in the Ethereum JSON-RPC API
    #[allow(clippy::enum_variant_names)]
    #[derive(Debug, PartialEq, strum_macros::EnumString, Clone, strum_macros::Display)]
    pub enum JsonRpcMethod {
        #[strum(serialize = "eth_getBlockByNumber")]
        EthGetBlockByNumber,

        #[strum(serialize = "eth_getLogs")]
        EthGetLogs,

        #[strum(serialize = "eth_getTransactionCount")]
        EthGetTransactionCount,

        #[strum(serialize = "eth_getTransactionReceipt")]
        EthGetTransactionReceipt,

        #[strum(serialize = "eth_feeHistory")]
        EthFeeHistory,

        #[strum(serialize = "eth_sendRawTransaction")]
        EthSendRawTransaction,
    }

    #[derive(Copy, Debug, PartialEq, Eq, Clone, PartialOrd, Ord, strum_macros::EnumIter)]
    pub enum JsonRpcProvider {
        //order is top-to-bottom and must match order used in production
        Ankr,
        PublicNode,
        Cloudflare,
    }

    impl JsonRpcProvider {
        fn url(&self) -> &str {
            match self {
                JsonRpcProvider::Ankr => "https://rpc.ankr.com/eth",
                JsonRpcProvider::PublicNode => "https://ethereum.publicnode.com",
                JsonRpcProvider::Cloudflare => "https://cloudflare-eth.com",
            }
        }
    }

    #[derive(Debug)]
    pub struct JsonRpcRequest {
        pub method: JsonRpcMethod,
        id: u64,
        params: serde_json::Value,
    }

    impl FromStr for JsonRpcRequest {
        type Err = String;

        fn from_str(request_body: &str) -> Result<Self, Self::Err> {
            let mut json_request: serde_json::Value = serde_json::from_str(request_body).unwrap();
            let method = json_request
                .get("method")
                .and_then(|method| method.as_str())
                .and_then(|method| JsonRpcMethod::from_str(method).ok())
                .ok_or("BUG: missing JSON RPC method")?;
            let id = json_request
                .get("id")
                .and_then(|id| id.as_u64())
                .ok_or("BUG: missing request ID")?;
            let params = json_request
                .get_mut("params")
                .ok_or("BUG: missing request parameters")?
                .take();
            Ok(Self { method, id, params })
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    pub struct JsonRpcRequestMatcher {
        http_method: CanisterHttpMethod,
        provider: JsonRpcProvider,
        json_rpc_method: JsonRpcMethod,
        match_request_params: Option<serde_json::Value>,
        max_response_bytes: Option<u64>,
    }

    impl JsonRpcRequestMatcher {
        pub fn new(provider: JsonRpcProvider, method: JsonRpcMethod) -> Self {
            Self {
                http_method: CanisterHttpMethod::POST,
                provider,
                json_rpc_method: method,
                match_request_params: None,
                max_response_bytes: None,
            }
        }

        pub fn with_request_params(mut self, params: Option<serde_json::Value>) -> Self {
            self.match_request_params = params;
            self
        }

        pub fn with_max_response_bytes(mut self, max_response_bytes: Option<u64>) -> Self {
            self.max_response_bytes = max_response_bytes;
            self
        }
    }

    impl Matcher for JsonRpcRequestMatcher {
        fn matches(&self, context: &CanisterHttpRequestContext) -> bool {
            let has_json_content_type_header = context
                .headers
                .iter()
                .any(|header| header.name == "Content-Type" && header.value == "application/json");
            let has_expected_max_response_bytes =
                match (self.max_response_bytes, context.max_response_bytes) {
                    (Some(expected), Some(actual)) => expected == actual.get(),
                    (Some(_), None) => false,
                    (None, _) => true,
                };
            let request_body = context
                .body
                .as_ref()
                .map(|body| std::str::from_utf8(body).unwrap())
                .expect("BUG: missing request body");
            let json_rpc_request =
                JsonRpcRequest::from_str(request_body).expect("BUG: invalid JSON RPC request");

            self.http_method == context.http_method
                && self.provider.url() == context.url
                && has_expected_max_response_bytes
                && has_json_content_type_header
                && self.json_rpc_method == json_rpc_request.method
                && self
                    .match_request_params
                    .as_ref()
                    .map(|expected_params| expected_params == &json_rpc_request.params)
                    .unwrap_or(true)
        }
    }

    #[derive(Debug, PartialEq, Clone)]
    struct StubOnce {
        matcher: JsonRpcRequestMatcher,
        response_result: serde_json::Value,
    }

    impl StubOnce {
        fn expect_rpc_call(self, env: &StateMachine, canister_id_cleanup_response: CanisterId) {
            self.tick_until_next_http_request(env);
            let (id, context) = env
                .canister_http_request_contexts()
                .into_iter()
                .find(|(_id, context)| self.matcher.matches(context))
                .unwrap_or_else(|| panic!("no request found matching the stub {:?}", self));
            let request_id = {
                let request_body = context
                    .body
                    .as_ref()
                    .map(|body| std::str::from_utf8(body).unwrap())
                    .expect("BUG: missing request body");
                JsonRpcRequest::from_str(request_body)
                    .expect("BUG: invalid JSON RPC request")
                    .id
            };

            let response_body = serde_json::to_vec(&json!({
                "jsonrpc":"2.0",
                "result": self.response_result,
                "id": request_id,
            }))
            .unwrap();

            if let Some(max_response_bytes) = context.max_response_bytes {
                if (response_body.len() as u64) > max_response_bytes.get() {
                    let mut payload = PayloadBuilder::new();
                    payload = payload.http_response_failure(
                        id,
                        RejectCode::SysFatal,
                        format!(
                            "Http body exceeds size limit of {} bytes.",
                            max_response_bytes
                        ),
                    );
                    env.execute_payload(payload);
                    return;
                }
            }

            let clean_up_context = match context.transform.clone() {
                Some(transform) => transform.context,
                None => vec![],
            };
            let transform_arg = TransformArgs {
                response: OutCallHttpResponse {
                    status: 200.into(),
                    headers: vec![],
                    body: response_body,
                },
                context: clean_up_context.to_vec(),
            };
            let clean_up_response = Decode!(
                &assert_reply(
                    env.execute_ingress(
                        canister_id_cleanup_response,
                        "cleanup_response",
                        Encode!(&transform_arg).unwrap(),
                    )
                    .expect("failed to query transform http response")
                ),
                OutCallHttpResponse
            )
            .unwrap();

            if let Some(max_response_bytes) = context.max_response_bytes {
                if (clean_up_response.body.len() as u64) > max_response_bytes.get() {
                    let mut payload = PayloadBuilder::new();
                    payload = payload.http_response_failure(
                        id,
                        RejectCode::SysFatal,
                        format!(
                            "Http body exceeds size limit of {} bytes.",
                            max_response_bytes
                        ),
                    );
                    env.execute_payload(payload);
                    return;
                }
            }

            let http_response = CanisterHttpResponsePayload {
                status: 200_u128,
                headers: vec![],
                body: clean_up_response.body,
            };
            let mut payload = PayloadBuilder::new();
            payload = payload.http_response(id, &http_response);
            env.execute_payload(payload);
        }

        fn tick_until_next_http_request(&self, env: &StateMachine) {
            let method = self.matcher.json_rpc_method.to_string();
            for _ in 0..MAX_TICKS {
                let matching_method =
                    env.canister_http_request_contexts()
                        .values()
                        .any(|context| {
                            JsonRpcRequest::from_str(
                                std::str::from_utf8(&context.body.clone().unwrap()).unwrap(),
                            )
                            .expect("BUG: invalid JSON RPC method")
                            .method
                            .to_string()
                                == method
                        });
                if matching_method {
                    break;
                }
                env.tick();
                env.advance_time(Duration::from_nanos(1));
            }
        }
    }

    impl MockJsonRpcProviders {
        pub fn when(json_rpc_method: JsonRpcMethod) -> MockJsonRpcProvidersBuilder {
            MockJsonRpcProvidersBuilder {
                json_rpc_method,
                json_rpc_params: None,
                max_response_bytes: None,
                responses: Default::default(),
            }
        }

        pub fn expect_rpc_calls(self, cketh: &CkEthSetup) {
            for stub in self.stubs {
                stub.expect_rpc_call(&cketh.env, cketh.minter_id);
            }
        }
    }

    pub struct MockJsonRpcProvidersBuilder {
        json_rpc_method: JsonRpcMethod,
        json_rpc_params: Option<serde_json::Value>,
        max_response_bytes: Option<u64>,
        responses: BTreeMap<JsonRpcProvider, serde_json::Value>,
    }

    impl MockJsonRpcProvidersBuilder {
        pub fn with_request_params(mut self, params: serde_json::Value) -> Self {
            self.json_rpc_params = Some(params);
            self
        }

        pub fn with_max_response_bytes(mut self, max_response_bytes: u64) -> Self {
            self.max_response_bytes = Some(max_response_bytes);
            self
        }

        pub fn respond_with<T: Serialize>(
            mut self,
            provider: JsonRpcProvider,
            response: T,
        ) -> Self {
            self.responses
                .insert(provider, serde_json::to_value(response).unwrap());
            self
        }

        pub fn modify_response<T: Serialize + DeserializeOwned, F: FnMut(&mut T)>(
            mut self,
            provider: JsonRpcProvider,
            mutator: &mut F,
        ) -> Self {
            let previous_serialized_response = self
                .responses
                .remove(&provider)
                .expect("BUG: no responses registered for provider");
            let mut previous_response: T = serde_json::from_value(previous_serialized_response)
                .expect("BUG: cannot deserialize previous response");
            mutator(&mut previous_response);
            self.respond_with(provider, previous_response)
        }

        pub fn respond_for_all_with<T: Serialize + Clone>(mut self, response: T) -> Self {
            for provider in JsonRpcProvider::iter() {
                self = self.respond_with(provider, response.clone());
            }
            self
        }

        pub fn modify_response_for_all<T: Serialize + DeserializeOwned, F: FnMut(&mut T)>(
            mut self,
            mutator: &mut F,
        ) -> Self {
            for provider in JsonRpcProvider::iter() {
                self = self.modify_response(provider, mutator)
            }
            self
        }

        pub fn build(self) -> MockJsonRpcProviders {
            assert!(
                !self.responses.is_empty(),
                "BUG: Missing at least one response for the mock!"
            );
            let mut stubs = Vec::with_capacity(self.responses.len());
            self.responses.into_iter().for_each(|(provider, response)| {
                stubs.push(StubOnce {
                    matcher: JsonRpcRequestMatcher::new(provider, self.json_rpc_method.clone())
                        .with_request_params(self.json_rpc_params.clone())
                        .with_max_response_bytes(self.max_response_bytes),
                    response_result: response,
                });
            });
            MockJsonRpcProviders { stubs }
        }
    }
}

#[test]
fn should_use_meaningful_constants() {
    let (default_tx, default_sig) = default_signed_eip_1559_transaction();

    assert_eq!(
        encode_transaction(default_tx.clone(), default_sig),
        DEFAULT_WITHDRAWAL_TRANSACTION
    );

    assert_eq!(
        format!("{:?}", hash_transaction(default_tx, default_sig)),
        DEFAULT_WITHDRAWAL_TRANSACTION_HASH
    );
}
