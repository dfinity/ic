use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_cketh_minter::blocklist::SAMPLE_BLOCKED_ADDRESS;
use ic_cketh_minter::endpoints::CandidBlockTag::Finalized;
use ic_cketh_minter::endpoints::events::{
    EventPayload, EventSource, TransactionReceipt, TransactionStatus, UnsignedTransaction,
};
use ic_cketh_minter::endpoints::{
    CandidBlockTag, DecodeLedgerMemoResult, DecodedMemo, EthTransaction, GasFeeEstimate, MemoType,
    MintMemo as EndpointsMint, MinterInfo, RetrieveEthStatus, TxFinalizedStatus, WithdrawalError,
    WithdrawalStatus,
};
use ic_cketh_minter::lifecycle::upgrade::UpgradeArg;
use ic_cketh_minter::memo::{BurnMemo, MintMemo};
use ic_cketh_minter::numeric::BlockNumber;
use ic_cketh_minter::{PROCESS_REIMBURSEMENT, SCRAPING_ETH_LOGS_INTERVAL};
use ic_cketh_test_utils::flow::{
    DepositCkEthParams, DepositCkEthWithSubaccountParams, DepositParams, ProcessWithdrawalParams,
    double_and_increment_base_fee_per_gas,
};
use ic_cketh_test_utils::mock::{JsonRpcMethod, MockJsonRpcProviders};
use ic_cketh_test_utils::response::{
    block_response, decode_transaction, default_signed_eip_1559_transaction, empty_logs,
    hash_transaction, multi_logs_for_single_transaction,
};
use ic_cketh_test_utils::{
    CKETH_MINIMUM_WITHDRAWAL_AMOUNT, CKETH_TRANSFER_FEE, CKETH_WITHDRAWAL_AMOUNT, CkEthSetup,
    DEFAULT_BLOCK_HASH, DEFAULT_BLOCK_NUMBER, DEFAULT_DEPOSIT_FROM_ADDRESS,
    DEFAULT_DEPOSIT_LOG_INDEX, DEFAULT_DEPOSIT_TRANSACTION_HASH, DEFAULT_PRINCIPAL_ID,
    DEFAULT_USER_SUBACCOUNT, DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS,
    DEFAULT_WITHDRAWAL_TRANSACTION_HASH, EFFECTIVE_GAS_PRICE, ETH_HELPER_CONTRACT_ADDRESS,
    EXPECTED_BALANCE, GAS_USED, JsonRpcProvider, LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL,
    MINTER_ADDRESS,
};
use ic_ethereum_types::Address;
use ic_management_canister_types_private::CanisterStatusType;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::{Burn, Mint};
use num_traits::cast::ToPrimitive;
use serde_json::json;
use std::str::FromStr;
use std::time::Duration;

#[test]
fn should_deposit_and_withdraw() {
    deposit_and_withdraw(
        CkEthSetup::default(),
        DepositParams::default(),
        CKETH_WITHDRAWAL_AMOUNT,
        DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
    );

    deposit_and_withdraw(
        CkEthSetup::default().add_support_for_subaccount(),
        DepositCkEthWithSubaccountParams {
            recipient_subaccount: Some(DEFAULT_USER_SUBACCOUNT),
            ..Default::default()
        },
        CKETH_WITHDRAWAL_AMOUNT,
        DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
    );

    fn deposit_and_withdraw<T: Into<DepositParams>>(
        cketh: CkEthSetup,
        deposit_params: T,
        withdrawal_amount: u64,
        destination: String,
    ) {
        let deposit_params = deposit_params.into();
        let account = match &deposit_params {
            DepositParams::CkEth(params) => Account {
                owner: params.recipient,
                subaccount: None,
            },
            DepositParams::CkEthWithSubaccount(params) => Account {
                owner: params.recipient,
                subaccount: params.recipient_subaccount,
            },
        };
        let minter: Principal = cketh.minter_id.into();
        let withdrawal_amount = Nat::from(withdrawal_amount);

        let cketh = cketh
            .deposit(deposit_params)
            .expect_mint()
            .call_ledger_get_transaction(0_u8)
            .expect_mint(Mint {
                amount: EXPECTED_BALANCE.into(),
                to: account,
                memo: Some(Memo::from(MintMemo::Convert {
                    from_address: DEFAULT_DEPOSIT_FROM_ADDRESS.parse().unwrap(),
                    tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
                    log_index: DEFAULT_DEPOSIT_LOG_INDEX.into(),
                })),
                created_at_time: None,
                fee: None,
            })
            .call_ledger_approve_minter(account.owner, EXPECTED_BALANCE, account.subaccount)
            .expect_ok(1)
            .call_minter_withdraw_eth(account, withdrawal_amount.clone(), destination.clone())
            .expect_withdrawal_request_accepted();

        let withdrawal_id = cketh.withdrawal_id().clone();

        let time = cketh.setup.env.get_time().as_nanos_since_unix_epoch();
        let max_fee_per_gas = Nat::from(33003708258u64);
        let gas_limit = Nat::from(21_000_u32);
        let max_priority_fee_per_gas = Nat::from(1_500_000_000_u32);

        let cketh = cketh
            .wait_and_validate_withdrawal(ProcessWithdrawalParams::default())
            .expect_finalized_status(TxFinalizedStatus::Success {
                transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
                effective_transaction_fee: Some((GAS_USED * EFFECTIVE_GAS_PRICE).into()),
            })
            .call_ledger_get_transaction(withdrawal_id.clone())
            .expect_burn(Burn {
                amount: withdrawal_amount.clone(),
                from: account,
                spender: Some(Account {
                    owner: minter,
                    subaccount: None,
                }),
                memo: Some(Memo::from(BurnMemo::Convert {
                    to_address: destination.parse().unwrap(),
                })),
                created_at_time: None,
                fee: None,
            });
        assert_eq!(cketh.balance_of(account), Nat::from(0_u8));

        cketh.assert_has_unique_events_in_order(&vec![
            EventPayload::AcceptedEthWithdrawalRequest {
                withdrawal_amount: withdrawal_amount.clone(),
                destination: destination.clone(),
                ledger_burn_index: withdrawal_id.clone(),
                from: account.owner,
                from_subaccount: account.subaccount,
                created_at: Some(time),
            },
            EventPayload::CreatedTransaction {
                withdrawal_id: withdrawal_id.clone(),
                transaction: UnsignedTransaction {
                    chain_id: Nat::from(1_u8),
                    nonce: Nat::from(0_u8),
                    max_priority_fee_per_gas,
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
                    gas_used: Nat::from(21_000_u32),
                    status: TransactionStatus::Success,
                    transaction_hash:
                    "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string(),
                },
            },
        ]);
    }
}

#[test]
fn should_retrieve_cache_transaction_price() {
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);
    let destination = DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string();

    let result = cketh.eip_1559_transaction_price(None);
    assert_matches!(result, Err(e) if e.code() == ic_state_machine_tests::ErrorCode::CanisterCalledTrap);

    let cketh = cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), destination.clone())
        .expect_withdrawal_request_accepted()
        .wait_and_validate_withdrawal(ProcessWithdrawalParams::default())
        .setup;

    let tx = cketh
        .get_all_events()
        .into_iter()
        .find_map(|event| match event.payload {
            EventPayload::CreatedTransaction { transaction, .. } => Some(transaction),
            _ => None,
        })
        .expect("missing CreatedTransaction event");

    let price = cketh.eip_1559_transaction_price_expecting_ok(None);
    assert_eq!(price.max_priority_fee_per_gas, tx.max_priority_fee_per_gas);
    assert_eq!(price.max_fee_per_gas, tx.max_fee_per_gas);
    assert_eq!(price.gas_limit, tx.gas_limit);

    cketh.env.tick();
    let second_price = cketh.eip_1559_transaction_price_expecting_ok(None);
    assert_eq!(price, second_price);

    let price_using_ledger_id =
        cketh.eip_1559_transaction_price_expecting_ok(Some(cketh.ledger_id.into()));
    assert_eq!(price, price_using_ledger_id);
}

#[test]
fn should_block_deposit_from_blocked_address() {
    let cketh = CkEthSetup::default();
    let from_address_blocked: Address = SAMPLE_BLOCKED_ADDRESS;

    cketh
        .deposit(DepositCkEthParams {
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
fn should_not_mint_when_logs_too_inconsistent() {
    let deposit_params = DepositCkEthParams::default();
    let (block_pi_logs, public_node_logs) = {
        let block_pi_log_entry = deposit_params.to_log_entry();
        let llama_nodes_log_entry = DepositCkEthParams {
            amount: deposit_params.amount + 1,
            ..deposit_params.clone()
        }
        .to_log_entry();
        (vec![block_pi_log_entry], vec![llama_nodes_log_entry])
    };
    assert_ne!(block_pi_logs, public_node_logs);

    CkEthSetup::default()
        .deposit(deposit_params)
        .with_mock_eth_get_logs(move |mock| {
            mock.respond_with(JsonRpcProvider::Provider1, block_pi_logs.clone())
                .respond_with(JsonRpcProvider::Provider2, public_node_logs.clone())
                .respond_with(JsonRpcProvider::Provider3, block_pi_logs.clone())
                .respond_with(JsonRpcProvider::Provider4, public_node_logs.clone())
        })
        .expect_no_mint();
}

#[test]
fn should_mint_when_1_error_with_3_out_of_4_strategy() {
    let deposit_params = DepositCkEthParams::default();
    let (block_pi_logs, public_node_logs) = {
        let block_pi_log_entry = deposit_params.to_log_entry();
        let llama_nodes_log_entry = DepositCkEthParams {
            amount: deposit_params.amount + 1,
            ..deposit_params.clone()
        }
        .to_log_entry();
        (vec![block_pi_log_entry], vec![llama_nodes_log_entry])
    };
    assert_ne!(block_pi_logs, public_node_logs);

    CkEthSetup::default()
        .deposit(deposit_params)
        .with_mock_eth_get_logs(move |mock| {
            mock.respond_with(JsonRpcProvider::Provider1, block_pi_logs.clone())
                .respond_with(JsonRpcProvider::Provider2, public_node_logs.clone())
                .respond_with(JsonRpcProvider::Provider3, block_pi_logs.clone())
                .respond_with(JsonRpcProvider::Provider4, block_pi_logs.clone())
        })
        .expect_mint();
}

#[test]
fn should_block_withdrawal_to_blocked_address() {
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);
    let blocked_address = SAMPLE_BLOCKED_ADDRESS.to_string();

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
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();

    cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_minter_withdraw_eth(
            caller,
            Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT),
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
        .expect_error(WithdrawalError::InsufficientAllowance {
            allowance: Nat::from(0_u64),
        });
}

#[test]
fn should_fail_to_withdraw_when_insufficient_funds() {
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();
    let deposit_amount = CKETH_MINIMUM_WITHDRAWAL_AMOUNT + CKETH_TRANSFER_FEE;
    let amount_after_approval = CKETH_MINIMUM_WITHDRAWAL_AMOUNT;
    assert!(deposit_amount > amount_after_approval);

    cketh
        .deposit(DepositCkEthParams {
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
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();
    cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_approve_minter(caller, CKETH_MINIMUM_WITHDRAWAL_AMOUNT, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(
            caller,
            Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT - 1),
            DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
        )
        .expect_error(WithdrawalError::AmountTooLow {
            min_withdrawal_amount: CKETH_MINIMUM_WITHDRAWAL_AMOUNT.into(),
        });
}

#[test]
fn should_not_finalize_transaction_when_receipts_do_not_match() {
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);

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
            ProcessWithdrawalParams::default().with_inconsistent_transaction_receipt(),
        )
        .expect_status(RetrieveEthStatus::TxSent(EthTransaction {
            transaction_hash: DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string(),
        }));
}

#[test]
fn should_not_send_eth_transaction_when_fee_history_inconsistent() {
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);

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
                JsonRpcProvider::Provider1,
                &mut |response: &mut ethers_core::types::FeeHistory| {
                    response.oldest_block = 0x17740742_u64.into()
                },
            )
            .modify_response(
                JsonRpcProvider::Provider2,
                &mut |response: &mut ethers_core::types::FeeHistory| {
                    response.oldest_block = 0x17740743_u64.into()
                },
            )
            .modify_response(
                JsonRpcProvider::Provider3,
                &mut |response: &mut ethers_core::types::FeeHistory| {
                    response.oldest_block = 0x17740744_u64.into()
                },
            )
        })
        .expect_status(RetrieveEthStatus::Pending, WithdrawalStatus::Pending);
}

#[test]
fn should_reimburse() {
    let cketh = CkEthSetup::default();
    let minter: Principal = cketh.minter_id.into();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);
    let destination = "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0".to_string();

    let cketh = cketh
        .deposit(DepositParams::default())
        .expect_mint()
        .call_ledger_get_transaction(0_u8)
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
            fee: None,
        })
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1);

    let balance_before_withdrawal = cketh.balance_of(caller);
    assert_eq!(balance_before_withdrawal, withdrawal_amount);

    // advance time so that time does not grow implicitly when executing a round
    cketh.env.advance_time(Duration::from_secs(1));
    let time_at_withdrawal = cketh.env.get_time().as_nanos_since_unix_epoch();

    let cketh = cketh
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), destination.clone())
        .expect_withdrawal_request_accepted();

    let withdrawal_id = cketh.withdrawal_id().clone();
    let (tx, _sig) = default_signed_eip_1559_transaction();
    let cketh = cketh
        .wait_and_validate_withdrawal(
            ProcessWithdrawalParams::default().with_failed_transaction_receipt(),
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
            fee: None,
        });

    assert_eq!(cketh.balance_of(caller), Nat::from(0_u8));

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
    let reimbursed_in_block = withdrawal_id.clone() + Nat::from(1_u8);
    let failed_tx_hash =
        "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string();
    assert_eq!(
        cketh.retrieve_eth_status(&withdrawal_id),
        RetrieveEthStatus::TxFinalized(TxFinalizedStatus::Reimbursed {
            reimbursed_amount: reimbursed_amount.clone(),
            reimbursed_in_block: reimbursed_in_block.clone(),
            transaction_hash: failed_tx_hash.clone(),
        })
    );

    let max_fee_per_gas = Nat::from(33003708258u64);
    let gas_limit = Nat::from(21_000_u32);

    cketh
        .call_ledger_get_transaction(reimbursed_in_block)
        .expect_mint(Mint {
            amount: reimbursed_amount.clone(),
            to: Account {
                owner: PrincipalId::new_user_test_id(DEFAULT_PRINCIPAL_ID).into(),
                subaccount: None,
            },
            memo: Some(Memo::from(MintMemo::ReimburseTransaction {
                withdrawal_id: withdrawal_id.0.to_u64().unwrap(),
                tx_hash: failed_tx_hash.parse().unwrap(),
            })),
            created_at_time: None,
            fee: None,
        })
        .assert_has_unique_events_in_order(&vec![
            EventPayload::AcceptedEthWithdrawalRequest {
                withdrawal_amount: withdrawal_amount.clone(),
                destination: destination.clone(),
                ledger_burn_index: withdrawal_id.clone(),
                from: caller,
                from_subaccount: None,
                created_at: Some(time_at_withdrawal),
            },
            EventPayload::CreatedTransaction {
                withdrawal_id: withdrawal_id.clone(),
                transaction: UnsignedTransaction {
                    chain_id: Nat::from(1_u8),
                    nonce: Nat::from(0_u8),
                    max_priority_fee_per_gas: Nat::from(1_500_000_000_u32),
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
                    gas_used: Nat::from(21_000_u32),
                    status: TransactionStatus::Failure,
                    transaction_hash:
                    "0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string(),
                },
            },
            EventPayload::ReimbursedEthWithdrawal {
                transaction_hash: Some("0x2cf1763e8ee3990103a31a5709b17b83f167738abb400844e67f608a98b0bdb5".to_string()),
                reimbursed_amount,
                withdrawal_id: withdrawal_id.clone(),
                reimbursed_in_block: withdrawal_id + Nat::from(1_u8),
            },
        ]);
}

#[test]
fn should_resubmit_transaction_as_is_when_price_still_actual() {
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);
    let (expected_tx, expected_sig) = default_signed_eip_1559_transaction();

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
        .process_withdrawal_with_resubmission_and_same_price(expected_tx, expected_sig)
        .assert_has_no_event_satisfying(|event| {
            matches!(event, EventPayload::ReplacedTransaction { .. })
        });
}

#[test]
fn should_resubmit_new_transaction_when_price_increased() {
    let cketh = CkEthSetup::default();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);
    let (expected_tx, expected_sig) = default_signed_eip_1559_transaction();
    let first_tx_hash = hash_transaction(expected_tx.clone(), expected_sig);
    let resubmitted_sent_tx = "0x02f873018084625900808507b81d70e382520894221e931fbfcb9bd54ddd26ce6f5e29e98add01c0880160cc412e75c2de80c001a03d58ee49c9dce3b3c646eeb18317b46cc852a5384be9026cb0aa3d59f9b16292a007276dfb5e003bd7f527675e15c8512f1324e6434c62e7ffa4c68971d726fa0b";
    let (resubmitted_tx, resubmitted_tx_sig) = decode_transaction(resubmitted_sent_tx);
    let resubmitted_tx_hash = hash_transaction(resubmitted_tx.clone(), resubmitted_tx_sig);
    assert_eq!(
        resubmitted_tx,
        expected_tx
            .clone()
            .value(99_303_772_126_560_990_u64)
            .max_priority_fee_per_gas(1_650_000_000_u64)
            .max_fee_per_gas(33_153_708_259_u64)
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

    cketh
        .process_withdrawal_with_resubmission_and_increased_price(
            expected_tx,
            expected_sig,
            &mut double_and_increment_base_fee_per_gas,
            resubmitted_tx.clone(),
            resubmitted_tx_sig,
        )
        .assert_has_unique_events_in_order(&vec![
            EventPayload::ReplacedTransaction {
                withdrawal_id: withdrawal_id.clone(),
                transaction: UnsignedTransaction {
                    chain_id: Nat::from(1_u8),
                    nonce: Nat::from(0_u8),
                    max_priority_fee_per_gas: Nat::from(
                        resubmitted_tx.max_priority_fee_per_gas.unwrap().as_u128(),
                    ),
                    max_fee_per_gas: Nat::from(resubmitted_tx.max_fee_per_gas.unwrap().as_u128()),
                    gas_limit: Nat::from(21_000_u32),
                    destination: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
                    value: Nat::from(resubmitted_tx.value.unwrap().as_u128()),
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
                    gas_used: Nat::from(21_000_u32),
                    status: TransactionStatus::Success,
                    transaction_hash: format!("{resubmitted_tx_hash:?}"),
                },
            },
        ]);
}

#[test]
fn should_not_overlap_when_scrapping_logs() {
    let cketh = CkEthSetup::default();
    let max_eth_logs_block_range = cketh.max_logs_block_range();

    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER))
        .build()
        .expect_rpc_calls(&cketh);

    let first_from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let first_to_block = first_from_block
        .checked_add(BlockNumber::from(max_eth_logs_block_range))
        .unwrap();
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": first_from_block,
            "toBlock": first_to_block,
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [cketh.received_eth_event_topic()]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);

    let second_from_block = first_to_block
        .checked_add(BlockNumber::from(1_u64))
        .unwrap();
    let second_to_block = second_from_block
        .checked_add(BlockNumber::from(max_eth_logs_block_range))
        .unwrap();
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": second_from_block,
            "toBlock": second_to_block,
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [cketh.received_eth_event_topic()]
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
    let cketh = CkEthSetup::default();
    let max_eth_logs_block_range = cketh.max_logs_block_range();
    let prev_events_len = cketh.get_all_events().len();

    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER))
        .build()
        .expect_rpc_calls(&cketh);
    let from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let to_block = from_block
        .checked_add(BlockNumber::from(max_eth_logs_block_range))
        .unwrap();
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [cketh.received_eth_event_topic()]
        }]))
        .respond_for_all_with(empty_logs())
        .respond_for_providers_with([JsonRpcProvider::Provider2, JsonRpcProvider::Provider4], json!({"error":{"code":-32000,"message":"max message response size exceed"},"id":74,"jsonrpc":"2.0"}))
        .build()
        .expect_rpc_calls(&cketh);

    let cketh = cketh
        .check_audit_logs_and_upgrade(Default::default())
        .check_events()
        .skip(prev_events_len)
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into(),
        }]);

    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER))
        .build()
        .expect_rpc_calls(&cketh);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [cketh.received_eth_event_topic()]
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
    let cketh = CkEthSetup::default();

    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1))
        .build()
        .expect_rpc_calls(&cketh);
    let from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
        .with_request_params(json!([{
            "fromBlock": from_block,
            "toBlock": from_block,
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [cketh.received_eth_event_topic()]
        }]))
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);
}

#[test]
fn should_document_current_behavior_of_being_unstoppable_while_scraping_blocks_has_open_call_context()
 {
    // TODO(DEFI-2566): This test documents the current behavior, where the ckETH minter is
    //  unstoppable while scraping (lots of) logs on a timer. Since log scraping calls are made on
    //  a loop in the callback handler for log scraping responses, the scraping continues until all
    //  logs have been scraped. The same call context is reused, and as long as there is an open
    //  call context, the minter is not stoppable.
    const UNSCRAPED_BLOCKS: u64 = 5_000;
    const NUM_BLOCK_RANGES: usize = 10;

    let cketh = CkEthSetup::default();
    let max_eth_logs_block_range = cketh.as_ref().max_logs_block_range();
    const MAX_BLOCK: u64 = LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + UNSCRAPED_BLOCKS;

    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);

    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(MAX_BLOCK))
        .build()
        .expect_rpc_calls(&cketh);

    // Only the first few eth_getLogs requests (e.g., 3 out of 10).
    // This leaves the scraping in progress with open call contexts.
    let mut from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let mut to_block = from_block
        .checked_add(BlockNumber::from(max_eth_logs_block_range))
        .unwrap();

    const BLOCKS_TO_PROCESS_BEFORE_STOP: usize = 3;
    for _ in 0..BLOCKS_TO_PROCESS_BEFORE_STOP {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": [ETH_HELPER_CONTRACT_ADDRESS],
                "topics": [cketh.received_eth_event_topic()]
            }]))
            .respond_for_all_with(empty_logs())
            .build()
            .expect_rpc_calls(&cketh);

        from_block = to_block.checked_increment().unwrap();
        to_block = from_block
            .checked_add(BlockNumber::from(max_eth_logs_block_range))
            .unwrap();
    }

    // At this point:
    // - 3 block ranges have been scraped
    // - The minter has made an HTTP outcall for the 4th block range
    // - There's an open call context waiting for that HTTP response
    // Request to stop the minter (without providing responses to pending HTTP outcalls).
    // The stop will NOT complete because there's an open call context.
    cketh.try_stop_minter_without_stopping_ongoing_https_outcalls();

    // Verify the minter is in "Stopping" state (not "Stopped")
    let status = cketh.tick_until_minter_canister_status(CanisterStatusType::Stopping);
    assert_eq!(
        status,
        CanisterStatusType::Stopping,
        "Expected minter to be in Stopping state due to open call contexts"
    );

    // Even while in "Stopping" state, when we provide a response to the pending HTTPS call, the
    // canister does not stop. Instead, the callback continuation runs and the next loop iteration
    // makes another outcall. The canister remains in "Stopping" state throughout.
    for i in BLOCKS_TO_PROCESS_BEFORE_STOP..NUM_BLOCK_RANGES {
        // Before providing response, verify canister is STILL in Stopping state
        let status_before = cketh.minter_status();
        assert_eq!(
            status_before,
            CanisterStatusType::Stopping,
            "Block range {}/{}: Canister should be in Stopping state before receiving response",
            i + 1,
            NUM_BLOCK_RANGES
        );

        // Provide response to the pending HTTPS call.
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": [ETH_HELPER_CONTRACT_ADDRESS],
                "topics": [cketh.received_eth_event_topic()]
            }]))
            .respond_for_all_with(empty_logs())
            .build()
            .expect_rpc_calls(&cketh);

        // After processing the response, verify the canister is still in Stopping state.
        let status_after = cketh.minter_status();

        if i < NUM_BLOCK_RANGES - 1 {
            assert_eq!(
                status_after,
                CanisterStatusType::Stopping,
                "Block range {}/{}: Canister should still be in Stopping state after receiving \
                 response (it made a new HTTP call for the next block range!)",
                i + 1,
                NUM_BLOCK_RANGES
            );
        } else {
            // Last block range - canister might transition to Stopped
            println!(
                "  Block range {}/{}: Final response received",
                i + 1,
                NUM_BLOCK_RANGES
            );
        }

        from_block = to_block.checked_increment().unwrap();
        to_block = from_block
            .checked_add(BlockNumber::from(max_eth_logs_block_range))
            .unwrap();
    }

    // After all scraping is complete, the canister should finally be Stopped.
    let status = cketh.tick_until_minter_canister_status(CanisterStatusType::Stopped);
    assert_eq!(
        status,
        CanisterStatusType::Stopped,
        "Expected minter to be Stopped after all call contexts closed"
    );
}

#[test]
fn should_panic_when_last_finalized_block_in_the_past() {
    let cketh = CkEthSetup::default();
    let prev_events_len = cketh.get_all_events().len();

    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL - 1))
        .build()
        .expect_rpc_calls(&cketh);

    let cketh = cketh
        .check_audit_logs_and_upgrade(Default::default())
        .check_events()
        .skip(prev_events_len)
        .assert_has_unique_events_in_order(&vec![EventPayload::SyncedToBlock {
            block_number: LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into(),
        }]);

    let last_finalized_block = LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 10;
    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
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
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [cketh.received_eth_event_topic()]
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
    let cketh = CkEthSetup::default().check_audit_logs_and_upgrade(UpgradeArg {
        ethereum_block_height: Some(CandidBlockTag::Safe),
        ..Default::default()
    });
    let received_eth_event_topic = cketh.received_eth_event_topic();
    cketh.env.tick();

    let cketh = cketh
        .deposit(DepositParams::default())
        .with_mock_eth_get_block_by_number(move |mock| {
            mock.with_request_params(json!(["safe", false]))
                .respond_for_all_with(block_response(safe_block_number))
        })
        .with_mock_eth_get_logs(move |mock| {
            mock.with_request_params(json!([{
                "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "toBlock": BlockNumber::from(safe_block_number),
                "address": [ETH_HELPER_CONTRACT_ADDRESS],
                "topics": [received_eth_event_topic]
            }]))
        })
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
    let cketh = CkEthSetup::default();
    let max_eth_logs_block_range = cketh.max_logs_block_range();
    let deposit = DepositParams::default().to_log_entry();
    // around 600 bytes per log
    // we need at least 3334 logs to reach the 2MB limit
    let large_amount_of_logs = multi_logs_for_single_transaction(deposit.clone(), 3_500);
    assert!(serde_json::to_vec(&large_amount_of_logs).unwrap().len() > 2_000_000);

    let from_block = BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1);
    let to_block = from_block
        .checked_add(BlockNumber::from(max_eth_logs_block_range))
        .unwrap();
    let half_to_block = from_block
        .checked_add(BlockNumber::from(max_eth_logs_block_range / 2))
        .unwrap();

    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(DEFAULT_BLOCK_NUMBER))
        .build()
        .expect_rpc_calls(&cketh);

    for max_response_bytes in cketh.all_eth_get_logs_response_size_estimates() {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": [ETH_HELPER_CONTRACT_ADDRESS],
                "topics": [cketh.received_eth_event_topic()]
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
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [cketh.received_eth_event_topic()]
        }]))
        .with_max_response_bytes(cketh.all_eth_get_logs_response_size_estimates()[0])
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
    let cketh = CkEthSetup::default();
    let deposit = DepositParams::default().to_log_entry();
    // around 600 bytes per log
    // we need at least 3334 logs to reach the 2MB limit
    let large_amount_of_logs = multi_logs_for_single_transaction(deposit.clone(), 3_500);
    assert!(serde_json::to_vec(&large_amount_of_logs).unwrap().len() > 2_000_000);

    cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
    MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
        .respond_for_all_with(block_response(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 3))
        .build()
        .expect_rpc_calls(&cketh);

    for max_response_bytes in cketh.all_eth_get_logs_response_size_estimates() {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "toBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 3),
                "address": [ETH_HELPER_CONTRACT_ADDRESS],
                "topics": [cketh.received_eth_event_topic()]
            }]))
            .with_max_response_bytes(max_response_bytes)
            .respond_for_all_with(large_amount_of_logs.clone())
            .build()
            .expect_rpc_calls(&cketh);
    }

    for max_response_bytes in cketh.all_eth_get_logs_response_size_estimates() {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "toBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 2),
                "address": [ETH_HELPER_CONTRACT_ADDRESS],
                "topics": [cketh.received_eth_event_topic()]
            }]))
            .with_max_response_bytes(max_response_bytes)
            .respond_for_all_with(large_amount_of_logs.clone())
            .build()
            .expect_rpc_calls(&cketh);
    }

    for max_response_bytes in cketh.all_eth_get_logs_response_size_estimates() {
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetLogs)
            .with_request_params(json!([{
                "fromBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "toBlock": BlockNumber::from(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1),
                "address": [ETH_HELPER_CONTRACT_ADDRESS],
                "topics": [cketh.received_eth_event_topic()]
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
            "address": [ETH_HELPER_CONTRACT_ADDRESS],
            "topics": [cketh.received_eth_event_topic()]
        }]))
        .with_max_response_bytes(cketh.all_eth_get_logs_response_size_estimates()[0])
        .respond_for_all_with(empty_logs())
        .build()
        .expect_rpc_calls(&cketh);

    cketh
        .check_audit_logs_and_upgrade(Default::default())
        .assert_has_unique_events_in_order(&vec![
            EventPayload::SkippedBlock {
                contract_address: Some(
                    ETH_HELPER_CONTRACT_ADDRESS
                        .parse::<Address>()
                        .unwrap()
                        .to_string(),
                ),
                block_number: (LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 1).into(),
            },
            EventPayload::SyncedToBlock {
                block_number: (LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 3).into(),
            },
        ]);
}

#[allow(deprecated)]
#[test]
fn should_retrieve_minter_info() {
    let cketh = CkEthSetup::default();
    let max_eth_logs_block_range = cketh.max_logs_block_range();
    let caller: Principal = cketh.caller.into();
    let withdrawal_amount = Nat::from(CKETH_WITHDRAWAL_AMOUNT);
    let destination = DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string();

    let info_at_start = cketh.get_minter_info();
    assert_eq!(
        info_at_start,
        MinterInfo {
            minter_address: Some(format_ethereum_address_to_eip_55(MINTER_ADDRESS)),
            smart_contract_address: Some(format_ethereum_address_to_eip_55(
                ETH_HELPER_CONTRACT_ADDRESS
            )),
            eth_helper_contract_address: Some(format_ethereum_address_to_eip_55(
                ETH_HELPER_CONTRACT_ADDRESS
            )),
            erc20_helper_contract_address: None,
            deposit_with_subaccount_helper_contract_address: None,
            supported_ckerc20_tokens: None,
            minimum_withdrawal_amount: Some(Nat::from(CKETH_MINIMUM_WITHDRAWAL_AMOUNT)),
            ethereum_block_height: Some(Finalized),
            last_observed_block_number: None,
            eth_balance: Some(Nat::from(0_u8)),
            last_gas_fee_estimate: None,
            erc20_balances: None,
            last_eth_scraped_block_number: Some(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into()),
            last_erc20_scraped_block_number: Some(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into()),
            last_deposit_with_subaccount_scraped_block_number: Some(
                LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL.into()
            ),
            cketh_ledger_id: Some(cketh.ledger_id.into()),
            evm_rpc_id: Some(cketh.evm_rpc_id.into()),
        }
    );

    let cketh = cketh.deposit(DepositParams::default()).expect_mint();
    let info_after_deposit = cketh.get_minter_info();
    let new_eth_scraped_block_number =
        LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + max_eth_logs_block_range + 1;
    assert_eq!(
        info_after_deposit,
        MinterInfo {
            last_observed_block_number: Some(Nat::from(new_eth_scraped_block_number)),
            eth_balance: Some(Nat::from(EXPECTED_BALANCE)),
            last_eth_scraped_block_number: Some(new_eth_scraped_block_number.into()),
            ..info_at_start
        }
    );

    let cketh = cketh
        .call_ledger_approve_minter(caller, EXPECTED_BALANCE, None)
        .expect_ok(1)
        .call_minter_withdraw_eth(caller, withdrawal_amount.clone(), destination.clone())
        .expect_withdrawal_request_accepted()
        .wait_and_validate_withdrawal(ProcessWithdrawalParams::default())
        .setup;
    let info_after_withdrawal = cketh.get_minter_info();
    let price = cketh.eip_1559_transaction_price_expecting_ok(None);
    let debited_amount =
        withdrawal_amount - (price.max_transaction_fee - GAS_USED * EFFECTIVE_GAS_PRICE);
    assert_eq!(
        info_after_withdrawal,
        MinterInfo {
            last_gas_fee_estimate: Some(GasFeeEstimate {
                max_fee_per_gas: price.max_fee_per_gas,
                max_priority_fee_per_gas: price.max_priority_fee_per_gas,
                timestamp: price.timestamp.unwrap(),
            }),
            eth_balance: info_after_deposit
                .eth_balance
                .map(|balance| balance - debited_amount),
            ..info_after_deposit
        }
    );
}

fn format_ethereum_address_to_eip_55(address: &str) -> String {
    Address::from_str(address).unwrap().to_string()
}

#[test]
fn should_decode_ledger_mint_convert_memo() {
    let cketh = CkEthSetup::default();
    let memo = MintMemo::Convert {
        from_address: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.parse().unwrap(),
        tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.parse().unwrap(),
        log_index: DEFAULT_DEPOSIT_LOG_INDEX.into(),
    };
    let mut buf = vec![];
    minicbor::encode(memo, &mut buf).expect("encoding should succeed");
    let result = cketh.decode_ledger_memo(MemoType::Mint, buf);
    let expected: DecodeLedgerMemoResult =
        Ok(Some(DecodedMemo::Mint(Some(EndpointsMint::Convert {
            from_address: DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.to_string(),
            tx_hash: DEFAULT_DEPOSIT_TRANSACTION_HASH.to_string(),
            log_index: Nat::from(DEFAULT_DEPOSIT_LOG_INDEX),
        }))));
    assert_eq!(
        result, expected,
        "Decoded Memo mismatch: {:?} vs {:?}",
        result, expected
    );
}

/// Tests with the EVM RPC canister
mod cketh_evm_rpc {
    use super::*;

    #[test]
    fn should_retrieve_block_number() {
        let cketh = CkEthSetup::default();

        cketh.env.advance_time(SCRAPING_ETH_LOGS_INTERVAL);
        MockJsonRpcProviders::when(JsonRpcMethod::EthGetBlockByNumber)
            .respond_for_all_with(block_response(LAST_SCRAPED_BLOCK_NUMBER_AT_INSTALL + 3))
            .build()
            .expect_rpc_calls(&cketh);
    }
}
