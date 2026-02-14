#[cfg(not(feature = "icrc3_disabled"))]
use crate::common::FEE;
use crate::common::{
    account, approve, default_archive_options, get_fee_collectors_ranges, icrc1_balance_of,
    icrc2_transfer_from, index_init_arg_without_interval, install_icrc3_test_ledger,
    install_index_ng, install_ledger, install_ledger_with_wasm, ledger_mainnet_v5_wasm,
    ledger_wasm, transfer, wait_until_sync_is_completed, wait_until_sync_is_completed_or_error,
};
use candid::{Encode, Nat};
use ic_agent::identity::Identity;
use ic_base_types::CanisterId;
use ic_icrc1_ledger::{
    BTYPE_107_LEDGER_SET, ChangeFeeCollector, LedgerArgument, UpgradeArgs as LedgerUpgradeArgs,
};
use ic_icrc1_test_utils::icrc3::BlockBuilder;
use ic_icrc1_test_utils::icrc3::account_to_icrc3_value;
use ic_icrc1_test_utils::minter_identity;
use ic_ledger_suite_state_machine_helpers::add_block;
use ic_ledger_suite_state_machine_tests::set_fc_107_by_controller;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::BlockIndex;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use icrc_ledger_types::icrc107::schema::{BTYPE_107, SET_FEE_COL_107};
#[cfg(not(feature = "icrc3_disabled"))]
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

mod common;

#[cfg(not(feature = "u256-tokens"))]
type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
type Tokens = ic_icrc1_tokens_u256::U256;

fn transfer_from(
    env: &StateMachine,
    ledger_id: CanisterId,
    from: Account,
    to: Account,
    spender: Account,
    amount: u64,
) -> BlockIndex {
    let Account { owner, subaccount } = spender;
    let req = TransferFromArgs {
        spender_subaccount: subaccount,
        from,
        to,
        amount: amount.into(),
        created_at_time: None,
        fee: None,
        memo: None,
    };
    icrc2_transfer_from(env, ledger_id, owner.into(), req)
}

#[track_caller]
fn assert_contain_same_elements<T: Debug + Eq + Hash>(vl: Vec<T>, vr: Vec<T>) {
    assert_eq!(
        vl.iter().collect::<HashSet<_>>(),
        vr.iter().collect::<HashSet<_>>(),
    )
}

fn upgrade_ledger(
    env: &StateMachine,
    ledger_id: CanisterId,
    fee_collector_account: Option<Account>,
    legacy_fc_wasm: bool,
) {
    let change_fee_collector =
        Some(fee_collector_account.map_or(ChangeFeeCollector::Unset, ChangeFeeCollector::SetTo));
    let args = LedgerArgument::Upgrade(Some(LedgerUpgradeArgs {
        metadata: None,
        token_name: None,
        token_symbol: None,
        transfer_fee: None,
        change_fee_collector,
        max_memo_length: None,
        feature_flags: None,
        change_archive_options: None,
        index_principal: None,
    }));
    let wasm = if legacy_fc_wasm {
        ledger_mainnet_v5_wasm()
    } else {
        ledger_wasm()
    };
    env.upgrade_canister(ledger_id, wasm, Encode!(&args).unwrap())
        .unwrap()
}

fn test_fee_collector_ranges(legacy: bool) {
    let env = &StateMachine::new();
    let fee_collector = account(42, 0);
    let minter = minter_identity().sender().unwrap();
    let ledger_id = if legacy {
        install_ledger_with_wasm(
            env,
            vec![(account(1, 0), 10_000_000)],
            default_archive_options(),
            Some(fee_collector),
            minter,
            ledger_mainnet_v5_wasm(),
        )
    } else {
        install_ledger(
            env,
            vec![(account(1, 0), 10_000_000)],
            default_archive_options(),
            Some(fee_collector),
            minter,
        )
    };
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    let mut range_start = 0u64;
    let mut curr_txid = 0u64;
    if !legacy {
        curr_txid += 1; // init fee collector block
    }

    assert_eq!(
        icrc1_balance_of(env, ledger_id, fee_collector),
        icrc1_balance_of(env, index_id, fee_collector)
    );

    transfer(env, ledger_id, account(1, 0), account(2, 0), 100_000);
    approve(env, ledger_id, account(1, 0), account(3, 0), 200_000);
    transfer_from(
        env,
        ledger_id,
        account(1, 0),
        account(2, 0),
        account(3, 0),
        150_000,
    );
    curr_txid += 3;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, fee_collector),
        icrc1_balance_of(env, index_id, fee_collector)
    );

    let mut expected = vec![(
        fee_collector,
        vec![(range_start.into(), (curr_txid + 1).into())],
    )];

    assert_contain_same_elements(
        get_fee_collectors_ranges(env, index_id).ranges,
        expected.clone(),
    );

    // Remove the fee collector to burn some transactions fees.
    upgrade_ledger(env, ledger_id, None, legacy);
    if !legacy {
        curr_txid += 1; // upgrade fee collector block
    }

    transfer(env, ledger_id, account(1, 0), account(2, 0), 400_000);
    transfer(env, ledger_id, account(1, 0), account(2, 0), 500_000);
    curr_txid += 2;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, fee_collector),
        icrc1_balance_of(env, index_id, fee_collector)
    );

    assert_contain_same_elements(
        get_fee_collectors_ranges(env, index_id).ranges,
        expected.clone(),
    );

    // Add a new fee collector different from the first one.
    let new_fee_collector = account(42, 42);
    upgrade_ledger(env, ledger_id, Some(new_fee_collector), legacy);
    if !legacy {
        curr_txid += 1; // upgrade fee collector block
        range_start = curr_txid; // new fee collector starts at the upgrade block
    }

    transfer(env, ledger_id, account(1, 0), account(2, 0), 400_000);
    curr_txid += 1;
    if legacy {
        range_start = curr_txid; // legacy fee collector starts at the first tx after it is set
    }

    wait_until_sync_is_completed(env, index_id, ledger_id);

    for fee_collector in &[fee_collector, new_fee_collector] {
        assert_eq!(
            icrc1_balance_of(env, ledger_id, *fee_collector),
            icrc1_balance_of(env, index_id, *fee_collector)
        );
    }

    expected.push((
        new_fee_collector,
        vec![(range_start.into(), (curr_txid + 1).into())],
    ));

    println!("expected: {:?}", expected);

    assert_contain_same_elements(
        get_fee_collectors_ranges(env, index_id).ranges,
        expected.clone(),
    );

    // Add back the original fee_collector and make a couple of transactions again.
    upgrade_ledger(env, ledger_id, Some(fee_collector), legacy);
    if !legacy {
        curr_txid += 1; // upgrade fee collector block
        range_start = curr_txid; // new fee collector starts at the upgrade block
    }

    transfer(env, ledger_id, account(1, 0), account(2, 0), 400_000);
    curr_txid += 1;
    if legacy {
        range_start = curr_txid; // legacy fee collector starts at the first tx after it is set
    }
    approve(env, ledger_id, account(1, 0), account(2, 0), 400_000);
    curr_txid += 1;

    wait_until_sync_is_completed(env, index_id, ledger_id);

    for fee_collector in &[fee_collector, new_fee_collector] {
        assert_eq!(
            icrc1_balance_of(env, ledger_id, *fee_collector),
            icrc1_balance_of(env, index_id, *fee_collector)
        );
    }

    expected[0]
        .1
        .push((range_start.into(), (curr_txid + 1).into()));

    assert_contain_same_elements(
        get_fee_collectors_ranges(env, index_id).ranges,
        expected.clone(),
    );

    if !legacy {
        set_fc_107_by_controller(env, ledger_id, Some(new_fee_collector));
        curr_txid += 1;
        range_start = curr_txid;
        transfer(env, ledger_id, account(1, 0), account(2, 0), 400_000);
        approve(env, ledger_id, account(1, 0), account(2, 0), 400_000);
        curr_txid += 2;

        wait_until_sync_is_completed(env, index_id, ledger_id);

        for fee_collector in &[fee_collector, new_fee_collector] {
            assert_eq!(
                icrc1_balance_of(env, ledger_id, *fee_collector),
                icrc1_balance_of(env, index_id, *fee_collector)
            );
        }

        expected[1]
            .1
            .push((range_start.into(), (curr_txid + 1).into()));

        assert_contain_same_elements(get_fee_collectors_ranges(env, index_id).ranges, expected);
    }
}

#[test]
fn test_fee_collector_ranges_legacy() {
    test_fee_collector_ranges(true);
}

#[cfg(not(feature = "icrc3_disabled"))]
#[test]
fn test_fee_collector_ranges_107() {
    test_fee_collector_ranges(false);
}

// This test uses the test ledger to test edge cases such as
// specifying the legacy fee collector after the 107 fee collector block
// was generated, which could not be tested with the prod ledger.
#[test]
fn test_fee_collector_107_edge_cases() {
    let env = &StateMachine::new();
    let ledger_id = install_icrc3_test_ledger(env);
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));
    let feecol_legacy = account(101, 0);
    let feecol_107 = account(102, 0);
    let regular_account = account(1, 0);

    let mut block_id = 0;

    let add_mint_block = |block_id: u64, fc: Option<Account>, fc_id: Option<u64>| {
        let mint = BlockBuilder::new(block_id, block_id).with_fee(Tokens::from(1u64));
        let mint = match fc {
            Some(fc) => mint.with_fee_collector(fc),
            None => mint,
        };
        let mint = match fc_id {
            Some(fc_id) => mint.with_fee_collector_block(fc_id),
            None => mint,
        };
        let mint = mint.mint(regular_account, Tokens::from(1000u64)).build();

        assert_eq!(
            Nat::from(block_id),
            add_block(env, ledger_id, &mint)
                .expect("error adding mint block to ICRC-3 test ledger")
        );
        wait_until_sync_is_completed(env, index_id, ledger_id);
        block_id + 1
    };

    let add_approve_block = |block_id: u64, fc: Option<Account>| {
        let approve = BlockBuilder::new(block_id, block_id).with_fee(Tokens::from(1u64));
        let approve = match fc {
            Some(fc) => approve.with_fee_collector(fc),
            None => approve,
        };
        let approve = approve
            .approve(regular_account, regular_account, Tokens::from(1u64))
            .build();

        assert_eq!(
            Nat::from(block_id),
            add_block(env, ledger_id, &approve)
                .expect("error adding approve block to ICRC-3 test ledger")
        );
        wait_until_sync_is_completed(env, index_id, ledger_id);
        block_id + 1
    };

    let add_fee_collector_107_block = |block_id: u64, fc: Option<Account>, mthd: Option<String>| {
        let fee_collector = BlockBuilder::<Tokens>::new(block_id, block_id)
            .with_btype(BTYPE_107.to_string())
            .fee_collector(fc, None, None, mthd)
            .build();

        assert_eq!(
            Nat::from(block_id),
            add_block(env, ledger_id, &fee_collector)
                .expect("error adding fee collector block to ICRC-3 test ledger")
        );
        wait_until_sync_is_completed(env, index_id, ledger_id);
        block_id + 1
    };

    // Legacy fee collector collects the fees
    block_id = add_mint_block(block_id, Some(feecol_legacy), None);
    assert_eq!(1, icrc1_balance_of(env, index_id, feecol_legacy));
    block_id = add_mint_block(block_id, None, Some(0));
    assert_eq!(2, icrc1_balance_of(env, index_id, feecol_legacy));

    // Legacy fee collector does not collect approve fees
    block_id = add_approve_block(block_id, Some(feecol_legacy));
    assert_eq!(2, icrc1_balance_of(env, index_id, feecol_legacy));

    // Set 107 fee collector to burn
    block_id = add_fee_collector_107_block(block_id, None, Some(SET_FEE_COL_107.to_string()));

    // No fees collected
    block_id = add_mint_block(block_id, None, None);
    assert_eq!(2, icrc1_balance_of(env, index_id, feecol_legacy));
    assert_eq!(0, icrc1_balance_of(env, index_id, feecol_107));

    // No fees collected with the legacy fee collector
    block_id = add_mint_block(block_id, Some(feecol_legacy), None);
    block_id = add_mint_block(block_id, None, Some(block_id - 1));
    assert_eq!(2, icrc1_balance_of(env, index_id, feecol_legacy));
    assert_eq!(0, icrc1_balance_of(env, index_id, feecol_107));

    // Set 107 fee collector to fee_collector_2
    block_id = add_fee_collector_107_block(block_id, Some(feecol_107), None);

    // New fee collector receives the fees
    block_id = add_mint_block(block_id, None, None);
    assert_eq!(2, icrc1_balance_of(env, index_id, feecol_legacy));
    assert_eq!(1, icrc1_balance_of(env, index_id, feecol_107));

    // Legacy fee collector has no effect, new fee collector receives the fees
    block_id = add_mint_block(block_id, Some(feecol_legacy), None);
    block_id = add_mint_block(block_id, None, Some(block_id - 1));
    assert_eq!(2, icrc1_balance_of(env, index_id, feecol_legacy));
    assert_eq!(3, icrc1_balance_of(env, index_id, feecol_107));

    // 107 fee collector is credited the approve fee
    block_id = add_approve_block(block_id, None);
    assert_eq!(2, icrc1_balance_of(env, index_id, feecol_legacy));
    assert_eq!(4, icrc1_balance_of(env, index_id, feecol_107));

    // Set 107 fee collector to burn
    block_id = add_fee_collector_107_block(block_id, None, Some(BTYPE_107_LEDGER_SET.to_string()));

    // No fees collected
    add_mint_block(block_id, None, None);
    assert_eq!(2, icrc1_balance_of(env, index_id, feecol_legacy));
    assert_eq!(4, icrc1_balance_of(env, index_id, feecol_107));
}

fn add_custom_block(
    env: &StateMachine,
    ledger_id: CanisterId,
    block_id: u64,
    btype: Option<&str>,
    tx_fields: Vec<(&str, ICRC3Value)>,
) {
    let mut block_builder = BlockBuilder::new(block_id, block_id).with_fee(Tokens::from(1u64));
    if let Some(btype) = btype {
        block_builder = block_builder.with_btype(String::from(btype));
    }
    let mut custom_tx_builder = block_builder.custom_transaction();
    for tx_field in tx_fields {
        custom_tx_builder = custom_tx_builder.add_field(tx_field.0, tx_field.1);
    }
    let block = custom_tx_builder.build();

    assert_eq!(
        Nat::from(block_id),
        add_block(env, ledger_id, &block).expect("error adding mint block to ICRC-3 test ledger")
    );
}

#[cfg(not(feature = "icrc3_disabled"))]
#[test]
fn test_fee_collector_107_with_ledger() {
    let env = &StateMachine::new();
    let feecol_legacy = account(101, 0);
    let feecol_107_1 = account(102, 0);
    let feecol_107_2 = account(103, 0);
    let sending_account = account(1, 0);
    let receiving_account = account(2, 0);
    let mut expected_balances = BTreeMap::new();
    let ledger_id = install_ledger_with_wasm(
        env,
        vec![(sending_account, 10_000_000)],
        default_archive_options(),
        Some(feecol_legacy),
        account(1000, 0).owner,
        ledger_mainnet_v5_wasm(),
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    let verify_fc_balances = |expected_balances: &BTreeMap<Account, u64>| {
        wait_until_sync_is_completed(env, index_id, ledger_id);
        for (fc_account, balance) in expected_balances {
            assert_eq!(*balance, icrc1_balance_of(env, index_id, *fc_account));
            assert_eq!(*balance, icrc1_balance_of(env, ledger_id, *fc_account));
        }
    };

    // Legacy fee collector collects the fees
    transfer(env, ledger_id, sending_account, receiving_account, 1);
    expected_balances.insert(feecol_legacy, FEE);
    expected_balances.insert(feecol_107_1, 0);
    expected_balances.insert(feecol_107_2, 0);
    verify_fc_balances(&expected_balances);

    // Legacy fee collector does not collect approve fees
    approve(env, ledger_id, sending_account, receiving_account, 1);
    verify_fc_balances(&expected_balances);

    // Set 107 fee collector to burn
    upgrade_ledger(env, ledger_id, None, false);

    // No fees are collected
    transfer(env, ledger_id, sending_account, receiving_account, 1);
    verify_fc_balances(&expected_balances);
    approve(env, ledger_id, sending_account, receiving_account, 1);
    verify_fc_balances(&expected_balances);

    set_fc_107_by_controller(env, ledger_id, Some(feecol_107_1));

    // The new fee collector collects all fees
    transfer(env, ledger_id, sending_account, receiving_account, 1);
    expected_balances.insert(feecol_107_1, expected_balances[&feecol_107_1] + FEE);
    verify_fc_balances(&expected_balances);
    approve(env, ledger_id, sending_account, receiving_account, 1);
    expected_balances.insert(feecol_107_1, expected_balances[&feecol_107_1] + FEE);
    verify_fc_balances(&expected_balances);

    set_fc_107_by_controller(env, ledger_id, Some(feecol_107_2));

    // The second new fee collector collects all fees
    transfer(env, ledger_id, sending_account, receiving_account, 1);
    expected_balances.insert(feecol_107_2, expected_balances[&feecol_107_2] + FEE);
    verify_fc_balances(&expected_balances);
    approve(env, ledger_id, sending_account, receiving_account, 1);
    expected_balances.insert(feecol_107_2, expected_balances[&feecol_107_2] + FEE);
    verify_fc_balances(&expected_balances);

    set_fc_107_by_controller(env, ledger_id, None);

    // No fees are collected
    transfer(env, ledger_id, sending_account, receiving_account, 1);
    verify_fc_balances(&expected_balances);
    approve(env, ledger_id, sending_account, receiving_account, 1);
    verify_fc_balances(&expected_balances);
}

#[test]
fn test_fee_collector_107_irregular_mthd() {
    const UNRECOGNIZED_MTHD_NAME: &str = "non_standard_fee_col_setter_endpoint_method_name";

    let env = &StateMachine::new();
    let ledger_id = install_icrc3_test_ledger(env);
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));
    let feecol_107 = account(102, 0);

    let tx_fields = vec![
        ("mthd", ICRC3Value::Text(UNRECOGNIZED_MTHD_NAME.to_string())),
        ("fee_collector", account_to_icrc3_value(&feecol_107)),
        ("ts", ICRC3Value::Nat(Nat::from(0u64))),
    ];

    add_custom_block(env, ledger_id, 0, Some(BTYPE_107), tx_fields);
    wait_until_sync_is_completed(env, index_id, ledger_id);
}

#[test]
fn test_fee_collector_107_op_instead_of_mthd() {
    let env = &StateMachine::new();
    let ledger_id = install_icrc3_test_ledger(env);
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));
    let feecol_107 = account(102, 0);

    let tx_fields = vec![
        ("op", ICRC3Value::Text(SET_FEE_COL_107.to_string())),
        ("fee_collector", account_to_icrc3_value(&feecol_107)),
        ("ts", ICRC3Value::Nat(Nat::from(0u64))),
    ];

    add_custom_block(env, ledger_id, 0, Some(BTYPE_107), tx_fields);
    let index_err_logs = wait_until_sync_is_completed_or_error(env, index_id, ledger_id)
        .expect_err(
            "unrecognized block with '107feecol' but tx.op instead of tx.mthd parsed successfully by index",
        );
    let expected_log_msg = "unknown fields";
    assert!(
        index_err_logs.contains(expected_log_msg),
        "index logs did not contain expected string '{}': {}",
        expected_log_msg,
        index_err_logs
    );
}

#[test]
fn test_block_with_no_btype_but_with_mthd() {
    let env = &StateMachine::new();
    let ledger_id = install_icrc3_test_ledger(env);
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    let tx_fields = vec![
        ("mthd", ICRC3Value::Text("107set_fee_collector".to_string())),
        ("ts", ICRC3Value::Nat(Nat::from(0u64))),
    ];

    add_custom_block(env, ledger_id, 0, None, tx_fields);
    let index_err_logs = wait_until_sync_is_completed_or_error(env, index_id, ledger_id)
        .expect_err(
            "unrecognized block with tx.mthd 'non_standard_mthd_name' parsed successfully by index",
        );
    let expected_log_msg =
        "Failed to deserialize transaction: No operation specified and/or unknown btype None";
    assert!(
        index_err_logs.contains(expected_log_msg),
        "index logs did not contain expected string '{}': {}",
        expected_log_msg,
        index_err_logs
    );
}

#[test]
fn test_block_with_no_btype_and_no_mthd() {
    let env = &StateMachine::new();
    let ledger_id = install_icrc3_test_ledger(env);
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    let tx_fields = vec![("ts", ICRC3Value::Nat(Nat::from(0u64)))];

    add_custom_block(env, ledger_id, 0, None, tx_fields);
    let index_err_logs = wait_until_sync_is_completed_or_error(env, index_id, ledger_id)
        .expect_err("unrecognized block with no btype and no tx.mthd parsed successfully by index");
    let expected_log_msg = "No operation specified and/or unknown btype";
    assert!(
        index_err_logs.contains(expected_log_msg),
        "index logs did not contain expected string '{}': {}",
        expected_log_msg,
        index_err_logs
    );
}
