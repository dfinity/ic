use crate::common::{
    default_archive_options, index_ng_wasm, install_index_ng, install_ledger,
    ledger_get_all_blocks, ledger_wasm, wait_until_sync_is_completed, ARCHIVE_TRIGGER_THRESHOLD,
    FEE, MAX_BLOCKS_FROM_ARCHIVE,
};
use candid::{Decode, Encode, Nat, Principal};
use ic_agent::identity::Identity;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index_ng::{
    FeeCollectorRanges, GetAccountTransactionsArgs, GetAccountTransactionsResponse,
    GetAccountTransactionsResult, GetBlocksResponse, IndexArg, InitArg as IndexInitArg,
    ListSubaccountsArgs, TransactionWithId, DEFAULT_MAX_BLOCKS_PER_RESPONSE,
};
use ic_icrc1_ledger::{ChangeFeeCollector, LedgerArgument, UpgradeArgs as LedgerUpgradeArgs};
use ic_icrc1_test_utils::{
    minter_identity, valid_transactions_strategy, ArgWithCaller, LedgerEndpointArg,
};
use ic_rosetta_test_utils::test_http_request_decoding_quota;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use icrc_ledger_types::icrc3::transactions::{Mint, Transaction, Transfer};
use num_traits::cast::ToPrimitive;
use proptest::test_runner::{Config as TestRunnerConfig, TestRunner};
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

mod common;

fn index_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-icrc1-index",
        &[],
    )
}

fn upgrade_ledger(
    env: &StateMachine,
    ledger_id: CanisterId,
    fee_collector_account: Option<Account>,
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
        accounts_overflow_trim_quantity: None,
        change_archive_options: None,
    }));
    env.upgrade_canister(ledger_id, ledger_wasm(), Encode!(&args).unwrap())
        .unwrap()
}

fn index_init_arg_without_interval(ledger_id: CanisterId) -> IndexInitArg {
    IndexInitArg {
        ledger_id: Principal::from(ledger_id),
        retrieve_blocks_from_ledger_interval_seconds: None,
    }
}

fn install_index(env: &StateMachine, ledger_id: CanisterId) -> CanisterId {
    let args = ic_icrc1_index::InitArgs { ledger_id };
    env.install_canister(index_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

fn account(owner: u64, subaccount: u128) -> Account {
    let mut sub: [u8; 32] = [0; 32];
    sub[..16].copy_from_slice(&subaccount.to_be_bytes());
    Account {
        owner: PrincipalId::new_user_test_id(owner).0,
        subaccount: Some(sub),
    }
}

fn icrc1_balance_of(env: &StateMachine, canister_id: CanisterId, account: Account) -> u64 {
    let res = env
        .execute_ingress(canister_id, "icrc1_balance_of", Encode!(&account).unwrap())
        .expect("Failed to send icrc1_balance_of")
        .bytes();
    Decode!(&res, Nat)
        .expect("Failed to decode icrc1_balance_of response")
        .0
        .to_u64()
        .expect("Balance must be a u64!")
}

fn index_get_blocks(
    env: &StateMachine,
    index_id: CanisterId,
    start: u64,
    length: u64,
) -> GetBlocksResponse {
    let req = GetBlocksRequest {
        start: start.into(),
        length: length.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
    let res = env
        .execute_ingress(index_id, "get_blocks", req)
        .expect("Failed to send get_blocks request")
        .bytes();
    Decode!(&res, GetBlocksResponse).expect("Failed to decode GetBlocksResponse")
}

// Returns all blocks in the index by iterating over the pages.
fn index_get_all_blocks(
    env: &StateMachine,
    index_id: CanisterId,
    start: u64,
    length: u64,
) -> GetBlocksResponse {
    let chain_length = index_get_blocks(env, index_id, 0, 0).chain_length;
    let mut res = GetBlocksResponse {
        blocks: vec![],
        chain_length,
    };
    while length > res.blocks.len() as u64 {
        let start = start + res.blocks.len() as u64;
        let length = length - res.blocks.len() as u64;
        let blocks = index_get_blocks(env, index_id, start, length).blocks;
        if blocks.is_empty() {
            return res;
        }
        res.blocks.extend(blocks);
    }
    res
}

fn icrc1_transfer(
    env: &StateMachine,
    ledger_id: CanisterId,
    caller: PrincipalId,
    arg: TransferArg,
) -> BlockIndex {
    let req = Encode!(&arg).expect("Failed to encode TransferArg");
    let res = env
        .execute_ingress_as(caller, ledger_id, "icrc1_transfer", req)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to transfer tokens. caller:{} arg:{:?} error:{}",
                caller, arg, e
            )
        })
        .bytes();
    Decode!(&res, Result<BlockIndex, TransferError>)
        .expect("Failed to decode Result<BlockIndex, TransferError>")
        .unwrap_or_else(|e| {
            panic!(
                "Failed to transfer tokens. caller:{} arg:{:?} error:{}",
                caller, arg, e
            )
        })
}

fn apply_arg_with_caller(
    env: &StateMachine,
    ledger_id: CanisterId,
    arg: ArgWithCaller,
) -> BlockIndex {
    match arg.arg {
        LedgerEndpointArg::ApproveArg(approve_arg) => icrc2_approve(
            env,
            ledger_id,
            PrincipalId(arg.caller.sender().unwrap()),
            approve_arg,
        ),
        LedgerEndpointArg::TransferArg(transfer_arg) => icrc1_transfer(
            env,
            ledger_id,
            PrincipalId(arg.caller.sender().unwrap()),
            transfer_arg,
        ),
    }
}

fn transfer(
    env: &StateMachine,
    ledger_id: CanisterId,
    from: Account,
    to: Account,
    amount: u64,
) -> BlockIndex {
    let Account { owner, subaccount } = from;
    let req = TransferArg {
        from_subaccount: subaccount,
        to,
        amount: amount.into(),
        created_at_time: None,
        fee: None,
        memo: None,
    };
    icrc1_transfer(env, ledger_id, owner.into(), req)
}

fn icrc2_approve(
    env: &StateMachine,
    ledger_id: CanisterId,
    caller: PrincipalId,
    arg: ApproveArgs,
) -> BlockIndex {
    let req = Encode!(&arg).expect("Failed to encode ApproveArgs");
    let res = env
        .execute_ingress_as(caller, ledger_id, "icrc2_approve", req)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to approve tokens. caller:{} arg:{:?} error:{}",
                caller, arg, e
            )
        })
        .bytes();
    Decode!(&res, Result<BlockIndex, ApproveError>)
        .expect("Failed to decode Result<BlockIndex, ApproveError>")
        .unwrap_or_else(|e| {
            panic!(
                "Failed to approve. caller:{} arg:{:?} error:{:?}",
                caller, arg, e
            )
        })
}

fn approve(
    env: &StateMachine,
    ledger: CanisterId,
    from: Account,
    spender: Account,
    amount: u64,
) -> u64 {
    let req = ApproveArgs {
        from_subaccount: from.subaccount,
        spender,
        amount: Nat::from(amount),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    icrc2_approve(env, ledger, PrincipalId(from.owner), req)
        .0
        .to_u64()
        .unwrap()
}

// Same as get_account_transactions but with the old index interface.
fn old_get_account_transactions(
    env: &StateMachine,
    index_id: CanisterId,
    account: Account,
    start: Option<u64>,
    max_results: u64,
) -> ic_icrc1_index::GetTransactionsResult {
    let req = ic_icrc1_index::GetAccountTransactionsArgs {
        account,
        start: start.map(|n| n.into()),
        max_results: max_results.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetAccountTransactionsArgs");
    let res = env
        .execute_ingress(index_id, "get_account_transactions", req)
        .expect("Failed to get_account_transactions")
        .bytes();
    Decode!(&res, ic_icrc1_index::GetTransactionsResult)
        .expect("Failed to decode GetTransactionsResult")
}

fn get_account_transactions(
    env: &StateMachine,
    index_id: CanisterId,
    account: Account,
    start: Option<u64>,
    max_results: u64,
) -> GetAccountTransactionsResponse {
    let req = GetAccountTransactionsArgs {
        account,
        start: start.map(|n| n.into()),
        max_results: max_results.into(),
    };
    let req = Encode!(&req).expect("Failed to encode GetAccountTransactionsArgs");
    let res = env
        .execute_ingress(index_id, "get_account_transactions", req)
        .expect("Failed to get_account_transactions")
        .bytes();
    Decode!(&res, GetAccountTransactionsResult)
        .expect("Failed to decode GetAccountTransactionsArgs")
        .expect("Failed to perform GetAccountTransactionsArgs")
}

fn list_subaccounts(
    env: &StateMachine,
    index: CanisterId,
    principal: PrincipalId,
    start: Option<Subaccount>,
) -> Vec<Subaccount> {
    Decode!(
        &env.execute_ingress_as(
            principal,
            index,
            "list_subaccounts",
            Encode!(&ListSubaccountsArgs {
                owner: principal.into(),
                start,
            })
            .unwrap()
        )
        .expect("failed to list_subaccounts")
        .bytes(),
        Vec<Subaccount>
    )
    .expect("failed to decode list_subaccounts response")
}

fn get_fee_collectors_ranges(env: &StateMachine, index: CanisterId) -> FeeCollectorRanges {
    Decode!(
        &env.execute_ingress(index, "get_fee_collectors_ranges", Encode!(&()).unwrap())
            .expect("failed to get_fee_collectors_ranges")
            .bytes(),
        FeeCollectorRanges
    )
    .expect("failed to decode get_fee_collectors_ranges response")
}

// Assert that the index canister contains the same blocks as the ledger.
#[track_caller]
fn assert_ledger_index_parity(env: &StateMachine, ledger_id: CanisterId, index_id: CanisterId) {
    let ledger_blocks = ledger_get_all_blocks(env, ledger_id, 0, u64::MAX);
    let index_blocks = index_get_all_blocks(env, index_id, 0, u64::MAX);
    assert_eq!(ledger_blocks.chain_length, index_blocks.chain_length);
    assert_eq!(ledger_blocks.blocks.len(), index_blocks.blocks.len());
    for (index, (ledger_block, index_block)) in ledger_blocks
        .blocks
        .into_iter()
        .zip(index_blocks.blocks.into_iter())
        .enumerate()
    {
        // If the hash matches then they are the same block.
        // We use the hash because nat64 and nat are not equal
        // but ICRC-3 doesn't have nat64.
        if ledger_block.hash() != index_block.hash() {
            panic!("Ledger block at index {} is different from the index block at the same index\nLedger block: {:?}\nIndex block:  {:?}", index, ledger_block, index_block);
        }
    }
}

#[cfg(any(feature = "get_blocks_disabled", feature = "icrc3_disabled"))]
#[test]
fn sanity_check_ledger() {
    // check that the endpoints are properly disabled in the Ledger
    let env = &StateMachine::new();
    let ledger_id = install_ledger(
        env,
        vec![],
        default_archive_options(),
        None,
        minter_identity().sender().unwrap(),
    );
    #[cfg(feature = "get_blocks_disabled")]
    {
        let req = Encode!(&GetBlocksRequest {
            start: Nat::from(0u64),
            length: Nat::from(0u64)
        })
        .unwrap();
        match env
            .query(ledger_id, "get_blocks", req)
            .map_err(|err| err.code())
        {
            Err(ic_state_machine_tests::ErrorCode::CanisterMethodNotFound) => {}
            _ => panic!(
                "{}",
                "get_blocks not disabled in the Ledger! (call result: {r:?})"
            ),
        }
    }
    #[cfg(feature = "icrc3_disabled")]
    {
        let req = Encode!(&vec![GetBlocksRequest {
            start: Nat::from(0u64),
            length: Nat::from(0u64)
        }])
        .unwrap();
        match env
            .query(ledger_id, "icrc3_get_blocks", req)
            .map_err(|err| err.code())
        {
            Err(ic_state_machine_tests::ErrorCode::CanisterMethodNotFound) => {}
            _ => panic!(
                "{}",
                "icrc3_get_blocks not disabled in the Ledger! (call result: {r:?})"
            ),
        }
    }
}

#[test]
fn test_ledger_growing() {
    // check that the index canister can incrementally get the blocks from the ledger.

    let initial_balances: Vec<_> = vec![(account(1, 0), 1_000_000_000_000)];
    let env = &StateMachine::new();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        default_archive_options(),
        None,
        minter_identity().sender().unwrap(),
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    // Test initial mint block.
    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // Test first transfer block.
    transfer(env, ledger_id, account(1, 0), account(2, 0), 1);
    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // Test multiple blocks.
    for (from, to, amount) in [
        (account(1, 0), account(1, 1), 1_000_000),
        (account(1, 0), account(2, 0), 1_000_001),
        (account(1, 1), account(2, 0), 1),
    ] {
        transfer(env, ledger_id, from, to, amount);
    }
    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // Test archived blocks.
    for _i in 0..(ARCHIVE_TRIGGER_THRESHOLD as usize + 1) {
        transfer(env, ledger_id, account(1, 0), account(1, 2), 1);
    }
    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);

    // Test block with an approval.
    approve(env, ledger_id, account(1, 0), account(2, 0), 100000);
    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);
    assert_eq!(
        icrc1_balance_of(env, ledger_id, account(1, 0)),
        icrc1_balance_of(env, index_id, account(1, 0))
    );
}

#[test]
fn test_archive_indexing() {
    let env = &StateMachine::new();
    let minter = minter_identity().sender().unwrap();
    let ledger_id = install_ledger(env, vec![], default_archive_options(), None, minter);
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    // Test indexing archive by forcing the ledger to archive some transactions
    // and by having enough transactions such that the index must use archive
    // pagination.
    for i in 0..(ARCHIVE_TRIGGER_THRESHOLD + MAX_BLOCKS_FROM_ARCHIVE * 4) {
        transfer(env, ledger_id, minter.into(), account(i, 0), i * 1_000_000);
    }

    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);
}

#[track_caller]
fn assert_tx_eq(tx1: &Transaction, tx2: &Transaction) {
    if let Some(burn1) = &tx1.burn {
        let burn2 = tx2.burn.as_ref().unwrap();
        assert_eq!(burn1.amount, burn2.amount, "amount");
        assert_eq!(burn1.from, burn2.from, "from");
        assert_eq!(burn1.memo, burn2.memo, "memo");
    } else if let Some(mint1) = &tx1.mint {
        let mint2 = tx2.mint.as_ref().unwrap();
        assert_eq!(mint1.amount, mint2.amount, "amount");
        assert_eq!(mint1.memo, mint2.memo, "memo");
        assert_eq!(mint1.to, mint2.to, "to");
    } else if let Some(transfer1) = &tx1.transfer {
        let transfer2 = tx2.transfer.as_ref().unwrap();
        assert_eq!(transfer1.amount, transfer2.amount, "amount");
        assert_eq!(transfer1.fee, transfer2.fee, "fee");
        assert_eq!(transfer1.from, transfer2.from, "from");
        assert_eq!(transfer1.memo, transfer2.memo, "memo");
        assert_eq!(transfer1.to, transfer2.to, "to");
    } else {
        panic!("Something is wrong with tx1: {:?}", tx1);
    }
}

// Checks that two txs are equal minus the fields set by the ledger (e.g. timestamp).
#[track_caller]
fn assert_tx_with_id_eq(tx1: &TransactionWithId, tx2: &TransactionWithId) {
    assert_eq!(tx1.id, tx2.id, "id");
    assert_tx_eq(&tx1.transaction, &tx2.transaction);
}

#[track_caller]
fn assert_txs_with_id_eq(txs1: Vec<TransactionWithId>, txs2: Vec<TransactionWithId>) {
    assert_eq!(
        txs1.len(),
        txs2.len(),
        "Different number of transactions!\ntxs1: {:?}\ntxs2: {:?}",
        txs1.iter().map(|tx| tx.id.clone()).collect::<Vec<Nat>>(),
        txs2.iter().map(|tx| tx.id.clone()).collect::<Vec<Nat>>()
    );
    for i in 0..txs1.len() {
        assert_tx_with_id_eq(&txs1[i], &txs2[i]);
    }
}

#[test]
fn test_get_account_transactions() {
    let initial_balances: Vec<_> = vec![(account(1, 0), 1_000_000_000_000)];
    let env = &StateMachine::new();
    let minter = minter_identity().sender().unwrap();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        default_archive_options(),
        None,
        minter,
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    // List of the transactions that the test is going to add. This exists to make
    // the test easier to read.
    let tx0 = TransactionWithId {
        id: 0u8.into(),
        transaction: Transaction::mint(
            Mint {
                to: account(1, 0),
                amount: 1_000_000_000_000_u64.into(),
                created_at_time: None,
                memo: None,
            },
            0,
        ),
    };
    let tx1 = TransactionWithId {
        id: 1u8.into(),
        transaction: Transaction::transfer(
            Transfer {
                from: account(1, 0),
                to: account(2, 0),
                spender: None,
                amount: 1_000_000u32.into(),
                fee: Some(FEE.into()),
                created_at_time: None,
                memo: None,
            },
            0,
        ),
    };
    let tx2 = TransactionWithId {
        id: 2u8.into(),
        transaction: Transaction::transfer(
            Transfer {
                from: account(1, 0),
                to: account(2, 0),
                spender: None,
                amount: 2_000_000u32.into(),
                fee: Some(FEE.into()),
                created_at_time: None,
                memo: None,
            },
            0,
        ),
    };
    let tx3 = TransactionWithId {
        id: 3u8.into(),
        transaction: Transaction::transfer(
            Transfer {
                from: account(2, 0),
                to: account(1, 1),
                spender: None,
                amount: 1_000_000u32.into(),
                fee: Some(FEE.into()),
                created_at_time: None,
                memo: None,
            },
            0,
        ),
    };

    ////////////
    //// Phase 1: only 1 mint to (1, 0).
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // Account (1, 0) has one mint.
    let actual_txs =
        get_account_transactions(env, index_id, account(1, 0), None, u64::MAX).transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx0.clone()]);

    // Account (2, 0) has no transactions.
    let actual_txs =
        get_account_transactions(env, index_id, account(2, 0), None, u64::MAX).transactions;
    assert_txs_with_id_eq(actual_txs, vec![]);

    /////////////
    //// Phase 2: transfer from (1, 0) to (2, 0).
    transfer(env, ledger_id, account(1, 0), account(2, 0), 1_000_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // Account (1, 0) has one transfer and one mint.
    let actual_txs =
        get_account_transactions(env, index_id, account(1, 0), None, u64::MAX).transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx1.clone(), tx0.clone()]);

    // Account (2, 0) has one transfer only.
    let actual_txs =
        get_account_transactions(env, index_id, account(2, 0), None, u64::MAX).transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx1.clone()]);

    // Account (3, 0), (1, 1) and (2, 1) have no transactions.
    for account in [account(3, 0), account(1, 1), account(2, 1)] {
        let actual_txs =
            get_account_transactions(env, index_id, account, None, u64::MAX).transactions;
        assert_txs_with_id_eq(actual_txs, vec![]);
    }

    ////////////
    //// Phase 3: transfer from (1, 0) to (2, 0)
    ////          transfer from (2, 0) to (1, 1).
    transfer(env, ledger_id, account(1, 0), account(2, 0), 2_000_000);
    transfer(env, ledger_id, account(2, 0), account(1, 1), 1_000_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // Account (1, 0) has two transfers and one mint.
    let actual_txs =
        get_account_transactions(env, index_id, account(1, 0), None, u64::MAX).transactions;
    let expected_txs = vec![tx2.clone(), tx1.clone(), tx0];
    assert_txs_with_id_eq(actual_txs, expected_txs);

    // Account (2, 0) has three transfers.
    let actual_txs =
        get_account_transactions(env, index_id, account(2, 0), None, u64::MAX).transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx3.clone(), tx2, tx1]);

    // Account (1, 1) has one transfer.
    let actual_txs =
        get_account_transactions(env, index_id, account(1, 1), None, u64::MAX).transactions;
    assert_txs_with_id_eq(actual_txs, vec![tx3]);
}

#[test]
fn test_get_account_transactions_start_length() {
    // 10 mint transactions to index for the same account.
    let initial_balances: Vec<_> = (0..10).map(|i| (account(1, 0), i * 10_000)).collect();
    let env = &StateMachine::new();
    let minter = minter_identity().sender().unwrap();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        default_archive_options(),
        None,
        minter,
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));
    let expected_txs: Vec<_> = (0..10u32)
        .map(|i| TransactionWithId {
            id: i.into(),
            transaction: Transaction::mint(
                Mint {
                    to: account(1, 0),
                    amount: (i * 10_000).into(),
                    created_at_time: None,
                    memo: None,
                },
                0,
            ),
        })
        .collect();

    wait_until_sync_is_completed(env, index_id, ledger_id);

    // Get the most n recent transaction with start set to `None`.
    for n in 1..10 {
        let actual_txs =
            get_account_transactions(env, index_id, account(1, 0), None, n).transactions;
        let expected_txs: Vec<_> = (0..10)
            .rev()
            .take(n as usize)
            .map(|i| expected_txs[i as usize].clone())
            .collect();
        assert_txs_with_id_eq(actual_txs, expected_txs.clone());
    }

    // Get the most n recent transaction with start set to some index.
    for start in 0..=10 {
        for n in 1..(10 - start) {
            let expected_txs: Vec<_> = (0..start)
                .rev()
                .take(n as usize)
                .map(|i| expected_txs[i as usize].clone())
                .collect();
            let actual_txs =
                get_account_transactions(env, index_id, account(1, 0), Some(start), n).transactions;
            assert_txs_with_id_eq(actual_txs, expected_txs);
        }
    }
}

#[test]
fn test_get_account_transactions_pagination() {
    // 10_000 mint transactions to index for the same account.
    let initial_balances: Vec<_> = (0..10_000).map(|i| (account(1, 0), i * 10_000)).collect();
    let env = &StateMachine::new();
    let minter = minter_identity().sender().unwrap();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        default_archive_options(),
        None,
        minter,
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    wait_until_sync_is_completed(env, index_id, ledger_id);

    // The index get_account_transactions endpoint returns batches of transactions
    // in descending order of index, i.e. the first index returned in the result
    // is the biggest id in the result while the last index is the lowest.
    // The start parameter of the function is the last seen index and the result
    // will contain the next batch of indexes after that one.

    let mut start = None; // The start id of the next batch request.

    // If start == `Some(0)` then we can stop as there is no index that is smaller
    // than 0.
    while start != Some(0) {
        let res = get_account_transactions(env, index_id, account(1, 0), start, u64::MAX);

        // If the batch is empty then get_account_transactions
        // didn't return the expected batch for the given start.
        if res.transactions.is_empty() {
            panic!(
                "get_account_transactions({:?}, u64::MAX) returned an empty batch!",
                start
            );
        }

        let mut last_seen_txid = start;
        for TransactionWithId { id, transaction } in &res.transactions {
            let id = id.0.to_u64().unwrap();

            // Transactions ids must be unique and in descending order.
            if let Some(last_seen_txid) = last_seen_txid {
                assert!(id < last_seen_txid);
            }
            last_seen_txid = Some(id);

            // Check the transaction itself.
            assert_tx_eq(
                &Transaction {
                    kind: "mint".into(),
                    burn: None,
                    mint: Some(Mint {
                        to: account(1, 0),
                        amount: (id * 10_000).into(),
                        created_at_time: None,
                        memo: None,
                    }),
                    transfer: None,
                    approve: None,
                    timestamp: 0,
                },
                transaction,
            );
        }

        // !res.transactions.is_empty() and the check on descending
        // order guarantee that last_seen_txid < start.
        start = last_seen_txid;
    }
}

#[test]
fn test_icrc1_balance_of() {
    // 1 case only because the test is expensive to run.
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    let now = SystemTime::now();
    let minter = Arc::new(minter_identity());
    let minter_principal = minter.sender().unwrap();
    runner
        .run(
            &(valid_transactions_strategy(minter, FEE, 100, now),),
            |(transactions,)| {
                let env = &StateMachine::new();
                // To match the time of the valid transaction strategy we have to align the StateMachine time with the generated strategy
                env.set_time(now);
                let ledger_id = install_ledger(
                    env,
                    vec![],
                    default_archive_options(),
                    None,
                    minter_principal,
                );
                let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

                for arg_with_caller in &transactions {
                    apply_arg_with_caller(env, ledger_id, arg_with_caller.clone());
                }
                wait_until_sync_is_completed(env, index_id, ledger_id);

                for account in transactions
                    .iter()
                    .flat_map(|tx| tx.accounts())
                    .collect::<HashSet<Account>>()
                {
                    assert_eq!(
                        icrc1_balance_of(env, ledger_id, account),
                        icrc1_balance_of(env, index_id, account)
                    );
                }
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_list_subaccounts() {
    // For this test, we add minting operations for some principals:
    // - The principal 1 has one account with the last possible
    // subaccount.
    // - The principal 2 has a number of subaccounts equals to
    // two times the DEFAULT_MAX_BLOCKS_PER_RESPONSE. Therefore fetching
    // its subaccounts will trigger pagination.
    // - The principal 3 has one account with the first possible
    // subaccount.
    // - The principal 4 has one account with the default subaccount,
    // which should map to [0;32] in the index.

    let account_1 = Account {
        owner: PrincipalId::new_user_test_id(1).into(),
        subaccount: Some([u8::MAX; 32]),
    };
    let accounts_2: Vec<_> = (0..(DEFAULT_MAX_BLOCKS_PER_RESPONSE * 2))
        .map(|i| account(2, i as u128))
        .collect();
    let account_3 = account(3, 0);
    let account_4 = Account {
        owner: PrincipalId::new_user_test_id(4).into(),
        subaccount: None,
    };

    let mut initial_balances: Vec<_> = vec![
        (account_1, 10_000),
        (account_3, 10_000),
        (account_4, 40_000),
    ];
    initial_balances.extend(accounts_2.iter().map(|account| (*account, 10_000)));

    let env = &StateMachine::new();
    let minter = minter_identity();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        default_archive_options(),
        None,
        minter.sender().unwrap(),
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    wait_until_sync_is_completed(env, index_id, ledger_id);

    // List account_1.owner subaccounts when no starting subaccount is specified.
    assert_eq!(
        vec![*account_1.effective_subaccount()],
        list_subaccounts(env, index_id, PrincipalId(account_1.owner), None)
    );

    // List account_3.owner subaccounts when no starting subaccount is specified.
    assert_eq!(
        vec![*account_3.effective_subaccount()],
        list_subaccounts(env, index_id, PrincipalId(account_3.owner), None)
    );

    // List account_3.owner subaccounts when an existing starting subaccount is specified but no subaccount is in that range.
    assert!(list_subaccounts(
        env,
        index_id,
        PrincipalId(account_3.owner),
        Some(*account(3, 1).effective_subaccount())
    )
    .is_empty());

    // List account_4.owner subaccounts should return the default subaccount
    // mapped to [0;32].
    assert_eq!(
        vec![[0; 32]],
        list_subaccounts(env, index_id, PrincipalId(account_4.owner), None)
    );

    // account_2.owner should have two batches of subaccounts.
    let principal_2 = accounts_2.first().unwrap().owner;
    let batch_1 = list_subaccounts(env, index_id, PrincipalId(principal_2), None);
    let expected_batch_1: Vec<_> = accounts_2
        .iter()
        .take(DEFAULT_MAX_BLOCKS_PER_RESPONSE as usize)
        .map(|account| *account.effective_subaccount())
        .collect();
    assert_eq!(expected_batch_1, batch_1);

    let batch_2 = list_subaccounts(
        env,
        index_id,
        PrincipalId(principal_2),
        Some(*batch_1.last().unwrap()),
    );
    let expected_batch_2: Vec<_> = accounts_2
        .iter()
        .skip(DEFAULT_MAX_BLOCKS_PER_RESPONSE as usize)
        .take(DEFAULT_MAX_BLOCKS_PER_RESPONSE as usize)
        .map(|account| *account.effective_subaccount())
        .collect();
    assert_eq!(expected_batch_2, batch_2);
}

#[test]
fn test_post_upgrade_start_timer() {
    let env = &StateMachine::new();
    let minter = minter_identity();
    let ledger_id = install_ledger(
        env,
        vec![(account(1, 0), 10_000_000)],
        default_archive_options(),
        None,
        minter.sender().unwrap(),
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    wait_until_sync_is_completed(env, index_id, ledger_id);

    env.upgrade_canister(
        index_id,
        index_ng_wasm(),
        Encode!(&None::<IndexArg>).unwrap(),
    )
    .unwrap();

    // Check that the index syncs the new block (wait_until_sync_is_completed fails
    // if the new block is not synced).
    transfer(env, ledger_id, account(1, 0), account(2, 0), 2_000_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);
}

#[test]
fn test_oldest_tx_id() {
    let env = &StateMachine::new();
    let minter = minter_identity().sender().unwrap();
    let ledger_id = install_ledger(
        env,
        vec![(account(1, 0), 10_000_000)],
        default_archive_options(),
        None,
        minter,
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    env.advance_time(Duration::from_secs(60));
    env.tick();

    // account(2, 0) and account(3, 0) have no transactions so oldest_tx_id should be `None`.
    for account in [account(2, 0), account(3, 0)] {
        let oldest_tx_id =
            get_account_transactions(env, index_id, account, None, u64::MAX).oldest_tx_id;
        assert_eq!(None, oldest_tx_id);
    }

    // account(1, 0) oldest_tx_id is 0, i.e. the mint at ledger init.
    let oldest_tx_id =
        get_account_transactions(env, index_id, account(1, 0), None, u64::MAX).oldest_tx_id;
    assert_eq!(Some(0u8.into()), oldest_tx_id);

    ////
    // Add one block for account(1, 0) and account(2, 0).
    transfer(env, ledger_id, account(1, 0), account(2, 0), 1_000_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // account(1, 0) oldest_tx_id is still 0.
    let oldest_tx_id =
        get_account_transactions(env, index_id, account(1, 0), None, u64::MAX).oldest_tx_id;
    assert_eq!(Some(0u8.into()), oldest_tx_id);

    // account(2, 0) oldest_tx_id is 1, i.e. the new transfer.
    let oldest_tx_id =
        get_account_transactions(env, index_id, account(2, 0), None, u64::MAX).oldest_tx_id;
    assert_eq!(Some(1u8.into()), oldest_tx_id);

    // account(3, 0) oldest_tx_id is still `None`.
    let oldest_tx_id =
        get_account_transactions(env, index_id, account(3, 0), None, u64::MAX).oldest_tx_id;
    assert_eq!(None, oldest_tx_id);

    ////
    // Add one block for account(1, 0) and account(2, 0).
    // Add the first block for account(3, 0).
    transfer(env, ledger_id, account(1, 0), account(2, 0), 2_000_000);
    transfer(env, ledger_id, account(1, 0), account(3, 0), 3_000_000);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // account(1, 0) oldest_tx_id is still 0.
    let oldest_tx_id =
        get_account_transactions(env, index_id, account(1, 0), None, u64::MAX).oldest_tx_id;
    assert_eq!(Some(0u8.into()), oldest_tx_id);

    // account(2, 0) oldest_tx_id is still 1.
    let oldest_tx_id =
        get_account_transactions(env, index_id, account(2, 0), None, u64::MAX).oldest_tx_id;
    assert_eq!(Some(1u8.into()), oldest_tx_id);

    // account(3, 0) oldest_tx_id is 3, i.e. the last block index.
    let oldest_tx_id =
        get_account_transactions(env, index_id, account(3, 0), None, u64::MAX).oldest_tx_id;
    assert_eq!(Some(3u8.into()), oldest_tx_id);

    // There should be no fee collector.
    assert_eq!(get_fee_collectors_ranges(env, index_id).ranges, vec![]);
}

#[track_caller]
fn assert_contain_same_elements<T: Debug + Eq + Hash>(vl: Vec<T>, vr: Vec<T>) {
    assert_eq!(
        vl.iter().collect::<HashSet<_>>(),
        vr.iter().collect::<HashSet<_>>(),
    )
}

#[test]
fn test_fee_collector() {
    let env = &StateMachine::new();
    let fee_collector = account(42, 0);
    let minter = minter_identity().sender().unwrap();
    let ledger_id = install_ledger(
        env,
        vec![(account(1, 0), 10_000_000)], // txid: 0
        default_archive_options(),
        Some(fee_collector),
        minter,
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    assert_eq!(
        icrc1_balance_of(env, ledger_id, fee_collector),
        icrc1_balance_of(env, index_id, fee_collector)
    );

    transfer(env, ledger_id, account(1, 0), account(2, 0), 100_000); // txid: 1
    transfer(env, ledger_id, account(1, 0), account(3, 0), 200_000); // txid: 2
    transfer(env, ledger_id, account(1, 0), account(2, 0), 300_000); // txid: 3

    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, fee_collector),
        icrc1_balance_of(env, index_id, fee_collector)
    );

    assert_contain_same_elements(
        get_fee_collectors_ranges(env, index_id).ranges,
        vec![(fee_collector, vec![(0u8.into(), 4u8.into())])],
    );

    // Remove the fee collector to burn some transactions fees.
    upgrade_ledger(env, ledger_id, None);

    transfer(env, ledger_id, account(1, 0), account(2, 0), 400_000); // txid: 4
    transfer(env, ledger_id, account(1, 0), account(2, 0), 500_000); // txid: 5

    wait_until_sync_is_completed(env, index_id, ledger_id);

    assert_eq!(
        icrc1_balance_of(env, ledger_id, fee_collector),
        icrc1_balance_of(env, index_id, fee_collector)
    );

    assert_contain_same_elements(
        get_fee_collectors_ranges(env, index_id).ranges,
        vec![(fee_collector, vec![(0u8.into(), 4u8.into())])],
    );

    // Add a new fee collector different from the first one.
    let new_fee_collector = account(42, 42);
    upgrade_ledger(env, ledger_id, Some(new_fee_collector));

    transfer(env, ledger_id, account(1, 0), account(2, 0), 400_000); // txid: 6

    wait_until_sync_is_completed(env, index_id, ledger_id);

    for fee_collector in &[fee_collector, new_fee_collector] {
        assert_eq!(
            icrc1_balance_of(env, ledger_id, *fee_collector),
            icrc1_balance_of(env, index_id, *fee_collector)
        );
    }

    assert_contain_same_elements(
        get_fee_collectors_ranges(env, index_id).ranges,
        vec![
            (new_fee_collector, vec![(6u8.into(), 7u8.into())]),
            (fee_collector, vec![(0u8.into(), 4u8.into())]),
        ],
    );

    // Add back the original fee_collector and make a couple of transactions again.
    upgrade_ledger(env, ledger_id, Some(fee_collector));

    transfer(env, ledger_id, account(1, 0), account(2, 0), 400_000); // txid: 7
    transfer(env, ledger_id, account(1, 0), account(2, 0), 400_000); // txid: 8

    wait_until_sync_is_completed(env, index_id, ledger_id);

    for fee_collector in &[fee_collector, new_fee_collector] {
        assert_eq!(
            icrc1_balance_of(env, ledger_id, *fee_collector),
            icrc1_balance_of(env, index_id, *fee_collector)
        );
    }

    assert_contain_same_elements(
        get_fee_collectors_ranges(env, index_id).ranges,
        vec![
            (new_fee_collector, vec![(6u8.into(), 7u8.into())]),
            (
                fee_collector,
                vec![(0u8.into(), 4u8.into()), (7u8.into(), 9u8.into())],
            ),
        ],
    );
}

#[test]
fn test_get_account_transactions_vs_old_index() {
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    let now = SystemTime::now();
    let minter = Arc::new(minter_identity());
    let minter_principal = minter.sender().unwrap();
    runner
        .run(
            &(valid_transactions_strategy(minter, FEE, 10, now),),
            |(transactions,)| {
                let env = &StateMachine::new();
                // To match the time of the valid transaction strategy we have to align the StateMachine time with the generated strategy
                env.set_time(now);
                let ledger_id = install_ledger(
                    env,
                    vec![],
                    default_archive_options(),
                    None,
                    minter_principal,
                );
                let index_ng_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));
                let index_id = install_index(env, ledger_id);

                for arg_with_caller in &transactions {
                    apply_arg_with_caller(env, ledger_id, arg_with_caller.clone());
                }
                wait_until_sync_is_completed(env, index_ng_id, ledger_id);

                for account in transactions
                    .iter()
                    .flat_map(|tx| tx.accounts())
                    .collect::<HashSet<Account>>()
                {
                    assert_eq!(
                        old_get_account_transactions(env, index_id, account, None, u64::MAX),
                        old_get_account_transactions(env, index_ng_id, account, None, u64::MAX),
                    );
                }

                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_upgrade_index_to_index_ng() {
    let mut runner = TestRunner::new(TestRunnerConfig {
        cases: 1,
        max_shrink_iters: 0,
        ..Default::default()
    });
    let now = SystemTime::now();
    let minter = Arc::new(minter_identity());
    let minter_principal = minter.sender().unwrap();
    runner
        .run(
            &(valid_transactions_strategy(minter, FEE, 10, now),),
            |(transactions,)| {
                let env = &StateMachine::new();
                // To match the time of the valid transaction strategy we have to align the StateMachine time with the generated strategy
                env.set_time(now);
                let ledger_id = install_ledger(
                    env,
                    vec![],
                    default_archive_options(),
                    None,
                    minter_principal,
                );
                let index_ng_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));
                let index_id = install_index(env, ledger_id);

                for arg_with_caller in &transactions {
                    apply_arg_with_caller(env, ledger_id, arg_with_caller.clone());
                }

                env.tick();
                wait_until_sync_is_completed(env, index_ng_id, ledger_id);

                // Upgrade the index canister to the index-ng.
                let arg = Encode!(&None::<IndexArg>).unwrap();
                env.upgrade_canister(index_id, index_ng_wasm(), arg)
                    .unwrap();

                wait_until_sync_is_completed(env, index_id, ledger_id);

                // Check that the old get_account_transactions still works and return
                // the right data.
                for account in transactions
                    .iter()
                    .flat_map(|tx| tx.accounts())
                    .collect::<HashSet<Account>>()
                {
                    assert_eq!(
                        old_get_account_transactions(env, index_id, account, None, u64::MAX),
                        old_get_account_transactions(env, index_ng_id, account, None, u64::MAX),
                    );
                }
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_index_ledger_coherence() {
    let mut runner = TestRunner::new(TestRunnerConfig::with_cases(1));
    let now = SystemTime::now();
    let minter = Arc::new(minter_identity());
    let minter_principal = minter.sender().unwrap();
    runner
        .run(
            &(valid_transactions_strategy(minter, FEE, 50, now),),
            |(transactions,)| {
                let env = &StateMachine::new();
                // To match the time of the valid transaction strategy we have to align the StateMachine time with the generated strategy
                env.set_time(now);
                let ledger_id = install_ledger(
                    env,
                    vec![],
                    default_archive_options(),
                    None,
                    minter_principal,
                );
                let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

                for arg_with_caller in &transactions {
                    apply_arg_with_caller(env, ledger_id, arg_with_caller.clone());
                }
                wait_until_sync_is_completed(env, index_id, ledger_id);
                assert_ledger_index_parity(env, ledger_id, index_id);
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn test_principal_subaccounts() {
    let initial_balances: Vec<_> = vec![(account(1, 0), 1_000_000_000_000)];
    let env = &StateMachine::new();
    let minter = minter_identity().sender().unwrap();
    let ledger_id = install_ledger(
        env,
        initial_balances,
        default_archive_options(),
        None,
        minter,
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    // Test initial mint block.
    wait_until_sync_is_completed(env, index_id, ledger_id);
    assert_ledger_index_parity(env, ledger_id, index_id);

    let subaccounts = list_subaccounts(env, index_id, PrincipalId(account(1, 0).owner), None);
    // There should exist a subaccount for the principal of account (1,0)
    assert_eq!(subaccounts.len(), 1);

    // Transfer some tokens to a different subaccount
    transfer(env, ledger_id, account(1, 0), account(1, 1), FEE + 1);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    let subaccounts = list_subaccounts(env, index_id, PrincipalId(account(1, 0).owner), None);

    // There should exist two subaccounts now for the principal of account (1,0)
    assert_eq!(subaccounts.len(), 2);
    assert!(subaccounts.contains(&account(1, 1).subaccount.unwrap()));

    // Reduce balance of subaccount 1 to 0
    transfer(env, ledger_id, account(1, 1), account(1, 2), 1);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // The balance of subaccount 1 should now be 0
    assert_eq!(icrc1_balance_of(env, ledger_id, account(1, 1)), 0);

    let subaccounts = list_subaccounts(env, index_id, PrincipalId(account(1, 0).owner), None);

    // There should exist three subaccounts now for the principal of account (1,0)
    assert_eq!(subaccounts.len(), 3);
    assert!(subaccounts.contains(&account(1, 1).subaccount.unwrap()));
    assert!(subaccounts.contains(&account(1, 2).subaccount.unwrap()));

    // Make an approve transaction with the spender being a completly new account
    approve(env, ledger_id, account(1, 0), account(2, 1), 100);
    wait_until_sync_is_completed(env, index_id, ledger_id);

    // The balance of the new account should be 0. Approve transactions do not change the balance of the spender
    assert_eq!(icrc1_balance_of(env, ledger_id, account(2, 1)), 0);

    let subaccounts = list_subaccounts(env, index_id, PrincipalId(account(2, 0).owner), None);

    // There should exist one subaccount for the principal of account (2,0)
    assert_eq!(subaccounts.len(), 1);
    // The subaccount 1 should show up in a `list_subaccount` query although it has only been involved in an Approve transaction
    assert!(subaccounts.contains(&account(2, 1).subaccount.unwrap()));
}

#[test]
fn test_index_http_request_decoding_quota() {
    let env = &StateMachine::new();
    let ledger_id = install_ledger(
        env,
        vec![],
        default_archive_options(),
        None,
        minter_identity().sender().unwrap(),
    );
    let index_id = install_index_ng(env, index_init_arg_without_interval(ledger_id));

    wait_until_sync_is_completed(env, index_id, ledger_id);

    test_http_request_decoding_quota(env, index_id);
}

mod metrics {
    use crate::index_wasm;
    use candid::Principal;
    use ic_icrc1_index_ng::InitArg;

    #[test]
    fn should_export_total_memory_usage_bytes_metrics() {
        ic_icrc1_ledger_sm_tests::metrics::assert_existence_of_index_total_memory_bytes_metric(
            index_wasm(),
            encode_init_args,
        );
    }

    fn encode_init_args(ledger_id: Principal) -> InitArg {
        InitArg {
            ledger_id,
            retrieve_blocks_from_ledger_interval_seconds: None,
        }
    }
}
