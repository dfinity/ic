use crate::{AccountIdentifier, Ledger, StorableAllowance, balances_len};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_canister_core::{
    archive::Archive,
    ledger as core_ledger,
    ledger::{LedgerContext, LedgerTransaction, TxApplyError},
};
use ic_ledger_core::{
    approvals::Allowance,
    balances::BalancesStore,
    block::{BlockIndex, BlockType},
    timestamp::TimeStamp,
    tokens::Tokens,
};
use ic_stable_structures::Storable;
use icp_ledger::{
    ArchiveOptions, Block, DEFAULT_TRANSFER_FEE, Memo, Operation, PaymentError, Transaction,
    TransferError, apply_operation,
};
use proptest::prelude::{any, prop_assert_eq, proptest};
use proptest::strategy::Strategy;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

fn test_account_id(n: u64) -> AccountIdentifier {
    PrincipalId::new_user_test_id(n).into()
}

fn tokens(n: u64) -> Tokens {
    Tokens::from_e8s(n)
}

fn ts(n: u64) -> TimeStamp {
    TimeStamp::from_nanos_since_unix_epoch(n)
}

#[test]
fn balances_remove_accounts_with_zero_balance() {
    let mut ctx = Ledger::default();
    let canister = CanisterId::from_u64(7).get().into();
    let target_canister = CanisterId::from_u64(13).into();
    let now = ts(123456789);
    apply_operation(
        &mut ctx,
        &Operation::Mint {
            to: canister,
            amount: Tokens::from_e8s(1000),
        },
        now,
    )
    .unwrap();
    // verify that an account entry exists for the `canister`
    assert_eq!(
        ctx.balances().store.get_balance(&canister),
        Some(&Tokens::from_e8s(1000)).copied()
    );
    // make 2 transfers that empty the account
    for _ in 0..2 {
        apply_operation(
            &mut ctx,
            &Operation::Transfer {
                from: canister,
                to: target_canister,
                spender: None,
                amount: Tokens::from_e8s(400),
                fee: Tokens::from_e8s(100),
            },
            now,
        )
        .unwrap();
    }
    // target canister's balance adds up
    assert_eq!(
        ctx.balances().store.get_balance(&target_canister),
        Some(&Tokens::from_e8s(800)).copied()
    );
    // source canister has been removed
    assert_eq!(ctx.balances().store.get_balance(&canister), None);
    assert_eq!(ctx.balances().account_balance(&canister), Tokens::ZERO);

    // one account left in the store
    assert_eq!(balances_len(), 1);

    apply_operation(
        &mut ctx,
        &Operation::Transfer {
            from: target_canister,
            to: canister,
            spender: None,
            amount: Tokens::from_e8s(0),
            fee: Tokens::from_e8s(100),
        },
        now,
    )
    .unwrap();
    // No new account should have been created
    assert_eq!(balances_len(), 1);
    // and the fee should have been taken from sender
    assert_eq!(
        ctx.balances().store.get_balance(&target_canister),
        Some(&Tokens::from_e8s(700)).copied()
    );

    apply_operation(
        &mut ctx,
        &Operation::Mint {
            to: canister,
            amount: Tokens::from_e8s(0),
        },
        now,
    )
    .unwrap();

    // No new account should have been created
    assert_eq!(balances_len(), 1);

    apply_operation(
        &mut ctx,
        &Operation::Burn {
            from: target_canister,
            amount: Tokens::from_e8s(700),
            spender: None,
        },
        now,
    )
    .unwrap();

    // And burn should have exhausted the target_canister
    assert_eq!(balances_len(), 0);
}

#[test]
fn balances_fee() {
    let mut ctx = Ledger::default();
    let pool_start_balance = ctx.balances().token_pool.get_e8s();
    let uid0 = PrincipalId::new_user_test_id(1000).into();
    let uid1 = PrincipalId::new_user_test_id(1007).into();
    let mint_amount = 1000000;
    let send_amount = 10000;
    let send_fee = 100;
    let now = ts(12345678);

    apply_operation(
        &mut ctx,
        &Operation::Mint {
            to: uid0,
            amount: Tokens::from_e8s(mint_amount),
        },
        now,
    )
    .unwrap();
    assert_eq!(
        ctx.balances().token_pool.get_e8s(),
        pool_start_balance - mint_amount
    );
    assert_eq!(ctx.balances().account_balance(&uid0).get_e8s(), mint_amount);

    apply_operation(
        &mut ctx,
        &Operation::Transfer {
            from: uid0,
            to: uid1,
            spender: None,
            amount: Tokens::from_e8s(send_amount),
            fee: Tokens::from_e8s(send_fee),
        },
        now,
    )
    .unwrap();

    assert_eq!(
        ctx.balances().token_pool.get_e8s(),
        pool_start_balance - mint_amount + send_fee
    );
    assert_eq!(
        ctx.balances().account_balance(&uid0).get_e8s(),
        mint_amount - send_amount - send_fee
    );
    assert_eq!(ctx.balances().account_balance(&uid1).get_e8s(), send_amount);
}

#[test]
fn serialize() {
    let mut state = Ledger::default();

    state.from_init(
        vec![(
            PrincipalId::new_user_test_id(0).into(),
            Tokens::new(2000000, 0).unwrap(),
        )]
        .into_iter()
        .collect(),
        PrincipalId::new_user_test_id(1000).into(),
        Some(PrincipalId::new_user_test_id(1000).0.into()),
        SystemTime::UNIX_EPOCH.into(),
        None,
        HashSet::new(),
        None,
        Some("ICP".into()),
        Some("icp".into()),
        None,
    );

    let txn = Transaction::new(
        PrincipalId::new_user_test_id(0).into(),
        PrincipalId::new_user_test_id(1).into(),
        None,
        Tokens::new(10000, 50).unwrap(),
        state.transfer_fee,
        Memo(456),
        TimeStamp::new(1, 0),
    );

    let block = Block {
        parent_hash: state.blockchain.last_hash,
        transaction: txn,
        timestamp: (SystemTime::UNIX_EPOCH + Duration::new(2000000000, 123456789)).into(),
    };

    let block_bytes = block.clone().encode();
    println!("block bytes = {:02x?}", block_bytes.0);
    let block_hash = Block::block_hash(&block_bytes);
    println!("block hash = {block_hash}");
    let block_decoded = Block::decode(block_bytes).unwrap();
    println!("block decoded = {block_decoded:#?}");
    assert_eq!(block, block_decoded);

    state.add_block(block).unwrap();

    let txn2 = Transaction::new(
        PrincipalId::new_user_test_id(0).into(),
        PrincipalId::new_user_test_id(200).into(),
        None,
        Tokens::new(30000, 10000).unwrap(),
        state.transfer_fee,
        Memo(0),
        TimeStamp::new(1, 100),
    );

    let block2 = Block {
        parent_hash: Some(block_hash),
        transaction: txn2,
        timestamp: (SystemTime::UNIX_EPOCH + Duration::new(2000000000, 123456790)).into(),
    };

    state.add_block(block2).unwrap();

    let state_bytes = serde_cbor::to_vec(&state).unwrap();

    let state_decoded: Ledger = serde_cbor::from_slice(&state_bytes).unwrap();

    assert_eq!(
        state.blockchain.chain_length(),
        state_decoded.blockchain.chain_length()
    );
    assert_eq!(
        state.blockchain.last_hash,
        state_decoded.blockchain.last_hash
    );
    assert_eq!(
        state.blockchain.num_unarchived_blocks(),
        state_decoded.blockchain.num_unarchived_blocks()
    );
    assert_eq!(state.balances.store, state_decoded.balances.store);
}

/// Check that 'created_at_time' is not too far in the past or
/// future.
#[test]
fn bad_created_at_time() {
    let mut state = Ledger::default();

    let user1 = PrincipalId::new_user_test_id(1).into();

    let transfer = Operation::Mint {
        to: user1,
        amount: Tokens::from_e8s(1000),
    };

    let now = SystemTime::now().into();

    assert_eq!(
        PaymentError::TransferError(TransferError::TxTooOld {
            allowed_window_nanos: Duration::from_secs(24 * 60 * 60).as_nanos() as u64,
        }),
        state
            .add_payment_with_timestamp(
                Memo(1),
                transfer.clone(),
                Some(now - state.transaction_window - Duration::from_secs(1)),
                now
            )
            .unwrap_err()
    );

    state
        .add_payment_with_timestamp(
            Memo(2),
            transfer.clone(),
            Some(now - Duration::from_secs(1)),
            now,
        )
        .unwrap();

    assert_eq!(
        PaymentError::TransferError(TransferError::TxCreatedInFuture),
        state
            .add_payment_with_timestamp(
                Memo(3),
                transfer.clone(),
                Some(now + Duration::from_secs(120)),
                now
            )
            .unwrap_err()
    );

    state
        .add_payment_with_timestamp(Memo(4), transfer, Some(now), now)
        .unwrap();
}

/// Check that block timestamps don't go backwards.
#[test]
#[should_panic(expected = "timestamp is older")]
fn monotonic_timestamps() {
    let mut state = Ledger::default();

    let user1 = PrincipalId::new_user_test_id(1).into();

    let transfer = Operation::Mint {
        to: user1,
        amount: Tokens::from_e8s(1000),
    };

    let now = TimeStamp::from_nanos_since_unix_epoch(1_000_000_000);

    state
        .add_payment_with_timestamp(Memo(1), transfer.clone(), None, now)
        .unwrap();

    state
        .add_payment_with_timestamp(Memo(2), transfer.clone(), None, now)
        .unwrap();

    state
        .add_payment_with_timestamp(
            Memo(2),
            transfer,
            None,
            state.blockchain.last_timestamp - Duration::from_secs(1),
        )
        .unwrap();
}

/// Check that duplicate transactions during transaction_window
/// are rejected.
#[test]
fn duplicate_txns() {
    let mut state = Ledger::default();

    state.blockchain.archive = Arc::new(RwLock::new(Some(Archive::new(ArchiveOptions {
        trigger_threshold: 2000,
        num_blocks_to_archive: 1000,
        node_max_memory_size_bytes: None,
        max_message_size_bytes: None,
        controller_id: CanisterId::from_u64(876).into(),
        more_controller_ids: None,
        cycles_for_archive_creation: Some(0),
        max_transactions_per_response: None,
    }))));

    let user1 = PrincipalId::new_user_test_id(1).into();

    let transfer = Operation::Mint {
        to: user1,
        amount: Tokens::from_e8s(1000),
    };

    let now = SystemTime::now().into();

    assert_eq!(
        state
            .add_payment_with_timestamp(Memo::default(), transfer.clone(), Some(now), now)
            .unwrap()
            .0,
        0
    );

    assert_eq!(
        state
            .add_payment_with_timestamp(Memo(123), transfer.clone(), Some(now), now)
            .unwrap()
            .0,
        1
    );

    assert_eq!(
        state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer.clone(),
                Some(now - Duration::from_secs(1)),
                now
            )
            .unwrap()
            .0,
        2
    );

    assert_eq!(
        state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer.clone(),
                Some(now - Duration::from_secs(2)),
                state.blockchain.last_timestamp + Duration::from_secs(10000)
            )
            .unwrap()
            .0,
        3
    );

    assert_eq!(
        PaymentError::TransferError(TransferError::TxDuplicate { duplicate_of: 0 }),
        state
            .add_payment_with_timestamp(Memo::default(), transfer.clone(), Some(now), now)
            .unwrap_err()
    );

    // A day later we should have forgotten about these transactions.
    let t = state.blockchain.last_timestamp + Duration::from_secs(1);
    assert_eq!(
        state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer.clone(),
                Some(t),
                state.blockchain.last_timestamp + state.transaction_window
            )
            .unwrap()
            .0,
        4
    );

    assert_eq!(
        PaymentError::TransferError(TransferError::TxDuplicate { duplicate_of: 4 }),
        state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer.clone(),
                Some(t),
                state.blockchain.last_timestamp + Duration::from_secs(1),
            )
            .unwrap_err()
    );

    // Corner case 1 -- attempts which are transaction_window apart from each other
    let t = state.blockchain.last_timestamp + Duration::from_secs(100);

    assert_eq!(
        state
            .add_payment_with_timestamp(Memo::default(), transfer.clone(), Some(t), t)
            .unwrap()
            .0,
        5
    );

    assert_eq!(
        PaymentError::TransferError(TransferError::TxDuplicate { duplicate_of: 5 }),
        state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer.clone(),
                Some(t),
                t + state.transaction_window,
            )
            .unwrap_err()
    );

    // Corner case 2 -- attempts which are transaction_window + drift apart from
    // each other
    let t = state.blockchain.last_timestamp + Duration::from_secs(200);
    let drift = ic_limits::PERMITTED_DRIFT;

    assert_eq!(
        PaymentError::TransferError(TransferError::TxCreatedInFuture),
        state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer.clone(),
                Some(t),
                t - (drift + Duration::from_nanos(1)),
            )
            .unwrap_err()
    );

    assert_eq!(
        state
            .add_payment_with_timestamp(Memo::default(), transfer.clone(), Some(t), t - drift)
            .unwrap()
            .0,
        6
    );

    assert_eq!(
        PaymentError::TransferError(TransferError::TxDuplicate { duplicate_of: 6 }),
        state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer.clone(),
                Some(t),
                t + state.transaction_window,
            )
            .unwrap_err()
    );

    assert_eq!(
        PaymentError::TransferError(TransferError::TxTooOld {
            allowed_window_nanos: state.transaction_window.as_nanos() as u64,
        }),
        state
            .add_payment_with_timestamp(
                Memo::default(),
                transfer,
                Some(t),
                t + state.transaction_window + Duration::from_nanos(1),
            )
            .unwrap_err()
    );
}

#[test]
fn get_blocks_returns_correct_blocks() {
    let mut blocks = vec![];

    let tx = Transaction {
        operation: Operation::Mint {
            to: PrincipalId::new_user_test_id(0).into(),
            amount: Tokens::from_e8s(1000),
        },
        memo: Memo(0),
        created_at_time: None,
        icrc1_memo: None,
    };
    blocks.push(
        Block {
            parent_hash: None,
            transaction: tx,
            timestamp: (SystemTime::UNIX_EPOCH + Duration::new(1, 0)).into(),
        }
        .encode(),
    );

    for i in 0..10 {
        let txn = Transaction::new(
            PrincipalId::new_user_test_id(0).into(),
            PrincipalId::new_user_test_id(1).into(),
            None,
            Tokens::new(1, 0).unwrap(),
            tokens(1),
            Memo(i),
            TimeStamp::new(1, 0),
        );

        let block = Block {
            parent_hash: None,
            transaction: txn,
            timestamp: (SystemTime::UNIX_EPOCH + Duration::new(1, 0)).into(),
        };

        blocks.push(block.encode());
    }

    let first_blocks = icp_ledger::get_blocks(&blocks, 0, 1, 5).0.unwrap();
    for i in 0..first_blocks.len() {
        let block = Block::decode(first_blocks.get(i).unwrap().clone()).unwrap();
        assert_eq!(block.transaction.memo.0, i as u64);
    }

    let last_blocks = icp_ledger::get_blocks(&blocks, 0, 6, 5).0.unwrap();
    for i in 0..last_blocks.len() {
        let block = Block::decode(last_blocks.get(i).unwrap().clone()).unwrap();
        assert_eq!(block.transaction.memo.0, 5 + i as u64);
    }
}

#[test]
fn test_purge() {
    let mut ledger = Ledger::default();
    let genesis = SystemTime::now().into();
    ledger.from_init(
        vec![
            (
                PrincipalId::new_user_test_id(0).into(),
                Tokens::new(1, 0).unwrap(),
            ),
            (
                PrincipalId::new_user_test_id(1).into(),
                Tokens::new(1, 0).unwrap(),
            ),
        ]
        .into_iter()
        .collect(),
        PrincipalId::new_user_test_id(1000).into(),
        Some(PrincipalId::new_user_test_id(1000).0.into()),
        genesis,
        Some(Duration::from_millis(10)),
        HashSet::new(),
        None,
        Some("ICP".into()),
        Some("icp".into()),
        None,
    );
    let little_later = genesis + Duration::from_millis(1);

    let res1 = ledger.change_notification_state(1, genesis, true, little_later);
    assert_eq!(res1, Ok(()), "The first notification succeeds");

    let res2 = ledger.blocks_notified.get(1);
    assert_eq!(res2, Some(&()), "You can see the lock in the store");

    core_ledger::purge_old_transactions(&mut ledger, genesis);

    let res2 = ledger.blocks_notified.get(1);
    assert_eq!(
        res2,
        Some(&()),
        "A purge before the end of the window doesn't remove the notification"
    );

    let later = genesis + Duration::from_secs(10) + ic_limits::PERMITTED_DRIFT;
    core_ledger::purge_old_transactions(&mut ledger, later);

    let res3 = ledger.blocks_notified.get(1);
    assert_eq!(res3, None, "A purge afterwards does");

    let res4 = ledger.blocks_notified.get(2);
    assert_eq!(res4, None);

    let res5 = ledger.change_notification_state(1, genesis, true, later);
    assert!(res5.unwrap_err().contains("that is more than"));

    let res5 = ledger.change_notification_state(1, genesis, false, later);
    assert!(res5.unwrap_err().contains("that is more than"));

    let res5 = ledger.change_notification_state(2, genesis, true, later);
    assert!(res5.unwrap_err().contains("that is more than"));

    let res6 = ledger.blocks_notified.get(2);
    assert_eq!(res6, None);
}

fn apply_at(ledger: &mut Ledger, op: &Operation, ts: TimeStamp) -> BlockIndex {
    let memo = Memo::default();
    ledger
        .add_payment_with_timestamp(memo, op.clone(), None, ts)
        .unwrap_or_else(|e| {
            panic!("Failed to execute operation {op:?} with memo {memo:?} at {ts:?}: {e:?}")
        })
        .0
}

#[test]
#[should_panic(expected = "Too many transactions")]
fn test_throttle_tx_per_second_nok() {
    let millis = Duration::from_millis;

    let mut ledger = Ledger {
        transaction_window: millis(2000),
        max_transactions_in_window: 2,
        ..Ledger::default()
    };

    let op = Operation::Mint {
        to: PrincipalId::new_user_test_id(1).into(),
        amount: Tokens::from_e8s(1000),
    };

    let now = TimeStamp::from_nanos_since_unix_epoch(1000000);

    assert_eq!(apply_at(&mut ledger, &op, now + millis(1)), 0);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(1002)), 1);

    // expecting panic here
    apply_at(&mut ledger, &op, now + millis(1003));
}

#[test]
fn test_throttle_tx_per_second_ok() {
    let millis = Duration::from_millis;

    let mut ledger = Ledger {
        transaction_window: millis(2000),
        max_transactions_in_window: 2,
        ..Ledger::default()
    };

    let op = Operation::Mint {
        to: PrincipalId::new_user_test_id(1).into(),
        amount: Tokens::from_e8s(1000),
    };
    let now = TimeStamp::from_nanos_since_unix_epoch(1000000);

    assert_eq!(apply_at(&mut ledger, &op, now + millis(1)), 0);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(1002)), 1);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(2003)), 2);
}

#[test]
fn test_throttle_two_tx_per_second_after_soft_limit_ok() {
    let millis = Duration::from_millis;

    let mut ledger = Ledger {
        transaction_window: millis(2000),
        max_transactions_in_window: 8,
        ..Ledger::default()
    };

    let op = Operation::Mint {
        to: PrincipalId::new_user_test_id(1).into(),
        amount: Tokens::from_e8s(1000),
    };
    let now = TimeStamp::from_nanos_since_unix_epoch(1000000);

    assert_eq!(apply_at(&mut ledger, &op, now + millis(1)), 0);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(2)), 1);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(3)), 2);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(4)), 3);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(1005)), 4);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(1006)), 5);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(2007)), 6);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(3008)), 7);
}

#[test]
#[should_panic(expected = "Too many transactions")]
fn test_throttle_two_tx_per_second_after_soft_limit_nok() {
    let millis = Duration::from_millis;

    let mut ledger = Ledger {
        transaction_window: millis(2000),
        max_transactions_in_window: 8,
        ..Ledger::default()
    };

    let op = Operation::Mint {
        to: PrincipalId::new_user_test_id(1).into(),
        amount: Tokens::from_e8s(1000),
    };
    let now = TimeStamp::from_nanos_since_unix_epoch(1000000);

    assert_eq!(apply_at(&mut ledger, &op, now + millis(1)), 0);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(2)), 1);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(3)), 2);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(4)), 3);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(1005)), 4);
    assert_eq!(apply_at(&mut ledger, &op, now + millis(1006)), 5);
    // expecting panic here
    apply_at(&mut ledger, &op, now + millis(1007));
}

/// Verify consistency of transaction hash after renaming transfer to
/// operation (see NNS1-765).
#[test]
fn test_transaction_hash_consistency() {
    let mut transaction = Transaction::new(
        PrincipalId::new_user_test_id(0).into(),
        PrincipalId::new_user_test_id(1).into(),
        None,
        Tokens::new(1, 0).unwrap(),
        DEFAULT_TRANSFER_FEE,
        Memo(123456),
        TimeStamp::new(1, 0),
    );
    let transaction_hash = transaction.hash();
    let hash_string = transaction_hash.to_string();
    assert_eq!(
        hash_string, "f39130181586ea3d166185104114d7697d1e18af4f65209a53627f39b2fa0996",
        "Transaction hash must be stable."
    );
    transaction.icrc1_memo = Some(icrc_ledger_types::icrc1::transfer::Memo::default().0);
    let transaction_hash = transaction.hash();
    let hash_string = transaction_hash.to_string();
    assert_ne!(
        hash_string, "f39130181586ea3d166185104114d7697d1e18af4f65209a53627f39b2fa0996",
        "ICRC1 Memo field is set, which should change the transaction hash."
    );
    assert_eq!(
        hash_string, "646bf98eac33a37c4f018f13eeef7cf1826156ab69523ecbb51c25345340bbdb",
        "Transaction hash must be stable."
    )
}

#[test]
fn test_approvals_are_not_cumulative() {
    let mut ctx = Ledger::default();

    let from = test_account_id(1);
    let spender = test_account_id(2);
    let now = ts(12345678);

    ctx.balances_mut().mint(&from, tokens(100_000)).unwrap();

    let approved_amount = tokens(150_000);
    let fee = tokens(10_000);

    apply_operation(
        &mut ctx,
        &Operation::Approve {
            from,
            spender,
            allowance: approved_amount,
            expected_allowance: None,
            expires_at: None,
            fee,
        },
        now,
    )
    .unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(90_000));
    assert_eq!(ctx.balances().account_balance(&spender), tokens(0));

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: approved_amount,
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );

    let new_allowance = tokens(200_000);

    let expiration = now + Duration::from_secs(300);
    apply_operation(
        &mut ctx,
        &Operation::Approve {
            from,
            spender,
            allowance: new_allowance,
            expected_allowance: None,
            expires_at: Some(expiration),
            fee,
        },
        now,
    )
    .unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(80_000));
    assert_eq!(ctx.balances().account_balance(&spender), tokens(0));
    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: new_allowance,
            expires_at: Some(expiration),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        }
    );
}

#[test]
fn test_approval_transfer_from() {
    let mut ctx = Ledger::default();

    let from = test_account_id(1);
    let spender = test_account_id(2);
    let to = test_account_id(3);
    let now = ts(1);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();
    let fee = tokens(10_000);

    assert_eq!(
        apply_operation(
            &mut ctx,
            &Operation::Transfer {
                from,
                to,
                spender: Some(spender),
                amount: tokens(100_000),
                fee,
            },
            now,
        )
        .unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: tokens(0)
        }
    );

    apply_operation(
        &mut ctx,
        &Operation::Approve {
            from,
            spender,
            allowance: tokens(150_000),
            expected_allowance: None,
            expires_at: None,
            fee,
        },
        now,
    )
    .unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(190_000));

    apply_operation(
        &mut ctx,
        &Operation::Transfer {
            from,
            to,
            spender: Some(spender),
            amount: tokens(100_000),
            fee,
        },
        now,
    )
    .unwrap();

    assert_eq!(ctx.balances().account_balance(&to), tokens(100_000));
    assert_eq!(ctx.balances().account_balance(&spender), Tokens::ZERO);
    assert_eq!(ctx.balances().account_balance(&from), tokens(80_000));

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(40_000),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );

    assert_eq!(
        apply_operation(
            &mut ctx,
            &Operation::Transfer {
                from,
                to,
                spender: Some(spender),
                amount: tokens(100_000),
                fee,
            },
            now,
        )
        .unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: tokens(40_000)
        }
    );

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(40_000),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );
    assert_eq!(ctx.balances().account_balance(&from), tokens(80_000),);
    assert_eq!(ctx.balances().account_balance(&to), tokens(100_000),);
}

#[test]
fn test_approval_expiration_override() {
    let mut ctx = Ledger::default();

    let from = test_account_id(1);
    let spender = test_account_id(2);
    let now = ts(1000);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();

    let approve = |amount: Tokens, expires_at: Option<u64>| Operation::Approve {
        from,
        spender,
        allowance: amount,
        expected_allowance: None,
        expires_at: expires_at.map(ts),
        fee: tokens(10_000),
    };

    apply_operation(&mut ctx, &approve(tokens(100_000), Some(2000)), now).unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(100_000),
            expires_at: Some(ts(2000)),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );

    apply_operation(&mut ctx, &approve(tokens(200_000), Some(1500)), now).unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(200_000),
            expires_at: Some(ts(1500)),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );

    apply_operation(&mut ctx, &approve(tokens(300_000), Some(2500)), now).unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(300_000),
            expires_at: Some(ts(2500)),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );

    // The expiration is in the past, the allowance is rejected.
    assert_eq!(
        apply_operation(&mut ctx, &approve(tokens(100_000), Some(500)), now).unwrap_err(),
        TxApplyError::ExpiredApproval { now }
    );

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(300_000),
            expires_at: Some(ts(2500)),
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );
}

#[test]
fn test_approval_no_fee_on_reject() {
    let mut ctx = Ledger::default();

    let from = test_account_id(1);
    let spender = test_account_id(2);
    let now = ts(1000);

    ctx.balances_mut().mint(&from, tokens(20_000)).unwrap();

    assert_eq!(
        apply_operation(
            &mut ctx,
            &Operation::Approve {
                from,
                spender,
                allowance: tokens(1_000),
                expected_allowance: None,
                expires_at: Some(ts(1)),
                fee: tokens(10_000),
            },
            ts(1000),
        )
        .unwrap_err(),
        TxApplyError::ExpiredApproval { now }
    );

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance::default(),
    );

    assert_eq!(ctx.balances().account_balance(&from), tokens(20_000));
}

#[test]
fn test_self_transfer_from() {
    let mut ctx = Ledger::default();

    let from = test_account_id(1);
    let to = test_account_id(2);
    let now = ts(1000);

    ctx.balances_mut().mint(&from, tokens(100_000)).unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &from, now),
        Allowance::default(),
    );

    apply_operation(
        &mut ctx,
        &Operation::Transfer {
            from,
            spender: Some(from),
            to,
            amount: tokens(20_000),
            fee: tokens(10_000),
        },
        ts(1000),
    )
    .unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(70_000));
    assert_eq!(ctx.balances().account_balance(&to), tokens(20_000));
}

#[test]
fn test_approval_allowance_covers_fee() {
    let mut ctx = Ledger::default();

    let from = test_account_id(1);
    let spender = test_account_id(2);
    let to = test_account_id(3);

    let now = ts(1);

    ctx.balances_mut().mint(&from, tokens(30_000)).unwrap();

    let fee = tokens(10_000);

    apply_operation(
        &mut ctx,
        &Operation::Approve {
            from,
            spender,
            allowance: tokens(10_000),
            expected_allowance: None,
            expires_at: None,
            fee,
        },
        now,
    )
    .unwrap();

    assert_eq!(
        apply_operation(
            &mut ctx,
            &Operation::Transfer {
                from,
                to,
                spender: Some(spender),
                amount: tokens(10_000),
                fee,
            },
            now,
        )
        .unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: tokens(10_000)
        }
    );

    apply_operation(
        &mut ctx,
        &Operation::Approve {
            from,
            spender,
            allowance: tokens(20_000),
            expected_allowance: None,
            expires_at: None,
            fee: Tokens::ZERO,
        },
        now,
    )
    .unwrap();

    apply_operation(
        &mut ctx,
        &Operation::Transfer {
            from,
            to,
            spender: Some(spender),
            amount: tokens(10_000),
            fee,
        },
        now,
    )
    .unwrap();

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(0),
            expires_at: None,
            arrived_at: ts(0),
        },
    );

    assert_eq!(ctx.balances().account_balance(&from), tokens(0));
    assert_eq!(ctx.balances().account_balance(&to), tokens(10_000));
    assert_eq!(ctx.balances().account_balance(&spender), tokens(0));
}

#[test]
fn test_burn_smoke() {
    let now = ts(12345678);

    let mut ctx = Ledger::default();

    let from = test_account_id(1);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();

    assert_eq!(ctx.balances().total_supply().get_e8s(), 200_000);

    apply_operation(
        &mut ctx,
        &Operation::Burn {
            from,
            amount: Tokens::from_e8s(100_000),
            spender: None,
        },
        now,
    )
    .unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(100_000));
    assert_eq!(ctx.balances().total_supply(), tokens(100_000));
}

#[test]
fn test_approval_burn_from() {
    let now = ts(12345678);

    let mut ctx = Ledger::default();

    let from = test_account_id(1);
    let spender = test_account_id(2);

    ctx.balances_mut().mint(&from, tokens(200_000)).unwrap();
    let fee = tokens(10_000);

    assert_eq!(ctx.balances().total_supply().get_e8s(), 200_000);

    assert_eq!(
        apply_operation(
            &mut ctx,
            &Operation::Burn {
                from,
                amount: Tokens::from_e8s(100_000),
                spender: Some(spender),
            },
            now,
        )
        .unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: Tokens::ZERO
        }
    );

    assert_eq!(ctx.balances().total_supply().get_e8s(), 200_000);

    apply_operation(
        &mut ctx,
        &Operation::Approve {
            from,
            spender,
            allowance: tokens(150_000),
            expected_allowance: None,
            expires_at: None,
            fee,
        },
        now,
    )
    .unwrap();

    assert_eq!(ctx.balances().account_balance(&from), tokens(190_000));
    assert_eq!(ctx.balances().total_supply(), tokens(190_000));

    apply_operation(
        &mut ctx,
        &Operation::Burn {
            from,
            amount: Tokens::from_e8s(100_000),
            spender: Some(spender),
        },
        now,
    )
    .unwrap();

    assert_eq!(ctx.balances().account_balance(&spender), Tokens::ZERO);
    assert_eq!(ctx.balances().account_balance(&from), tokens(90_000));
    assert_eq!(ctx.balances().total_supply().get_e8s(), 90_000);
    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(50_000),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );

    assert_eq!(
        apply_operation(
            &mut ctx,
            &Operation::Burn {
                from,
                amount: Tokens::from_e8s(100_000),
                spender: Some(spender),
            },
            now,
        )
        .unwrap_err(),
        TxApplyError::InsufficientAllowance {
            allowance: tokens(50_000)
        }
    );

    assert_eq!(
        ctx.approvals().allowance(&from, &spender, now),
        Allowance {
            amount: tokens(50_000),
            expires_at: None,
            arrived_at: TimeStamp::from_nanos_since_unix_epoch(0),
        },
    );
    assert_eq!(ctx.balances().account_balance(&from), tokens(90_000));
    assert_eq!(ctx.balances().account_balance(&spender), Tokens::ZERO);
    assert_eq!(ctx.balances().total_supply().get_e8s(), 90_000);
}

#[test]
fn allowance_serialization() {
    fn arb_token() -> impl Strategy<Value = Tokens> {
        any::<u64>().prop_map(tokens)
    }

    fn arb_timestamp() -> impl Strategy<Value = TimeStamp> {
        any::<u64>().prop_map(TimeStamp::from_nanos_since_unix_epoch)
    }
    fn arb_opt_expiration() -> impl Strategy<Value = Option<TimeStamp>> {
        proptest::option::of(any::<u64>().prop_map(TimeStamp::from_nanos_since_unix_epoch))
    }
    fn arb_allowance() -> impl Strategy<Value = Allowance<Tokens>> {
        (arb_token(), arb_opt_expiration(), arb_timestamp()).prop_map(
            |(amount, expires_at, arrived_at)| Allowance {
                amount,
                expires_at,
                arrived_at,
            },
        )
    }
    proptest!(|(allowance in arb_allowance())| {
        let storable_allowance: StorableAllowance = allowance.clone().into();
        let new_allowance: Allowance<Tokens> = StorableAllowance::from_bytes(storable_allowance.to_bytes()).into();
        prop_assert_eq!(new_allowance.amount, allowance.amount);
        prop_assert_eq!(new_allowance.expires_at, allowance.expires_at);
        prop_assert_eq!(
            new_allowance.arrived_at,
            TimeStamp::from_nanos_since_unix_epoch(0)
        );
    })
}
