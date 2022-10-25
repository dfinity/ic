use crate::Ledger;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_canister_core::{archive::Archive, ledger as core_ledger, ledger::LedgerTransaction};
use ic_ledger_core::{
    block::{BlockIndex, BlockType},
    timestamp::TimeStamp,
    tokens::Tokens,
};
use icp_ledger::{
    apply_operation, ArchiveOptions, Block, LedgerBalances, Memo, Operation, PaymentError,
    Transaction, TransferError, DEFAULT_TRANSFER_FEE,
};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

#[test]
fn balances_overflow() {
    let balances = LedgerBalances::new();
    let mut state = Ledger {
        balances,
        maximum_number_of_accounts: 8,
        accounts_overflow_trim_quantity: 2,
        minting_account_id: Some(PrincipalId::new_user_test_id(137).into()),
        ..Default::default()
    };
    assert_eq!(state.balances.token_pool, Tokens::MAX);
    println!(
        "minting canister initial balance: {}",
        state.balances.token_pool
    );
    let mut credited = Tokens::ZERO;

    // 11 accounts. The one with 0 will not be added
    // The rest will be added and trigger a trim of 2 once
    // the total number reaches 8 + 2
    // the number of active accounts won't go below 8 after trimming
    for i in 0..11 {
        let amount = Tokens::new(i, 0).unwrap();
        state
            .add_payment(
                Memo::default(),
                Operation::Mint {
                    to: PrincipalId::new_user_test_id(i).into(),
                    amount,
                },
                None,
            )
            .unwrap();
        credited += amount
    }
    println!("amount credited to accounts: {}", credited);

    println!("balances: {:?}", state.balances);

    // The two accounts with lowest balances, 0 and 1 respectively, have been
    // removed
    assert_eq!(state.balances.store.len(), 8);
    assert_eq!(
        state
            .balances
            .account_balance(&PrincipalId::new_user_test_id(0).into()),
        Tokens::ZERO
    );
    assert_eq!(
        state
            .balances
            .account_balance(&PrincipalId::new_user_test_id(1).into()),
        Tokens::ZERO
    );
    // We have credited 55 Tokens to various accounts but the three accounts
    // with lowest balances, 0, 1 and 2, should have been removed and their
    // balance returned to the minting canister
    let expected_minting_canister_balance =
        ((Tokens::MAX - credited).unwrap() + Tokens::new(1 + 2, 0).unwrap()).unwrap();
    assert_eq!(state.balances.token_pool, expected_minting_canister_balance);
}

#[test]
fn balances_remove_accounts_with_zero_balance() {
    let mut b = LedgerBalances::new();
    let canister = CanisterId::from_u64(7).get().into();
    let target_canister = CanisterId::from_u64(13).into();
    apply_operation(
        &mut b,
        &Operation::Mint {
            to: canister,
            amount: Tokens::from_e8s(1000),
        },
    )
    .unwrap();
    // verify that an account entry exists for the `canister`
    assert_eq!(b.store.get(&canister), Some(&Tokens::from_e8s(1000)));
    // make 2 transfers that empty the account
    for _ in 0..2 {
        apply_operation(
            &mut b,
            &Operation::Transfer {
                from: canister,
                to: target_canister,
                amount: Tokens::from_e8s(400),
                fee: Tokens::from_e8s(100),
            },
        )
        .unwrap();
    }
    // target canister's balance adds up
    assert_eq!(b.store.get(&target_canister), Some(&Tokens::from_e8s(800)));
    // source canister has been removed
    assert_eq!(b.store.get(&canister), None);
    assert_eq!(b.account_balance(&canister), Tokens::ZERO);

    // one account left in the store
    assert_eq!(b.store.len(), 1);

    apply_operation(
        &mut b,
        &Operation::Transfer {
            from: target_canister,
            to: canister,
            amount: Tokens::from_e8s(0),
            fee: Tokens::from_e8s(100),
        },
    )
    .unwrap();
    // No new account should have been created
    assert_eq!(b.store.len(), 1);
    // and the fee should have been taken from sender
    assert_eq!(b.store.get(&target_canister), Some(&Tokens::from_e8s(700)));

    apply_operation(
        &mut b,
        &Operation::Mint {
            to: canister,
            amount: Tokens::from_e8s(0),
        },
    )
    .unwrap();

    // No new account should have been created
    assert_eq!(b.store.len(), 1);

    apply_operation(
        &mut b,
        &Operation::Burn {
            from: target_canister,
            amount: Tokens::from_e8s(700),
        },
    )
    .unwrap();

    // And burn should have exhausted the target_canister
    assert_eq!(b.store.len(), 0);
}

#[test]
fn balances_fee() {
    let mut b = LedgerBalances::new();
    let pool_start_balance = b.token_pool.get_e8s();
    let uid0 = PrincipalId::new_user_test_id(1000).into();
    let uid1 = PrincipalId::new_user_test_id(1007).into();
    let mint_amount = 1000000;
    let send_amount = 10000;
    let send_fee = 100;

    apply_operation(
        &mut b,
        &Operation::Mint {
            to: uid0,
            amount: Tokens::from_e8s(mint_amount),
        },
    )
    .unwrap();
    assert_eq!(b.token_pool.get_e8s(), pool_start_balance - mint_amount);
    assert_eq!(b.account_balance(&uid0).get_e8s(), mint_amount);

    apply_operation(
        &mut b,
        &Operation::Transfer {
            from: uid0,
            to: uid1,
            amount: Tokens::from_e8s(send_amount),
            fee: Tokens::from_e8s(send_fee),
        },
    )
    .unwrap();

    assert_eq!(
        b.token_pool.get_e8s(),
        pool_start_balance - mint_amount + send_fee
    );
    assert_eq!(
        b.account_balance(&uid0).get_e8s(),
        mint_amount - send_amount - send_fee
    );
    assert_eq!(b.account_balance(&uid1).get_e8s(), send_amount);
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
        SystemTime::UNIX_EPOCH.into(),
        None,
        HashSet::new(),
        None,
        Some("ICP".into()),
        Some("icp".into()),
    );

    let txn = Transaction::new(
        PrincipalId::new_user_test_id(0).into(),
        PrincipalId::new_user_test_id(1).into(),
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
    println!("block hash = {}", block_hash);
    let block_decoded = Block::decode(block_bytes).unwrap();
    println!("block decoded = {:#?}", block_decoded);
    assert_eq!(block, block_decoded);

    state.add_block(block).unwrap();

    let txn2 = Transaction::new(
        PrincipalId::new_user_test_id(0).into(),
        PrincipalId::new_user_test_id(200).into(),
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
        state.blockchain.blocks.len(),
        state_decoded.blockchain.blocks.len()
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

    let now = dfn_core::api::now().into();

    assert_eq!(
        PaymentError::TransferError(TransferError::TxTooOld {
            allowed_window_nanos: Duration::from_secs(24 * 60 * 60).as_nanos() as u64,
        }),
        state
            .add_payment(
                Memo(1),
                transfer.clone(),
                Some(now - state.transaction_window - Duration::from_secs(1))
            )
            .unwrap_err()
    );

    state
        .add_payment(
            Memo(2),
            transfer.clone(),
            Some(now - Duration::from_secs(1)),
        )
        .unwrap();

    assert_eq!(
        PaymentError::TransferError(TransferError::TxCreatedInFuture),
        state
            .add_payment(
                Memo(3),
                transfer.clone(),
                Some(now + Duration::from_secs(120))
            )
            .unwrap_err()
    );

    state.add_payment(Memo(4), transfer, Some(now)).unwrap();
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

    state.add_payment(Memo(1), transfer.clone(), None).unwrap();

    state.add_payment(Memo(2), transfer.clone(), None).unwrap();

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
        cycles_for_archive_creation: Some(0),
        max_transactions_per_response: None,
    }))));

    let user1 = PrincipalId::new_user_test_id(1).into();

    let transfer = Operation::Mint {
        to: user1,
        amount: Tokens::from_e8s(1000),
    };

    let now = dfn_core::api::now().into();

    assert_eq!(
        state
            .add_payment(Memo::default(), transfer.clone(), Some(now))
            .unwrap()
            .0,
        0
    );

    assert_eq!(
        state
            .add_payment(Memo(123), transfer.clone(), Some(now))
            .unwrap()
            .0,
        1
    );

    assert_eq!(
        state
            .add_payment(
                Memo::default(),
                transfer.clone(),
                Some(now - Duration::from_secs(1))
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
            .add_payment(Memo::default(), transfer.clone(), Some(now))
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
    let drift = ic_constants::PERMITTED_DRIFT;

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
    let mut state = Ledger::default();

    state.from_init(
        vec![(
            PrincipalId::new_user_test_id(0).into(),
            Tokens::new(1000000, 0).unwrap(),
        )]
        .into_iter()
        .collect(),
        PrincipalId::new_user_test_id(1000).into(),
        SystemTime::UNIX_EPOCH.into(),
        None,
        HashSet::new(),
        None,
        Some("ICP".into()),
        Some("icp".into()),
    );

    for i in 0..10 {
        let txn = Transaction::new(
            PrincipalId::new_user_test_id(0).into(),
            PrincipalId::new_user_test_id(1).into(),
            Tokens::new(1, 0).unwrap(),
            state.transfer_fee,
            Memo(i),
            TimeStamp::new(1, 0),
        );

        let block = Block {
            parent_hash: state.blockchain.last_hash,
            transaction: txn,
            timestamp: (SystemTime::UNIX_EPOCH + Duration::new(1, 0)).into(),
        };

        state.add_block(block).unwrap();
    }

    let blocks = &state.blockchain.blocks;

    let first_blocks = icp_ledger::get_blocks(blocks, 0, 1, 5).0.unwrap();
    for i in 0..first_blocks.len() {
        let block = Block::decode(first_blocks.get(i).unwrap().clone()).unwrap();
        assert_eq!(block.transaction.memo.0, i as u64);
    }

    let last_blocks = icp_ledger::get_blocks(blocks, 0, 6, 5).0.unwrap();
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
        genesis,
        Some(Duration::from_millis(10)),
        HashSet::new(),
        None,
        Some("ICP".into()),
        Some("icp".into()),
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

    let later = genesis + Duration::from_secs(10) + ic_constants::PERMITTED_DRIFT;
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
            panic!(
                "Failed to execute operation {:?} with memo {:?} at {:?}: {:?}",
                op, memo, ts, e
            )
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

    let now: TimeStamp = dfn_core::api::now().into();

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
    let now: TimeStamp = dfn_core::api::now().into();

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
    let now: TimeStamp = dfn_core::api::now().into();

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
    let now: TimeStamp = dfn_core::api::now().into();

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
    let transaction = Transaction::new(
        PrincipalId::new_user_test_id(0).into(),
        PrincipalId::new_user_test_id(1).into(),
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
}
