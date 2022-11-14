use ic_ledger_canister_blocks_synchronizer::{
    balance_book::BalanceBook,
    blocks::{BlockStoreError, Blocks},
};
use ic_ledger_canister_blocks_synchronizer_test_utils::{
    create_tmp_dir, init_test_logger, sample_data::Scribe,
};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::{balances::BalancesStore, block::BlockType, Tokens};
use icp_ledger::{apply_operation, AccountIdentifier, Block, Operation};
use rusqlite::params;
use std::path::Path;
pub(crate) fn sqlite_on_disk_store(path: &Path) -> Blocks {
    Blocks::new_persistent(path).unwrap()
}
#[actix_rt::test]
async fn store_smoke_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = sqlite_on_disk_store(tmpdir.path());
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb).unwrap();
    }

    for hb in &scribe.blockchain {
        assert_eq!(store.get_hashed_block(&hb.index).unwrap(), *hb);
        assert_eq!(
            store.get_transaction(&hb.index).unwrap(),
            Block::decode((*hb).clone().block).unwrap().transaction
        );
    }
    assert_eq!(
        store.get_first_hashed_block().unwrap(),
        *scribe.blockchain.get(0).unwrap()
    );
    assert_eq!(
        store.get_latest_hashed_block().unwrap(),
        *scribe.blockchain.get(109).unwrap()
    );
    let last_idx = scribe.blockchain.back().unwrap().index;
    assert_eq!(
        store.get_hashed_block(&(last_idx + 1)).unwrap_err(),
        BlockStoreError::NotFound(last_idx + 1)
    );
}

#[actix_rt::test]
async fn store_coherance_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();

    let location = tmpdir.path();

    let store = sqlite_on_disk_store(location);
    let scribe = Scribe::new_with_sample_data(10, 100);
    let path = location.join("db.sqlite");
    let con = rusqlite::Connection::open(path).unwrap();
    for hb in &scribe.blockchain {
        let hash = hb.hash.into_bytes().to_vec();
        let parent_hash = hb.parent_hash.map(|ph| ph.into_bytes().to_vec());
        let command = "INSERT INTO blocks (hash, block, parent_hash, idx, verified) VALUES (?1, ?2, ?3, ?4, FALSE)";
        con.execute(
            command,
            params![hash, hb.block.clone().into_vec(), parent_hash, hb.index],
        )
        .unwrap();
    }
    drop(con);
    for hb in &scribe.blockchain {
        assert_eq!(store.get_hashed_block(&hb.index).unwrap(), *hb);
        assert_eq!(store.get_transaction_hash(&hb.index).unwrap(), None);
        assert!(store.get_all_accounts().unwrap().is_empty());
    }
    let store = sqlite_on_disk_store(location);
    for hb in &scribe.blockchain {
        assert_eq!(store.get_hashed_block(&hb.index).unwrap(), *hb);
        assert_eq!(
            store.get_transaction_hash(&hb.index).unwrap(),
            Some(Block::decode(hb.block.clone()).unwrap().transaction.hash())
        );
    }
    assert_eq!(store.get_all_accounts().unwrap().len(), 10);
}

#[actix_rt::test]
async fn store_account_balances_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = sqlite_on_disk_store(tmpdir.path());
    let scribe = Scribe::new_with_sample_data(10, 100);
    let mut account_balances = &mut BalanceBook::default();
    for hb in &scribe.blockchain {
        let tx = Block::decode(hb.block.clone()).unwrap().transaction;
        let operation = tx.operation;
        account_balances.store.transaction_context = Some(hb.index);
        apply_operation(account_balances, &operation).ok();
        account_balances.store.transaction_context = None;
        store.push(hb).unwrap();
        store.set_hashed_block_to_verified(&hb.index).unwrap();
        let to_account: Option<String>;
        let from_account: Option<String>;
        match operation {
            Operation::Burn { from, amount: _ } => {
                from_account = Some(from.to_hex());
                to_account = None;
            }
            Operation::Mint { to, amount: _ } => {
                from_account = None;
                to_account = Some(to.to_hex());
            }
            Operation::Transfer {
                from,
                to,
                amount: _,
                fee: _,
            } => {
                from_account = Some(from.to_hex());
                to_account = Some(to.to_hex());
            }
        }
        if let Some(acc_str) = from_account {
            let id = AccountIdentifier::from_hex(acc_str.as_str()).unwrap();
            let amount_from = store.get_account_balance(&id, &hb.index).unwrap();
            let amount_local = *account_balances.store.get_balance(&id).unwrap();
            assert_eq!(amount_from, amount_local);
        }
        if let Some(acc_str) = to_account {
            let id = AccountIdentifier::from_hex(acc_str.as_str()).unwrap();
            let amount_to = store.get_account_balance(&id, &hb.index).unwrap();
            let amount_local = *account_balances.store.get_balance(&id).unwrap();
            assert_eq!(amount_to, amount_local);
        }
    }
    for (acc, history) in account_balances.store.acc_to_hist.iter() {
        for (block_index, tokens) in history.get_history(None) {
            let amount = store.get_account_balance(acc, block_index).unwrap();
            assert_eq!(*tokens, amount);
        }
    }
}

#[actix_rt::test]
async fn store_prune_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = sqlite_on_disk_store(tmpdir.path());
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb).unwrap();
        store.set_hashed_block_to_verified(&hb.index).unwrap();
    }

    prune(&scribe, &mut store, 10);
    verify_pruned(&scribe, &mut store, 10);

    prune(&scribe, &mut store, 20);
    verify_pruned(&scribe, &mut store, 20);
}

#[actix_rt::test]
async fn store_prune_corner_cases_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = sqlite_on_disk_store(tmpdir.path());
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb).unwrap();
    }

    prune(&scribe, &mut store, 0);
    verify_pruned(&scribe, &mut store, 0);

    prune(&scribe, &mut store, 1);
    verify_pruned(&scribe, &mut store, 0);

    let last_idx = scribe.blockchain.back().unwrap().index;

    prune(&scribe, &mut store, last_idx);
    verify_pruned(&scribe, &mut store, last_idx);
}

#[actix_rt::test]
async fn store_prune_first_balance_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = sqlite_on_disk_store(tmpdir.path());
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb).unwrap();
        store.set_hashed_block_to_verified(&hb.index).unwrap();
    }

    prune(&scribe, &mut store, 10);
    verify_pruned(&scribe, &mut store, 10);
    verify_balance_snapshot(&scribe, &mut store, 10);

    prune(&scribe, &mut store, 20);
    verify_pruned(&scribe, &mut store, 20);
    verify_balance_snapshot(&scribe, &mut store, 20);
}

#[actix_rt::test]
async fn store_prune_and_load_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = sqlite_on_disk_store(tmpdir.path());

    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb).unwrap();
        store.set_hashed_block_to_verified(&hb.index).unwrap();
    }

    prune(&scribe, &mut store, 10);
    verify_pruned(&scribe, &mut store, 10);
    verify_balance_snapshot(&scribe, &mut store, 10);

    prune(&scribe, &mut store, 20);
    verify_pruned(&scribe, &mut store, 20);
    verify_balance_snapshot(&scribe, &mut store, 20);

    drop(store);
    // Now reload from disk
    let mut store = sqlite_on_disk_store(tmpdir.path());
    verify_pruned(&scribe, &mut store, 20);
    verify_balance_snapshot(&scribe, &mut store, 20);

    prune(&scribe, &mut store, 30);
    verify_pruned(&scribe, &mut store, 30);
    verify_balance_snapshot(&scribe, &mut store, 30);

    drop(store);
    // Reload once again
    let mut store = sqlite_on_disk_store(tmpdir.path());
    verify_pruned(&scribe, &mut store, 30);
    verify_balance_snapshot(&scribe, &mut store, 30);
}

fn prune(scribe: &Scribe, store: &mut Blocks, prune_at: u64) {
    let oldest_idx = prune_at;
    let oldest_block = scribe.blockchain.get(oldest_idx as usize).unwrap();
    store.prune(oldest_block).unwrap();
}

fn verify_pruned(scribe: &Scribe, store: &mut Blocks, prune_at: u64) {
    let after_last_idx = scribe.blockchain.len() as u64;
    let oldest_idx = prune_at.min(after_last_idx);

    if after_last_idx > 1 {
        // Genesis block (at idx 0) should still be accessible
        assert_eq!(
            store.get_hashed_block(&0).unwrap(),
            *scribe.blockchain.get(0).unwrap()
        );
    }

    for i in 1..oldest_idx {
        assert_eq!(
            store.get_hashed_block(&i).unwrap_err(),
            BlockStoreError::NotFound(i)
        );
        assert_eq!(
            store.get_transaction(&i).unwrap_err(),
            BlockStoreError::NotFound(i)
        );
    }

    if oldest_idx < after_last_idx {
        assert_eq!(
            store.get_first_hashed_block().ok().map(|x| x.index),
            Some(oldest_idx)
        );
    }

    for i in oldest_idx..after_last_idx {
        assert_eq!(
            store.get_hashed_block(&i).unwrap(),
            *scribe.blockchain.get(i as usize).unwrap()
        );
    }

    for i in oldest_idx..after_last_idx {
        let block = (*scribe.blockchain.get(i as usize).unwrap()).clone().block;
        assert_eq!(
            store.get_transaction(&i).unwrap(),
            Block::decode(block).unwrap().transaction
        );
    }

    for i in after_last_idx..=scribe.blockchain.len() as u64 {
        assert_eq!(
            store.get_hashed_block(&i).unwrap_err(),
            BlockStoreError::NotFound(i)
        );
    }
}

fn verify_balance_snapshot(scribe: &Scribe, store: &mut Blocks, prune_at: u64) {
    let oldest_idx = prune_at as usize;
    let oldest_block = store.get_first_hashed_block().unwrap();
    assert_eq!(oldest_block, *scribe.blockchain.get(oldest_idx).unwrap());

    let scribe_balances = scribe.balance_history.get(oldest_idx).unwrap().clone();
    for (acc, tokens) in scribe_balances {
        let balance = store
            .get_account_balance(&acc, &(oldest_idx as u64))
            .unwrap();
        assert_eq!(balance, tokens);
    }
    let mut sum_icpt = Tokens::ZERO;
    for amount in scribe.balance_history.get(oldest_idx).unwrap().values() {
        sum_icpt += *amount;
    }
    let accounts = store.get_all_accounts().unwrap();
    let mut total = Tokens::ZERO;
    for account in accounts {
        let amount = store
            .get_account_balance(&account, &(oldest_idx as u64))
            .unwrap();
        total += amount;
    }
    assert_eq!(sum_icpt, total);
}
