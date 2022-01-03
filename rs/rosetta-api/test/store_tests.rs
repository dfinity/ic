use super::*;
use ic_rosetta_api::store::{BlockStoreError, SQLiteStore};
use std::path::Path;

pub(crate) fn sqlite_on_disk_store(path: &Path) -> SQLiteStore {
    SQLiteStore::new_on_disk(path).expect("Unable to create store")
}

#[actix_rt::test]
async fn store_smoke_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = sqlite_on_disk_store(tmpdir.path());
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb.clone()).unwrap();
    }

    for hb in &scribe.blockchain {
        assert_eq!(store.get_at(hb.index).unwrap(), *hb);
    }

    let last_idx = scribe.blockchain.back().unwrap().index;
    assert_eq!(
        store.get_at(last_idx + 1).unwrap_err(),
        BlockStoreError::NotFound(last_idx + 1)
    );
}

#[actix_rt::test]
async fn store_prune_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let mut store = sqlite_on_disk_store(tmpdir.path());
    let scribe = Scribe::new_with_sample_data(10, 100);

    for hb in &scribe.blockchain {
        store.push(hb.clone()).unwrap();
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
        store.push(hb.clone()).unwrap();
    }

    prune(&scribe, &mut store, 0);
    verify_pruned(&scribe, &mut store, 0);

    prune(&scribe, &mut store, 1);
    verify_pruned(&scribe, &mut store, 1);

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
        store.push(hb.clone()).unwrap();
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
        store.push(hb.clone()).unwrap();
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

fn prune(scribe: &Scribe, store: &mut SQLiteStore, prune_at: u64) {
    let oldest_idx = prune_at;
    let oldest_block = scribe.blockchain.get(oldest_idx as usize).unwrap();
    let oldest_balance = to_balances(
        scribe
            .balance_history
            .get(oldest_idx as usize)
            .unwrap()
            .clone(),
        oldest_idx,
    );

    store.prune(oldest_block, &oldest_balance).unwrap();
}

fn verify_pruned(scribe: &Scribe, store: &mut SQLiteStore, prune_at: u64) {
    let after_last_idx = scribe.blockchain.len() as u64;
    let oldest_idx = prune_at.min(after_last_idx);

    if after_last_idx > 1 {
        // Genesis block (at idx 0) should still be accessible
        assert_eq!(store.get_at(0).unwrap(), *scribe.blockchain.get(0).unwrap());
    }

    for i in 1..oldest_idx {
        assert_eq!(
            store.get_at(i).unwrap_err(),
            BlockStoreError::NotAvailable(i)
        );
    }

    if oldest_idx < after_last_idx {
        assert_eq!(store.first().unwrap().map(|x| x.index), Some(oldest_idx));
    }

    for i in oldest_idx..after_last_idx {
        assert_eq!(
            store.get_at(i).unwrap(),
            *scribe.blockchain.get(i as usize).unwrap()
        );
    }
    for i in after_last_idx..=scribe.blockchain.len() as u64 {
        assert_eq!(store.get_at(i).unwrap_err(), BlockStoreError::NotFound(i));
    }
}

fn verify_balance_snapshot(scribe: &Scribe, store: &mut SQLiteStore, prune_at: u64) {
    let oldest_idx = prune_at as usize;
    let (oldest_block, balances) = store.first_snapshot().unwrap();
    assert_eq!(oldest_block, *scribe.blockchain.get(oldest_idx).unwrap());

    let scribe_balances = scribe.balance_history.get(oldest_idx).unwrap().clone();

    assert_eq!(balances.store.acc_to_hist.len(), scribe_balances.len());
    for (acc, hist) in &balances.store.acc_to_hist {
        assert_eq!(
            balances.store.get_at(*acc, prune_at).unwrap(),
            *scribe_balances.get(acc).unwrap()
        );
        if let Some(last_entry) = hist.get_history(None).last().map(|x| x.0) {
            assert_eq!(last_entry, prune_at);
        }
    }

    let mut sum_icpt = Tokens::ZERO;
    for amount in scribe.balance_history.get(oldest_idx).unwrap().values() {
        sum_icpt += *amount;
    }
    assert_eq!((Tokens::MAX - sum_icpt).unwrap(), balances.token_pool);
}
