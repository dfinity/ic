use super::*;

use ic_rosetta_api::models::*;

use ic_rosetta_api::convert::{amount_, block_id, from_hash, timestamp, to_hash};
use ic_rosetta_api::ledger_client::LedgerAccess;
use ic_rosetta_api::transaction_id::TransactionIdentifier;
use ic_rosetta_api::{RosettaRequestHandler, API_VERSION, NODE_VERSION};

use std::sync::Arc;

#[actix_rt::test]
async fn smoke_test() {
    init_test_logger();

    let mut scribe = Scribe::new();
    let num_transactions: usize = 1000;
    let num_accounts = 100;
    let transaction_fee = Tokens::from_e8s(2_000);

    scribe.gen_accounts(num_accounts, 1_000_000);
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    let ledger = Arc::new(TestLedger {
        transfer_fee: transaction_fee,
        ..Default::default()
    });
    let req_handler = RosettaRequestHandler::new(ledger.clone());
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
    }

    assert_eq!(
        scribe.blockchain.len() as u64,
        ledger
            .read_blocks()
            .await
            .last_verified()
            .unwrap()
            .unwrap()
            .index
            + 1
    );

    for i in 0..num_accounts {
        let acc = acc_id(i);
        assert_eq!(
            get_balance(&req_handler, None, acc).await.unwrap(),
            *scribe.balance_book.get(&acc).unwrap()
        );
    }

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.network_status(msg).await;
    assert_eq!(
        res,
        Ok(NetworkStatusResponse::new(
            block_id(scribe.blockchain.back().unwrap()).unwrap(),
            timestamp(
                scribe
                    .blockchain
                    .back()
                    .unwrap()
                    .block
                    .decode()
                    .unwrap()
                    .timestamp()
                    .into()
            )
            .unwrap(),
            block_id(scribe.blockchain.front().unwrap()).unwrap(),
            None,
            SyncStatus {
                current_index: scribe.blockchain.back().unwrap().index as i64,
                target_index: None,
                stage: None,
                synced: None
            },
            vec![]
        ))
    );

    let chain_len = scribe.blockchain.len();
    ledger.blockchain.write().await.try_prune(&Some(10), 0).ok();
    let expected_first_block = chain_len - 11;
    assert_eq!(
        ledger
            .read_blocks()
            .await
            .first_verified()
            .unwrap()
            .unwrap()
            .index as usize,
        expected_first_block
    );
    let b = ledger
        .read_blocks()
        .await
        .last_verified()
        .unwrap()
        .unwrap()
        .index;
    let a = ledger
        .read_blocks()
        .await
        .first_verified()
        .unwrap()
        .unwrap()
        .index;
    assert_eq!(b - a, 10);

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.network_status(msg).await;
    assert_eq!(
        res.unwrap().oldest_block_identifier,
        Some(block_id(scribe.blockchain.get(expected_first_block).unwrap()).unwrap())
    );

    let msg = MetadataRequest::new();
    let res = req_handler.network_list(msg).await;
    assert_eq!(
        res,
        Ok(NetworkListResponse::new(vec![req_handler.network_id()]))
    );

    let msg = NetworkRequest::new(req_handler.network_id());
    let network_options = req_handler
        .network_options(msg)
        .await
        .expect("failed to fetch network options");

    assert_eq!(network_options.version.rosetta_version, API_VERSION);
    assert_eq!(network_options.version.node_version, NODE_VERSION);
    assert!(!network_options.allow.operation_statuses.is_empty());
    assert!(network_options
        .allow
        .operation_types
        .contains(&"TRANSACTION".to_string()));
    assert!(network_options
        .allow
        .operation_types
        .contains(&"FEE".to_string()));
    assert!(!network_options.allow.errors.is_empty());
    assert!(network_options.allow.historical_balance_lookup);

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.mempool(msg).await;
    assert_eq!(res, Ok(MempoolResponse::new(vec![])));

    let msg = MempoolTransactionRequest::new(
        req_handler.network_id(),
        TransactionIdentifier {
            hash: "hello there".to_string(),
        },
    );
    let res = req_handler.mempool_transaction(msg).await;
    assert_eq!(
        res,
        Err(ApiError::MempoolTransactionMissing(
            false,
            Default::default()
        ))
    );

    let msg = AccountBalanceRequest::new(
        req_handler.network_id(),
        ic_rosetta_api::convert::to_model_account_identifier(&acc_id(0)),
    );
    let res = req_handler.account_balance(msg).await;
    assert_eq!(
        res,
        Ok(AccountBalanceResponse::new(
            block_id(scribe.blockchain.back().unwrap()).unwrap(),
            vec![amount_(
                *scribe.balance_book.get(&acc_id(0)).unwrap(),
                DEFAULT_TOKEN_NAME
            )
            .unwrap()]
        ))
    );

    let (acc_id, _ed_kp, pk, _pid) = ic_rosetta_test_utils::make_user(4);
    let msg = ConstructionDeriveRequest::new(req_handler.network_id(), pk);
    let res = req_handler.construction_derive(msg).await;
    assert_eq!(
        res,
        Ok(ConstructionDeriveResponse {
            address: None,
            account_identifier: Some(to_model_account_identifier(&acc_id)),
            metadata: None
        })
    );

    let (_acc_id, _ed_kp, mut pk, _pid) = ic_rosetta_test_utils::make_user(4);
    pk.curve_type = CurveType::Secp256K1;
    let msg = ConstructionDeriveRequest::new(req_handler.network_id(), pk);
    let res = req_handler.construction_derive(msg).await;
    assert!(res.is_err(), "This pk should not have been accepted");

    let msg = ConstructionMetadataRequest::new(req_handler.network_id());
    let res = req_handler.construction_metadata(msg).await;
    assert_eq!(
        res,
        Ok(ConstructionMetadataResponse {
            metadata: Default::default(),
            suggested_fee: Some(vec![Amount {
                value: format!("{}", transaction_fee.get_e8s()),
                currency: Currency {
                    symbol: "ICP".to_string(),
                    decimals: 8,
                    metadata: None,
                },
                metadata: None,
            }]),
        })
    );
}

#[actix_rt::test]
async fn blocks_test() {
    init_test_logger();

    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new(ledger.clone());
    let mut scribe = Scribe::new();
    let num_transactions: usize = 100;
    let num_accounts = 10;

    scribe.gen_accounts(num_accounts, 1_000_000);
    for _i in 0..num_transactions {
        scribe.gen_transaction();
    }

    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
    }

    let h = num_accounts as usize + 17;
    for i in 0..num_accounts {
        let acc = acc_id(i);
        assert_eq!(
            get_balance(&req_handler, Some(h), acc).await.unwrap(),
            *scribe.balance_history[h].get(&acc).unwrap()
        );
    }

    // fetch by index
    let block_id = PartialBlockIdentifier {
        index: Some(h as i64),
        hash: None,
    };
    let msg = BlockRequest::new(req_handler.network_id(), block_id);
    let resp = req_handler.block(msg).await.unwrap();

    let block = resp.block.unwrap();
    assert_eq!(
        to_hash(&block.block_identifier.hash).unwrap(),
        scribe.blockchain[h].hash
    );

    // fetch by hash
    let block_id = PartialBlockIdentifier {
        index: None,
        hash: Some(from_hash(&scribe.blockchain[h].hash)),
    };
    let msg = BlockRequest::new(req_handler.network_id(), block_id);
    let resp = req_handler.block(msg).await.unwrap();
    let block = resp.block.unwrap();

    assert_eq!(block.block_identifier.index, h as i64);
    assert_eq!(block.parent_block_identifier.index, h as i64 - 1);
    assert_eq!(
        to_hash(&block.parent_block_identifier.hash).unwrap(),
        scribe.blockchain[h - 1].hash
    );

    // now fetch a transaction
    let trans = block.transactions[0].clone();

    let block_id = BlockIdentifier {
        index: h as i64,
        hash: from_hash(&scribe.blockchain[h].hash),
    };
    let msg = BlockTransactionRequest::new(
        req_handler.network_id(),
        block_id.clone(),
        trans.transaction_identifier.clone(),
    );
    let resp = req_handler.block_transaction(msg).await.unwrap();

    assert_eq!(
        trans.transaction_identifier.hash,
        resp.transaction.transaction_identifier.hash
    );

    let resp = req_handler
        .search_transactions(SearchTransactionsRequest::new(
            req_handler.network_id(),
            Some(trans.transaction_identifier.clone()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.transactions,
        vec![BlockTransaction::new(block_id, trans)]
    );
    assert_eq!(resp.total_count, 1);

    let resp = req_handler
        .search_transactions(SearchTransactionsRequest::new(
            req_handler.network_id(),
            None,
            None,
        ))
        .await
        .unwrap();

    assert_eq!(resp.total_count, scribe.blockchain.len() as i64);
    assert_eq!(resp.transactions.len(), scribe.blockchain.len());
    assert_eq!(resp.next_offset, None);

    let mut req = SearchTransactionsRequest::new(req_handler.network_id(), None, None);
    req.max_block = Some(100);
    req.limit = Some(10);
    req.offset = Some(30);

    let resp = req_handler.search_transactions(req.clone()).await.unwrap();

    assert_eq!(resp.total_count, 71);
    assert_eq!(resp.transactions.len(), 10);
    assert_eq!(
        resp.transactions.first().unwrap().block_identifier.index,
        70
    );
    assert_eq!(resp.transactions.last().unwrap().block_identifier.index, 61);
    assert_eq!(resp.next_offset, Some(40));

    req.offset = Some(40);

    let resp = req_handler.search_transactions(req.clone()).await.unwrap();

    assert_eq!(resp.total_count, 61);
    assert_eq!(resp.transactions.len(), 10);
    assert_eq!(
        resp.transactions.first().unwrap().block_identifier.index,
        60
    );
    assert_eq!(resp.transactions.last().unwrap().block_identifier.index, 51);
    assert_eq!(resp.next_offset, Some(50));
}

#[actix_rt::test]
async fn balances_test() {
    init_test_logger();

    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new(ledger.clone());
    let mut scribe = Scribe::new();

    scribe.gen_accounts(2, 1_000_000);
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
    }

    let acc0 = acc_id(0);
    let acc1 = acc_id(1);

    assert_eq!(
        get_balance(&req_handler, None, acc0).await.unwrap(),
        *scribe.balance_book.get(&acc0).unwrap()
    );
    assert_eq!(
        get_balance(&req_handler, None, acc1).await.unwrap(),
        *scribe.balance_book.get(&acc1).unwrap()
    );

    scribe.buy(acc0, 10);
    ledger
        .add_block(scribe.blockchain.back().unwrap().clone())
        .await
        .ok();
    assert_eq!(
        get_balance(&req_handler, None, acc0).await.unwrap(),
        *scribe.balance_book.get(&acc0).unwrap()
    );
    assert_eq!(
        get_balance(&req_handler, None, acc1).await.unwrap(),
        *scribe.balance_book.get(&acc1).unwrap()
    );

    let after_buy_balance = *scribe.balance_book.get(&acc0).unwrap();

    scribe.sell(acc0, 100);
    ledger
        .add_block(scribe.blockchain.back().unwrap().clone())
        .await
        .ok();
    assert_eq!(
        get_balance(&req_handler, None, acc0).await.unwrap(),
        *scribe.balance_book.get(&acc0).unwrap()
    );
    assert_eq!(
        get_balance(&req_handler, None, acc1).await.unwrap(),
        *scribe.balance_book.get(&acc1).unwrap()
    );

    scribe.transfer(acc0, acc1, 1000);
    ledger
        .add_block(scribe.blockchain.back().unwrap().clone())
        .await
        .ok();
    assert_eq!(
        get_balance(&req_handler, None, acc0).await.unwrap(),
        *scribe.balance_book.get(&acc0).unwrap()
    );
    assert_eq!(
        get_balance(&req_handler, None, acc1).await.unwrap(),
        *scribe.balance_book.get(&acc1).unwrap()
    );

    // and test if we can access arbitrary block
    assert_eq!(
        get_balance(&req_handler, Some(2), acc0).await.unwrap(),
        after_buy_balance
    );
}

fn verify_balances(scribe: &Scribe, blocks: &Blocks, start_idx: usize) {
    for hb in scribe.blockchain.iter().skip(start_idx) {
        assert_eq!(*hb, blocks.get_verified_at(hb.index).unwrap());
        assert_eq!(*hb, blocks.get_verified(hb.hash).unwrap());
        for (account, amount) in scribe.balance_history.get(hb.index as usize).unwrap() {
            assert_eq!(blocks.get_balance(account, hb.index).unwrap(), *amount);
        }
    }
    let mut sum_icpt = Tokens::ZERO;
    for amount in scribe.balance_history.back().unwrap().values() {
        sum_icpt += *amount;
    }
    assert_eq!(
        (Tokens::MAX - sum_icpt).unwrap(),
        blocks.balance_book.token_pool
    );
}

async fn query_search_transactions(
    req_handler: &RosettaRequestHandler,
    acc: &ledger_canister::AccountIdentifier,
    max_block: Option<i64>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<SearchTransactionsResponse, ApiError> {
    let mut msg = SearchTransactionsRequest::new(
        req_handler.network_id(),
        None,
        Some(ic_rosetta_api::convert::to_model_account_identifier(acc)),
    );
    msg.max_block = max_block;
    msg.offset = offset;
    msg.limit = limit;
    req_handler.search_transactions(msg).await
}

async fn verify_account_search(
    scribe: &Scribe,
    req_handler: &RosettaRequestHandler,
    oldest_idx: u64,
    last_verified_idx: u64,
) {
    let mut history = BTreeMap::new();
    for hb in &scribe.blockchain {
        match hb.block.decode().unwrap().transaction.operation {
            ledger_canister::Operation::Burn { from, .. } => {
                history.entry(from).or_insert_with(Vec::new).push(hb.index);
            }
            ledger_canister::Operation::Mint { to, .. } => {
                history.entry(to).or_insert_with(Vec::new).push(hb.index);
            }
            ledger_canister::Operation::Transfer { from, to, .. } => {
                history.entry(from).or_insert_with(Vec::new).push(hb.index);
                if from != to {
                    history.entry(to).or_insert_with(Vec::new).push(hb.index);
                }
            }
        }
    }

    let middle_idx = (scribe.blockchain.len() as u64 - 1 + oldest_idx) / 2;
    for acc in &scribe.accounts {
        let h2: Vec<BlockHeight> = history
            .get(acc)
            .unwrap()
            .clone()
            .into_iter()
            .rev()
            .filter(|i| *i >= oldest_idx && *i <= last_verified_idx)
            .collect();

        let search_res = query_search_transactions(req_handler, acc, None, None, None)
            .await
            .unwrap();
        let h: Vec<BlockHeight> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockHeight)
            .collect();

        assert_eq!(h, h2);

        let limit = 3;
        let h1: Vec<BlockHeight> = history
            .get(acc)
            .unwrap()
            .clone()
            .into_iter()
            .rev()
            .filter(|i| *i <= middle_idx && *i >= oldest_idx && *i <= last_verified_idx)
            .collect();

        let search_res = query_search_transactions(
            req_handler,
            acc,
            Some(middle_idx as i64),
            None,
            Some(limit as i64),
        )
        .await
        .unwrap();
        let h: Vec<BlockHeight> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockHeight)
            .collect();

        let next_offset = if h1.len() > limit {
            Some(limit as i64)
        } else {
            None
        };

        let mut h1_limit = h1.clone();
        h1_limit.truncate(limit);

        assert_eq!(h, h1_limit);
        assert_eq!(search_res.next_offset, next_offset);

        let offset = 1;
        let search_res = query_search_transactions(
            req_handler,
            acc,
            Some(middle_idx as i64),
            Some(offset),
            Some(limit as i64),
        )
        .await
        .unwrap();
        let h: Vec<BlockHeight> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockHeight)
            .collect();

        let next_offset = if h1.len() > limit + offset as usize {
            Some(limit as i64 + offset)
        } else {
            None
        };

        let mut h1_offset = h1.clone();
        h1_offset = h1_offset.split_off(offset as usize);
        h1_offset.truncate(limit);

        assert_eq!(h, h1_offset);
        assert_eq!(search_res.next_offset, next_offset);
    }
}

#[actix_rt::test]
async fn load_from_store_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location);
    let mut last_verified = 0;
    for hb in &scribe.blockchain {
        blocks.add_block(hb.clone()).unwrap();
        if hb.index < 20 {
            blocks.block_store.mark_last_verified(hb.index).unwrap();
            last_verified = hb.index;
        }
    }

    let some_acc = scribe.accounts.front().cloned().unwrap();

    assert!(blocks.get_verified_at(10).is_ok());
    assert!(blocks.get_balance(&some_acc, 10).is_ok());
    assert!(blocks.get_verified_at(20).is_err());
    assert!(blocks.get_balance(&some_acc, 20).is_err());

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new(ledger);
    verify_account_search(&scribe, &req_handler, 0, last_verified).await;

    drop(req_handler);

    let mut blocks = Blocks::new_persistent(location);
    blocks.load_from_store().unwrap();

    assert!(blocks.get_verified_at(10).is_ok());
    assert!(blocks.get_balance(&some_acc, 10).is_ok());
    assert!(blocks.get_verified_at(20).is_err());
    assert!(blocks.get_balance(&some_acc, 20).is_err());
    last_verified = (scribe.blockchain.len() - 1) as u64;
    blocks
        .block_store
        .mark_last_verified(last_verified)
        .unwrap();

    assert!(blocks.get_balance(&some_acc, 20).is_ok());

    drop(blocks);

    let mut blocks = Blocks::new_persistent(location);
    blocks.load_from_store().unwrap();

    verify_balances(&scribe, &blocks, 0);

    // now load pruned
    blocks
        .try_prune(&Some((scribe.blockchain.len() - 11) as u64), 0)
        .unwrap();

    assert!(blocks.get_verified_at(9).is_err());
    assert!(blocks.get_verified_at(10).is_ok());
    verify_balances(&scribe, &blocks, 10);
    // height 10 is the first block available for balance query, but not for
    // transaction search. Transaction search is available from 11
    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new(ledger);
    verify_account_search(&scribe, &req_handler, 11, last_verified).await;

    drop(req_handler);

    let mut blocks = Blocks::new_persistent(location);
    blocks.load_from_store().unwrap();

    verify_balances(&scribe, &blocks, 10);

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new(ledger);
    verify_account_search(&scribe, &req_handler, 11, last_verified).await;

    let resp = req_handler
        .search_transactions(SearchTransactionsRequest::new(
            req_handler.network_id(),
            None,
            None,
        ))
        .await
        .unwrap();

    assert_eq!(resp.total_count as u64, last_verified - 10 + 1);
    assert_eq!(resp.transactions.len() as u64, last_verified - 10 + 1);
    assert_eq!(resp.next_offset, None);
    assert_eq!(
        resp.transactions.first().unwrap().block_identifier.index as u64,
        last_verified
    );
    assert_eq!(resp.transactions.last().unwrap().block_identifier.index, 10);
}

// remove this test if it's in the way of a new spec
#[actix_rt::test]
async fn load_unverified_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location);
    for hb in &scribe.blockchain {
        blocks.add_block(hb.clone()).unwrap();
        if hb.index < 20 {
            blocks.block_store.mark_last_verified(hb.index).unwrap();
        }
    }

    blocks
        .try_prune(&Some((scribe.blockchain.len() - 51) as u64), 0)
        .unwrap();

    assert!(blocks.get_verified_at(49).is_err());
    assert!(blocks.get_verified_at(50).is_err());

    drop(blocks);

    let mut blocks = Blocks::new_persistent(location);
    blocks.load_from_store().unwrap();
    let last_verified = (scribe.blockchain.len() - 1) as u64;
    blocks
        .block_store
        .mark_last_verified(last_verified)
        .unwrap();

    assert!(blocks.get_verified_at(49).is_err());
    assert!(blocks.get_verified_at(50).is_ok());

    verify_balances(&scribe, &blocks, 50);

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new(ledger);
    verify_account_search(&scribe, &req_handler, 51, last_verified).await;
}

#[actix_rt::test]
async fn store_batch_test() {
    init_test_logger();
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location);
    for hb in &scribe.blockchain {
        if hb.index < 21 {
            blocks.add_block(hb.clone()).unwrap();
        }
    }

    assert_eq!(
        blocks.block_store.get_at(20).unwrap(),
        *scribe.blockchain.get(20).unwrap()
    );
    assert!(blocks.block_store.get_at(21).is_err());

    let mut part2: Vec<HashedBlock> = scribe.blockchain.iter().skip(21).cloned().collect();

    let mut part3 = part2.split_off(10);
    part3.push(scribe.blockchain.get(30).unwrap().clone()); // this will cause an error

    blocks.add_blocks_batch(part2).unwrap();
    assert_eq!(
        blocks.block_store.get_at(30).unwrap(),
        *scribe.blockchain.get(30).unwrap()
    );
    assert!(blocks.block_store.get_at(31).is_err());

    assert!(blocks.add_blocks_batch(part3.clone()).is_err());
    assert_eq!(
        blocks.block_store.get_at(30).unwrap(),
        *scribe.blockchain.get(30).unwrap()
    );
    assert!(blocks.block_store.get_at(31).is_err());

    part3.pop();

    blocks.add_blocks_batch(part3).unwrap();
    let last_idx = scribe.blockchain.back().unwrap().index;
    assert_eq!(
        blocks.block_store.get_at(last_idx).unwrap(),
        *scribe.blockchain.back().unwrap()
    );
    assert!(blocks.block_store.get_at(last_idx + 1).is_err());

    blocks.block_store.mark_last_verified(last_idx).unwrap();
    verify_balances(&scribe, &blocks, 0);
}
