use crate::test_utils::{get_balance, TestLedger};
use ic_ledger_canister_blocks_synchronizer::blocks::Blocks;
use ic_ledger_canister_blocks_synchronizer::blocks::HashedBlock;
use ic_ledger_canister_blocks_synchronizer_test_utils::create_tmp_dir;
use ic_ledger_canister_blocks_synchronizer_test_utils::sample_data::{acc_id, Scribe};
use ic_ledger_core::block::BlockType;
use ic_ledger_core::tokens::CheckedAdd;
use ic_rosetta_api::convert::{block_id, from_hash, to_hash, to_model_account_identifier};
use ic_rosetta_api::errors::ApiError;
use ic_rosetta_api::ledger_client::LedgerAccess;
use ic_rosetta_api::models::amount::tokens_to_amount;
use ic_rosetta_api::models::Amount;
use ic_rosetta_api::models::CallRequest;
use ic_rosetta_api::models::QueryBlockRangeRequest;
use ic_rosetta_api::models::QueryBlockRangeResponse;
use ic_rosetta_api::models::{AccountBalanceRequest, PartialBlockIdentifier};
use ic_rosetta_api::models::{
    AccountBalanceResponse, BlockIdentifier, BlockRequest, BlockTransaction,
    BlockTransactionRequest, ConstructionDeriveRequest, ConstructionDeriveResponse,
    ConstructionMetadataRequest, ConstructionMetadataResponse, Currency, CurveType,
    MempoolTransactionRequest, NetworkRequest, NetworkStatusResponse, SearchTransactionsRequest,
    SearchTransactionsResponse,
};
use ic_rosetta_api::request_handler::RosettaRequestHandler;
use ic_rosetta_api::transaction_id::TransactionIdentifier;
use ic_rosetta_api::DEFAULT_TOKEN_SYMBOL;
use ic_rosetta_api::MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST;
use ic_rosetta_api::{models, API_VERSION, NODE_VERSION};
use icp_ledger::{self, AccountIdentifier, Block, BlockIndex, Tokens};
use rosetta_core::objects::ObjectMap;
use rosetta_core::response_types::{MempoolResponse, NetworkListResponse};
use std::collections::BTreeMap;
use std::sync::Arc;

mod test_utils;

#[actix_rt::test]
async fn smoke_test() {
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
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger.clone());
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.ok();
    }

    assert_eq!(
        scribe.blockchain.len() as u64,
        ledger
            .read_blocks()
            .await
            .get_latest_verified_hashed_block()
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
            models::timestamp::from_system_time(
                Block::decode(scribe.blockchain.back().unwrap().block.clone())
                    .unwrap()
                    .timestamp()
                    .into()
            )
            .unwrap()
            .0
            .try_into()
            .unwrap(),
            block_id(scribe.blockchain.front().unwrap()).unwrap(),
            None,
            None,
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
            .get_first_verified_hashed_block()
            .unwrap()
            .index as usize,
        expected_first_block
    );
    let b = ledger
        .read_blocks()
        .await
        .get_latest_verified_hashed_block()
        .unwrap()
        .index;
    let a = ledger
        .read_blocks()
        .await
        .get_first_verified_hashed_block()
        .unwrap()
        .index;
    assert_eq!(b - a, 10);

    let msg = NetworkRequest::new(req_handler.network_id());
    let res = req_handler.network_status(msg).await;
    assert_eq!(
        res.unwrap().oldest_block_identifier,
        Some(block_id(scribe.blockchain.get(expected_first_block).unwrap()).unwrap())
    );

    let res = req_handler.network_list().await;
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
        TransactionIdentifier::from("hello there".to_string()).into(),
    );
    let res = req_handler.mempool_transaction(msg).await;
    assert_eq!(
        res,
        Err(ApiError::MempoolTransactionMissing(
            false,
            Default::default()
        ))
    );

    let msg = AccountBalanceRequest {
        network_identifier: req_handler.network_id(),
        account_identifier: ic_rosetta_api::convert::to_model_account_identifier(&acc_id(0)),
        block_identifier: None,
        metadata: None,
    };

    let res = req_handler.account_balance(msg).await;
    assert_eq!(
        res,
        Ok(AccountBalanceResponse {
            block_identifier: block_id(scribe.blockchain.back().unwrap()).unwrap(),
            balances: vec![tokens_to_amount(
                *scribe.balance_book.get(&acc_id(0)).unwrap(),
                DEFAULT_TOKEN_SYMBOL
            )
            .unwrap()],
            metadata: None
        })
    );

    let (acc_id, _ed_kp, pk, _pid) = ic_rosetta_test_utils::make_user_ed25519(4);
    let msg = ConstructionDeriveRequest::new(req_handler.network_id(), pk);
    let res = req_handler.construction_derive(msg);
    assert_eq!(
        res,
        Ok(ConstructionDeriveResponse {
            address: None,
            account_identifier: Some(to_model_account_identifier(&acc_id)),
            metadata: None
        })
    );

    let (_acc_id, _ed_kp, mut pk, _pid) = ic_rosetta_test_utils::make_user_ed25519(4);
    pk.curve_type = CurveType::Secp256K1;
    let msg = ConstructionDeriveRequest::new(req_handler.network_id(), pk);
    let res = req_handler.construction_derive(msg);
    assert!(res.is_err(), "This pk should not have been accepted");

    let msg = ConstructionMetadataRequest {
        network_identifier: req_handler.network_id(),
        options: None,
        public_keys: None,
    };
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
    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger.clone());
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
        index: Some(h.try_into().unwrap()),
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

    assert_eq!(block.block_identifier.index as usize, h);
    assert_eq!(block.parent_block_identifier.index as usize, h - 1);
    assert_eq!(
        to_hash(&block.parent_block_identifier.hash).unwrap(),
        scribe.blockchain[h - 1].hash
    );

    // now fetch a transaction
    let trans = block.transactions[0].clone();

    let block_id = BlockIdentifier {
        index: h.try_into().unwrap(),
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
        .search_transactions(
            SearchTransactionsRequest::builder(req_handler.network_id())
                .with_transaction_identifier(trans.transaction_identifier.clone()),
        )
        .build()
        .await
        .unwrap();
    assert_eq!(
        resp.transactions,
        vec![BlockTransaction {
            block_identifier: block_id,
            transaction: trans
        }]
    );
    assert_eq!(resp.total_count, 1);

    let resp = req_handler
        .search_transactions(SearchTransactionsRequest::builder(req_handler.network_id()).build())
        .await
        .unwrap();

    assert_eq!(resp.total_count, scribe.blockchain.len() as i64);
    assert_eq!(resp.transactions.len(), scribe.blockchain.len());
    assert_eq!(resp.next_offset, None);

    let mut req = SearchTransactionsRequest::builder(req_handler.network_id()).build();
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

    for block in scribe.blockchain.clone() {
        let partial_block_id = PartialBlockIdentifier {
            index: Some(block.index),
            hash: None,
        };
        let msg = BlockRequest::new(req_handler.network_id(), partial_block_id);
        let resp = req_handler.block(msg).await.unwrap();
        let transactions = vec![
            ic_rosetta_api::convert::hashed_block_to_rosetta_core_transaction(
                &block,
                ic_rosetta_api::DEFAULT_TOKEN_SYMBOL,
            )
            .unwrap(),
        ];
        assert_eq!(resp.clone().block.unwrap().transactions, transactions);
        let transaction = resp.block.unwrap().transactions[0].clone();
        let block_id = BlockIdentifier {
            index: block.index,
            hash: from_hash(&block.hash),
        };
        let msg = BlockTransactionRequest::new(
            req_handler.network_id(),
            block_id.clone(),
            transaction.transaction_identifier.clone(),
        );
        let resp = req_handler.block_transaction(msg).await.unwrap();
        assert_eq!(resp.transaction, transactions[0]);
        let resp = req_handler
            .search_transactions(
                SearchTransactionsRequest::builder(req_handler.network_id())
                    .with_transaction_identifier(transaction.transaction_identifier)
                    .build(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.transactions
                .into_iter()
                .map(|t| t.transaction)
                .collect::<Vec<ic_rosetta_api::models::Transaction>>()[0],
            transactions[0]
        );
    }
}

#[actix_rt::test]
async fn balances_test() {
    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger.clone());
    let mut scribe = Scribe::new();

    scribe.gen_accounts(2, 1_000_000);
    for b in &scribe.blockchain {
        ledger.add_block(b.clone()).await.unwrap();
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
        .unwrap();
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
        .unwrap();
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
        .unwrap();
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
        assert_eq!(*hb, blocks.get_hashed_block(&hb.index).unwrap());
        assert!(blocks.is_verified_by_hash(&hb.hash).unwrap());
        for (account, amount) in scribe.balance_history.get(hb.index as usize).unwrap() {
            assert_eq!(
                blocks.get_account_balance(account, &hb.index).unwrap(),
                *amount
            );
        }
    }
    let mut sum_icpt = Tokens::ZERO;
    let latest = blocks.get_latest_verified_hashed_block().unwrap();
    for amount in scribe.balance_history.back().unwrap().values() {
        sum_icpt = sum_icpt.checked_add(amount).unwrap();
    }
    let accounts = blocks.get_all_accounts().unwrap();
    let mut total = Tokens::ZERO;
    for account in accounts {
        let amount = blocks.get_account_balance(&account, &latest.index).unwrap();
        total = total.checked_add(&amount).unwrap();
    }
    assert_eq!(sum_icpt, total);
}

async fn query_search_transactions(
    req_handler: &RosettaRequestHandler,
    acc: &icp_ledger::AccountIdentifier,
    max_block: Option<i64>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<SearchTransactionsResponse, ApiError> {
    let mut msg = SearchTransactionsRequest::builder(req_handler.network_id())
        .with_account_identifier(ic_rosetta_api::convert::to_model_account_identifier(acc))
        .build();
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

    let mut index = |account: AccountIdentifier, block_index: u64| {
        history
            .entry(account)
            .or_insert_with(Vec::new)
            .push(block_index);
    };

    for hb in &scribe.blockchain {
        match Block::decode(hb.block.clone())
            .unwrap()
            .transaction
            .operation
        {
            icp_ledger::Operation::Burn { from, .. } => {
                index(from, hb.index);
            }
            icp_ledger::Operation::Mint { to, .. } => {
                index(to, hb.index);
            }
            icp_ledger::Operation::Transfer {
                from, to, spender, ..
            } => {
                index(from, hb.index);
                if from != to {
                    index(to, hb.index);
                }
                // https://github.com/rust-lang/rust-clippy/issues/4530
                #[allow(clippy::unnecessary_unwrap)]
                if spender.is_some() && spender.unwrap() != from && spender.unwrap() != to {
                    index(spender.unwrap(), hb.index);
                }
            }
            icp_ledger::Operation::Approve { from, spender, .. } => {
                assert_ne!(from, spender);
                index(from, hb.index);
            }
        }
    }

    let middle_idx = (scribe.blockchain.len() as u64 - 1 + oldest_idx) / 2;
    for acc in &scribe.accounts {
        let mut h2: Vec<BlockIndex> = history
            .get(acc)
            .unwrap()
            .clone()
            .into_iter()
            .filter(|i| *i >= oldest_idx && *i <= last_verified_idx)
            .collect();

        let search_res = query_search_transactions(req_handler, acc, None, None, None)
            .await
            .unwrap();
        let mut h: Vec<BlockIndex> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockIndex)
            .collect();
        h.sort_by(|a, b| a.partial_cmp(b).unwrap());
        h2.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(h, h2);

        let limit = 3;
        let h1: Vec<BlockIndex> = history
            .get(acc)
            .unwrap()
            .clone()
            .into_iter()
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
        let h: Vec<BlockIndex> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockIndex)
            .collect();

        let next_offset = if h1.len() > limit {
            Some(limit as i64)
        } else {
            None
        };

        let mut h1_limit = h1.clone();
        h1_limit.truncate(limit);
        h1_limit.sort_by(|a, b| a.partial_cmp(b).unwrap());
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
        let h: Vec<BlockIndex> = search_res
            .transactions
            .iter()
            .map(|t| t.block_identifier.index as BlockIndex)
            .collect();

        let next_offset = if h1.len() > limit + offset as usize {
            Some(limit as i64 + offset)
        } else {
            None
        };

        let mut h1_offset = h1.clone();
        h1_offset = h1_offset.split_off(offset as usize);
        h1_offset.truncate(limit);
        h1_offset.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(h, h1_offset);
        assert_eq!(search_res.next_offset, next_offset);
    }
}

#[actix_rt::test]
async fn load_from_store_test() {
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    let mut last_verified = 0;
    for hb in &scribe.blockchain {
        blocks.push(hb).unwrap();
        if hb.index < 20 {
            blocks.set_hashed_block_to_verified(&hb.index).unwrap();
            last_verified = hb.index;
        }
    }

    let some_acc = scribe.accounts.front().cloned().unwrap();

    assert!(blocks.is_verified_by_idx(&10).unwrap());
    assert!(blocks.get_account_balance(&some_acc, &10).is_ok());
    assert!(!blocks.is_verified_by_idx(&20).unwrap());
    assert!(blocks.get_account_balance(&some_acc, &20).is_err());

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    verify_account_search(&scribe, &req_handler, 0, last_verified).await;

    drop(req_handler);

    let blocks = Blocks::new_persistent(location, false).unwrap();
    assert!(blocks.is_verified_by_idx(&10).unwrap());
    assert!(blocks.get_account_balance(&some_acc, &10).is_ok());
    assert!(!blocks.is_verified_by_idx(&20).unwrap());
    assert!(blocks.get_account_balance(&some_acc, &20).is_err());
    last_verified = (scribe.blockchain.len() - 1) as u64;
    blocks.set_hashed_block_to_verified(&last_verified).unwrap();

    assert!(blocks.get_account_balance(&some_acc, &20).is_ok());

    drop(blocks);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    verify_balances(&scribe, &blocks, 0);

    // now load pruned
    blocks
        .try_prune(&Some((scribe.blockchain.len() - 11) as u64), 0)
        .unwrap();

    assert!(blocks.is_verified_by_idx(&9).is_err());
    assert!(blocks.is_verified_by_idx(&10).unwrap());
    verify_balances(&scribe, &blocks, 10);
    // height 10 is the first block available for balance query, but not for
    // transaction search. Transaction search is available from 11
    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    verify_account_search(&scribe, &req_handler, 11, last_verified).await;

    drop(req_handler);

    let blocks = Blocks::new_persistent(location, false).unwrap();
    verify_balances(&scribe, &blocks, 10);

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    verify_account_search(&scribe, &req_handler, 11, last_verified).await;

    let resp = req_handler
        .search_transactions(SearchTransactionsRequest::builder(req_handler.network_id()).build())
        .await
        .unwrap();

    assert_eq!(resp.total_count as u64, last_verified - 10 + 1);
    assert_eq!(resp.transactions.len() as u64, last_verified - 10 + 1);
    assert_eq!(resp.next_offset, None);
    assert_eq!(
        resp.transactions.first().unwrap().block_identifier.index,
        last_verified
    );
    assert_eq!(resp.transactions.last().unwrap().block_identifier.index, 10);
}

// remove this test if it's in the way of a new spec
#[actix_rt::test]
async fn load_unverified_test() {
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    for hb in &scribe.blockchain {
        blocks.push(hb).unwrap();
        if hb.index < 20 {
            blocks.set_hashed_block_to_verified(&hb.index).unwrap();
        }
    }

    blocks
        .try_prune(&Some((scribe.blockchain.len() - 51) as u64), 0)
        .unwrap();

    assert!(blocks.is_verified_by_idx(&49).is_err());
    assert!(!blocks.is_verified_by_idx(&50).unwrap());

    drop(blocks);

    let blocks = Blocks::new_persistent(location, false).unwrap();
    let last_verified = (scribe.blockchain.len() - 1) as u64;
    blocks.set_hashed_block_to_verified(&last_verified).unwrap();

    assert!(blocks.is_verified_by_idx(&49).is_err());
    assert!(blocks.is_verified_by_idx(&50).unwrap());

    verify_balances(&scribe, &blocks, 50);

    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    verify_account_search(&scribe, &req_handler, 51, last_verified).await;
}

#[actix_rt::test]
async fn store_batch_test() {
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 150);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    for hb in &scribe.blockchain {
        if hb.index < 21 {
            blocks.push(hb).unwrap();
        }
    }

    assert_eq!(
        blocks.get_hashed_block(&20).unwrap(),
        *scribe.blockchain.get(20).unwrap()
    );
    assert!(blocks.get_hashed_block(&21).is_err());

    let mut part2: Vec<HashedBlock> = scribe.blockchain.iter().skip(21).cloned().collect();

    let mut part3 = part2.split_off(10);
    part3.push(scribe.blockchain.get(30).unwrap().clone()); // this will cause an error

    blocks.push_batch(part2.clone()).unwrap();

    assert_eq!(
        blocks.get_hashed_block(&30).unwrap(),
        *scribe.blockchain.get(30).unwrap()
    );
    assert!(blocks.get_hashed_block(&31).is_err());

    assert!(blocks.push_batch(part3.clone()).is_err());
    assert_eq!(
        blocks.get_hashed_block(&30).unwrap(),
        *scribe.blockchain.get(30).unwrap()
    );
    assert!(blocks.get_hashed_block(&31).is_err());

    part3.pop();

    blocks.push_batch(part3).unwrap();
    let last_idx = scribe.blockchain.back().unwrap().index;
    assert_eq!(
        blocks.get_hashed_block(&last_idx).unwrap(),
        *scribe.blockchain.back().unwrap()
    );
    assert!(blocks.get_hashed_block(&(last_idx + 1)).is_err());

    blocks.set_hashed_block_to_verified(&last_idx).unwrap();
    verify_balances(&scribe, &blocks, 0);
}

#[actix_rt::test]
async fn test_query_block_range() {
    let tmpdir = create_tmp_dir();
    let location = tmpdir.path();
    let scribe = Scribe::new_with_sample_data(10, 1000);

    let mut blocks = Blocks::new_persistent(location, false).unwrap();
    let mut block_indices = Vec::new();

    // Test with empty rosetta
    let ledger = Arc::new(TestLedger::new());
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);
    let response: QueryBlockRangeResponse = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),

            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(QueryBlockRangeRequest {
                highest_block_index: 100,
                number_of_blocks: 10,
            })
            .unwrap(),
        })
        .await
        .unwrap()
        .result
        .try_into()
        .unwrap();
    assert!(response.blocks.is_empty());

    for hb in &scribe.blockchain {
        blocks.push(hb).unwrap();
        blocks.set_hashed_block_to_verified(&hb.index).unwrap();
        block_indices.push(hb.index);
    }
    block_indices.sort();

    // Test with non-empty rosetta
    let ledger = Arc::new(TestLedger::from_blockchain(blocks));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(ledger);

    let highest_block_index = block_indices.last().unwrap();
    // Call with 0 numbers of blocks
    let response: QueryBlockRangeResponse = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),
            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(QueryBlockRangeRequest {
                highest_block_index: *highest_block_index,
                number_of_blocks: 0,
            })
            .unwrap(),
        })
        .await
        .unwrap()
        .result
        .try_into()
        .unwrap();
    assert!(response.blocks.is_empty());
    // Call with higher index than there are blocks in the database
    let response = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),
            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(QueryBlockRangeRequest {
                highest_block_index: (block_indices.len() * 2) as u64,
                number_of_blocks: std::cmp::max(
                    block_indices.len() as u64,
                    MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST,
                ),
            })
            .unwrap(),
        })
        .await
        .unwrap();
    let query_block_response: QueryBlockRangeResponse = response.result.try_into().unwrap();
    // If the blocks measured from the highest block index asked for are not in the database the service should return an empty array of blocks
    if block_indices.len() >= MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize {
        assert_eq!(query_block_response.blocks.len(), 0);
        assert!(!response.idempotent);
    }
    // If some of the blocks measured from the highest block index asked for are in the database the service should return the blocks that are in the database
    else {
        if block_indices.len() * 2 > MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize {
            assert_eq!(
                query_block_response.blocks.len(),
                block_indices
                    .len()
                    .saturating_sub(
                        (block_indices.len() * 2)
                            .saturating_sub(MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize)
                    )
                    .saturating_sub(1)
            );
        } else {
            assert_eq!(query_block_response.blocks.len(), block_indices.len());
        }
        assert!(!response.idempotent);
    }
    let number_of_blocks = (block_indices.len() / 2) as u64;
    let query_blocks_request = QueryBlockRangeRequest {
        highest_block_index: *highest_block_index,
        number_of_blocks,
    };

    let query_blocks_response = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),

            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(query_blocks_request.clone()).unwrap(),
        })
        .await
        .unwrap();
    assert!(query_blocks_response.idempotent);
    let response: QueryBlockRangeResponse = query_blocks_response.result.try_into().unwrap();

    let querried_blocks = response.blocks;
    assert_eq!(
        querried_blocks.len(),
        std::cmp::min(number_of_blocks, MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST) as usize
    );
    if !querried_blocks.is_empty() {
        assert_eq!(
            querried_blocks.first().unwrap().block_identifier.index,
            highest_block_index
                .saturating_sub(std::cmp::min(
                    number_of_blocks,
                    MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST
                ))
                .saturating_add(1)
        );
        assert_eq!(
            querried_blocks.last().unwrap().block_identifier.index,
            *highest_block_index
        );
    }

    let query_blocks_request = QueryBlockRangeRequest {
        highest_block_index: *highest_block_index,
        number_of_blocks: MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST + 1,
    };

    let query_blocks_response: QueryBlockRangeResponse = req_handler
        .call(CallRequest {
            network_identifier: req_handler.network_id(),

            method_name: "query_block_range".to_owned(),
            parameters: ObjectMap::try_from(query_blocks_request).unwrap(),
        })
        .await
        .unwrap()
        .result
        .try_into()
        .unwrap();
    assert_eq!(
        query_blocks_response.blocks.len(),
        std::cmp::min(
            MAX_BLOCKS_PER_QUERY_BLOCK_RANGE_REQUEST as usize,
            block_indices.len()
        )
    );
}
