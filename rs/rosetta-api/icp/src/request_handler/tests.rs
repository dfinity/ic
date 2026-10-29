//! Tests for the RosettaRequestHandler.

use crate::{
    convert,
    errors::{ApiError, Details},
    ledger_client::LedgerAccess,
    models::{
        AccountBalanceRequest, BlockRequest, BlockTransactionRequest, CallRequest, NetworkRequest,
        ObjectMap, PartialBlockIdentifier, QueryBlockRangeRequest, QueryBlockRangeResponse,
        SearchTransactionsRequest,
    },
    request_handler::RosettaRequestHandler,
};
use async_trait::async_trait;
use futures::{FutureExt, TryFutureExt, future::LocalBoxFuture};
use ic_ledger_canister_blocks_synchronizer::blocks::{
    Blocks, HashedBlock, RosettaBlocksMode, RosettaDbConfig,
};
use ic_ledger_canister_blocks_synchronizer_test_utils::sample_data::Scribe;
use ic_ledger_core::block::BlockType;
use ic_nns_governance_api::{KnownNeuron, ProposalInfo, manage_neuron::NeuronIdOrSubaccount};
use ic_types::{CanisterId, PrincipalId};
use icp_ledger::{
    AccountIdentifier, Block, DEFAULT_TRANSFER_FEE, Memo, Operation, TimeStamp, Tokens, TransferFee,
};
use rosetta_core::metrics::RosettaMetrics;
use std::{
    ops::Deref,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[allow(clippy::disallowed_types)]
use tokio::sync::RwLock;

/// A minimal mock ledger for testing the request handler.
/// Only implements enough to test `network_status` and the endpoints that read blocks.
#[allow(clippy::disallowed_types)]
struct MockLedger {
    blockchain: RwLock<Blocks>,
    canister_id: CanisterId,
    governance_canister_id: CanisterId,
}

#[allow(clippy::disallowed_types)]
impl MockLedger {
    fn new() -> Self {
        Self::new_with_blocks(Blocks::new_in_memory(RosettaDbConfig::default_disabled()).unwrap())
    }

    fn new_with_blocks(blockchain: Blocks) -> Self {
        Self {
            blockchain: RwLock::new(blockchain),
            canister_id: CanisterId::unchecked_from_principal(
                ic_types::PrincipalId::from_str("5v3p4-iyaaa-aaaaa-qaaaa-cai").unwrap(),
            ),
            governance_canister_id: ic_nns_constants::GOVERNANCE_CANISTER_ID,
        }
    }
}

#[async_trait]
impl LedgerAccess for MockLedger {
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a> {
        Box::new(self.blockchain.read().await)
    }

    async fn sync_blocks(&self, _stopped: Arc<AtomicBool>) -> Result<(), ApiError> {
        Ok(())
    }

    fn ledger_canister_id(&self) -> &CanisterId {
        &self.canister_id
    }

    fn governance_canister_id(&self) -> &CanisterId {
        &self.governance_canister_id
    }

    async fn submit(
        &self,
        _signed_transaction: crate::models::SignedTransaction,
    ) -> Result<crate::request::transaction_results::TransactionResults, ApiError> {
        unimplemented!("Not needed for this test")
    }

    async fn cleanup(&self) {}

    fn token_symbol(&self) -> &str {
        "ICP"
    }

    async fn neuron_info(
        &self,
        _id: NeuronIdOrSubaccount,
        _verified: bool,
    ) -> Result<ic_nns_governance_api::NeuronInfo, ApiError> {
        unimplemented!("Not needed for this test")
    }

    async fn proposal_info(&self, _proposal_id: u64) -> Result<ProposalInfo, ApiError> {
        unimplemented!("Not needed for this test")
    }

    async fn pending_proposals(&self) -> Result<Vec<ProposalInfo>, ApiError> {
        unimplemented!("Not needed for this test")
    }

    async fn minimum_dissolve_delay(&self) -> Result<Option<u64>, ApiError> {
        unimplemented!("Not needed for this test")
    }

    async fn list_known_neurons(&self) -> Result<Vec<KnownNeuron>, ApiError> {
        unimplemented!("Not needed for this test")
    }

    async fn transfer_fee(&self) -> Result<TransferFee, ApiError> {
        unimplemented!("Not needed for this test")
    }

    // Like `LedgerClient`, read the mode under the blockchain lock.
    async fn rosetta_blocks_mode(&self) -> RosettaBlocksMode {
        self.blockchain.read().await.rosetta_blocks_mode
    }
}

/// Test that `network_status` returns an error when `initial_sync_complete` is false.
#[tokio::test]
async fn test_network_status_returns_error_during_initial_sync() {
    let ledger = Arc::new(MockLedger::new());
    let canister_id = ledger.ledger_canister_id();
    let canister_id_str = hex::encode(canister_id.get_ref().as_slice());

    let initial_sync_complete = Arc::new(AtomicBool::new(false));
    let req_handler = RosettaRequestHandler::new(
        crate::DEFAULT_BLOCKCHAIN.to_string(),
        ledger,
        RosettaMetrics::new(crate::DEFAULT_TOKEN_SYMBOL.to_string(), canister_id_str),
        Arc::clone(&initial_sync_complete),
    );

    let network_request = NetworkRequest {
        network_identifier: req_handler.network_id(),
        metadata: None,
    };

    // Verify that network_status returns an error when initial sync is incomplete
    let result = req_handler.network_status(network_request).await;
    assert!(
        result.is_err(),
        "Expected error when initial_sync_complete is false"
    );

    match result.unwrap_err() {
        ApiError::NotAvailableOffline(retriable, details) => {
            assert!(retriable, "Error should be retriable");
            assert_eq!(
                details,
                Details::from(
                    "The node is still syncing the blocks from the ledger canister. \
                     Please wait until the initial sync is complete."
                        .to_string()
                )
            );
        }
        other => panic!("Expected NotAvailableOffline error, got: {:?}", other),
    }
}

/// Test that the endpoints that read blocks return the retriable error of `/network/status`
/// until the initial sync is complete, before they read the blocks: they answer even while the
/// blockchain is write-locked.
#[tokio::test]
async fn test_endpoints_that_read_blocks_return_error_during_initial_sync() {
    let ledger_blocks = make_ledger_blocks(&[1, 2]);
    let mut blockchain = Blocks::new_in_memory(RosettaDbConfig::default_disabled()).unwrap();
    sync(&mut blockchain, &ledger_blocks);
    let ledger = Arc::new(MockLedger::new_with_blocks(blockchain));
    let initial_sync_complete = Arc::new(AtomicBool::new(false));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(
        ledger.clone(),
        Arc::clone(&initial_sync_complete),
    );
    let still_syncing = ApiError::NotAvailableOffline(
        true,
        Details::from(
            "The node is still syncing the blocks from the ledger canister. \
             Please wait until the initial sync is complete."
                .to_string(),
        ),
    );

    {
        let _writer = ledger.blockchain.write().await;
        for (endpoint, request) in requests_that_read_blocks(&req_handler, &ledger_blocks) {
            assert_eq!(
                request.now_or_never(),
                Some(Err(still_syncing.clone())),
                "{endpoint} during the initial sync"
            );
        }
    }

    initial_sync_complete.store(true, Ordering::Relaxed);
    for (endpoint, request) in requests_that_read_blocks(&req_handler, &ledger_blocks) {
        if let Err(err) = request.await {
            panic!("{endpoint} failed after the initial sync: {err:?}");
        }
    }
}

/// Test that during the initial sync, invalid requests to the endpoints that read blocks get
/// their own errors, and so do the `/call` methods that don't read blocks.
#[tokio::test]
async fn test_invalid_requests_get_their_own_errors_during_initial_sync() {
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(
        Arc::new(MockLedger::new()),
        Arc::new(AtomicBool::new(false)),
    );
    let network_identifier = req_handler.network_id();

    let mut account = convert::to_model_account_identifier(&AccountIdentifier::new(
        PrincipalId::new_anonymous(),
        None,
    ));
    account.address = "not an account".to_string();
    let result = req_handler
        .account_balance(
            AccountBalanceRequest::builder(network_identifier.clone(), account).build(),
        )
        .await;
    assert!(
        matches!(result, Err(ApiError::InvalidAccountId(false, _))),
        "{result:?}"
    );

    let result = req_handler
        .call(CallRequest::new(
            network_identifier.clone(),
            "query_block_range".to_string(),
            ObjectMap::new(),
        ))
        .await;
    assert!(
        matches!(result, Err(ApiError::InternalError(false, _))),
        "{result:?}"
    );

    let result = req_handler
        .call(CallRequest::new(
            network_identifier.clone(),
            "unsupported_method".to_string(),
            ObjectMap::new(),
        ))
        .await;
    assert!(
        matches!(result, Err(ApiError::InvalidRequest(false, _))),
        "{result:?}"
    );

    let mut search_transactions_request =
        SearchTransactionsRequest::builder(network_identifier).build();
    search_transactions_request.success = Some(true);
    let result = req_handler
        .search_transactions(search_transactions_request)
        .await;
    assert!(
        matches!(result, Err(ApiError::InvalidRequest(false, _))),
        "{result:?}"
    );
}

/// Returns a request to each endpoint that reads blocks, for a store with the given ledger
/// blocks, which mint to the anonymous principal.
fn requests_that_read_blocks<'a>(
    req_handler: &'a RosettaRequestHandler,
    ledger_blocks: &[HashedBlock],
) -> Vec<(&'static str, LocalBoxFuture<'a, Result<(), ApiError>>)> {
    let tip = ledger_blocks.last().unwrap();
    let network_identifier = req_handler.network_id();
    let account = convert::to_model_account_identifier(&AccountIdentifier::new(
        PrincipalId::new_anonymous(),
        None,
    ));
    let transaction_identifier = convert::hashed_block_to_rosetta_core_transaction(tip, "ICP")
        .unwrap()
        .transaction_identifier;
    vec![
        (
            "/account/balance",
            req_handler
                .account_balance(
                    AccountBalanceRequest::builder(network_identifier.clone(), account).build(),
                )
                .map_ok(|_| ())
                .boxed_local(),
        ),
        (
            "/block",
            block(req_handler, Some(tip.index), None)
                .map_ok(|_| ())
                .boxed_local(),
        ),
        (
            "/block/transaction",
            req_handler
                .block_transaction(BlockTransactionRequest::new(
                    network_identifier.clone(),
                    convert::block_id(tip).unwrap(),
                    transaction_identifier,
                ))
                .map_ok(|_| ())
                .boxed_local(),
        ),
        (
            "/call query_block_range",
            query_block_range(req_handler, tip.index, 1)
                .map_ok(|_| ())
                .boxed_local(),
        ),
        (
            "/network/status",
            req_handler
                .network_status(NetworkRequest {
                    network_identifier: network_identifier.clone(),
                    metadata: None,
                })
                .map_ok(|_| ())
                .boxed_local(),
        ),
        (
            "/search/transactions",
            req_handler
                .search_transactions(SearchTransactionsRequest::builder(network_identifier).build())
                .map_ok(|_| ())
                .boxed_local(),
        ),
    ]
}

/// Test that requests reading blocks don't deadlock with a writer of the blockchain, like the
/// sync thread. Tokio's `RwLock` is write-preferring, so a handler that read-locks the
/// blockchain while holding a read lock on it waits for a queued writer, which waits for the
/// handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_requests_do_not_deadlock_with_concurrent_writer() {
    assert_requests_do_not_deadlock_with_concurrent_writer(RosettaDbConfig::default_disabled())
        .await;
}

/// Like `test_requests_do_not_deadlock_with_concurrent_writer`, but with Rosetta blocks, which
/// `/block` returns for index 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_requests_do_not_deadlock_with_concurrent_writer_in_rosetta_blocks_mode() {
    assert_requests_do_not_deadlock_with_concurrent_writer(RosettaDbConfig::default_enabled())
        .await;
}

async fn assert_requests_do_not_deadlock_with_concurrent_writer(config: RosettaDbConfig) {
    let mut blockchain = Blocks::new_in_memory(config).unwrap();
    sync(
        &mut blockchain,
        &Vec::from(Scribe::new_with_sample_data(2, 0).blockchain),
    );
    let ledger = Arc::new(MockLedger::new_with_blocks(blockchain));
    let req_handler = RosettaRequestHandler::new_with_default_blockchain(
        ledger.clone(),
        Arc::new(AtomicBool::new(true)),
    );

    let writer = tokio::spawn(async move {
        loop {
            drop(ledger.blockchain.write().await);
            tokio::task::yield_now().await;
        }
    });
    let block_request = BlockRequest {
        network_identifier: req_handler.network_id(),
        block_identifier: PartialBlockIdentifier {
            index: Some(1),
            hash: None,
        },
    };
    let query_block_range_request = CallRequest::new(
        req_handler.network_id(),
        "query_block_range".to_string(),
        ObjectMap::try_from(QueryBlockRangeRequest {
            highest_block_index: 1,
            number_of_blocks: 2,
        })
        .unwrap(),
    );
    let search_transactions_request =
        SearchTransactionsRequest::builder(req_handler.network_id()).build();
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(1) {
            req_handler.block(block_request.clone()).await.unwrap();
            req_handler
                .call(query_block_range_request.clone())
                .await
                .unwrap();
            req_handler
                .search_transactions(search_transactions_request.clone())
                .await
                .unwrap();
        }
    })
    .await;
    writer.abort();
    assert!(
        result.is_ok(),
        "request handler deadlocked with a concurrent writer"
    );
}

/// Returns ledger blocks with the given timestamps in seconds, each with a
/// different transaction, so that consecutive blocks with the same timestamp
/// end up in the same Rosetta block.
fn make_ledger_blocks(timestamps_secs: &[u64]) -> Vec<HashedBlock> {
    let mut blocks: Vec<HashedBlock> = vec![];
    for (index, timestamp_secs) in timestamps_secs.iter().enumerate() {
        let parent_hash = blocks.last().map(|hb| hb.hash);
        let timestamp = TimeStamp::from_nanos_since_unix_epoch(timestamp_secs * 1_000_000_000);
        let block = Block::new(
            parent_hash,
            Operation::Mint {
                to: AccountIdentifier::new(PrincipalId::new_anonymous(), None),
                amount: Tokens::from_e8s(index as u64 + 1),
            },
            Memo(index as u64),
            timestamp,
            timestamp,
            DEFAULT_TRANSFER_FEE,
        )
        .unwrap();
        blocks.push(HashedBlock::hash_block(
            block.encode(),
            parent_hash,
            index as u64,
            timestamp,
        ));
    }
    blocks
}

/// Stores `ledger_blocks`, verifies them and makes their Rosetta blocks, like
/// a sync does.
fn sync(blockchain: &mut Blocks, ledger_blocks: &[HashedBlock]) {
    for hb in ledger_blocks {
        blockchain.push(hb).unwrap();
    }
    let tip_index = ledger_blocks.last().unwrap().index;
    blockchain.set_hashed_block_to_verified(&tip_index).unwrap();
    blockchain
        .make_rosetta_blocks_if_enabled(tip_index)
        .unwrap();
}

fn handler(blockchain: Blocks) -> RosettaRequestHandler {
    RosettaRequestHandler::new_with_default_blockchain(
        Arc::new(MockLedger::new_with_blocks(blockchain)),
        Arc::new(AtomicBool::new(true)),
    )
}

async fn query_block_range(
    req_handler: &RosettaRequestHandler,
    highest_block_index: u64,
    number_of_blocks: u64,
) -> Result<QueryBlockRangeResponse, ApiError> {
    let response = req_handler
        .call(CallRequest::new(
            req_handler.network_id(),
            "query_block_range".to_string(),
            ObjectMap::try_from(QueryBlockRangeRequest {
                highest_block_index,
                number_of_blocks,
            })
            .unwrap(),
        ))
        .await?;
    Ok(QueryBlockRangeResponse::try_from(response.result).unwrap())
}

async fn block(
    req_handler: &RosettaRequestHandler,
    index: Option<u64>,
    hash: Option<String>,
) -> Result<rosetta_core::objects::Block, ApiError> {
    let response = req_handler
        .block(BlockRequest {
            network_identifier: req_handler.network_id(),
            block_identifier: PartialBlockIdentifier { index, hash },
        })
        .await?;
    Ok(response.block.unwrap())
}

/// Asserts that the endpoints that return ledger blocks give every ledger block
/// the previous ledger block as parent, by checking that they return the same
/// as with Rosetta blocks disabled.
async fn assert_ledger_blocks_have_ledger_parents(
    req_handler: &RosettaRequestHandler,
    ledger_blocks: &[HashedBlock],
) {
    let mut blockchain = Blocks::new_in_memory(RosettaDbConfig::default_disabled()).unwrap();
    sync(&mut blockchain, ledger_blocks);
    let without_rosetta_blocks = handler(blockchain);

    let num_blocks = ledger_blocks.len() as u64;
    let block_range = query_block_range(req_handler, num_blocks - 1, num_blocks)
        .await
        .unwrap();
    assert_eq!(
        block_range.blocks[0].parent_block_identifier,
        block_range.blocks[0].block_identifier
    );
    for pair in block_range.blocks.windows(2) {
        assert_eq!(pair[1].parent_block_identifier, pair[0].block_identifier);
    }
    for highest_block_index in 0..num_blocks {
        assert_eq!(
            query_block_range(req_handler, highest_block_index, num_blocks)
                .await
                .unwrap(),
            query_block_range(&without_rosetta_blocks, highest_block_index, num_blocks)
                .await
                .unwrap()
        );
    }

    let search_request = SearchTransactionsRequest::builder(req_handler.network_id()).build();
    assert_eq!(
        req_handler
            .search_transactions(search_request.clone())
            .await
            .unwrap(),
        without_rosetta_blocks
            .search_transactions(search_request)
            .await
            .unwrap()
    );

    for hb in ledger_blocks {
        let hash = convert::block_id(hb).unwrap().hash;
        assert_eq!(
            block(req_handler, None, Some(hash.clone())).await.unwrap(),
            block(&without_rosetta_blocks, None, Some(hash))
                .await
                .unwrap()
        );
    }
}

/// Test that in Rosetta blocks mode the endpoints that return ledger blocks give
/// them the previous ledger block as parent, instead of looking the parent up
/// among the Rosetta blocks.
#[tokio::test]
async fn test_ledger_blocks_have_ledger_parents_in_rosetta_blocks_mode() {
    let ledger_blocks = make_ledger_blocks(&[1, 1, 1, 2, 2, 2]);
    let mut blockchain = Blocks::new_in_memory(RosettaDbConfig::default_enabled()).unwrap();
    sync(&mut blockchain, &ledger_blocks);
    // Rosetta block 0 holds ledger blocks 0 to 2 and Rosetta block 1 holds
    // ledger blocks 3 to 5.
    assert_eq!(
        blockchain.rosetta_blocks_mode,
        RosettaBlocksMode::Enabled {
            first_rosetta_block_index: 0
        }
    );
    assert_eq!(
        blockchain.get_highest_rosetta_block_index().unwrap(),
        Some(1)
    );
    assert_eq!(
        Vec::from_iter(
            blockchain
                .get_rosetta_block(0)
                .unwrap()
                .transactions
                .into_keys()
        ),
        vec![0, 1, 2]
    );
    let req_handler = handler(blockchain);

    assert_ledger_blocks_have_ledger_parents(&req_handler, &ledger_blocks).await;

    let rosetta_block_0 = block(&req_handler, Some(0), None).await.unwrap();
    let rosetta_block_1 = block(&req_handler, Some(1), None).await.unwrap();
    assert_eq!(
        rosetta_block_0.parent_block_identifier,
        rosetta_block_0.block_identifier
    );
    assert_eq!(
        rosetta_block_1.parent_block_identifier,
        rosetta_block_0.block_identifier
    );
}

/// Like `test_ledger_blocks_have_ledger_parents_in_rosetta_blocks_mode`, but
/// with Rosetta blocks enabled on a store that already holds ledger blocks, so
/// that the first Rosetta block's parent is a ledger block.
#[tokio::test]
async fn test_ledger_blocks_have_ledger_parents_after_the_first_rosetta_block() {
    let ledger_blocks = make_ledger_blocks(&[1, 2, 3, 3, 4, 4]);
    let store_dir = tempfile::tempdir().unwrap();
    sync(
        &mut Blocks::new_persistent(store_dir.path(), RosettaDbConfig::default_disabled()).unwrap(),
        &ledger_blocks[..2],
    );
    let mut blockchain =
        Blocks::new_persistent(store_dir.path(), RosettaDbConfig::default_enabled()).unwrap();
    sync(&mut blockchain, &ledger_blocks[2..]);
    // Rosetta block 2 holds ledger blocks 2 and 3 and Rosetta block 3 holds
    // ledger blocks 4 and 5.
    assert_eq!(
        blockchain.rosetta_blocks_mode,
        RosettaBlocksMode::Enabled {
            first_rosetta_block_index: 2
        }
    );
    assert_eq!(
        blockchain.get_highest_rosetta_block_index().unwrap(),
        Some(3)
    );
    assert_eq!(
        Vec::from_iter(
            blockchain
                .get_rosetta_block(2)
                .unwrap()
                .transactions
                .into_keys()
        ),
        vec![2, 3]
    );
    let req_handler = handler(blockchain);

    assert_ledger_blocks_have_ledger_parents(&req_handler, &ledger_blocks).await;

    let rosetta_block_2 = block(&req_handler, Some(2), None).await.unwrap();
    let rosetta_block_3 = block(&req_handler, Some(3), None).await.unwrap();
    assert_eq!(
        rosetta_block_2.parent_block_identifier,
        convert::block_id(&ledger_blocks[1]).unwrap()
    );
    assert_eq!(
        rosetta_block_3.parent_block_identifier,
        rosetta_block_2.block_identifier
    );
}

/// Test that `/search/transactions` finds the transactions of the oldest block
/// of a pruned store, whose parent the store no longer holds.
#[tokio::test]
async fn test_search_transactions_in_pruned_store() {
    let ledger_blocks = Vec::from(Scribe::new_with_sample_data(10, 0).blockchain);
    let mut blockchain = Blocks::new_in_memory(RosettaDbConfig::default_disabled()).unwrap();
    sync(&mut blockchain, &ledger_blocks);
    // Keeps block 0 and blocks 5 to 9.
    blockchain.prune(&ledger_blocks[5]).unwrap();
    let req_handler = handler(blockchain);

    let response = req_handler
        .search_transactions(SearchTransactionsRequest::builder(req_handler.network_id()).build())
        .await
        .unwrap();
    assert_eq!(
        Vec::from_iter(
            response
                .transactions
                .iter()
                .map(|tx| tx.block_identifier.index)
        ),
        vec![9, 8, 7, 6, 5, 0]
    );
    assert_eq!(response.next_offset, None);
}
