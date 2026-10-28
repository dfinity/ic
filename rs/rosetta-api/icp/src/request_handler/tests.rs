//! Tests for the RosettaRequestHandler.

use crate::{
    errors::{ApiError, Details},
    ledger_client::LedgerAccess,
    models::{NetworkRequest, SearchTransactionsRequest},
    request_handler::{MAX_SEARCH_LIMIT, RosettaRequestHandler},
};
use async_trait::async_trait;
use ic_ledger_canister_blocks_synchronizer::blocks::{Blocks, RosettaBlocksMode, RosettaDbConfig};
use ic_ledger_canister_blocks_synchronizer_test_utils::sample_data::Scribe;
use ic_nns_governance_api::{KnownNeuron, ProposalInfo, manage_neuron::NeuronIdOrSubaccount};
use ic_types::CanisterId;
use icp_ledger::TransferFee;
use rosetta_core::metrics::RosettaMetrics;
use std::{
    ops::Deref,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};

/// A minimal mock ledger for testing the request handler.
/// Only implements enough to test `network_status` and `search_transactions` behavior.
struct MockLedger {
    canister_id: CanisterId,
    governance_canister_id: CanisterId,
    blocks: Blocks,
}

impl MockLedger {
    fn new() -> Self {
        Self {
            canister_id: CanisterId::unchecked_from_principal(
                ic_types::PrincipalId::from_str("5v3p4-iyaaa-aaaaa-qaaaa-cai").unwrap(),
            ),
            governance_canister_id: ic_nns_constants::GOVERNANCE_CANISTER_ID,
            blocks: Blocks::new_in_memory(RosettaDbConfig::default_disabled()).unwrap(),
        }
    }
}

#[async_trait]
impl LedgerAccess for MockLedger {
    async fn read_blocks<'a>(&'a self) -> Box<dyn Deref<Target = Blocks> + 'a> {
        Box::new(&self.blocks)
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

    async fn rosetta_blocks_mode(&self) -> RosettaBlocksMode {
        RosettaBlocksMode::Disabled
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

/// Test that `search_transactions` caps a caller-supplied `limit` to `MAX_SEARCH_LIMIT`.
#[tokio::test]
async fn test_search_transactions_caps_limit() {
    let mut ledger = MockLedger::new();
    // Fund the accounts generously so that fees do not drain them while generating transactions.
    let mut scribe = Scribe::new();
    scribe.gen_accounts(10, 1_000_000_000_000);
    for _ in 0..MAX_SEARCH_LIMIT {
        scribe.gen_transaction();
    }
    let num_blocks = scribe.blockchain.len() as u64;
    assert!(num_blocks > MAX_SEARCH_LIMIT as u64);
    ledger
        .blocks
        .push_batch(scribe.blockchain.into_iter().collect(), None)
        .unwrap();
    ledger
        .blocks
        .set_hashed_block_to_verified(&(num_blocks - 1))
        .unwrap();

    let ledger = Arc::new(ledger);
    let canister_id_str = hex::encode(ledger.ledger_canister_id().get_ref().as_slice());
    let req_handler = RosettaRequestHandler::new(
        crate::DEFAULT_BLOCKCHAIN.to_string(),
        ledger,
        RosettaMetrics::new(crate::DEFAULT_TOKEN_SYMBOL.to_string(), canister_id_str),
        Arc::new(AtomicBool::new(true)),
    );
    let request = |limit: i64, offset: Option<i64>| SearchTransactionsRequest {
        network_identifier: req_handler.network_id(),
        limit: Some(limit),
        offset,
        ..Default::default()
    };

    // A limit above the maximum is capped to the maximum
    let result = req_handler
        .search_transactions(request(i64::MAX, None))
        .await
        .unwrap();
    assert_eq!(result.transactions.len(), MAX_SEARCH_LIMIT);
    assert_eq!(result.total_count, MAX_SEARCH_LIMIT as i64);
    assert_eq!(result.next_offset, Some(MAX_SEARCH_LIMIT as i64));

    // The remaining transactions can be fetched using the returned offset
    let result = req_handler
        .search_transactions(request(i64::MAX, result.next_offset))
        .await
        .unwrap();
    assert_eq!(
        result.transactions.len() as u64,
        num_blocks - MAX_SEARCH_LIMIT as u64
    );
    assert_eq!(result.next_offset, None);

    // A negative limit is still rejected
    assert!(
        req_handler
            .search_transactions(request(-1, None))
            .await
            .is_err()
    );
}
