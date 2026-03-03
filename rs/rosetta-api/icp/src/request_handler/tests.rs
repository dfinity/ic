//! Tests for the RosettaRequestHandler.

use crate::{
    errors::{ApiError, Details},
    ledger_client::LedgerAccess,
    models::NetworkRequest,
    request_handler::RosettaRequestHandler,
};
use async_trait::async_trait;
use ic_ledger_canister_blocks_synchronizer::blocks::{Blocks, RosettaBlocksMode};
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
/// Only implements enough to test `network_status` behavior.
struct MockLedger {
    canister_id: CanisterId,
    governance_canister_id: CanisterId,
}

impl MockLedger {
    fn new() -> Self {
        Self {
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
        unimplemented!("Not needed for this test")
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
    let canister_id_str = hex::encode(canister_id.get().into_vec());

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
