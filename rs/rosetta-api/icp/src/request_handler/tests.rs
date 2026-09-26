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

/// Helpers shared by the tests of the `/construction/*` handlers.
pub(super) mod construction {
    use crate::{
        ledger_client::LedgerClient,
        models::{
            Amount, ConstructionCombineRequest, ConstructionDeriveRequest,
            ConstructionPayloadsRequest, ConstructionPayloadsResponse, Currency, CurveType,
            NetworkIdentifier, Operation, OperationIdentifier, PublicKey, Signature, SignatureType,
            operation::OperationType,
        },
        request::Request,
        request_handler::RosettaRequestHandler,
        request_types::Disburse,
    };
    use ic_base_types::CanisterId;
    use rand_chacha::rand_core::OsRng;
    use rosetta_core::{convert::principal_id_from_public_key, metrics::RosettaMetrics};
    use std::{
        str::FromStr,
        sync::{Arc, atomic::AtomicBool},
    };
    use url::Url;

    /// Builds an offline-capable `RosettaRequestHandler` together with a signer
    /// keypair.
    pub(crate) fn setup_handler() -> (
        RosettaRequestHandler,
        NetworkIdentifier,
        PublicKey,
        ic_ed25519::PrivateKey,
    ) {
        let key = ic_ed25519::PrivateKey::generate_using_rng(&mut OsRng);
        let ledger_client = futures::executor::block_on(LedgerClient::new(
            Url::from_str("http://localhost:1234").unwrap(),
            CanisterId::from_u64(1),
            "TKN".into(),
            CanisterId::from_u64(2),
            None,
            None,
            true,
            None,
            false,
            false, // optimize_search_indexes: disabled for tests
        ))
        .unwrap();
        let mock_canister_id_hex = "00000000000000000101";
        let initial_sync_complete = AtomicBool::new(true);
        let handler = RosettaRequestHandler::new(
            "Internet Computer".into(),
            ledger_client.into(),
            RosettaMetrics::new("TKN".into(), mock_canister_id_hex.into()),
            Arc::new(initial_sync_complete),
        );

        let network_identifier = handler.network_id();
        let pub_key = PublicKey {
            hex_bytes: hex::encode(key.public_key().serialize_raw()),
            curve_type: CurveType::Edwards25519,
        };

        (handler, network_identifier, pub_key, key)
    }

    /// Builds a handler together with a single ICP transfer (debit + credit +
    /// fee) and the signer's public and private keys.
    pub(crate) fn setup_transfer_test() -> (
        RosettaRequestHandler,
        NetworkIdentifier,
        Vec<Operation>,
        PublicKey,
        ic_ed25519::PrivateKey,
    ) {
        let (handler, network_identifier, pub_key, key) = setup_handler();
        let currency = Currency {
            symbol: "TKN".into(),
            decimals: 8,
            metadata: None,
        };

        let account = handler
            .construction_derive(ConstructionDeriveRequest {
                network_identifier: network_identifier.clone(),
                public_key: pub_key.clone(),
                metadata: None,
            })
            .unwrap()
            .account_identifier;

        let operations = vec![
            Operation {
                operation_identifier: OperationIdentifier {
                    index: 0,
                    network_index: None,
                },
                related_operations: None,
                type_: OperationType::Transaction.to_string(),
                status: None,
                account: account.clone(),
                amount: Some(Amount {
                    value: "-100000000".into(),
                    currency: currency.clone(),
                    metadata: None,
                }),
                coin_change: None,
                metadata: None,
            },
            Operation {
                operation_identifier: OperationIdentifier {
                    index: 1,
                    network_index: None,
                },
                related_operations: None,
                type_: OperationType::Transaction.to_string(),
                status: None,
                account: account.clone(),
                amount: Some(Amount {
                    value: "100000000".into(),
                    currency: currency.clone(),
                    metadata: None,
                }),
                coin_change: None,
                metadata: None,
            },
            Operation {
                operation_identifier: OperationIdentifier {
                    index: 2,
                    network_index: None,
                },
                related_operations: None,
                type_: OperationType::Fee.to_string(),
                status: None,
                account,
                amount: Some(Amount {
                    value: "-1000000".into(),
                    currency,
                    metadata: None,
                }),
                coin_change: None,
                metadata: None,
            },
        ];

        (handler, network_identifier, operations, pub_key, key)
    }

    /// Signs every payload of `payloads` with `key` and combines them into a
    /// signed transaction, exactly as an offline signer would.
    pub(crate) fn sign_and_combine(
        handler: &RosettaRequestHandler,
        network_identifier: &NetworkIdentifier,
        pub_key: &PublicKey,
        key: &ic_ed25519::PrivateKey,
        payloads: ConstructionPayloadsResponse,
    ) -> String {
        let signatures = payloads
            .payloads
            .into_iter()
            .map(|payload| {
                let bytes = hex::decode(payload.clone().hex_bytes).unwrap();
                Signature {
                    signing_payload: payload,
                    public_key: pub_key.clone(),
                    signature_type: SignatureType::Ed25519,
                    hex_bytes: hex::encode(key.sign_message(&bytes)),
                }
            })
            .collect();

        handler
            .construction_combine(ConstructionCombineRequest {
                network_identifier: network_identifier.clone(),
                unsigned_transaction: payloads.unsigned_transaction,
                signatures,
            })
            .unwrap()
            .signed_transaction
    }

    /// Builds and genuinely signs a complete-stake `DISBURSE` of `neuron_index`
    /// to a third party, returning the operations it represents along with the
    /// unsigned and signed transactions.
    pub(crate) fn signed_disburse(
        handler: &RosettaRequestHandler,
        network_identifier: &NetworkIdentifier,
        pub_key: &PublicKey,
        key: &ic_ed25519::PrivateKey,
        neuron_index: u64,
    ) -> (Vec<Operation>, String, String) {
        let account =
            icp_ledger::AccountIdentifier::from(principal_id_from_public_key(pub_key).unwrap());
        let operations = Request::requests_to_operations(
            &[Request::Disburse(Disburse {
                account,
                amount: None,
                recipient: Some(icp_ledger::AccountIdentifier::from(
                    ic_types::PrincipalId::new_user_test_id(42),
                )),
                neuron_index,
            })],
            "TKN",
        )
        .unwrap();

        let payloads = handler
            .construction_payloads(ConstructionPayloadsRequest {
                network_identifier: network_identifier.clone(),
                operations: operations.clone(),
                metadata: None,
                public_keys: Some(vec![pub_key.clone()]),
            })
            .unwrap();
        let unsigned_transaction = payloads.unsigned_transaction.clone();
        let signed_transaction =
            sign_and_combine(handler, network_identifier, pub_key, key, payloads);

        (operations, unsigned_transaction, signed_transaction)
    }
}
