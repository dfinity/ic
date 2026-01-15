use crate::errors::ApiError;
use crate::models::{ConstructionSubmitRequest, ConstructionSubmitResponse, SignedTransaction};
use crate::request::transaction_operation_results::TransactionOperationResults;
use crate::request::transaction_results::TransactionResults;
use crate::request_handler::{RosettaRequestHandler, verify_network_id};
use crate::transaction_id::{self, TransactionIdentifier};
use std::str::FromStr;

impl RosettaRequestHandler {
    /// Submit a Signed Transaction.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionsubmit
    // Normally we'd just use the canister client Agent for this but because this
    // request is constructed in such an odd way it's easier to just do it from
    // scratch
    pub async fn construction_submit(
        &self,
        msg: ConstructionSubmitRequest,
    ) -> Result<ConstructionSubmitResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let envelopes = SignedTransaction::from_str(&msg.signed_transaction).map_err(|e| {
            ApiError::invalid_transaction(format!("Failed to parse signed transaction: {e}"))
        })?;
        let results = self.ledger.submit(envelopes).await?;
        let transaction_identifier = transaction_identifier(&results);
        let metadata = TransactionOperationResults::from_transaction_results(
            results,
            self.ledger.token_symbol(),
        )?;
        Ok(ConstructionSubmitResponse {
            transaction_identifier: transaction_identifier.into(),
            metadata: Some((&metadata).into()),
        })
    }
}

/// Return the last transaction identifier if any or a pseudo one otherwise.
fn transaction_identifier(results: &TransactionResults) -> TransactionIdentifier {
    results.last_transaction_id().cloned().unwrap_or_else(|| {
        assert!(
            results
                .operations
                .iter()
                .all(|r| r._type.is_neuron_management())
        );
        TransactionIdentifier::from(transaction_id::NEURON_MANAGEMENT_PSEUDO_HASH.to_owned())
    })
}
