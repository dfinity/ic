use crate::errors::ApiError;
use crate::models::{ConstructionHashRequest, ConstructionHashResponse, SignedTransaction};
use crate::request_handler::{RosettaRequestHandler, verify_network_id};
use crate::transaction_id::{self, TransactionIdentifier};
use serde_json::map::Map;
use std::str::FromStr;

impl RosettaRequestHandler {
    /// Get the Hash of a Signed Transaction.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionhash
    pub fn construction_hash(
        &self,
        msg: ConstructionHashRequest,
    ) -> Result<ConstructionHashResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let signed_transaction = SignedTransaction::from_str(&msg.signed_transaction)
            .map_err(|err| ApiError::invalid_transaction(format!("{err:?}")))?;
        let transaction_identifier = if let Some((request_type, envelope_pairs)) =
            signed_transaction
                .requests
                .iter()
                .rev()
                .find(|(rt, _)| rt.is_transfer())
        {
            TransactionIdentifier::try_from_envelope(
                request_type.clone(),
                &envelope_pairs[0].update,
            )
        } else if signed_transaction
            .requests
            .iter()
            .all(|(r, _)| r.is_neuron_management())
        {
            Ok(TransactionIdentifier::from(
                transaction_id::NEURON_MANAGEMENT_PSEUDO_HASH.to_owned(),
            ))
        } else {
            Err(ApiError::invalid_request(
                "There is no hash for this transaction",
            ))
        }?;

        Ok(ConstructionHashResponse {
            transaction_identifier: transaction_identifier.into(),
            metadata: Map::new(),
        })
    }
}
