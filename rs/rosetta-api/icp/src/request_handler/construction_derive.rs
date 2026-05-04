use crate::convert::{account_from_public_key, neuron_account_from_public_key};
use crate::errors::ApiError;
use crate::models::{
    self, AccountType, ConstructionDeriveRequestMetadata, ConstructionDeriveResponse,
};
use crate::request_handler::{RosettaRequestHandler, verify_network_id};

impl RosettaRequestHandler {
    /// Derive an AccountIdentifier from a PublicKey.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionderive
    pub fn construction_derive(
        &self,
        msg: models::ConstructionDeriveRequest,
    ) -> Result<ConstructionDeriveResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;

        let account_identifier = if let Some(object) = msg.metadata {
            match ConstructionDeriveRequestMetadata::try_from(Some(object))? {
                ConstructionDeriveRequestMetadata {
                    account_type: AccountType::Neuron { neuron_index },
                    ..
                } => neuron_account_from_public_key(
                    self.ledger.governance_canister_id(),
                    &msg.public_key,
                    neuron_index,
                )?,
                ConstructionDeriveRequestMetadata {
                    account_type: AccountType::Ledger,
                    ..
                } => account_from_public_key(&msg.public_key)?,
            }
        } else {
            account_from_public_key(&msg.public_key)?
        };

        Ok(ConstructionDeriveResponse {
            account_identifier: Some(account_identifier),
            address: None,
            metadata: None,
        })
    }
}
