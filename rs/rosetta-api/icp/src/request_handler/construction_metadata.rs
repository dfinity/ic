use crate::errors::ApiError;
use crate::models::amount::tokens_to_amount;
use crate::models::{
    ConstructionMetadataRequest, ConstructionMetadataRequestOptions, ConstructionMetadataResponse,
    ConstructionPayloadsRequestMetadata,
};
use crate::request_handler::{RosettaRequestHandler, verify_network_id};
use crate::request_types::RequestType;

impl RosettaRequestHandler {
    /// Get Metadata for Transaction Construction.
    /// See https://www.rosetta-api.org/docs/ConstructionApi.html#constructionmetadata
    pub async fn construction_metadata(
        &self,
        msg: ConstructionMetadataRequest,
    ) -> Result<ConstructionMetadataResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let suggested_fee = match msg.options {
            Some(opts)
                if ConstructionMetadataRequestOptions::try_from(opts.clone())?
                    .request_types
                    .iter()
                    .all(RequestType::is_neuron_management) =>
            {
                None
            }
            _ => {
                let transfer_fee = self.ledger.transfer_fee().await?.transfer_fee;
                Some(vec![tokens_to_amount(
                    transfer_fee,
                    self.ledger.token_symbol(),
                )?])
            }
        };
        Ok(ConstructionMetadataResponse {
            metadata: ConstructionPayloadsRequestMetadata::default().try_into()?,
            suggested_fee,
        })
    }
}
