use crate::convert;
use crate::errors::ApiError;
use crate::models::{
    ConstructionMetadataRequest, ConstructionMetadataResponse, ConstructionPayloadsRequestMetadata,
};
use crate::request_handler::{verify_network_id, RosettaRequestHandler};
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
                if opts
                    .request_types
                    .iter()
                    .all(RequestType::is_neuron_management) =>
            {
                None
            }
            _ => {
                let transfer_fee = self.ledger.transfer_fee().await?.transfer_fee;
                Some(vec![convert::amount_(
                    transfer_fee,
                    self.ledger.token_symbol(),
                )?])
            }
        };
        Ok(ConstructionMetadataResponse {
            metadata: ConstructionPayloadsRequestMetadata::default(),
            suggested_fee,
        })
    }
}
