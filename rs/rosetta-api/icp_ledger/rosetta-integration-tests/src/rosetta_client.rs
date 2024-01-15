use ic_rosetta_api::models::{
    Block, BlockRequest, BlockResponse, NetworkIdentifier, PartialBlockIdentifier,
};
use rosetta_core::request_types::MetadataRequest;
use rosetta_core::response_types::NetworkListResponse;
use url::Url;
pub struct RosettaClient {
    pub url: Url,
}

impl RosettaClient {
    pub async fn network_list(&self) -> Result<Vec<NetworkIdentifier>, reqwest::Error> {
        let request = MetadataRequest::new();
        let client = reqwest::Client::new();
        let response = client
            .post(self.url.join("/network/list").unwrap())
            .json(&request)
            .send()
            .await?
            .json::<NetworkListResponse>()
            .await?;
        Ok(response
            .network_identifiers
            .into_iter()
            .map(NetworkIdentifier)
            .collect::<Vec<NetworkIdentifier>>())
    }

    pub async fn block(
        &self,
        network_identifier: NetworkIdentifier,
        index: u64,
    ) -> Result<Option<Block>, reqwest::Error> {
        let block_identifier = PartialBlockIdentifier {
            index: Some(index),
            hash: None,
        };
        let request = BlockRequest {
            network_identifier: network_identifier.into(),
            block_identifier,
        };
        let client = reqwest::Client::new();
        let response = client
            .post(self.url.join("/block").unwrap())
            .json(&request)
            .send()
            .await?
            .json::<BlockResponse>()
            .await?;
        Ok(response.block)
    }
}
