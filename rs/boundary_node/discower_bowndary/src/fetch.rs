use async_trait::async_trait;
use ic_agent::{
    agent::http_transport::{reqwest_transport::reqwest::Client, ReqwestTransport},
    export::Principal,
    Agent, AgentError,
};
use std::fmt::Debug;
use thiserror::Error;
use url::Url;

use crate::node::Node;

#[async_trait]
pub trait NodesFetcher: Sync + Send + Debug {
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, NodeFetchError>;
}

#[derive(Error, Debug)]
pub enum NodeFetchError {
    #[error(r#"Failed to create agent: "{0}""#)]
    AgentError(#[from] AgentError),
}

#[derive(Debug)]
pub struct NodesFetcherImpl {
    http_client: Client,
    // TODO: change to subnet_id once ic-agent 0.35.0 is released
    canister_id: Principal,
}

impl NodesFetcherImpl {
    pub fn new(http_client: Client, canister_id: Principal) -> Self {
        Self {
            http_client,
            canister_id,
        }
    }
}

#[async_trait]
impl NodesFetcher for NodesFetcherImpl {
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, NodeFetchError> {
        let transport = ReqwestTransport::create_with_client(url, self.http_client.clone())?;
        let agent = Agent::builder().with_transport(transport).build()?;
        agent.fetch_root_key().await?;
        let api_bns = agent
            .fetch_api_boundary_nodes_by_canister_id(self.canister_id)
            .await?;
        let nodes: Vec<Node> = api_bns.iter().map(|node| node.into()).collect();
        Ok(nodes)
    }
}
