use async_trait::async_trait;
use ic_agent::{export::Principal, Agent, AgentError};
use std::{fmt::Debug, sync::Arc};
use thiserror::Error;
use url::Url;

use crate::{
    node::Node,
    transport::{TransportProvider, TransportProviderError},
};

#[async_trait]
pub trait NodesFetcher: Sync + Send + Debug {
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, NodeFetchError>;
}

#[derive(Error, Debug)]
pub enum NodeFetchError {
    #[error("Agent error occurred: {0}")]
    AgentError(#[from] AgentError),
    #[error("Transport error occurred: {0}")]
    TransportError(#[from] TransportProviderError),
}

#[derive(Debug)]
pub struct NodesFetcherImpl {
    subnet_id: Principal,
    transport_provider: Arc<dyn TransportProvider>,
}

impl NodesFetcherImpl {
    pub fn new(transport_provider: Arc<dyn TransportProvider>, subnet_id: Principal) -> Self {
        Self {
            subnet_id,
            transport_provider,
        }
    }
}

#[async_trait]
impl NodesFetcher for NodesFetcherImpl {
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, NodeFetchError> {
        let transport = self.transport_provider.get_transport(url)?;
        let agent = Agent::builder().with_transport(transport).build()?;
        agent.fetch_root_key().await?;
        let api_bns = agent
            .fetch_api_boundary_nodes_by_subnet_id(self.subnet_id)
            .await?;
        let nodes: Vec<Node> = api_bns.iter().map(|node| node.into()).collect();
        Ok(nodes)
    }
}
