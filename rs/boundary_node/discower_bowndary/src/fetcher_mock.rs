use std::sync::Arc;

use crate::{
    fetch::{NodeFetchError, NodesFetcher},
    node::Node,
    types::GlobalShared,
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use url::Url;

#[derive(Debug)]
pub struct NodesFetchMock {
    pub nodes: GlobalShared<Vec<Node>>,
}

#[async_trait]
impl NodesFetcher for NodesFetchMock {
    async fn fetch(&self, _url: Url) -> Result<Vec<Node>, NodeFetchError> {
        let nodes = (*self.nodes.load_full()).clone();
        Ok(nodes)
    }
}

impl Default for NodesFetchMock {
    fn default() -> Self {
        Self::new()
    }
}

impl NodesFetchMock {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(ArcSwap::from_pointee(vec![])),
        }
    }

    pub fn overwrite_existing_domains(&self, domains: Vec<&str>) {
        let nodes = domains.into_iter().map(Node::new).collect();
        self.nodes.store(Arc::new(nodes));
    }
}
