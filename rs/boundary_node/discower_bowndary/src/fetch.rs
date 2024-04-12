use async_trait::async_trait;
use std::fmt::Debug;
use url::Url;

use crate::node::Node;

#[async_trait]
pub trait NodesFetcher: Sync + Send + Debug {
    async fn fetch(&self, url: Url) -> Result<Vec<Node>, NodeFetchError>;
}

#[derive(Debug, Clone)]
pub enum NodeFetchError {}

#[derive(Debug)]
pub struct NodesFetchMock;

#[async_trait]
impl NodesFetcher for NodesFetchMock {
    async fn fetch(&self, _url: Url) -> Result<Vec<Node>, NodeFetchError> {
        Ok(vec![
            Node::new("api-1.com".to_string()),
            Node::new("api-2.com".to_string()),
            Node::new("api-3.com".to_string()),
        ])
    }
}
