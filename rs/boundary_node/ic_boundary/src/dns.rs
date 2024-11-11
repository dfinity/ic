use std::{net::SocketAddr, sync::Arc};

use arc_swap::ArcSwapOption;
use futures_util::future::ready;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::snapshot::RegistrySnapshot;

const UNUSED_PORT: u16 = 0;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct DnsError(String);

#[derive(Clone, Debug)]
pub struct DnsResolver {
    snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
}

impl DnsResolver {
    pub fn new(snapshot: Arc<ArcSwapOption<RegistrySnapshot>>) -> Self {
        Self { snapshot }
    }
}

// Implement resolver based on the routing table
// It's used by reqwest to resolve node IDs to an IP address
impl Resolve for DnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        // Load a routing table if we have one
        let snapshot = match self.snapshot.load_full() {
            Some(v) => v,
            None => {
                return Box::pin(ready(Err(Box::from(DnsError(
                    "No routing table available".into(),
                )))));
            }
        };

        match snapshot.nodes.get(name.as_str()) {
            // If there's no node with given id - return future with error
            None => Box::pin(ready(Err(Box::from(DnsError(format!(
                "Node '{name:#?}' not found in the routing table",
            )))))),

            // Return future that resolves to an iterator with a node IP address
            Some(n) => {
                let addrs: Addrs = Box::new(vec![SocketAddr::new(n.addr, UNUSED_PORT)].into_iter());
                Box::pin(ready(Ok(addrs)))
            }
        }
    }
}

#[cfg(test)]
pub mod test;
