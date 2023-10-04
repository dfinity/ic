use std::{net::SocketAddr, sync::Arc};

use arc_swap::ArcSwapOption;
use futures_util::future::ready;
use hyper::client::connect::dns::Name;
use reqwest::dns::{Addrs, Resolve, Resolving};

use crate::snapshot::RoutingTable;

const UNUSED_PORT: u16 = 0;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct DnsError(String);

pub struct DnsResolver {
    rt: Arc<ArcSwapOption<RoutingTable>>,
}

impl DnsResolver {
    pub fn new(rt: Arc<ArcSwapOption<RoutingTable>>) -> Self {
        Self { rt }
    }
}

// Implement resolver based on the routing table
// It's used by reqwest to resolve node IDs to an IP address
impl Resolve for DnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        // Load a routing table if we have one
        let rt = match self.rt.load_full() {
            Some(rt) => rt,
            None => {
                return Box::pin(ready(Err(Box::from(DnsError(
                    "No routing table available".into(),
                )))));
            }
        };

        match rt.nodes.get(name.as_str()) {
            // If there's no node with given id - return future with error
            None => Box::pin(ready(Err(Box::from(DnsError(format!(
                "Node '{name}' not found in the routing table",
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
