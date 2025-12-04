use std::{net::SocketAddr, sync::Arc};

use arc_swap::ArcSwapOption;
use futures_util::future::ready;
use ic_bn_lib_common::traits::dns::CloneableDnsResolver;
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
impl CloneableDnsResolver for DnsResolver {}

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
mod test {
    use super::*;

    use std::{str::FromStr, time::Duration};

    use anyhow::Error;

    use crate::{
        snapshot::{Snapshot, Snapshotter},
        test_utils::create_fake_registry_client,
    };

    // Check that resolver yields correct IPs
    #[tokio::test]
    async fn test_resolve() -> Result<(), Error> {
        use reqwest::dns::Name;

        let (reg, nodes, _) = create_fake_registry_client(4, 1, None);
        let reg = Arc::new(reg);
        let snapshot = Arc::new(ArcSwapOption::empty());
        let dns_resolver = DnsResolver::new(snapshot.clone());

        let (channel_send, _) = tokio::sync::watch::channel(None);
        let snapshotter = Snapshotter::new(snapshot.clone(), channel_send, reg, Duration::ZERO);
        snapshotter.snapshot()?;

        // Check that resolved node's IPs match expected ones
        for node in nodes.into_iter() {
            let res = dns_resolver
                .resolve(Name::from_str(node.0.to_string().as_str()).unwrap())
                .await;

            match res {
                Ok(mut r) => {
                    assert_eq!(r.next().unwrap().clone().ip().to_string(), node.1);
                }

                Err(_) => {
                    panic!("should not error out")
                }
            }
        }

        // Check the lookup failure for unknown node name
        let res = dns_resolver
            .resolve(Name::from_str("foo-bar-baz").unwrap())
            .await;
        assert!(res.is_err());

        Ok(())
    }
}
