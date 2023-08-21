use std::{net::SocketAddr, sync::Arc, time::Instant};

use arc_swap::ArcSwapOption;
use futures_util::{future::ready, FutureExt};
use hyper::client::connect::dns::Name;
use opentelemetry::KeyValue;
use reqwest::dns::{Addrs, Resolve, Resolving};
use tracing::info;

use crate::{
    metrics::{MetricParams, WithMetrics},
    snapshot::RoutingTable,
};

const UNUSED_PORT: u16 = 0;

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
                return Box::pin(ready(Err(Box::from(
                    "no routing table available".to_string(),
                ))));
            }
        };

        match rt.nodes.get(name.as_str()) {
            // If there's no node with given id - return future with error
            None => Box::pin(ready(Err(Box::from(format!(
                "Node '{name}' not found in routing table",
            ))))),

            // Return future that resolves to an iterator with a node IP address
            Some(n) => {
                let addrs: Addrs = Box::new(vec![SocketAddr::new(n.addr, UNUSED_PORT)].into_iter());
                Box::pin(ready(Ok(addrs)))
            }
        }
    }
}

impl<T: Resolve> Resolve for WithMetrics<T> {
    fn resolve(&self, name: Name) -> Resolving {
        let start_time = Instant::now();

        self.0
            .resolve(name.clone())
            .map(move |out| {
                let status = match out {
                    Ok(_) => "ok",
                    Err(_) => "fail",
                };

                let duration = start_time.elapsed().as_secs_f64();

                // Examine IPs
                let out = out.map(|addrs| Vec::from_iter(addrs.map(|addr| addr.ip())));

                info!(
                    action = "resolve",
                    name = name.as_str(),
                    status,
                    duration,
                    ips = ?out.as_ref().ok(),
                    error = ?out.as_ref().err(),
                );

                // Revert back to correct form (SocketAddr)
                out.map(|ips| {
                    Addrs::from(Box::new(
                        ips.into_iter().map(|ip| SocketAddr::new(ip, UNUSED_PORT)),
                    ))
                })
            })
            .boxed()
    }
}
