use std::{net::SocketAddr, sync::Arc, time::Instant};

use arc_swap::ArcSwapOption;
use futures_util::{future::ready, FutureExt};
use hyper::client::connect::dns::Name;
use reqwest::dns::{Addrs, Resolve, Resolving};

use crate::{metrics::MetricParams, metrics::WithMetrics, snapshot::RoutingTable};

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
        let MetricParams {
            counter, recorder, ..
        } = self.1.clone();

        self.0
            .resolve(name.clone())
            .map(move |out| {
                let duration = start_time.elapsed().as_secs_f64();
                let status = if out.is_ok() { "ok" } else { "fail" };

                let labels = &[status, name.as_str()];

                counter.with_label_values(labels).inc();
                recorder.with_label_values(labels).observe(duration);

                // Examine IPs
                let out = out.map(|addrs| Vec::from_iter(addrs.map(|addr| addr.ip())));

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

#[cfg(test)]
pub mod test;
