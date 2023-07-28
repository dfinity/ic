use std::{
    fmt,
    num::Wrapping,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_scoped::TokioScope;
use async_trait::async_trait;
use bytes::Buf;
use candid::Principal;
use dashmap::DashMap;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use mockall::automock;
use opentelemetry::{baggage::BaggageExt, trace::FutureExt, Context as TlmContext, KeyValue};
use simple_moving_average::{SingleSumSMA, SMA};

use crate::{
    persist::Persist,
    snapshot::RoutingTable,
    snapshot::{Node, Subnet},
    Run, WithRetryLimited,
};

struct NodeState {
    ok_count: u8,
    average_latency: SingleSumSMA<Duration, u32, 10>,
    success_rate: SingleSumSMA<f32, f32, 10>,
    last_check_id: Wrapping<u64>,
    replica_version: String,
}

struct NodeCheckResult {
    node: Node,
    ok_count: u8,
    height: u64,
    average_latency: f32,
    success_rate: f32,
}

#[derive(Debug, PartialEq, Clone)]
pub enum CheckError {
    Generic(String),
    Network(String),  // Unable to make HTTP request
    Http(u16),        // Got non-200 status code
    ReadBody(String), // Cannot read response body
    Cbor(String),     // Cannot parse CBOR payload
    Health,           // Node reported itself as un-healthy
}

impl CheckError {
    pub fn short(&self) -> &str {
        match self {
            Self::Generic(e) => "generic",
            Self::Network(e) => "network",
            Self::Http(code) => "http",
            Self::ReadBody(e) => "read_body",
            Self::Cbor(e) => "cbor",
            Self::Health => "health",
        }
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Generic(e) => write!(f, "Error: {e}"),
            Self::Network(e) => write!(f, "Network error: {e}"),
            Self::Http(code) => write!(f, "Got non-2xx response code: {code}"),
            Self::ReadBody(e) => write!(f, "Unable to read body: {e}"),
            Self::Cbor(e) => write!(f, "Unable to decode CBOR: {e}"),
            Self::Health => write!(f, "Node reported itself as unhealthy"),
        }
    }
}

pub struct Runner<P: Persist, C: Check> {
    published_routing_table: Arc<ArcSwapOption<RoutingTable>>,
    node_states: Arc<DashMap<Principal, NodeState>>,
    last_check_id: Wrapping<u64>,
    min_ok_count: u8,
    max_height_lag: u64,
    persist: P,
    checker: C,
}

// Sort given node check results by score and emit nodes
fn nodes_sort_by_score(mut nodes: Vec<NodeCheckResult>) -> Vec<Node> {
    // Calculate min/max latencies
    let latencies = nodes.iter().map(|x| x.average_latency).collect::<Vec<_>>();
    let latency_min = latencies
        .clone()
        .into_iter()
        .reduce(f32::min)
        .unwrap_or(0.0);
    let latency_max = latencies.into_iter().reduce(f32::max).unwrap_or(0.0);

    // Normalize latency to 0..1 range
    nodes.iter_mut().for_each(|mut x| {
        x.average_latency = (x.average_latency - latency_min) / (latency_max - latency_min)
    });

    // Calculate the score as latency/success_rate - the lower the latency and higher success rate - the lower (better) is score
    // Score is mapped to 0..1000 range
    // Sort nodes by score in ascending order
    nodes.sort_unstable_by_key(|x| ((x.average_latency / x.success_rate) * 1000.0) as u32);
    nodes.into_iter().map(|x| x.node).collect()
}

impl<P: Persist, C: Check> Runner<P, C> {
    pub fn new(
        published_routing_table: Arc<ArcSwapOption<RoutingTable>>,
        min_ok_count: u8,
        max_height_lag: u64,
        persist: P,
        checker: C,
    ) -> Self {
        Self {
            published_routing_table,
            node_states: Arc::new(DashMap::new()),
            last_check_id: Wrapping(0u64),
            min_ok_count,
            max_height_lag,
            persist,
            checker,
        }
    }

    // Perform a health check on a given node
    async fn check_node(&self, node: Node) -> Result<NodeCheckResult, CheckError> {
        let ctx = TlmContext::current_with_baggage(vec![
            KeyValue::new("subnet_id", node.subnet_id.to_string()),
            KeyValue::new("node_id", node.id.to_string()),
            KeyValue::new("addr", format!("[{}]:{}", node.addr, node.port)),
        ]);

        // Perform Health Check
        let check_result = self.checker.check(&node).with_context(ctx.clone()).await;

        // Look up the node state and get a mutable reference if there's any
        // Locking behavior on DashMap is relevant to multiple locks from a single thread
        // In Tokio environment where we have a thread-per-node it shouldn't deadlock
        let node_state = self.node_states.get_mut(&node.id);

        // Just return the result if it's an error while also updating the state
        if check_result.is_err() {
            if let Some(mut x) = node_state {
                x.success_rate.add_sample(0.0);
                x.ok_count = 0;
                x.last_check_id = self.last_check_id;
            }

            return Err(check_result.err().unwrap());
        }

        let check_result = check_result.unwrap();

        let ok_count = match &node_state {
            // If it's a first success -> set to max
            None => self.min_ok_count,

            Some(entry) => {
                // If replica version has changed -> then the node just came up after the upgrade
                // Bump to min_ok_count to bring it up immediately
                if entry.replica_version != check_result.replica_version {
                    self.min_ok_count
                } else {
                    // Otherwise, increment OK count
                    self.min_ok_count.min(entry.ok_count + 1)
                }
            }
        };

        // Insert or update the entry and obtain averages
        let (average_latency, success_rate) = match node_state {
            None => {
                let mut average_latency = SingleSumSMA::from_zero(Duration::ZERO);
                average_latency.add_sample(check_result.latency);

                let mut success_rate = SingleSumSMA::from_zero(0f32);
                success_rate.add_sample(1.0);

                self.node_states.insert(
                    node.id,
                    NodeState {
                        average_latency,
                        success_rate,
                        ok_count,
                        last_check_id: self.last_check_id,
                        replica_version: check_result.replica_version.clone(),
                    },
                );

                (check_result.latency.as_secs_f32(), 1.0)
            }

            Some(mut e) => {
                e.average_latency.add_sample(check_result.latency);
                e.success_rate.add_sample(1.0);
                e.ok_count = ok_count;
                e.last_check_id = self.last_check_id;
                e.replica_version = check_result.replica_version;

                (
                    e.average_latency.get_average().as_secs_f32(),
                    e.success_rate.get_average(),
                )
            }
        };

        Ok(NodeCheckResult {
            node,
            height: check_result.height,
            ok_count,
            average_latency,
            success_rate,
        })
    }

    // Healthcheck all the nodes in a subnet
    async fn check_subnet(&self, subnet: Subnet) -> Subnet {
        // Check all nodes, using green threads for each node
        let ((), nodes) = TokioScope::scope_and_block(|s| {
            for node in subnet.nodes.into_iter() {
                s.spawn(self.check_node(node));
            }
        });

        // Filter out bad nodes
        let mut nodes = nodes
            .into_iter()
            .filter_map(Result::ok) // Filter any green thread errors
            .filter_map(Result::ok) // Filter any `check` errors
            .collect::<Vec<_>>();

        // Calculate the minimum block height requirement for given subnet
        let min_height = match nodes.len() {
            0 => 0,
            _ => {
                nodes.sort_by_key(|node| node.height);
                let mid_height_0 = nodes[(nodes.len() - 1) / 2].height;
                let mid_height_1 = nodes[nodes.len() / 2].height;
                // We use the median because it's a good approximation of
                // the "consensus" and keeps us resilient to malicious replicas
                // sending an artificially high height to DOS the BNs
                let median_height = (mid_height_0 + mid_height_1) / 2;
                median_height.saturating_sub(self.max_height_lag)
            }
        };

        // Filter out nodes that fail the predicates
        let mut nodes = nodes
            .into_iter()
            .filter(|x| x.height >= min_height) // Filter below min_height
            .filter(|x| x.ok_count >= self.min_ok_count) // Filter below min_ok_count
            .collect::<Vec<_>>();

        let nodes = nodes_sort_by_score(nodes);
        Subnet { nodes, ..subnet }
    }
}

#[async_trait]
impl<P: Persist, C: Check> Run for Runner<P, C> {
    async fn run(&mut self) -> Result<(), Error> {
        // Clone the the latest routing table from the registry if there's one
        let routing_table = self
            .published_routing_table
            .load_full()
            .ok_or_else(|| anyhow!("no routing table published"))?
            .as_ref()
            .clone();

        // Increment the id so we can delete stale entries
        self.last_check_id += 1;

        // Check all the subnets, using green threads for each subnet
        let ((), subnets) = TokioScope::scope_and_block(|s| {
            for subnet in routing_table.subnets.into_iter() {
                s.spawn(self.check_subnet(subnet));
            }
        });

        // Clear stale entries.
        // All entries current have now been updated with `last_check_id`
        // Anything that didn't get touched is stale.
        self.node_states
            .retain(|_, x| x.last_check_id == self.last_check_id);

        // Construct Effective Routing Table
        let subnets = subnets.into_iter().filter_map(Result::ok).collect();
        let effective_routing_table = RoutingTable {
            subnets,
            ..routing_table
        };

        // Persist Effective Routing Table
        self.persist
            .persist(effective_routing_table)
            .await
            .context("failed to persist routing table")?;

        Ok(())
    }
}

pub struct CheckResult {
    pub height: u64,
    pub latency: Duration,
    pub replica_version: String,
}

#[automock]
#[async_trait]
pub trait Check: Send + Sync {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError>;
}

pub struct Checker {
    http_client: Arc<reqwest::Client>,
}

impl Checker {
    pub fn new(http_client: Arc<reqwest::Client>) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError> {
        let request = match self
            .http_client
            .get(format!("https://{}:{}/api/v2/status", node.id, node.port))
            .build()
        {
            Ok(v) => v,
            Err(e) => return Err(CheckError::Generic(e.to_string())),
        };

        let start_time = Instant::now();
        let response = match self.http_client.execute(request).await {
            Ok(v) => v,
            Err(e) => return Err(CheckError::Network(e.to_string())),
        };

        let latency = start_time.elapsed();

        if response.status() != reqwest::StatusCode::OK {
            return Err(CheckError::Http(response.status().into()));
        }

        let response_reader = match response.bytes().await {
            Ok(v) => v.reader(),
            Err(e) => return Err(CheckError::ReadBody(e.to_string())),
        };

        let HttpStatusResponse {
            replica_health_status,
            certified_height,
            impl_version,
            ..
        } = match serde_cbor::from_reader(response_reader) {
            Ok(v) => v,
            Err(e) => return Err(CheckError::Cbor(e.to_string())),
        };

        if replica_health_status != Some(ReplicaHealthStatus::Healthy) {
            return Err(CheckError::Health);
        }

        if impl_version.is_none() {
            return Err(CheckError::Generic("No replica version available".into()));
        }

        Ok(CheckResult {
            height: certified_height.map_or(0, |v| v.get()),
            latency,
            replica_version: impl_version.unwrap(),
        })
    }
}

#[async_trait]
impl<T: Check> Check for WithRetryLimited<T> {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError> {
        let mut remaining_attempts = self.1;
        let attempt_interval = self.2;

        loop {
            let start_time = Instant::now();

            let out = self.0.check(node).with_context(TlmContext::current()).await;
            // Retry only on network errors
            match &out {
                Ok(_) => return out,
                Err(e) => match e {
                    CheckError::Network(_) => {}
                    _ => return out,
                },
            }

            remaining_attempts -= 1;
            if remaining_attempts == 0 {
                return out;
            }

            let duration = start_time.elapsed();
            if duration < attempt_interval {
                tokio::time::sleep(attempt_interval - duration).await;
            }
        }
    }
}

#[cfg(test)]
mod test;
