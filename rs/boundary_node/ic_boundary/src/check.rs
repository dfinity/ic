use std::{
    fmt,
    num::Wrapping,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Error};
use arc_swap::ArcSwapOption;
use async_scoped::TokioScope;
use async_trait::async_trait;
use bytes::Buf;
use candid::Principal;
use dashmap::DashMap;
use http::Method;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use mockall::automock;
use tracing::info;
use url::Url;

use crate::{
    core::{Run, WithRetryLimited},
    http::HttpClient,
    metrics::{MetricParamsCheck, WithMetricsCheck},
    persist::Persist,
    snapshot::RegistrySnapshot,
    snapshot::{Node, Subnet},
};

struct NodeState {
    ok_count: u8,
    last_check_id: Wrapping<u64>,
    replica_version: String,
}

struct NodeCheckResult {
    node: Node,
    ok_count: u8,
    height: u64,
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
            Self::Generic(_) => "generic",
            Self::Network(_) => "network",
            Self::Http(_) => "http",
            Self::ReadBody(_) => "read_body",
            Self::Cbor(_) => "cbor",
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
    published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    node_states: Arc<DashMap<Principal, NodeState>>,
    last_check_id: Wrapping<u64>,
    min_ok_count: u8,
    max_height_lag: u64,
    persist: P,
    checker: C,
}

impl<P: Persist, C: Check> Runner<P, C> {
    pub fn new(
        published_registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
        min_ok_count: u8,
        max_height_lag: u64,
        persist: P,
        checker: C,
    ) -> Self {
        Self {
            published_registry_snapshot,
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
        // Perform Health Check
        let check_result = self.checker.check(&node).await;

        // Look up the node state and get a mutable reference if there's any
        // Locking behavior on DashMap is relevant to multiple locks from a single thread
        // In Tokio environment where we have a thread-per-node it shouldn't deadlock
        let node_state = self.node_states.get_mut(&node.id);

        let check_result = match check_result {
            // Just return the result if it's an error while also updating the state
            Err(e) => {
                if let Some(mut x) = node_state {
                    x.ok_count = 0;
                    x.last_check_id = self.last_check_id;
                }

                return Err(e);
            }

            Ok(v) => v,
        };

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

        let height = check_result.height;

        // Insert or update the entry
        match node_state {
            None => {
                self.node_states.insert(
                    node.id,
                    NodeState {
                        ok_count,
                        last_check_id: self.last_check_id,
                        replica_version: check_result.replica_version,
                    },
                );
            }

            Some(mut e) => {
                e.ok_count = ok_count;
                e.last_check_id = self.last_check_id;
                e.replica_version = check_result.replica_version;
            }
        };

        Ok(NodeCheckResult {
            node,
            height,
            ok_count,
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
        let nodes = nodes
            .into_iter()
            .filter(|x| x.height >= min_height) // Filter below min_height
            .filter(|x| x.ok_count >= self.min_ok_count) // Filter below min_ok_count
            .collect::<Vec<_>>();

        let nodes = nodes.into_iter().map(|x| x.node).collect();
        Subnet { nodes, ..subnet }
    }
}

#[async_trait]
impl<P: Persist, C: Check> Run for Runner<P, C> {
    async fn run(&mut self) -> Result<(), Error> {
        // Clone the the latest registry snapshot if there's one
        let snapshot = self
            .published_registry_snapshot
            .load_full()
            .ok_or_else(|| anyhow!("no registry snapshot available"))?
            .as_ref()
            .clone();

        // Increment the id so we can delete stale entries
        self.last_check_id += 1;

        // Check all the subnets, using green threads for each subnet
        let ((), subnets) = TokioScope::scope_and_block(|s| {
            for subnet in snapshot.subnets.into_iter() {
                s.spawn(self.check_subnet(subnet));
            }
        });

        // Filter out failed subnets
        let subnets = subnets.into_iter().filter_map(Result::ok).collect();

        // Clear stale entries.
        // All entries that existed in a registry have now been updated with `last_check_id`
        // Anything that didn't get touched is stale.
        self.node_states
            .retain(|_, x| x.last_check_id == self.last_check_id);

        // Persist the routing table
        self.persist.persist(subnets).await;

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
    http_client: Arc<dyn HttpClient>,
}

impl Checker {
    pub fn new(http_client: Arc<dyn HttpClient>) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError> {
        // Create request
        let u = Url::from_str(&format!("https://{}:{}/api/v2/status", node.id, node.port))
            .map_err(|err| CheckError::Generic(err.to_string()))?;

        let request = reqwest::Request::new(Method::GET, u);

        // Execute request
        let start_time = Instant::now();

        let response = self
            .http_client
            .execute(request)
            .await
            .map_err(|err| CheckError::Network(err.to_string()))?;

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

            let out = self.0.check(node).await;
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

#[async_trait]
impl<T: Check> Check for WithMetricsCheck<T> {
    async fn check(&self, node: &Node) -> Result<CheckResult, CheckError> {
        let start_time = Instant::now();
        let out = self.0.check(node).await;
        let duration = start_time.elapsed().as_secs_f64();

        let result = match &out {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("error_{}", e.short()),
        };

        let (block_height, replica_version) = out.as_ref().map_or((-1, "unknown"), |out| {
            (out.height as i64, out.replica_version.as_str())
        });

        let MetricParamsCheck {
            counter,
            recorder,
            status,
        } = &self.1;

        let subnet_id = node.subnet_id.to_string();
        let node_id = node.id.to_string();
        let node_addr = node.addr.to_string();

        let labels = &[
            result.as_str(),
            node_id.as_str(),
            subnet_id.as_str(),
            node_addr.as_str(),
        ];

        counter.with_label_values(labels).inc();
        recorder.with_label_values(labels).observe(duration);
        status
            .with_label_values(&labels[1..4])
            .set(out.is_ok().into());

        info!(
            action = "check",
            result,
            duration,
            block_height,
            replica_version,
            subnet_id,
            node_id,
            node_addr,
            error = out.as_ref().err().map(|x| x.to_string()),
        );

        out
    }
}

#[cfg(test)]
pub mod test;
