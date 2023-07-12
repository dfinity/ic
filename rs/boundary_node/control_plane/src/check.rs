use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Error};
use async_scoped::TokioScope;
use async_trait::async_trait;
use bytes::Buf;
use dashmap::DashMap;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use mockall::automock;
use opentelemetry::{baggage::BaggageExt, trace::FutureExt, KeyValue};

use crate::{
    persist::Persist,
    registry::{Node, RoutingTable, Subnet},
    Run,
};

/// A counter to track if a `CheckState` is up to date.
///
/// Out of date entries are considered stale and are removed at the end
/// of each update
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
struct CheckRunId(u64);

impl CheckRunId {
    /// Increment the counter, wrapping around.
    pub fn inc(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

#[derive(Default, Debug)]
struct CheckState {
    ok_count: u8,
    last_updated: CheckRunId,
    replica_version: String,
}

pub struct CheckPersistRunner<R: Retrieve, C: Check, P: Persist> {
    // Dependencies
    routing_table: R,
    checks: Arc<DashMap<(String, String), CheckState>>,
    current_run_id: CheckRunId,
    checker: C,
    persister: P,

    // Configuration
    min_ok_count: u8,
    max_height_lag: u64,
}

impl<R: Retrieve, C: Check, P: Persist> CheckPersistRunner<R, C, P> {
    pub fn new(
        routing_table: R,
        checker: C,
        persister: P,
        min_ok_count: u8,
        max_height_lag: u64,
    ) -> Self {
        Self {
            routing_table,
            checks: Arc::new(DashMap::new()),
            current_run_id: CheckRunId::default(),
            checker,
            persister,
            min_ok_count,
            max_height_lag,
        }
    }

    pub fn get_active_checker(&self) -> impl ActiveChecker {
        Arc::clone(&self.checks)
    }
}

#[automock]
pub trait Retrieve {
    /// Gets a copy of the routing table for this moment in time
    fn retrieve(&self) -> Result<RoutingTable, Error>;
}

impl Retrieve for Arc<Mutex<Option<RoutingTable>>> {
    fn retrieve(&self) -> Result<RoutingTable, Error> {
        self.lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow!("routing_table not available"))
    }
}

pub trait ActiveChecker: Clone {
    /// Check if a node is still present in the registry
    fn is_active(&self, subnet_node_id: &(String, String)) -> bool;
}

impl ActiveChecker for Arc<DashMap<(String, String), CheckState>> {
    fn is_active(&self, subnet_node_id: &(String, String)) -> bool {
        self.contains_key(subnet_node_id)
    }
}

impl<F: Clone + Fn(&(String, String)) -> bool> ActiveChecker for F {
    fn is_active(&self, subnet_node_id: &(String, String)) -> bool {
        self(subnet_node_id)
    }
}

struct NodeCheck {
    node: Node,
    ok_count: u8,
    height: u64,
}

impl<R: Retrieve + Send + Sync, C: Check, P: Persist> CheckPersistRunner<R, C, P> {
    /// Healthcheck a nodes in a subnet
    async fn check_node(
        node: Node,
        checker: &C,
        checks: &Arc<DashMap<(String, String), CheckState>>,
        current_run_id: CheckRunId,
        min_ok_count: u8,
        subnet_id: &str,
    ) -> Result<NodeCheck, Error> {
        let _ctx = opentelemetry::Context::current_with_baggage(vec![
            KeyValue::new("subnet_id", subnet_id.to_string()),
            KeyValue::new("node_id", node.node_id.to_string()),
            KeyValue::new("socket_addr", node.socket_addr.to_string()),
        ]);

        // Perform Health Check
        let check_result = checker
            .check(&node.socket_addr)
            .with_context(_ctx.clone())
            .await
            .context("failed to check node");

        let k = (
            subnet_id.to_string(), // subnet
            node.node_id.clone(),  // node
        );

        let (ok_count, replica_version) = match (checks.get(&k), &check_result) {
            // If check failed, reset OK count to 0

            // If it's not 1st check and there was an error -> just pass the previous replica_version forward
            (Some(entry), Err(_)) => (0, entry.replica_version.clone()),

            // Otherwise use empty string
            (None, Err(_)) => (0, "".to_string()),

            // If check succeeded, but is also the first check, set OK count to max-value
            (None, Ok(v)) => (min_ok_count, v.replica_version.clone()),

            (Some(entry), Ok(v)) => {
                let ok_count = if entry.replica_version == v.replica_version {
                    // If versions are the same - just increment
                    min_ok_count.min(entry.ok_count + 1)
                } else {
                    // If there was an upgrade -> bump to max
                    min_ok_count
                };

                (ok_count, v.replica_version.clone())
            }
        };

        // Update the `checks` entry
        checks.insert(
            k,
            CheckState {
                ok_count,
                last_updated: current_run_id,
                replica_version,
            },
        );

        // Return the node
        check_result.map(|check_result| NodeCheck {
            node,
            height: check_result.height,
            ok_count,
        })
    }

    /// Healthcheck all the nodes in a subnet
    async fn check_subnet(&self, subnet: Subnet) -> Subnet {
        // Check all nodes, using green threads for each node
        let ((), nodes) = TokioScope::scope_and_block(|s| {
            for node in subnet.nodes.into_iter() {
                s.spawn(Self::check_node(
                    node,
                    &self.checker,
                    &self.checks,
                    self.current_run_id,
                    self.min_ok_count,
                    subnet.subnet_id.as_str(),
                ));
            }
        });

        // Filter out bad nodes
        let mut nodes = nodes
            .into_iter()
            .filter_map(Result::ok) // Filter any green thread errors
            .filter_map(Result::ok) // Filter any `checker.check` errors
            .collect::<Vec<_>>();

        // Calculate the minimum block height requirement
        let min_height = if !nodes.is_empty() {
            nodes.sort_by_key(|node| node.height);
            let mid_height_0 = nodes[(nodes.len() - 1) / 2].height;
            let mid_height_1 = nodes[nodes.len() / 2].height;
            // We use the median because it's a good approximation of
            // the "consensus" and keeps us resilient to malicious replicas
            // sending an artificially high height to DOS the BNs
            let median_height = (mid_height_0 + mid_height_1) / 2;
            median_height.saturating_sub(self.max_height_lag)
        } else {
            0
        };

        let nodes = nodes
            .into_iter()
            .skip_while(|node| node.height < min_height) // Filter below min_height
            .filter(|node| node.ok_count >= self.min_ok_count) // Filter below min_ok_count
            .map(|node| node.node)
            .collect();

        Subnet { nodes, ..subnet }
    }
}

#[async_trait]
impl<R: Retrieve + Send + Sync, C: Check, P: Persist> Run for CheckPersistRunner<R, C, P> {
    async fn run(&mut self) -> Result<(), Error> {
        // Retrieve the the latest routing table from the registry
        let routing_table = self.routing_table.retrieve()?;

        // Increment the run id so we can delete stale entries
        self.current_run_id.inc();

        // Check all the subnets, using green threads for each subnet
        let ((), subnets) = TokioScope::scope_and_block(|s| {
            for subnet in routing_table.subnets.into_iter() {
                s.spawn(self.check_subnet(subnet));
            }
        });

        // Clear stale entries.
        // All entries current have now been updated with `current_run_id`
        // Anything that didn't get touched is stale.
        self.checks
            .retain(|_, v| v.last_updated == self.current_run_id);

        // Construct Effective Routing Table
        let subnets = subnets.into_iter().filter_map(Result::ok).collect();
        let effective_routing_table = RoutingTable {
            subnets,
            ..routing_table
        };

        // Persist Effective Routing Table
        self.persister
            .persist(&effective_routing_table)
            .await
            .context("failed to persist routing table")?;

        Ok(())
    }
}

pub struct CheckResult {
    pub height: u64,
    pub replica_version: String,
}

#[automock]
#[async_trait]
pub trait Check: 'static + Send + Sync {
    async fn check(&self, addr: &str) -> Result<CheckResult, Error>;
}

pub struct Checker {
    http_client: reqwest::Client,
}

impl Checker {
    pub fn new(http_client: reqwest::Client) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, addr: &str) -> Result<CheckResult, Error> {
        let request = self
            .http_client
            .request(reqwest::Method::GET, format!("http://{addr}/api/v2/status"))
            .build()
            .context("failed to build request")?;

        let response = self
            .http_client
            .execute(request)
            .await
            .context("request failed")?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(anyhow!("request failed with status {}", response.status()));
        }

        let response_reader = response
            .bytes()
            .await
            .context("failed to get response bytes")?
            .reader();

        let HttpStatusResponse {
            replica_health_status,
            certified_height,
            impl_version,
            ..
        } = serde_cbor::from_reader(response_reader).context("failed to parse cbor response")?;

        if replica_health_status != Some(ReplicaHealthStatus::Healthy) {
            return Err(anyhow!("replica reported unhealthy status"));
        }

        Ok(CheckResult {
            height: certified_height.map_or(0, |v| v.get()),
            replica_version: impl_version.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use mockall::{predicate, Sequence};

    use super::*;
    use crate::{persist::MockPersist, registry::Node, PersistStatus};

    fn node(id: &str, addr: &str) -> Node {
        Node {
            node_id: id.into(),
            socket_addr: addr.into(),
            tls_certificate_pem: String::new(),
        }
    }
    fn table(
        registry_version: u64,
        subnets: &[(&str, &[(&str, &str)])],
    ) -> impl Fn() -> Result<RoutingTable, Error> {
        let v = RoutingTable {
            registry_version,
            nns_subnet_id: String::new(),
            canister_routes: vec![],
            subnets: subnets
                .iter()
                .map(|&(subnet_id, nodes)| Subnet {
                    subnet_id: subnet_id.into(),
                    subnet_type: String::new(),
                    nodes: nodes.iter().map(|(id, addr)| node(id, addr)).collect(),
                })
                .collect(),
        };
        move || Ok(v.clone())
    }
    fn single_subnet_table(
        registry_version: u64,
        subnet_name: &str,
        nodes: &[(&str, &str)],
    ) -> impl Fn() -> Result<RoutingTable, Error> {
        table(registry_version, &[(subnet_name, nodes)])
    }
    fn get_subnet_nodes(rt: &RoutingTable) -> Vec<(&str, &str)> {
        rt.subnets
            .iter()
            .flat_map(|subnet| {
                subnet
                    .nodes
                    .iter()
                    .map(|node| (subnet.subnet_id.as_str(), node.node_id.as_str()))
            })
            .collect::<Vec<_>>()
    }

    /// This test ensures CheckPersistRunner handles replicas disappearing from the registry
    /// and failing health checks.
    #[tokio::test(flavor = "multi_thread")]
    async fn simple() {
        let mut routing = MockRetrieve::new();
        let mut retrieve_seq = Sequence::new();
        routing
            .expect_retrieve()
            .times(2)
            .returning(single_subnet_table(
                0,
                "subnetA",
                &[
                    ("nodeA1", "addrA1"),
                    ("nodeA2", "addrA2"),
                    ("nodeA3", "addrA3"),
                ],
            ))
            .in_sequence(&mut retrieve_seq);
        routing
            .expect_retrieve()
            .times(1)
            .returning(single_subnet_table(
                1,
                "subnetA",
                &[("nodeA1", "addrA1"), ("nodeA3", "addrA3")],
            ))
            .in_sequence(&mut retrieve_seq);

        let mut check = MockCheck::new();
        let mut na1_seq = Sequence::new();
        let mut nb1_seq = Sequence::new();
        check
            .expect_check()
            .with(predicate::eq("addrA1"))
            .times(3)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 10,
                    replica_version: "ver1".to_string(),
                })
            })
            .in_sequence(&mut na1_seq);
        check
            .expect_check()
            .with(predicate::in_iter(["addrA2", "addrA3"]))
            .times(2)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 10,
                    replica_version: "ver1".to_string(),
                })
            })
            .in_sequence(&mut nb1_seq);
        check
            .expect_check()
            .with(predicate::in_iter(["addrA2", "addrA3"]))
            .times(2)
            .returning(|_addr| Err(anyhow!("bad")))
            .in_sequence(&mut nb1_seq);
        check
            .expect_check()
            .with(predicate::eq("addrA3"))
            .times(1)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 10,
                    replica_version: "ver1".to_string(),
                })
            })
            .in_sequence(&mut nb1_seq);

        let mut persist_seq = Sequence::new();
        let mut persist = MockPersist::new();
        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 3);
                assert!(subnet_nodes.contains(&("subnetA", "nodeA1")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA2")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA3")));
                Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);
        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 1);
                assert!(subnet_nodes.contains(&("subnetA", "nodeA1")));
                assert!(!subnet_nodes.contains(&("subnetA", "nodeA2")));
                assert!(!subnet_nodes.contains(&("subnetA", "nodeA3")));
                Result::<_, Error>::Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);
        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 2);
                assert!(subnet_nodes.contains(&("subnetA", "nodeA1")));
                assert!(!subnet_nodes.contains(&("subnetA", "nodeA2")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA3")));
                Result::<_, Error>::Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);

        let mut cpr = CheckPersistRunner::new(routing, check, persist, 0, 1000);
        let active = cpr.get_active_checker();
        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA2".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA3".into())));

        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA2".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA3".into())));

        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));
        assert!(!active.is_active(&("subnetA".into(), "nodeA2".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA3".into())));
    }

    /// This test ensures CheckPersistRunner handles replicas returning disparate heights.
    #[tokio::test(flavor = "multi_thread")]
    async fn height() {
        let mut routing = MockRetrieve::new();
        routing.expect_retrieve().returning(single_subnet_table(
            0,
            "subnetA",
            &[
                ("nodeA1", "addrA1"),
                ("nodeA2", "addrA2"),
                ("nodeA3", "addrA3"),
            ],
        ));

        let mut check = MockCheck::new();
        let mut na1_seq = Sequence::new();
        let mut nb1_seq = Sequence::new();
        check
            .expect_check()
            .with(predicate::eq("addrA1"))
            .times(2)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 10,
                    replica_version: "ver1".to_string(),
                })
            })
            .in_sequence(&mut na1_seq);
        check
            .expect_check()
            .with(predicate::eq("addrA1"))
            .times(1)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 11,
                    replica_version: "ver1".to_string(),
                })
            })
            .in_sequence(&mut na1_seq);
        check
            .expect_check()
            .with(predicate::in_iter(["addrA2", "addrA3"]))
            .times(2)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 10,
                    replica_version: "ver1".to_string(),
                })
            })
            .in_sequence(&mut nb1_seq);
        check
            .expect_check()
            .with(predicate::in_iter(["addrA2", "addrA3"]))
            .times(4)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 1011,
                    replica_version: "ver1".to_string(),
                })
            })
            .in_sequence(&mut nb1_seq);

        let mut persist_seq = Sequence::new();
        let mut persist = MockPersist::new();
        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 3);
                assert!(subnet_nodes.contains(&("subnetA", "nodeA1")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA2")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA3")));
                Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);
        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 2);
                assert!(!subnet_nodes.contains(&("subnetA", "nodeA1")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA2")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA3")));
                Result::<_, Error>::Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);
        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 3);
                assert!(subnet_nodes.contains(&("subnetA", "nodeA1")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA2")));
                assert!(subnet_nodes.contains(&("subnetA", "nodeA3")));
                Result::<_, Error>::Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);

        let mut cpr = CheckPersistRunner::new(routing, check, persist, 0, 1000);
        let active = cpr.get_active_checker();
        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA2".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA3".into())));

        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA2".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA3".into())));

        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA2".into())));
        assert!(active.is_active(&("subnetA".into(), "nodeA3".into())));
    }

    // Make sure that if the node comes up with different version after being erroring out -> it is brought up immediately
    #[tokio::test(flavor = "multi_thread")]
    async fn node_upgrade() {
        let mut routing = MockRetrieve::new();
        routing.expect_retrieve().returning(single_subnet_table(
            0,
            "subnetA",
            &[("nodeA1", "addrA1")],
        ));

        let mut check = MockCheck::new();
        let mut seq = Sequence::new();

        check
            .expect_check()
            .with(predicate::eq("addrA1"))
            .times(1)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 1,
                    replica_version: "ver1".to_string(),
                })
            })
            .in_sequence(&mut seq);
        check
            .expect_check()
            .with(predicate::eq("addrA1"))
            .times(1)
            .returning(|_addr| Err(anyhow!("some_err")))
            .in_sequence(&mut seq);
        check
            .expect_check()
            .with(predicate::in_iter(["addrA1"]))
            .times(1)
            .returning(|_addr| {
                Ok(CheckResult {
                    height: 1,
                    replica_version: "ver2".to_string(),
                })
            })
            .in_sequence(&mut seq);

        let mut persist_seq = Sequence::new();
        let mut persist = MockPersist::new();

        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 1);
                assert!(subnet_nodes.contains(&("subnetA", "nodeA1")));
                Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);

        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 0);
                assert!(!subnet_nodes.contains(&("subnetA", "nodeA1")));
                Result::<_, Error>::Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);

        persist
            .expect_persist()
            .times(1)
            .returning(|rt: &RoutingTable| {
                let subnet_nodes = get_subnet_nodes(rt);
                assert_eq!(subnet_nodes.len(), 1);
                assert!(subnet_nodes.contains(&("subnetA", "nodeA1")));
                Result::<_, Error>::Ok(PersistStatus::Completed)
            })
            .in_sequence(&mut persist_seq);

        let mut cpr = CheckPersistRunner::new(routing, check, persist, 0, 1000);
        let active = cpr.get_active_checker();
        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));

        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));

        cpr.run().await.expect("no errors");
        assert!(active.is_active(&("subnetA".into(), "nodeA1".into())));
    }
}
