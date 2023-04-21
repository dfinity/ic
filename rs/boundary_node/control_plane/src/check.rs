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
    successful_checks: u8,
    last_updated: CheckRunId,
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
}

impl<R: Retrieve, C: Check, P: Persist> CheckPersistRunner<R, C, P> {
    pub fn new(routing_table: R, checker: C, persister: P, min_ok_count: u8) -> Self {
        Self {
            routing_table,
            checks: Arc::new(DashMap::new()),
            current_run_id: CheckRunId::default(),
            checker,
            persister,
            min_ok_count,
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

impl<R: Retrieve + Send + Sync, C: Check, P: Persist> CheckPersistRunner<R, C, P> {
    /// Healthcheck a nodes in a subnet
    async fn check_node(
        node: Node,
        checker: &C,
        checks: &Arc<DashMap<(String, String), CheckState>>,
        current_run_id: CheckRunId,
        min_ok_count: u8,
        subnet_id: &str,
    ) -> Result<(Node, u8), Error> {
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

        // Update the `checks` entry
        let mut entry = checks
            .entry((subnet_id.to_string(), node.node_id.clone()))
            .or_default();
        entry.last_updated = current_run_id;
        match check_result {
            Err(e) => {
                entry.successful_checks = 0;
                Err(e)
            }
            Ok(_) => {
                entry.successful_checks = min_ok_count.min(entry.successful_checks + 1);
                Ok((node, entry.successful_checks))
            }
        }
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
        let nodes = nodes
            .into_iter()
            .filter_map(Result::ok) // Filter any green thread errors
            .filter_map(Result::ok) // Filter any `checker.check` errors
            .filter(|node| node.1 >= self.min_ok_count) // Filter below min_ok_count
            .map(|node| node.0)
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

pub struct CheckResult {}

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
            ..
        } = serde_cbor::from_reader(response_reader).context("failed to parse cbor response")?;

        if replica_health_status != Some(ReplicaHealthStatus::Healthy) {
            return Err(anyhow!("replica reported unhealthy status"));
        }

        Ok(CheckResult {})
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
    fn table<'a>(
        registry_version: u64,
        subnets: &'a [(&str, &[(&str, &str)])],
    ) -> impl Fn() -> Result<RoutingTable, Error> + 'a {
        move || {
            Ok(RoutingTable {
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
            })
        }
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
            .returning(table(
                0,
                &[(
                    "subnetA",
                    &[
                        ("nodeA1", "addrA1"),
                        ("nodeA2", "addrA2"),
                        ("nodeA3", "addrA3"),
                    ],
                )],
            ))
            .in_sequence(&mut retrieve_seq);
        routing
            .expect_retrieve()
            .times(1)
            .returning(table(
                0,
                &[("subnetA", &[("nodeA1", "addrA1"), ("nodeA3", "addrA3")])],
            ))
            .in_sequence(&mut retrieve_seq);

        let mut check = MockCheck::new();
        let mut na1_seq = Sequence::new();
        let mut nb1_seq = Sequence::new();
        check
            .expect_check()
            .with(predicate::eq("addrA1"))
            .times(3)
            .returning(|_addr| Ok(CheckResult {}))
            .in_sequence(&mut na1_seq);
        check
            .expect_check()
            .with(predicate::in_iter(["addrA2", "addrA3"]))
            .times(2)
            .returning(|_addr| Ok(CheckResult {}))
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
            .returning(|_addr| Ok(CheckResult {}))
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

        let mut cpr = CheckPersistRunner::new(routing, check, persist, 0);
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
}
