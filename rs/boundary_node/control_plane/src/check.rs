use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Error};
use async_scoped::TokioScope;
use async_trait::async_trait;
use bytes::Buf;
use dashmap::{mapref::entry::Entry, DashMap, DashSet};
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use opentelemetry::{baggage::BaggageExt, trace::FutureExt, KeyValue};

use crate::{
    persist::Persist,
    registry::{RoutingTable, Subnet},
    Run,
};

struct CheckState {
    successful_checks: u8,
}

pub struct CheckPersistRunner<R: Retrieve, C: Check, P: Persist> {
    // Dependencies
    routing_table: R,
    checks: Arc<DashMap<(String, String), CheckState>>,
    checker: Arc<C>,
    persister: P,

    // Configuration
    min_ok_count: u8,
}

impl<R: Retrieve, C: Check, P: Persist> CheckPersistRunner<R, C, P> {
    pub fn new(routing_table: R, checker: C, persister: P, min_ok_count: u8) -> Self {
        Self {
            routing_table,
            checks: Arc::new(DashMap::new()),
            checker: Arc::new(checker),
            persister,
            min_ok_count,
        }
    }

    pub fn get_active_checker(&self) -> impl ActiveChecker {
        Arc::clone(&self.checks)
    }
}

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

#[async_trait]
impl<R: Retrieve + Send + Sync, C: Check, P: Persist> Run for CheckPersistRunner<R, C, P> {
    async fn run(&mut self) -> Result<(), Error> {
        let routing_table = self.routing_table.retrieve()?;

        // Clean checks of targets that no longer exist
        let current_targets = DashSet::<(String, String)>::new();
        let stale_targets = DashSet::<(String, String)>::new();

        for subnet in routing_table.clone().subnets {
            for node in subnet.nodes {
                current_targets.insert((
                    subnet.subnet_id.clone(), // subnet_id
                    node.node_id.clone(),     // node_id
                ));
            }
        }

        for c in self.checks.iter() {
            let k = c.key();
            if !current_targets.contains(k) {
                stale_targets.insert(k.to_owned());
            }
        }

        for k in stale_targets.iter() {
            self.checks.remove(&k);
        }

        // Perform Health Checks
        let ((), futs) = TokioScope::scope_and_block(|s| {
            for subnet in routing_table.clone().subnets {
                for node in subnet.nodes {
                    let checks = Arc::clone(&self.checks);
                    let checker = Arc::clone(&self.checker);
                    let min_ok_count = self.min_ok_count;

                    let (subnet_id, node_id, socket_addr) = (
                        subnet.subnet_id.clone(),
                        node.node_id.clone(),
                        node.socket_addr.clone(),
                    );

                    s.spawn(async move {
                        let _ctx = opentelemetry::Context::current_with_baggage(vec![
                            KeyValue::new("subnet_id", subnet_id.to_string()),
                            KeyValue::new("node_id", node_id.to_string()),
                            KeyValue::new("socket_addr", socket_addr.to_string()),
                        ]);

                        let _out = checker
                            .check(&socket_addr)
                            .with_context(_ctx.clone())
                            .await
                            .context("failed to check node");

                        match checks.entry((subnet_id, node_id)) {
                            Entry::Occupied(mut o) => {
                                let o = o.get_mut();
                                // clamp
                                o.successful_checks = min_ok_count.min(o.successful_checks + 1);
                            }
                            Entry::Vacant(v) => {
                                v.insert(CheckState {
                                    successful_checks: 1,
                                });
                            }
                        };
                    });
                }
            }
        });

        for fut in futs {
            let _ = fut?;
        }

        // Construct Effective Routing Table
        let effective_routing_table = RoutingTable {
            subnets: routing_table
                .subnets
                .into_iter()
                .map(|subnet| Subnet {
                    nodes: subnet
                        .nodes
                        .into_iter()
                        .filter(|node| {
                            let k = (
                                subnet.subnet_id.clone(), // subnet_id
                                node.node_id.clone(),     // node_id
                            );

                            let ok_cnt = match self.checks.get(&k) {
                                Some(c) => c.value().successful_checks,
                                None => 0,
                            };

                            ok_cnt >= self.min_ok_count
                        })
                        .collect(),
                    ..subnet
                })
                .collect(),
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
