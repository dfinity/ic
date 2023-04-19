use std::{
    cmp::min,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use bytes::Buf;
use dashmap::{DashMap, DashSet};
use futures::stream::FuturesUnordered;
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use opentelemetry::{baggage::BaggageExt, trace::FutureExt, KeyValue};
use tokio::task;

use crate::{
    persist::Persist,
    registry::{RoutingTable, Subnet},
    Run,
};

pub struct CheckPersistRunner<C: Check, P: Persist> {
    // Dependencies
    routing_table: Arc<Mutex<Option<RoutingTable>>>,
    checks: Arc<DashMap<(String, String), u8>>,
    checker: Arc<C>,
    persister: P,

    // Configuration
    min_ok_count: u8,
}

impl<C: Check, P: Persist> CheckPersistRunner<C, P> {
    pub fn new(
        routing_table: Arc<Mutex<Option<RoutingTable>>>,
        checks: Arc<DashMap<(String, String), u8>>,
        checker: C,
        persister: P,
        min_ok_count: u8,
    ) -> Self {
        Self {
            routing_table,
            checks,
            checker: Arc::new(checker),
            persister,
            min_ok_count,
        }
    }
}

#[async_trait]
impl<C: Check, P: Persist> Run for CheckPersistRunner<C, P> {
    async fn run(&mut self) -> Result<(), Error> {
        let routing_table = {
            let rt = self.routing_table.lock().unwrap();
            rt.clone()
                .ok_or_else(|| anyhow!("routing_table not available"))?
        };

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
        let futs = FuturesUnordered::new();

        for subnet in routing_table.clone().subnets {
            for node in subnet.nodes {
                let checks = Arc::clone(&self.checks);
                let checker = Arc::clone(&self.checker);
                let min_ok_count = self.min_ok_count.to_owned();

                let (subnet_id, node_id, socket_addr) = (
                    subnet.subnet_id.clone(),
                    node.node_id.clone(),
                    node.socket_addr.clone(),
                );

                futs.push(task::spawn(async move {
                    let _ctx = opentelemetry::Context::current_with_baggage(vec![
                        KeyValue::new("subnet_id", subnet_id.to_string()),
                        KeyValue::new("node_id", node_id.to_string()),
                        KeyValue::new("socket_addr", socket_addr.to_string()),
                    ]);

                    let out = checker
                        .check(&socket_addr)
                        .with_context(_ctx.clone())
                        .await
                        .context("failed to check node");

                    let k = (subnet_id, node_id);
                    let ok_cnt = match checks.get(&k) {
                        Some(c) => c.value().to_owned(),
                        None => 0,
                    };

                    match out {
                        Ok(_) => checks.insert(
                            k,
                            min(
                                min_ok_count, // clamp to this value
                                ok_cnt + 1,
                            ),
                        ),
                        Err(_) => checks.insert(k, 0),
                    };

                    out
                }));
            }
        }

        for fut in futs {
            let _ = fut.await?;
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
                                Some(c) => c.value().to_owned(),
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

#[async_trait]
pub trait Check: 'static + Send + Sync {
    async fn check(&self, addr: &str) -> Result<(), Error>;
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
    async fn check(&self, addr: &str) -> Result<(), Error> {
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

        Ok(())
    }
}
