use crate::core::Run;
use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use candid::{Decode, Encode};
use ic_canister_client::Agent;
use ic_types::CanisterId;
use prometheus::{
    register_int_counter_vec_with_registry, register_int_gauge_with_registry, IntCounterVec,
    IntGauge, Registry,
};
use salt_sharing_api::GetSaltResponse;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{sync::Arc, time::Duration};
use tokio::time::sleep;
use tracing::warn;

struct Metrics {
    last_successful_fetch: IntGauge,
    fetches: IntCounterVec,
    last_salt_id: IntGauge,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        Self {
            last_successful_fetch: register_int_gauge_with_registry!(
                format!("salt_sharing_last_successful_fetch"),
                format!("The Unix timestamp of the last successful salt fetch"),
                registry
            )
            .unwrap(),

            last_salt_id: register_int_gauge_with_registry!(
                format!("salt_sharing_last_salt_id"),
                format!("ID of the latest fetched salt"),
                registry,
            )
            .unwrap(),

            fetches: register_int_counter_vec_with_registry!(
                format!("salt_sharing_fetches"),
                format!("Count of salt fetches and their outcome"),
                &["result"],
                registry
            )
            .unwrap(),
        }
    }
}

pub struct SharedSaltFetcher {
    agent: Agent,
    canister_id: CanisterId,
    polling_interval: Duration,
    anonymization_salt: Arc<ArcSwapOption<Vec<u8>>>,
    metrics: Metrics,
}

impl SharedSaltFetcher {
    pub fn new(
        agent: Agent,
        canister_id: Principal,
        polling_interval: Duration,
        anonymization_salt: Arc<ArcSwapOption<Vec<u8>>>,
        registry: &Registry,
    ) -> Self {
        Self {
            agent,
            canister_id: CanisterId::try_from_principal_id(canister_id.into()).unwrap(),
            anonymization_salt,
            polling_interval,
            metrics: Metrics::new(registry),
        }
    }
}

#[async_trait]
impl Run for Arc<SharedSaltFetcher> {
    async fn run(&mut self) -> Result<(), Error> {
        loop {
            let response = self
                .agent
                .execute_query(&self.canister_id, "get_salt", Encode!().unwrap())
                .await
                .map_err(|e| anyhow!("failed to fetch salt from the canister: {e:#}"))?
                .ok_or_else(|| anyhow!("got empty response from the canister"))?;

            let response = Decode!(&response, GetSaltResponse)
                .context("failed to decode candid response")?
                .map_err(|e| anyhow!("failed to get salt: {e:?}"));

            self.metrics
                .fetches
                .with_label_values(&[if response.is_ok() {
                    "success"
                } else {
                    "failure"
                }])
                .inc();

            match response {
                Ok(resp) => {
                    // Overwrite salt used for hashing sensitive data
                    self.anonymization_salt.store(Some(Arc::new(resp.salt)));
                    // Update metrics
                    self.metrics.last_salt_id.set(resp.salt_id as i64);
                    self.metrics.last_successful_fetch.set(
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64,
                    );
                }
                Err(err) => {
                    warn!("SharedSaltFetcher: unable to fetch: {err:#}");
                }
            }

            sleep(self.polling_interval).await;
        }
    }
}
