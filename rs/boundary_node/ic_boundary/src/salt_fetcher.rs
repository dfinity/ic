use crate::core::Run;
use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::Principal;
use candid::{Decode, Encode};
use ic_bn_lib::prometheus::{
    register_int_counter_vec_with_registry, register_int_gauge_with_registry, IntCounterVec,
    IntGauge, Registry,
};
use ic_canister_client::Agent;
use ic_types::CanisterId;
use salt_sharing_api::{GetSaltError, GetSaltResponse};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{sync::Arc, time::Duration};
use tokio::time::{interval, MissedTickBehavior};
use tracing::warn;

const SERVICE: &str = "AnonymizationSaltFetcher";
const METRIC_PREFIX: &str = "anonymization_salt";

fn nonce() -> Vec<u8> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()
        .to_vec()
}

struct Metrics {
    last_successful_fetch: IntGauge,
    fetches: IntCounterVec,
    last_salt_id: IntGauge,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        Self {
            last_successful_fetch: register_int_gauge_with_registry!(
                format!("{METRIC_PREFIX}_last_successful_fetch"),
                format!("The Unix timestamp of the last successful salt fetch"),
                registry
            )
            .unwrap(),

            last_salt_id: register_int_gauge_with_registry!(
                format!("{METRIC_PREFIX}_last_salt_id"),
                format!("ID of the latest fetched salt"),
                registry,
            )
            .unwrap(),

            fetches: register_int_counter_vec_with_registry!(
                format!("{METRIC_PREFIX}_fetches"),
                format!("Count of salt fetches and their outcome"),
                &["status", "message"],
                registry
            )
            .unwrap(),
        }
    }
}

pub struct AnonymizationSaltFetcher {
    agent: Agent,
    canister_id: CanisterId,
    polling_interval: Duration,
    anonymization_salt: Arc<ArcSwapOption<Vec<u8>>>,
    metrics: Metrics,
}

impl AnonymizationSaltFetcher {
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

    async fn fetch_salt(&self) {
        let update_fetch_metric = |status: &str, message: &str| {
            self.metrics
                .fetches
                .with_label_values(&[status, message])
                .inc();
        };

        let query_response = match self
            .agent
            .execute_update(
                &self.canister_id,
                &self.canister_id,
                "get_salt",
                Encode!().unwrap(),
                nonce(),
            )
            .await
        {
            Ok(response) => match response {
                Some(response) => response,
                None => {
                    update_fetch_metric("failure", "empty_response");
                    warn!("{SERVICE}: got empty response from the canister");
                    return;
                }
            },
            Err(err) => {
                update_fetch_metric("failure", "update_call_failure");
                warn!("{SERVICE}: failed to get salt from the canister: {err:#}");
                return;
            }
        };

        let salt_response = match Decode!(&query_response, GetSaltResponse) {
            Ok(response) => response,
            Err(err) => {
                update_fetch_metric("failure", "response_decoding_failure");
                warn!("{SERVICE}: failed to decode candid response: {err:?}");
                return;
            }
        };

        match salt_response {
            Ok(resp) => {
                update_fetch_metric("success", "");
                // Overwrite salt (used for hashing sensitive data)
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
                let message = match err {
                    GetSaltError::SaltNotInitialized => "salt_not_initialized",
                    GetSaltError::Unauthorized => "unauthorized",
                    GetSaltError::Internal(_) => "internal",
                };
                update_fetch_metric("failure", message);
                warn!("{SERVICE}: get_salt failed: {err:?}");
            }
        }
    }
}

#[async_trait]
impl Run for Arc<AnonymizationSaltFetcher> {
    async fn run(&mut self) -> Result<(), Error> {
        // Create an interval to enable strictly periodic execution
        let mut interval = interval(self.polling_interval);
        // Skip missed ticks to prevent timing drift and maintain absolute schedule
        // Example: with 5s interval, if fetch_salt() takes 7s at 0s:
        //   0s: first execution starts
        //   7s: first execution completes (5s tick was missed)
        //   10s: next execution starts (skips to next absolute tick)
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.fetch_salt().await;
        }
    }
}
