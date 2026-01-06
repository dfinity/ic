use std::{
    fmt::Display,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Error;
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use ic_bn_lib::prometheus::{
    IntCounterVec, IntGauge, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};
use ic_bn_lib_common::traits::Run;
use salt_sharing_api::{GetSaltError, GetSaltResponse};
use tokio::{
    select,
    time::{MissedTickBehavior, interval},
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

struct Metrics {
    last_successful_fetch: IntGauge,
    fetches: IntCounterVec,
    last_salt_id: IntGauge,
}

impl Metrics {
    fn new(registry: &Registry) -> Self {
        const METRIC_PREFIX: &str = "anonymization_salt";

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

/// Fetches & applies the anonymization salt from the canister
pub struct AnonymizationSaltFetcher {
    agent: Agent,
    canister_id: Principal,
    polling_interval: Duration,
    anonymization_salt: Arc<ArcSwapOption<Vec<u8>>>,
    metrics: Metrics,
}

impl Display for AnonymizationSaltFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnonymizationSaltFetcher")
    }
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
            canister_id,
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
            .update(&self.canister_id, "get_salt")
            .with_arg(Encode!().unwrap())
            .call_and_wait()
            .await
        {
            Ok(response) if !response.is_empty() => response,
            Ok(_) => {
                update_fetch_metric("failure", "empty_response");
                warn!("{self}: got empty response from the canister");
                return;
            }
            Err(err) => {
                update_fetch_metric("failure", "update_call_failure");
                warn!("{self}: failed to get salt from the canister: {err:#}");
                return;
            }
        };

        let salt_response = match Decode!(&query_response, GetSaltResponse) {
            Ok(response) => response,
            Err(err) => {
                update_fetch_metric("failure", "response_decoding_failure");
                warn!("{self}: failed to decode candid response: {err:?}");
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
                warn!("{self}: get_salt failed: {err:?}");
            }
        }
    }
}

#[async_trait]
impl Run for AnonymizationSaltFetcher {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        // Create an interval to enable strictly periodic execution
        let mut interval = interval(self.polling_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            select! {
                biased;

                _ = token.cancelled() => {
                    return Ok(());
                }

                _ = interval.tick() => {
                    self.fetch_salt().await
                }
            }
        }
    }
}
