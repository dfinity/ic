use chrono::NaiveDate;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    DailyNodeFailureRate, DailyResults,
};
use std::cell::RefCell;
use std::collections::BTreeMap;

/// Instruction counter helper that counts instructions in the call context.
pub struct InstructionCounter {
    start: u64,
    lap_start: u64,
}

impl InstructionCounter {
    /// Creates a new instruction counter.  If the argument is None,
    /// the current context instruction counter is used.
    pub fn new(start_counter: Option<u64>) -> Self {
        let c = start_counter.unwrap_or(ic_cdk::api::call_context_instruction_counter());
        Self {
            start: c,
            lap_start: c,
        }
    }

    /// Tallies up the instructions executed since the last call to
    /// lap() or (if never called) the instantiation of this counter,
    /// and returns them.
    pub fn lap(&mut self) -> u64 {
        let now = ic_cdk::api::call_context_instruction_counter();
        let difference = now - self.lap_start;
        self.lap_start = now;
        difference
    }

    /// Returns the instructions executed since the instantiation of
    /// this counter.
    pub fn sum(self) -> u64 {
        ic_cdk::api::call_context_instruction_counter() - self.start
    }
}

impl Default for InstructionCounter {
    fn default() -> Self {
        Self::new(None)
    }
}

// Represents a pair of Prometheus metrics labels.
pub type LabelPair<'a> = (&'a str, &'a str);

#[derive(Default)]
struct ProviderMetrics {
    total_adjusted_rewards_xdr_permyriad: f64,
    total_based_rewards_xdr_permyriad: f64,
    relative_failure_rate: BTreeMap<(NodeId, SubnetId), f64>,
    original_failure_rate: BTreeMap<(NodeId, SubnetId), f64>,
    nodes_count: f64,
}

#[derive(Default)]
struct RewardsCalculationMetrics {
    provider_metrics: BTreeMap<PrincipalId, ProviderMetrics>,
    subnets_failure_rate: BTreeMap<SubnetId, f64>,
}

#[derive(Default)]
pub struct PrometheusMetrics {
    /// Records the time the last sync began.
    last_sync_start: f64,

    /// Records the time that sync last succeeded.
    last_sync_success: f64,

    /// Records the time that sync last ended (successfully or in failure).
    /// If last_sync_start > last_sync_end, sync is in progress, else sync is not taking place.
    /// If last_sync_success == last_sync_end, last sync was successful.
    last_sync_end: f64,

    /// Records the number of instructions spent in last sync
    last_sync_instructions: f64,

    /// Number of instruction for executing get_node_providers_rewards
    last_get_node_providers_rewards_instructions: f64,

    /// Rewards calculation metrics
    rewards_calculation_metrics: BTreeMap<NaiveDate, RewardsCalculationMetrics>,
}

static LAST_SYNC_START_HELP: &str = "Last time the sync of metrics started.  If this metric is present but zero, the first sync during this canister's current execution has not yet begun or taken place.";
static LAST_SYNC_END_HELP: &str = "Last time the sync of metrics ended (successfully or with failure).  If this metric is present but zero, the first sync during this canister's current execution has not started or finished yet, either successfully or with errors.   Else, subtracting this from the last sync start should yield a positive value if the sync ended (successfully or with errors), and a negative value if the sync is still ongoing but has not finished.";
static LAST_SYNC_SUCCESS_HELP: &str = "Last time the sync of metrics succeeded.  If this metric is present but zero, no sync has yet succeeded during this canister's current execution.  Else, subtracting this number from last_sync_start_timestamp_seconds gives a positive time delta when the last sync succeeded, or a negative value if either the last sync failed or a sync is currently being performed.  By definition, this and last_sync_end_timestamp_seconds will be identical when the last sync succeeded.";
static LAST_SYNC_INSTRUCTIONS_HELP: &str = "Count of instructions that the last sync incurred.  Label total is the sum total of instructions, and the other labels represent different phases.";
impl PrometheusMetrics {
    pub fn mark_last_sync_start(&mut self) {
        self.last_sync_start = (ic_cdk::api::time() / 1_000_000_000) as f64
    }

    pub fn mark_last_sync_success(&mut self) {
        self.last_sync_end = (ic_cdk::api::time() / 1_000_000_000) as f64;
        self.last_sync_success = self.last_sync_end
    }

    pub fn mark_last_sync_failure(&mut self) {
        self.last_sync_end = (ic_cdk::api::time() / 1_000_000_000) as f64
    }

    pub fn record_last_sync_instructions(&mut self, total: u64) {
        self.last_sync_instructions = total as f64;
    }

    pub fn record_last_get_node_providers_rewards_instructions(&mut self, total: u64) {
        self.last_get_node_providers_rewards_instructions = total as f64;
    }

    pub fn rewards_dates_stored(&self) -> Vec<NaiveDate> {
        self.rewards_calculation_metrics.keys().cloned().collect()
    }

    pub fn remove_rewards_date(&mut self, date: NaiveDate) {
        self.rewards_calculation_metrics.remove(&date);
    }

    pub fn record_node_providers_rewards(&mut self, date: NaiveDate, daily_results: DailyResults) {
        let mut provider_metrics = BTreeMap::new();
        for (provider_id, daily_rewards) in daily_results.provider_results {
            let mut nodes_count: f64 = 0f64;
            let mut original_failure_rate = BTreeMap::new();
            let mut relative_failure_rate = BTreeMap::new();

            for daily_node_rewards in daily_rewards.daily_nodes_rewards {
                nodes_count += 1.0;

                match daily_node_rewards.daily_node_failure_rate {
                    Some(DailyNodeFailureRate::SubnetMember { node_metrics }) => {
                        let node_metrics = node_metrics.unwrap_or_default();
                        let subnet_assigned =
                            SubnetId::from(node_metrics.subnet_assigned.unwrap_or_default());
                        let node_id = NodeId::from(daily_node_rewards.node_id.unwrap_or_default());

                        original_failure_rate.insert(
                            (node_id, subnet_assigned),
                            node_metrics.original_failure_rate.unwrap_or_default(),
                        );
                        relative_failure_rate.insert(
                            (node_id, subnet_assigned),
                            node_metrics.relative_failure_rate.unwrap_or_default(),
                        );
                    }
                    _ => continue,
                }
            }

            provider_metrics.insert(
                provider_id,
                ProviderMetrics {
                    total_adjusted_rewards_xdr_permyriad: daily_rewards
                        .total_adjusted_rewards_xdr_permyriad
                        .unwrap_or_default()
                        as f64,
                    total_based_rewards_xdr_permyriad: daily_rewards
                        .total_base_rewards_xdr_permyriad
                        .unwrap_or_default()
                        as f64,
                    relative_failure_rate,
                    original_failure_rate,
                    nodes_count,
                },
            );
        }

        self.rewards_calculation_metrics.insert(
            date,
            RewardsCalculationMetrics {
                provider_metrics,
                subnets_failure_rate: daily_results.subnets_failure_rate,
            },
        );
    }

    pub fn encode_metrics(
        &self,
        w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
    ) -> std::io::Result<()> {
        // General resource consumption.
        w.encode_gauge(
            "canister_stable_memory_size_bytes",
            ic_nervous_system_common::stable_memory_size_bytes() as f64,
            "Size of the stable memory allocated by this canister measured in bytes.",
        )?;
        w.encode_gauge(
            "canister_total_memory_size_bytes",
            ic_nervous_system_common::total_memory_size_bytes() as f64,
            "Size of the total memory allocated by this canister measured in bytes.",
        )?;

        // Calculation start timestamp seconds.
        //
        // * 0.0 -> first calculation not yet begun since canister started.
        // * Any other positive number -> at least one calculation has started.
        w.encode_gauge(
            "last_sync_start_timestamp_seconds",
            self.last_sync_start,
            LAST_SYNC_START_HELP,
        )?;
        // Calculation finish timestamp seconds.
        // * 0.0 -> first calculation not yet finished since canister started.
        // * last_sync_end_timestamp_seconds - last_sync_start_timestamp_seconds > 0 -> last calculation finished, next calculation not started yet
        // * last_sync_end_timestamp_seconds - last_sync_start_timestamp_seconds < 0 -> calculation ongoing, not finished yet
        w.encode_gauge(
            "last_sync_end_timestamp_seconds",
            self.last_sync_end,
            LAST_SYNC_END_HELP,
        )?;
        // Calculation success timestamp seconds.
        // * 0.0 -> no calculation has yet succeeded since canister started.
        // * last_sync_end_timestamp_seconds == last_sync_success_timestamp_seconds -> last calculation finished successfully
        // * last_sync_end_timestamp_seconds != last_sync_success_timestamp_seconds -> last calculation failed
        w.encode_gauge(
            "last_sync_success_timestamp_seconds",
            self.last_sync_success,
            LAST_SYNC_SUCCESS_HELP,
        )?;

        w.encode_gauge(
            "last_sync_instructions",
            self.last_sync_instructions,
            LAST_SYNC_INSTRUCTIONS_HELP,
        )?;

        w.encode_gauge(
            "last_get_node_providers_rewards_instructions",
            self.last_get_node_providers_rewards_instructions,
            LAST_SYNC_INSTRUCTIONS_HELP,
        )?;

        Ok(())
    }

    pub fn encode_rewards_calculation_metrics_paginated(
        &self,
        page: usize,
        limit: usize,
    ) -> std::io::Result<Vec<u8>> {
        let mut paginated_metrics = Vec::new();

        // Compute pagination window
        let start = page.saturating_mul(limit);

        // Iterate only over the selected slice
        for (_, (date, rewards_calculation_metrics)) in self
            .rewards_calculation_metrics
            .iter()
            .enumerate()
            .skip(start)
            .take(limit)
        {
            let noon_time = date
                .and_hms_opt(12, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp_millis();

            let mut w = ic_metrics_encoder::MetricsEncoder::new(vec![], noon_time);
            self.encode_rewards_calculation_metrics_single(rewards_calculation_metrics, &mut w)?;
            paginated_metrics.extend_from_slice(w.into_inner().as_slice());
        }

        Ok(paginated_metrics)
    }

    fn encode_rewards_calculation_metrics_single(
        &self,
        rewards_calculation_metrics: &RewardsCalculationMetrics,
        w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
    ) -> std::io::Result<()> {
        {
            let mut metric = w.gauge_vec(
                "latest_nodes_count",
                "Node counts for a provider on latest_rewards_calculation_date",
            )?;
            for (provider_id, provider_metrics) in &rewards_calculation_metrics.provider_metrics {
                metric = metric.value(
                    &[("provider_id", &provider_id.to_string())],
                    provider_metrics.nodes_count,
                )?;
            }
        }

        {
            let mut metric = w.gauge_vec(
                    "latest_total_adjusted_rewards_xdr_permyriad",
                    "Sum of adjusted rewards across all nodes for a provider on latest_rewards_calculation_date",
                )?;
            for (provider_id, provider_metrics) in &rewards_calculation_metrics.provider_metrics {
                metric = metric.value(
                    &[("provider_id", &provider_id.to_string())],
                    provider_metrics.total_adjusted_rewards_xdr_permyriad,
                )?;
            }
        }

        {
            let mut metric = w.gauge_vec(
                    "latest_total_base_rewards_xdr_permyriad",
                    "Sum of base rewards across all nodes for a provider on latest_rewards_calculation_date",
                )?;
            for (provider_id, provider_metrics) in &rewards_calculation_metrics.provider_metrics {
                metric = metric.value(
                    &[("provider_id", &provider_id.to_string())],
                    provider_metrics.total_based_rewards_xdr_permyriad,
                )?;
            }
        }

        {
            let mut metric = w.gauge_vec(
                "latest_original_failure_rate",
                "Original failure rate of one node on latest_rewards_calculation_date",
            )?;
            for (provider_id, provider_metrics) in &rewards_calculation_metrics.provider_metrics {
                for ((node_id, subnet_assigned), original_failure_rate) in
                    &provider_metrics.original_failure_rate
                {
                    metric = metric.value(
                        &[
                            ("node_id", &node_id.to_string()),
                            ("provider_id", &provider_id.to_string()),
                            ("subnet_id", &subnet_assigned.to_string()),
                        ],
                        *original_failure_rate,
                    )?;
                }
            }
        }

        {
            let mut metric = w.gauge_vec(
                "subnet_failure_rate",
                "Failure rate of one subnet on latest_rewards_calculation_date",
            )?;
            for (subnet_id, failure_rate) in &rewards_calculation_metrics.subnets_failure_rate {
                metric = metric.value(&[("subnet_id", &subnet_id.to_string())], *failure_rate)?;
            }
        }

        {
            let mut metric = w.gauge_vec(
                "latest_relative_failure_rate",
                "Relative failure rate of one node on latest_rewards_calculation_date",
            )?;
            for (provider_id, provider_metrics) in &rewards_calculation_metrics.provider_metrics {
                for ((node_id, subnet_assigned), relative_failure_rate) in
                    &provider_metrics.relative_failure_rate
                {
                    metric = metric.value(
                        &[
                            ("node_id", &node_id.to_string()),
                            ("provider_id", &provider_id.to_string()),
                            ("subnet_id", &subnet_assigned.to_string()),
                        ],
                        *relative_failure_rate,
                    )?;
                }
            }
        }

        Ok(())
    }
}

thread_local! {
    pub static PROMETHEUS_METRICS: RefCell<PrometheusMetrics> = RefCell::new(PrometheusMetrics::default());
}
