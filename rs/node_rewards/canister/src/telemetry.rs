use std::cell::RefCell;

/// The instructions executed so far in the current call context, which spans every message the
/// call is made of, not just the one running now.
#[cfg(target_arch = "wasm32")]
fn call_context_instructions() -> u64 {
    ic_cdk::api::call_context_instruction_counter()
}

/// Outside a canister — in unit tests — there is no counter to read, so every measurement is zero.
#[cfg(not(target_arch = "wasm32"))]
fn call_context_instructions() -> u64 {
    0
}

/// The current time, as the whole seconds since the Unix epoch that Prometheus timestamps use.
fn now_seconds() -> f64 {
    (crate::canister::current_time().as_nanos_since_unix_epoch() / 1_000_000_000) as f64
}

/// Instruction counter helper that counts instructions in the call context.
pub struct InstructionCounter {
    start: u64,
    lap_start: u64,
}

impl InstructionCounter {
    /// Creates a new instruction counter.  If the argument is None,
    /// the current context instruction counter is used.
    pub fn new(start_counter: Option<u64>) -> Self {
        let c = start_counter.unwrap_or(call_context_instructions());
        Self {
            start: c,
            lap_start: c,
        }
    }

    /// Tallies up the instructions executed since the last call to
    /// lap() or (if never called) the instantiation of this counter,
    /// and returns them.
    pub fn lap(&mut self) -> u64 {
        let now = call_context_instructions();
        let difference = now - self.lap_start;
        self.lap_start = now;
        difference
    }

    /// Returns the instructions executed since the instantiation of
    /// this counter.
    pub fn sum(self) -> u64 {
        call_context_instructions() - self.start
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

    /// Records the time the last node provider rewards calculation succeeded.
    last_get_node_providers_rewards_success: f64,

    /// Number of instruction for executing get_node_providers_rewards
    last_get_node_providers_rewards_instructions: f64,

    /// Number of instructions spent by the costliest single message of the last
    /// get_node_providers_rewards.
    last_get_node_providers_rewards_max_message_instructions: f64,
}

static LAST_SYNC_START_HELP: &str = "Last time the sync of metrics started.  If this metric is present but zero, the first sync during this canister's current execution has not yet begun or taken place.";
static LAST_SYNC_END_HELP: &str = "Last time the sync of metrics ended (successfully or with failure).  If this metric is present but zero, the first sync during this canister's current execution has not started or finished yet, either successfully or with errors.   Else, subtracting this from the last sync start should yield a positive value if the sync ended (successfully or with errors), and a negative value if the sync is still ongoing but has not finished.";
static LAST_SYNC_SUCCESS_HELP: &str = "Last time the sync of metrics succeeded.  If this metric is present but zero, no sync has yet succeeded during this canister's current execution.  Else, subtracting this number from last_sync_start_timestamp_seconds gives a positive time delta when the last sync succeeded, or a negative value if either the last sync failed or a sync is currently being performed.  By definition, this and last_sync_end_timestamp_seconds will be identical when the last sync succeeded.";
static LAST_SYNC_INSTRUCTIONS_HELP: &str = "Count of instructions that the last sync incurred.  Label total is the sum total of instructions, and the other labels represent different phases.";

static LAST_GET_NODE_PROVIDERS_REWARDS_SUCCESS_HELP: &str = "Last time a node provider rewards calculation succeeded.  If this metric is present but zero, none has succeeded during this canister's current execution.  The calculation is attempted once a day, so a value much older than that means node provider rewards can no longer be computed, and is the condition worth alerting on.";

static LAST_GET_NODE_PROVIDERS_REWARDS_INSTRUCTIONS_HELP: &str = "Count of instructions that the canister's own daily rewards calculation incurred, summed over its whole call context.  It always covers the same number of days, so it is comparable over time, but the calculation splits itself into one message per day and no instruction limit applies to the sum across them: this measures cost and its trend, not how much headroom is left.  For headroom see last_get_node_providers_rewards_max_message_instructions.";

static LAST_GET_NODE_PROVIDERS_REWARDS_MAX_MESSAGE_INSTRUCTIONS_HELP: &str = "Count of instructions incurred by the costliest single message of the last rewards calculation to complete, whether that was the canister's own daily one or a caller's.  A message computes one day of the reward period, and this is the number the subnet's instruction limits apply to: above the per-slice limit a message pauses and resumes in a later round, and above the per-message limit it traps.";

impl PrometheusMetrics {
    pub fn mark_last_sync_start(&mut self) {
        self.last_sync_start = now_seconds()
    }

    pub fn mark_last_sync_success(&mut self) {
        self.last_sync_end = now_seconds();
        self.last_sync_success = self.last_sync_end
    }

    pub fn mark_last_sync_failure(&mut self) {
        self.last_sync_end = now_seconds()
    }

    pub fn record_last_sync_instructions(&mut self, total: u64) {
        self.last_sync_instructions = total as f64;
    }

    pub fn mark_last_get_node_providers_rewards_success(&mut self) {
        self.last_get_node_providers_rewards_success = now_seconds()
    }

    pub fn record_last_get_node_providers_rewards_instructions(&mut self, total: u64) {
        self.last_get_node_providers_rewards_instructions = total as f64;
    }

    pub fn record_last_get_node_providers_rewards_max_message_instructions(&mut self, max: u64) {
        self.last_get_node_providers_rewards_max_message_instructions = max as f64;
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

        // Node provider rewards calculation success timestamp seconds.
        //
        // * 0.0 -> no calculation has succeeded since the canister started.
        // * Any other positive number -> the last time one succeeded. The calculation is attempted
        //   daily, so this going stale is what says rewards can no longer be computed. A failed
        //   attempt deliberately leaves the two instruction metrics below untouched: failing early
        //   is cheaper than succeeding, so recording it would read as the cost improving.
        w.encode_gauge(
            "last_get_node_providers_rewards_success_timestamp_seconds",
            self.last_get_node_providers_rewards_success,
            LAST_GET_NODE_PROVIDERS_REWARDS_SUCCESS_HELP,
        )?;

        w.encode_gauge(
            "last_get_node_providers_rewards_instructions",
            self.last_get_node_providers_rewards_instructions,
            LAST_GET_NODE_PROVIDERS_REWARDS_INSTRUCTIONS_HELP,
        )?;

        w.encode_gauge(
            "last_get_node_providers_rewards_max_message_instructions",
            self.last_get_node_providers_rewards_max_message_instructions,
            LAST_GET_NODE_PROVIDERS_REWARDS_MAX_MESSAGE_INSTRUCTIONS_HELP,
        )?;

        Ok(())
    }
}

thread_local! {
    pub static PROMETHEUS_METRICS: RefCell<PrometheusMetrics> = RefCell::new(PrometheusMetrics::default());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_metrics(metrics: &PrometheusMetrics) -> String {
        let mut encoder = ic_metrics_encoder::MetricsEncoder::new(vec![], 0);
        metrics.encode_metrics(&mut encoder).unwrap();

        String::from_utf8(encoder.into_inner()).unwrap()
    }

    /// Alert rules refer to these by name, in a repository that cannot be changed in the same
    /// commit as this one, so renaming one silently stops the alert from ever firing again.
    #[test]
    fn test_reward_calculation_metrics_are_exposed_under_their_alerted_names() {
        // Step 1: Prepare the world.
        let mut metrics = PrometheusMetrics::default();

        // Step 2: Run the code under test.
        metrics.record_last_get_node_providers_rewards_instructions(40_000_000_000);
        metrics.record_last_get_node_providers_rewards_max_message_instructions(1_100_000_000);
        let encoded = encoded_metrics(&metrics);

        // Step 3: Verify results.
        assert!(
            encoded.contains("last_get_node_providers_rewards_instructions 40000000000"),
            "{encoded}"
        );
        assert!(
            encoded.contains("last_get_node_providers_rewards_max_message_instructions 1100000000"),
            "{encoded}"
        );
        // Never marked successful, so it stays at zero rather than looking recent.
        assert!(
            encoded.contains("last_get_node_providers_rewards_success_timestamp_seconds 0"),
            "{encoded}"
        );
    }

    /// The two instruction metrics describe different quantities, and the alert on headroom must
    /// use the per-message one: only that number is bounded by the subnet's instruction limits.
    #[test]
    fn test_per_message_instructions_are_reported_separately_from_the_total() {
        let mut metrics = PrometheusMetrics::default();

        metrics.record_last_get_node_providers_rewards_instructions(40_000_000_000);
        metrics.record_last_get_node_providers_rewards_max_message_instructions(1_100_000_000);

        assert_eq!(
            metrics.last_get_node_providers_rewards_instructions,
            40_000_000_000.0
        );
        assert_eq!(
            metrics.last_get_node_providers_rewards_max_message_instructions,
            1_100_000_000.0
        );
    }

    #[test]
    fn test_success_is_marked_with_the_current_time() {
        let mut metrics = PrometheusMetrics::default();
        assert_eq!(metrics.last_get_node_providers_rewards_success, 0.0);

        metrics.mark_last_get_node_providers_rewards_success();

        assert_eq!(
            metrics.last_get_node_providers_rewards_success,
            now_seconds()
        );
    }
}
