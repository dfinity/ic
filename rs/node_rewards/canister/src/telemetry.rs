use std::cell::RefCell;

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
}

thread_local! {
    pub static PROMETHEUS_METRICS: RefCell<PrometheusMetrics> = RefCell::new(PrometheusMetrics::default());
}
