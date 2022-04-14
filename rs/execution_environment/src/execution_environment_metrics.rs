use ic_error_types::UserError;
use ic_ic00_types as ic00;
use ic_metrics::buckets::decimal_buckets;
use ic_metrics::{MetricsRegistry, Timer};
use prometheus::HistogramVec;
use std::str::FromStr;

/// Metrics used to monitor the performance of the execution environment.
pub(crate) struct ExecutionEnvironmentMetrics {
    subnet_messages: HistogramVec,
}

impl ExecutionEnvironmentMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            subnet_messages: metrics_registry.histogram_vec(
                "execution_subnet_message_duration_seconds",
                "Duration of a subnet message execution, in seconds.",
                // Instruction limit for `install_code` would allow for about 100s execution, so
                // ensure we include at least until that bucket value.
                // Buckets: 1ms, 2ms, 5ms, ..., 100s, 200s, 500s
                decimal_buckets(-3, 2),
                // The `outcome` label is deprecated and should be replaced by `status` eventually.
                &["method_name", "outcome", "status"],
            ),
        }
    }

    /// Observe the duration and count of subnet messages.
    ///
    /// The observation is divided by the name of the method as well as by the
    /// "outcome" (i.e. whether or not execution succeeded).
    ///
    /// Example 1: A successful call to ic00::create_canister is observed as:
    /// subnet_message({
    ///     "method_name": "ic00_create_canister",
    ///     "outcome": "success",
    ///     "status": "success",
    /// })
    ///
    /// Example 2: An unsuccessful call to ic00::install_code is observed as:
    /// subnet_message({
    ///     "method_name": "ic00_install_code",
    ///     "outcome": "error",
    ///     "status": "CanisterContractViolation",
    /// })
    ///
    /// Example 3: A call to a non-existing method is observed as:
    /// subnet_message({
    ///     "method_name": "unknown_method",
    ///     "outcome": "error",
    ///     "status": "CanisterMethodNotFound",
    /// })
    pub fn observe_subnet_message(
        &self,
        method_name: &str,
        timer: Timer,
        res: &Result<Vec<u8>, UserError>,
    ) {
        let method_name_label = if let Ok(method_name) = ic00::Method::from_str(method_name) {
            format!("ic00_{}", method_name)
        } else {
            String::from("unknown_method")
        };

        let (outcome_label, status_label) = match res {
            Ok(_) => (String::from("success"), String::from("success")),
            Err(err) => (String::from("error"), format!("{:?}", err.code())),
        };

        self.subnet_messages
            .with_label_values(&[&method_name_label, &outcome_label, &status_label])
            .observe(timer.elapsed());
    }
}
