use ic_cycles_account_manager::{
    CRITICAL_ERROR_EXECUTION_CYCLES_REFUND, CRITICAL_ERROR_RESPONSE_CYCLES_REFUND,
};
use ic_error_types::ErrorCode;
use ic_logger::{error, ReplicaLogger};
use ic_management_canister_types as ic00;
use ic_metrics::buckets::{decimal_buckets, decimal_buckets_with_zero};
use ic_metrics::MetricsRegistry;
use ic_replicated_state::metadata_state::subnet_call_context_manager::InstallCodeCallId;
use ic_types::CanisterId;
use prometheus::{Histogram, HistogramVec, IntCounter};
use std::str::FromStr;

pub const FINISHED_OUTCOME_LABEL: &str = "finished";
pub const SUBMITTED_OUTCOME_LABEL: &str = "submitted";
pub const ERROR_OUTCOME_LABEL: &str = "error";
pub const SUCCESS_STATUS_LABEL: &str = "success";

pub const CRITICAL_ERROR_CALL_ID_WITHOUT_INSTALL_CODE_CALL: &str =
    "execution_environment_call_id_without_install_code_call";

/// Metrics used to monitor the performance of the execution environment.
pub(crate) struct ExecutionEnvironmentMetrics {
    subnet_messages: HistogramVec,
    pub executions_aborted: IntCounter,
    pub(crate) compute_allocation_in_install_code_total: IntCounter,
    pub(crate) memory_allocation_in_install_code_total: IntCounter,
    pub(crate) call_durations: Histogram,

    /// Critical error for responses above the maximum allowed size.
    pub(crate) response_cycles_refund_error: IntCounter,
    /// Critical error for executions above the maximum allowed size.
    pub(crate) execution_cycles_refund_error: IntCounter,
    /// Critical error for call ID and no matching install code call.
    pub(crate) call_id_without_install_code_call: IntCounter,
    /// Critical error for encountering an ingress with cycles.
    pub(crate) ingress_with_cycles_error: IntCounter,
    /// Critical error for ingresses that should have been filtered out.
    pub(crate) unfiltered_ingress_error: IntCounter,
    /// Critical error for missing canister state.
    pub(crate) canister_not_found_error: IntCounter,
    /// Critical error for encountering an unexpected error while applying the state changes.
    pub(crate) state_changes_error: IntCounter,
    /// Critical error for illegal system calls.
    pub(crate) invalid_system_call_error: IntCounter,
    /// Critical error for costs exceeding the cycles balance.
    pub(crate) charging_from_balance_error: IntCounter,
    /// Critical error for encountering an unexpected response.
    pub(crate) unexpected_response_error: IntCounter,
    /// Critical error for unexpected invalid canister state.
    pub(crate) invalid_canister_state_error: IntCounter,
    /// Critical error for failed canister creation.
    pub(crate) canister_creation_error: IntCounter,
    /// Intra-subnet messages that would be oversize if they were between
    /// different subnets (not including install_code messages). This metric can
    /// be removed if the limit for intra-subnet messages and inter-subnet
    /// messages are brought back in sync.
    pub(crate) oversize_intra_subnet_messages: IntCounter,
    /// Critical error for attempting to execute new message
    /// while already in progress a long-running message.
    pub(crate) long_execution_already_in_progress: IntCounter,
    /// Time spent in queue for canister message before executing it.
    pub(crate) canister_message_queue_latency: HistogramVec,
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
                &["method_name", "outcome", "status", "speed"],
            ),
            executions_aborted: metrics_registry
                .int_counter("executions_aborted", "Total number of aborted executions"),
            compute_allocation_in_install_code_total: metrics_registry.int_counter(
                "execution_compute_allocation_in_install_code_total",
                "Total number of times compute allocation used in install_code requests",
            ),
            memory_allocation_in_install_code_total: metrics_registry.int_counter(
                "execution_memory_allocation_in_install_code_total",
                "Total number of times memory allocation used in install_code requests",
            ),
            call_durations: metrics_registry.histogram(
                "execution_call_duration_seconds",
                "Call durations, measured as call context age when completed / dropped.",
                // Buckets: 0s, 0.1s, 0.2s, 0.5s, ..., 5M seconds
                decimal_buckets_with_zero(-1, 6),
            ),
            response_cycles_refund_error: metrics_registry
                .error_counter(CRITICAL_ERROR_RESPONSE_CYCLES_REFUND),
            execution_cycles_refund_error: metrics_registry
                .error_counter(CRITICAL_ERROR_EXECUTION_CYCLES_REFUND),
            call_id_without_install_code_call: metrics_registry
                .error_counter(CRITICAL_ERROR_CALL_ID_WITHOUT_INSTALL_CODE_CALL),
            ingress_with_cycles_error: metrics_registry
                .error_counter("execution_environment_ingress_with_cycles"),
            unfiltered_ingress_error: metrics_registry
                .error_counter("execution_environment_unfiltered_ingress"),
            canister_not_found_error: metrics_registry
                .error_counter("execution_environment_canister_not_found"),
            state_changes_error: metrics_registry
                .error_counter("execution_environment_state_changes"),
            invalid_system_call_error: metrics_registry
                .error_counter("execution_environment_invalid_system_call"),
            charging_from_balance_error: metrics_registry
                .error_counter("execution_environment_charging_from_balance"),
            unexpected_response_error: metrics_registry
                .error_counter("execution_environment_unexpected_response"),
            invalid_canister_state_error: metrics_registry
                .error_counter("execution_environment_invalid_canister_state"),
            canister_creation_error: metrics_registry
                .error_counter("execution_environment_canister_creation_failed"),
            oversize_intra_subnet_messages: metrics_registry.int_counter(
                "execution_environment_oversize_intra_subnet_messages_total",
                "Total number of intra-subnet messages that exceed the 2 MiB limit for inter-subnet messages."
            ),
            long_execution_already_in_progress: metrics_registry.error_counter("execution_environment_long_execution_already_in_progress"),
            canister_message_queue_latency: metrics_registry.histogram_vec(
                "execution_canister_message_queue_latency_seconds",
                "Time spent in queue for canister message before executing it in seconds.",
                // Buckets: 0s, 0.1s, 0.2s, 0.5s, ..., 500 seconds
                decimal_buckets_with_zero(-1, 2),
                &["message_type"],
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
    ///     "speed": "fast",
    /// })
    ///
    /// Example 2: An unsuccessful call to ic00::install_code is observed as:
    /// subnet_message({
    ///     "method_name": "ic00_install_code",
    ///     "outcome": "error",
    ///     "status": "CanisterContractViolation",
    ///     "speed": "slow",
    /// })
    ///
    /// Example 3: A call to a non-existing method is observed as:
    /// subnet_message({
    ///     "method_name": "unknown_method",
    ///     "outcome": "error",
    ///     "status": "CanisterMethodNotFound",
    ///     "speed": "unknown_speed",
    /// })
    pub fn observe_subnet_message<T>(
        &self,
        method_name: &str,
        duration: f64,
        res: &Result<T, ErrorCode>,
    ) {
        let (outcome_label, status_label) = match res {
            Ok(_) => (FINISHED_OUTCOME_LABEL.into(), SUCCESS_STATUS_LABEL.into()),
            Err(err_code) => (ERROR_OUTCOME_LABEL.into(), format!("{:?}", err_code)),
        };

        self.observe_message_with_label(method_name, duration, outcome_label, status_label)
    }

    /// Helper function to observe the duration and count of subnet messages.
    pub(crate) fn observe_message_with_label(
        &self,
        method_name: &str,
        duration: f64,
        outcome_label: String,
        status_label: String,
    ) {
        let (method_name_label, speed_label) = match ic00::Method::from_str(method_name) {
            Ok(method_name) => {
                let speed_label = match method_name {
                    ic00::Method::CanisterStatus
                    | ic00::Method::CanisterInfo
                    | ic00::Method::CreateCanister
                    | ic00::Method::DeleteCanister
                    | ic00::Method::DepositCycles
                    | ic00::Method::RawRand
                    | ic00::Method::SetupInitialDKG
                    | ic00::Method::StartCanister
                    | ic00::Method::UninstallCode
                    | ic00::Method::ECDSAPublicKey
                    | ic00::Method::SchnorrPublicKey
                    | ic00::Method::UpdateSettings
                    | ic00::Method::BitcoinGetBalance
                    | ic00::Method::BitcoinGetUtxos
                    | ic00::Method::BitcoinGetBlockHeaders
                    | ic00::Method::BitcoinSendTransaction
                    | ic00::Method::BitcoinGetCurrentFeePercentiles
                    | ic00::Method::NodeMetricsHistory
                    | ic00::Method::FetchCanisterLogs
                    | ic00::Method::ProvisionalCreateCanisterWithCycles
                    | ic00::Method::ProvisionalTopUpCanister
                    | ic00::Method::UploadChunk
                    | ic00::Method::StoredChunks
                    | ic00::Method::ClearChunkStore
                    | ic00::Method::TakeCanisterSnapshot
                    | ic00::Method::LoadCanisterSnapshot
                    | ic00::Method::ListCanisterSnapshots
                    | ic00::Method::DeleteCanisterSnapshot => String::from("fast"),

                    // "Slow" management methods that might require several execution
                    // rounds to be completed, either due to using DTS or due to
                    // having to wait for consensus to produce a response.
                    // Any method that does not fall into the above category should
                    // be considered "fast".
                    ic00::Method::InstallCode
                    | ic00::Method::InstallChunkedCode
                    | ic00::Method::StopCanister
                    | ic00::Method::HttpRequest
                    | ic00::Method::SignWithECDSA
                    | ic00::Method::SignWithSchnorr
                    | ic00::Method::ComputeInitialIDkgDealings
                    | ic00::Method::BitcoinSendTransactionInternal
                    | ic00::Method::BitcoinGetSuccessors => String::from("slow"),
                };
                (format!("ic00_{}", method_name), speed_label)
            }
            Err(_) => (
                String::from("unknown_method"),
                String::from("unknown_speed"),
            ),
        };

        self.subnet_messages
            .with_label_values(&[
                &method_name_label,
                &outcome_label,
                &status_label,
                &speed_label,
            ])
            .observe(duration);
    }

    pub fn observe_call_id_without_install_code_call_error_counter(
        &self,
        log: &ReplicaLogger,
        call_id: InstallCodeCallId,
        canister_id: CanisterId,
    ) {
        self.call_id_without_install_code_call.inc();
        error!(
            log,
            "[EXC-BUG] Could not find any install code call for the specified call ID {} for canister {} after the execution of install code",
            call_id,
            canister_id,
        );
    }
}
