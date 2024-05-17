use ic_config::execution_environment::Config;
use ic_error_types::{ErrorCode, RejectCode};
use ic_interfaces::execution_environment::{
    IngressHistoryError, IngressHistoryReader, IngressHistoryWriter,
};
use ic_interfaces_state_manager::{StateManagerError, StateReader};
use ic_logger::{fatal, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_replicated_state::ReplicatedState;
use ic_types::{ingress::IngressState, ingress::IngressStatus, messages::MessageId, Height, Time};
use prometheus::{Histogram, HistogramVec};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Struct that implements the ingress history reader trait. Consumers of this
/// trait can use this to inspect the ingress history.
pub struct IngressHistoryReaderImpl {
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
}

impl IngressHistoryReaderImpl {
    pub fn new(state_reader: Arc<dyn StateReader<State = ReplicatedState>>) -> Self {
        Self { state_reader }
    }
}

impl IngressHistoryReader for IngressHistoryReaderImpl {
    fn get_latest_status(&self) -> Box<dyn Fn(&MessageId) -> IngressStatus> {
        let history = self
            .state_reader
            .get_latest_state()
            .take()
            .get_ingress_history()
            .clone();
        Box::new(move |message_id| {
            history
                .get(message_id)
                .cloned()
                .unwrap_or(IngressStatus::Unknown)
        })
    }

    fn get_status_at_height(
        &self,
        height: Height,
    ) -> Result<Box<dyn Fn(&MessageId) -> IngressStatus>, IngressHistoryError> {
        let labeled_state = self
            .state_reader
            .get_state_at(height)
            .map_err(|e| match e {
                StateManagerError::StateRemoved(h) => IngressHistoryError::StateRemoved(h),
                StateManagerError::StateNotCommittedYet(h) => {
                    IngressHistoryError::StateNotAvailableYet(h)
                }
            })?;
        let history = labeled_state.take().get_ingress_history().clone();
        Ok(Box::new(move |message_id| {
            history
                .get(message_id)
                .cloned()
                .unwrap_or(IngressStatus::Unknown)
        }))
    }
}

/// Records the Internet Computer time and system time of an event.
/// This allows us to see what the difference is between the IC's view of how
/// long something took to complete, and the replica's view (based on "realtime
/// clock" or "absolute time").
struct TransitionStartTime {
    ic_time: Time,
    system_time: Instant,
}

/// Struct that implements the ingress history writer trait. Consumers of this
/// trait can use this to update the ingress history.
pub struct IngressHistoryWriterImpl {
    config: Config,
    log: ReplicaLogger,
    // Wrapped in a RwLock for interior mutability, otherwise &self in methods
    // has to be &mut self.
    received_time: RwLock<HashMap<MessageId, TransitionStartTime>>,
    message_state_transition_completed_ic_duration_seconds: Histogram,
    message_state_transition_completed_wall_clock_duration_seconds: Histogram,
    message_state_transition_failed_ic_duration_seconds: HistogramVec,
    message_state_transition_failed_wall_clock_duration_seconds: HistogramVec,
}

impl IngressHistoryWriterImpl {
    pub fn new(config: Config, log: ReplicaLogger, metrics_registry: &MetricsRegistry) -> Self {
        Self {
            config,
            log,
            received_time: RwLock::new(HashMap::new()),
            message_state_transition_completed_ic_duration_seconds: metrics_registry.histogram(
                "message_state_transition_completed_ic_duration_seconds",
                "The IC time taken for a message to transition from the Received state to Completed state",
                // 100μs, 200μs, 500μs, ..., 10s, 20s, 50s
                decimal_buckets(-4, 1),
            ),
            message_state_transition_completed_wall_clock_duration_seconds: metrics_registry.histogram(
                "message_state_transition_completed_wallclock_duration_seconds",
                "The wall-clock time taken for a message to transition from the Received state to Completed state",
                // 100μs, 200μs, 500μs, ..., 10s, 20s, 50s
                decimal_buckets(-4, 1),
            ),
            message_state_transition_failed_ic_duration_seconds: metrics_registry.histogram_vec(
                "message_state_transition_failed_ic_duration_seconds",
                "The IC time taken for a message to transition from the Received state to Failed state",
                // 100μs, 200μs, 500μs, ..., 10s, 20s, 50s
                decimal_buckets(-4, 1),
                // The `reject_code` label corresponds to the rejection codes described in
                // the public spec.
                // The `user_error_code` label is internal information that provides more
                // detail about the reason for rejection.
                &["reject_code", "user_error_code"],
            ),
            message_state_transition_failed_wall_clock_duration_seconds: metrics_registry.histogram_vec(
                "message_state_transition_failed_wall_clock_duration_seconds",
                "The wall-clock time taken for a message to transition from the Received state to Failed state",
                // 100μs, 200μs, 500μs, ..., 10s, 20s, 50s
                decimal_buckets(-4, 1),
                // The `reject_code` label corresponds to the rejection codes described in
                // the public spec.
                // The `user_error_code` label is internal information that provides more
                // detail about the reason for rejection.
                &["reject_code", "user_error_code"],
            )
        }
    }
}

impl IngressHistoryWriter for IngressHistoryWriterImpl {
    type State = ReplicatedState;

    fn set_status(&self, state: &mut Self::State, message_id: MessageId, status: IngressStatus) {
        let time = state.time();
        let current_status = state.get_ingress_status(&message_id);

        // Guard against an invalid state transition
        if !current_status.is_valid_state_transition(&status) {
            fatal!(
                self.log,
                "message (id='{}', current_status='{:?}') cannot be transitioned to '{:?}'",
                message_id,
                current_status,
                status
            );
        }
        use IngressState::*;
        use IngressStatus::*;
        match &status {
            Known {
                state: Received, ..
            } => {
                let mut map = self.received_time.write().unwrap();
                map.insert(
                    message_id.clone(),
                    TransitionStartTime {
                        ic_time: time,
                        system_time: Instant::now(),
                    },
                );
            }
            Known {
                state: Completed(_),
                ..
            } => {
                if let Some((ic_duration, wall_duration)) =
                    self.calculate_durations(&message_id, time)
                {
                    self.message_state_transition_completed_ic_duration_seconds
                        .observe(ic_duration);
                    self.message_state_transition_completed_wall_clock_duration_seconds
                        .observe(wall_duration);
                }
            }
            Known {
                state: Failed(user_error),
                ..
            } => {
                if let Some((ic_duration, wall_duration)) =
                    self.calculate_durations(&message_id, time)
                {
                    let user_error_code = user_error.code();
                    let reject_code = RejectCode::from(user_error_code).to_string();
                    let user_error_code_string = dashboard_label_value_from(user_error_code);

                    self.message_state_transition_failed_ic_duration_seconds
                        .with_label_values(&[&reject_code, user_error_code_string])
                        .observe(ic_duration);

                    self.message_state_transition_failed_wall_clock_duration_seconds
                        .with_label_values(&[&reject_code, user_error_code_string])
                        .observe(wall_duration);
                }
            }
            _ => {}
        };

        state.set_ingress_status(
            message_id,
            status,
            self.config.ingress_history_memory_capacity,
        );
    }
}

impl IngressHistoryWriterImpl {
    /// Return an Option<(ic_time_duration, wall_clock_duration)>.
    fn calculate_durations(&self, message_id: &MessageId, time: Time) -> Option<(f64, f64)> {
        let mut map = self.received_time.write().unwrap();
        map.remove(message_id).map(|timer| {
            (
                (time.saturating_duration_since(timer.ic_time)).as_secs_f64(),
                timer.system_time.elapsed().as_secs_f64(),
            )
        })
    }
}

fn dashboard_label_value_from(code: ErrorCode) -> &'static str {
    use ErrorCode::*;
    // Caution! These values are inserted in to monitoring labels and are used
    // to aggregate data on monitoring dashboards. If you plan to change one
    // of these values you will need to plan to change dashboards as well.
    match code {
        // 1xx -- `RejectCode::SysFatal`
        SubnetOversubscribed => "Subnet Oversubscribed",
        MaxNumberOfCanistersReached => "Max Number of Canisters Reached",
        // 2xx -- `RejectCode::SysTransient`
        CanisterQueueFull => "Canister Queue Full",
        IngressMessageTimeout => "Ingress Message Timeout",
        CanisterQueueNotEmpty => "Canister Queues Not Empty",
        IngressHistoryFull => "Ingress History Full",
        CanisterIdAlreadyExists => "Canister ID already exists",
        StopCanisterRequestTimeout => "Stop canister request timed out",
        CanisterOutOfCycles => "Canister Out Of Cycles",
        CertifiedStateUnavailable => "Certified State Unavailable",
        CanisterInstallCodeRateLimited => {
            "Canister is rate limited because it executed too many instructions \
                in the previous install_code messages"
        }
        CanisterHeapDeltaRateLimited => "Canister Heap Delta Rate Limited",
        // 3xx -- `RejectCode::DestinationInvalid`
        CanisterNotFound => "Canister Not Found",
        CanisterSnapshotNotFound => "Canister Snapshot Not Found",
        // 4xx -- `RejectCode::CanisterReject`
        InsufficientMemoryAllocation => "Insufficient memory allocation given to canister",
        InsufficientCyclesForCreateCanister => "Insufficient Cycles for Create Canister Request",
        SubnetNotFound => "Subnet not found",
        CanisterNotHostedBySubnet => "Canister is not hosted by subnet",
        CanisterRejectedMessage => "Canister rejected the message",
        UnknownManagementMessage => "Unknown management method",
        InvalidManagementPayload => "Invalid management message payload",
        // 5xx -- `RejectCode::CanisterError`
        CanisterTrapped => "Canister Trapped",
        CanisterCalledTrap => "Canister Called Trap",
        CanisterContractViolation => "Canister Contract Violation",
        CanisterInvalidWasm => "Canister Invalid Wasm",
        CanisterDidNotReply => "Canister Did Not Reply",
        CanisterOutOfMemory => "Canister Out Of Memory",
        CanisterStopped => "Canister Stopped",
        CanisterStopping => "Canister Stopping",
        CanisterNotStopped => "Canister Not Stopped",
        CanisterStoppingCancelled => "Canister Stopping Cancelled",
        CanisterInvalidController => "Canister Invalid Controller",
        CanisterFunctionNotFound => "Canister Function Not Found",
        CanisterNonEmpty => "Canister Non-Empty",
        QueryCallGraphLoopDetected => "Loop in inter-canister query call graph",
        InsufficientCyclesInCall => "Canister tried to keep more cycles than available in the call",
        CanisterWasmEngineError => "Wasm engine error",
        CanisterInstructionLimitExceeded => {
            "Canister exceeded the instruction limit for single message execution"
        }

        CanisterMemoryAccessLimitExceeded => {
            "Canister exceeded the limit for the number of modified stable memory pages \
                for a single message execution"
        }
        QueryCallGraphTooDeep => "Query call graph contains too many nested calls",
        QueryCallGraphTotalInstructionLimitExceeded => {
            "Total instructions limit exceeded for query call graph"
        }
        CompositeQueryCalledInReplicatedMode => {
            "Composite query cannot be called in replicated mode"
        }
        QueryTimeLimitExceeded => "Canister exceeded the time limit for composite query execution",
        QueryCallGraphInternal => "System error while executing a composite query",
        InsufficientCyclesInComputeAllocation => {
            "Canister does not have enough cycles to increase its compute allocation"
        }
        InsufficientCyclesInMemoryAllocation => {
            "Canister does not have enough cycles to increase its memory allocation"
        }
        InsufficientCyclesInMemoryGrow => "Canister does not have enough cycles to grow memory",
        ReservedCyclesLimitExceededInMemoryAllocation => {
            "Canister cannot increase memory allocation due to its reserved cycles limit"
        }
        ReservedCyclesLimitExceededInMemoryGrow => {
            "Canister cannot grow memory due to its reserved cycles limit"
        }
        InsufficientCyclesInMessageMemoryGrow => {
            "Canister does not have enough cycles to grow message memory"
        }
        CanisterMethodNotFound => "Canister Method Not Found",
        CanisterWasmModuleNotFound => "Canister Wasm Module Not Found",
        CanisterAlreadyInstalled => "Canister Already Installed",
        CanisterWasmMemoryLimitExceeded => "Canister exceeded its Wasm memory limit",
    }
}
