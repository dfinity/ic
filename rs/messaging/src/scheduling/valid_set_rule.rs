use ic_base_types::NumBytes;
use ic_cycles_account_manager::{CyclesAccountManager, IngressInductionCost};
use ic_error_types::{ErrorCode, UserError};
use ic_interfaces::{
    execution_environment::IngressHistoryWriter,
    messaging::{
        IngressInductionError, LABEL_VALUE_CANISTER_METHOD_NOT_FOUND,
        LABEL_VALUE_CANISTER_NOT_FOUND, LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
        LABEL_VALUE_CANISTER_STOPPED, LABEL_VALUE_CANISTER_STOPPING,
        LABEL_VALUE_INGRESS_HISTORY_FULL, LABEL_VALUE_INVALID_MANAGEMENT_PAYLOAD,
    },
};
use ic_limits::{INGRESS_HISTORY_MAX_MESSAGES, SMALL_APP_SUBNET_MAX_SIZE};
use ic_logger::{ReplicaLogger, debug, error, trace};
use ic_management_canister_types_private::CanisterStatusType;
use ic_metrics::{MetricsRegistry, buckets::decimal_buckets, buckets::linear_buckets};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Time,
    ingress::{IngressState, IngressStatus},
    messages::{
        HttpRequestContent, Ingress, ParseIngressError, SignedIngress,
        extract_effective_canister_id,
    },
    time::expiry_time_from_now,
};
use prometheus::{Histogram, HistogramVec, IntCounterVec, IntGauge};
use std::sync::Arc;

struct VsrMetrics {
    /// Counts of ingress message induction attempts, by status.
    inducted_ingress_messages: IntCounterVec,
    /// Successfully inducted ingress message payload sizes.
    inducted_ingress_payload_sizes: Histogram,
    /// Latency of inducting an ingress message, by induction status.
    /// The latency metric is unreliable because we assume expiry time
    /// was set by 'expiry_time'.
    unreliable_induct_ingress_message_duration: HistogramVec,
    /// Memory currently used by payloads of statuses in the ingress
    /// history.
    ingress_history_size: IntGauge,
}

const METRIC_INDUCTED_INGRESS_MESSAGES: &str = "mr_inducted_ingress_message_count";
const METRIC_INDUCTED_INGRESS_PAYLOAD_SIZES: &str = "mr_inducted_ingress_payload_size_bytes";
const METRIC_UNRELIABLE_INDUCT_INGRESS_MESSAGE_DURATION: &str =
    "mr_unreliable_induct_ingress_message_duration_seconds";
const METRIC_INGRESS_HISTORY_SIZE: &str = "mr_ingress_history_size_bytes";

const LABEL_STATUS: &str = "status";

const LABEL_VALUE_SUCCESS: &str = "success";
const LABEL_VALUE_DUPLICATE: &str = "duplicate";

impl VsrMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        let inducted_ingress_messages = metrics_registry.int_counter_vec(
            METRIC_INDUCTED_INGRESS_MESSAGES,
            "Counts of ingress message induction attempts, by status.",
            &[LABEL_STATUS],
        );
        let inducted_ingress_payload_sizes = metrics_registry.histogram(
            METRIC_INDUCTED_INGRESS_PAYLOAD_SIZES,
            "Successfully inducted ingress message payload sizes.",
            // 10 B - 5 MB
            decimal_buckets(1, 6),
        );
        let unreliable_induct_ingress_message_duration = metrics_registry.histogram_vec(
            METRIC_UNRELIABLE_INDUCT_INGRESS_MESSAGE_DURATION,
            "Latency of inducting an ingress message, by induction status.",
            linear_buckets(0.0, 0.5, 20),
            &[LABEL_STATUS],
        );
        let ingress_history_size = metrics_registry.int_gauge(
            METRIC_INGRESS_HISTORY_SIZE,
            "Memory currently used by payloads of statuses in the ingress history",
        );

        // Initialize all `inducted_ingress_messages` counters with zero, so they are
        // all exported from process start (`IntCounterVec` is really a map).
        for status in &[
            LABEL_VALUE_SUCCESS,
            LABEL_VALUE_DUPLICATE,
            LABEL_VALUE_CANISTER_NOT_FOUND,
            LABEL_VALUE_INGRESS_HISTORY_FULL,
            LABEL_VALUE_CANISTER_STOPPED,
            LABEL_VALUE_CANISTER_STOPPING,
            LABEL_VALUE_CANISTER_OUT_OF_CYCLES,
            LABEL_VALUE_CANISTER_METHOD_NOT_FOUND,
            LABEL_VALUE_INVALID_MANAGEMENT_PAYLOAD,
        ] {
            inducted_ingress_messages.with_label_values(&[status]);
        }

        Self {
            inducted_ingress_messages,
            inducted_ingress_payload_sizes,
            unreliable_induct_ingress_message_duration,
            ingress_history_size,
        }
    }
}

pub(crate) trait ValidSetRule: Send {
    /// Inducts the provided messages into the ReplicatedState.
    fn induct_messages(&self, state: &mut ReplicatedState, msgs: Vec<SignedIngress>);
}

pub(crate) struct ValidSetRuleImpl<
    IngressHistoryWriter_: IngressHistoryWriter<State = ReplicatedState>,
> {
    ingress_history_writer: Arc<IngressHistoryWriter_>,
    ingress_history_max_messages: usize,
    cycles_account_manager: Arc<CyclesAccountManager>,
    metrics: VsrMetrics,
    log: ReplicaLogger,
}

impl<IngressHistoryWriter_: IngressHistoryWriter<State = ReplicatedState>>
    ValidSetRuleImpl<IngressHistoryWriter_>
{
    pub(crate) fn new(
        ingress_history_writer: Arc<IngressHistoryWriter_>,
        cycles_account_manager: Arc<CyclesAccountManager>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            ingress_history_writer,
            ingress_history_max_messages: INGRESS_HISTORY_MAX_MESSAGES,
            metrics: VsrMetrics::new(metrics_registry),
            cycles_account_manager,
            log,
        }
    }

    /// Tries to induct a single ingress message and sets the message status in
    /// `state` accordingly (to `Received` if successful; or to `Failed` with
    /// the relevant error code on failure).
    fn induct_message(&self, state: &mut ReplicatedState, msg: SignedIngress, subnet_size: usize) {
        trace!(self.log, "induct_message");
        let ingress_content = msg.content();
        let message_id = ingress_content.id();
        let source = ingress_content.sender();
        let receiver = ingress_content.canister_id();
        let payload_bytes = ingress_content.arg().len();
        let time = state.time();
        let ingress_expiry = ingress_content.ingress_expiry();

        let status = match self.enqueue(state, msg, subnet_size) {
            Ok(()) => {
                self.observe_inducted_ingress_payload_size(payload_bytes);
                self.ingress_history_writer.set_status(
                    state,
                    message_id,
                    IngressStatus::Known {
                        receiver: receiver.get(),
                        user_id: source,
                        time,
                        state: IngressState::Received,
                    },
                );
                LABEL_VALUE_SUCCESS
            }
            Err(err) => {
                if let IngressInductionError::CanisterNotFound(canister_id) = &err {
                    error!(
                        self.log,
                        "Failed to induct message: canister does not exist";
                        messaging.message_id => format!("{}", message_id),
                        messaging.canister_id => format!("{}", canister_id),
                    );
                }
                let error_code = ErrorCode::from(&err);
                self.ingress_history_writer.set_status(
                    state,
                    message_id,
                    IngressStatus::Known {
                        receiver: receiver.get(),
                        user_id: source,
                        time,
                        state: IngressState::Failed(UserError::new(error_code, err.to_string())),
                    },
                );
                err.to_label_value()
            }
        };
        self.observe_inducted_ingress_status(status);
        self.observe_unreliable_induct_ingress_message_duration(status, ingress_expiry);
    }

    /// Checks whether the given message has already been inducted.
    fn is_duplicate(&self, state: &ReplicatedState, msg: &SignedIngress) -> bool {
        state.get_ingress_status(&msg.content().id()) != &IngressStatus::Unknown
    }

    /// Records the result of inducting an ingress message.
    fn observe_inducted_ingress_status(&self, status: &str) {
        self.metrics
            .inducted_ingress_messages
            .with_label_values(&[status])
            .inc();
    }

    /// Records the size of a successfully inducted ingress message payload.
    fn observe_inducted_ingress_payload_size(&self, bytes: usize) {
        self.metrics
            .inducted_ingress_payload_sizes
            .observe(bytes as f64);
    }

    /// Records the (unreliably) estimated duration to induct one ingress
    /// message.
    fn observe_unreliable_induct_ingress_message_duration(
        &self,
        status: &str,
        ingress_expiry: Time,
    ) {
        let delta_in_nanos = expiry_time_from_now().saturating_duration_since(ingress_expiry);
        self.metrics
            .unreliable_induct_ingress_message_duration
            .with_label_values(&[status])
            .observe(delta_in_nanos.as_secs_f64());
    }

    /// Records the memory currently used for the ingress history.
    fn observe_ingress_history_size(&self, bytes: NumBytes) {
        self.metrics.ingress_history_size.set(bytes.get() as i64);
    }

    // Enqueues an ingress message into input queues.
    fn enqueue(
        &self,
        state: &mut ReplicatedState,
        signed_ingress: SignedIngress,
        subnet_size: usize,
    ) -> Result<(), IngressInductionError> {
        if state.metadata.own_subnet_type != SubnetType::System
            && state.metadata.ingress_history.len() >= self.ingress_history_max_messages
        {
            return Err(IngressInductionError::IngressHistoryFull {
                capacity: self.ingress_history_max_messages,
            });
        }

        let msg = signed_ingress.content();

        let effective_canister_id = match extract_effective_canister_id(msg) {
            Ok(effective_canister_id) => effective_canister_id,
            Err(ParseIngressError::UnknownSubnetMethod) => {
                return Err(IngressInductionError::CanisterMethodNotFound(
                    msg.method_name().to_string(),
                ));
            }
            Err(ParseIngressError::SubnetMethodNotAllowed) => {
                return Err(IngressInductionError::SubnetMethodNotAllowed(
                    msg.method_name().to_string(),
                ));
            }
            Err(ParseIngressError::InvalidSubnetPayload(_)) => {
                return Err(IngressInductionError::InvalidManagementPayload);
            }
        };

        // Compute the cost of induction.
        let cost_schedule = state.get_own_cost_schedule();
        let induction_cost = self.cycles_account_manager.ingress_induction_cost(
            &signed_ingress,
            effective_canister_id,
            subnet_size,
            cost_schedule,
        );

        let ingress = Ingress::from((signed_ingress.take_content(), effective_canister_id));
        match induction_cost {
            IngressInductionCost::Free => {
                // Only subnet methods can be free. These are enqueued directly.
                assert!(ingress.is_addressed_to_subnet());
                state.push_ingress(ingress)
            }

            IngressInductionCost::Fee { payer, cost } => {
                // Get the paying canister from the state.
                let canister = match state.canister_states.get_mut(&payer) {
                    Some(canister) => canister,
                    None => return Err(IngressInductionError::CanisterNotFound(payer)),
                };

                // Withdraw cost of inducting the message.
                let memory_usage = canister.memory_usage();
                let message_memory_usage = canister.message_memory_usage();
                let compute_allocation = canister.scheduler_state.compute_allocation;
                let reveal_top_up = canister.controllers().contains(&ingress.source.get());
                if let Err(err) = self.cycles_account_manager.charge_ingress_induction_cost(
                    canister,
                    memory_usage,
                    message_memory_usage,
                    compute_allocation,
                    cost,
                    subnet_size,
                    cost_schedule,
                    reveal_top_up,
                ) {
                    return Err(IngressInductionError::CanisterOutOfCycles(err));
                }

                // Ensure the canister is running if the message isn't to a subnet.
                if !ingress.is_addressed_to_subnet() {
                    match canister.status() {
                        CanisterStatusType::Running => {}
                        CanisterStatusType::Stopping => {
                            return Err(IngressInductionError::CanisterStopping(
                                canister.canister_id(),
                            ));
                        }
                        CanisterStatusType::Stopped => {
                            return Err(IngressInductionError::CanisterStopped(
                                canister.canister_id(),
                            ));
                        }
                    }
                }

                state.push_ingress(ingress)
            }
        }
    }
}

impl<IngressHistoryWriter_: IngressHistoryWriter<State = ReplicatedState>> ValidSetRule
    for ValidSetRuleImpl<IngressHistoryWriter_>
{
    fn induct_messages(&self, state: &mut ReplicatedState, msgs: Vec<SignedIngress>) {
        let subnet_size = state
            .metadata
            .network_topology
            .get_subnet_size(&state.metadata.own_subnet_id)
            .unwrap_or(SMALL_APP_SUBNET_MAX_SIZE);
        for msg in msgs {
            let message_id = msg.content().id();
            if !self.is_duplicate(state, &msg) {
                self.induct_message(state, msg, subnet_size);
            } else {
                self.observe_inducted_ingress_status(LABEL_VALUE_DUPLICATE);
                debug!(self.log, "Didn't induct duplicate message {}", message_id);
            }
        }
        self.observe_ingress_history_size(state.total_ingress_memory_taken());
    }
}

#[cfg(test)]
mod test;
