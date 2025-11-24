use crate::message_routing::{
    ApiBoundaryNodes, CRITICAL_ERROR_INDUCT_RESPONSE_FAILED, MessageRoutingMetrics, NodePublicKeys,
};
use crate::routing::demux::Demux;
use crate::routing::stream_builder::StreamBuilder;
use ic_config::execution_environment::Config as HypervisorConfig;
use ic_interfaces::execution_environment::{
    ExecutionRoundSummary, ExecutionRoundType, RegistryExecutionSettings, Scheduler,
};
use ic_interfaces::time_source::system_time_now;
use ic_logger::{ReplicaLogger, error, fatal};
use ic_query_stats::deliver_query_stats;
use ic_registry_subnet_features::SubnetFeatures;
use ic_replicated_state::{NetworkTopology, ReplicatedState};
use ic_types::batch::{Batch, BatchContent, BatchMessages};
use ic_types::{Cycles, ExecutionRound, NumBytes};
use std::time::Instant;

#[cfg(test)]
mod tests;

const PHASE_INDUCTION: &str = "induction";
const PHASE_EXECUTION: &str = "execution";
const PHASE_MESSAGE_ROUTING: &str = "message_routing";
const PHASE_TIME_OUT_CALLBACKS: &str = "time_out_callbacks";
const PHASE_TIME_OUT_MESSAGES: &str = "time_out_messages";
const PHASE_SHED_MESSAGES: &str = "shed_messages";

pub(crate) trait StateMachine: Send {
    fn execute_round(
        &self,
        state: ReplicatedState,
        network_topology: NetworkTopology,
        batch: Batch,
        subnet_features: SubnetFeatures,
        registry_settings: &RegistryExecutionSettings,
        node_public_keys: NodePublicKeys,
        api_boundary_nodes: ApiBoundaryNodes,
    ) -> ReplicatedState;
}
pub(crate) struct StateMachineImpl {
    scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
    demux: Box<dyn Demux>,
    stream_builder: Box<dyn StreamBuilder>,
    best_effort_message_memory_capacity: NumBytes,
    log: ReplicaLogger,
    metrics: MessageRoutingMetrics,
}

impl StateMachineImpl {
    pub(crate) fn new(
        scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
        demux: Box<dyn Demux>,
        stream_builder: Box<dyn StreamBuilder>,
        hypervisor_config: HypervisorConfig,
        log: ReplicaLogger,
        metrics: MessageRoutingMetrics,
    ) -> Self {
        Self {
            scheduler,
            demux,
            stream_builder,
            best_effort_message_memory_capacity: hypervisor_config
                .best_effort_message_memory_capacity,
            log,
            metrics,
        }
    }

    /// Adds an observation to the `METRIC_PROCESS_BATCH_PHASE_DURATION`
    /// histogram for the given phase.
    fn observe_phase_duration(&self, phase: &str, since: &Instant) {
        self.metrics
            .process_batch_phase_duration
            .with_label_values(&[phase])
            .observe(since.elapsed().as_secs_f64());
    }
}

impl StateMachine for StateMachineImpl {
    fn execute_round(
        &self,
        mut state: ReplicatedState,
        network_topology: NetworkTopology,
        mut batch: Batch,
        subnet_features: SubnetFeatures,
        registry_settings: &RegistryExecutionSettings,
        node_public_keys: NodePublicKeys,
        api_boundary_nodes: ApiBoundaryNodes,
    ) -> ReplicatedState {
        let since = Instant::now();

        let batch_messages = match batch.content {
            BatchContent::Data(batch_messages) => batch_messages,
            BatchContent::Splitting { .. } => BatchMessages::default(),
        };

        // Get query stats from blocks and add them to the state, so that they can be aggregated later.
        if let Some(query_stats) = &batch_messages.query_stats {
            deliver_query_stats(
                query_stats,
                &mut state,
                &self.log,
                &self.metrics.query_stats_metrics,
            );
        }

        if batch.time > state.metadata.batch_time {
            state.metadata.batch_time = batch.time;
        } else {
            // Batch time did not advance. This is a bug. (Implicitly) retain the old batch time.
            self.metrics.observe_non_increasing_batch_time(
                &self.log,
                state.metadata.batch_time,
                batch.time,
                batch.batch_number,
            )
        }

        state.metadata.network_topology = network_topology;
        state.metadata.own_subnet_features = subnet_features;
        state.metadata.node_public_keys = node_public_keys;
        state.metadata.api_boundary_nodes = api_boundary_nodes;
        if let Err(message) = state.metadata.init_allocation_ranges_if_empty() {
            self.metrics
                .observe_no_canister_allocation_range(&self.log, message);
        }

        // Time out expired messages.
        //
        // Preservation of cycles is validated (in debug builds) here for timing out and
        // below for routing + shedding. Validation for induction is only done for each
        // inducted message separately, as doing it for induction as a whole would
        // require detailed accounting of GC-ed and rejected messages.
        #[cfg(debug_assertions)]
        let balance_before_time_out = state.balance_with_messages();

        state.time_out_messages(&self.metrics);
        self.observe_phase_duration(PHASE_TIME_OUT_MESSAGES, &since);

        // Time out expired callbacks.
        let since = Instant::now();
        let (timed_out_callbacks, errors) = state.time_out_callbacks();
        self.metrics
            .timed_out_callbacks_total
            .inc_by(timed_out_callbacks as u64);
        for error in errors {
            // Critical error, responses should always be inducted successfully.
            error!(
                self.log,
                "{}: Inducting deadline expired response failed: {}",
                CRITICAL_ERROR_INDUCT_RESPONSE_FAILED,
                error
            );
            self.metrics.critical_error_induct_response_failed.inc();
        }
        #[cfg(debug_assertions)]
        state.assert_balance_with_messages(balance_before_time_out);

        self.observe_phase_duration(PHASE_TIME_OUT_CALLBACKS, &since);

        // Preprocess messages and add messages to the induction pool through the Demux.
        let since = Instant::now();

        let mut state_with_messages = self.demux.process_payload(state, batch_messages);
        // Batch creation time is essentially wall time (on some replica), so the median
        // duration should be meaningful.
        self.metrics.induct_batch_latency.observe(
            system_time_now()
                .saturating_duration_since(batch.time)
                .as_secs_f64(),
        );

        // Append additional responses to the consensus queue.
        state_with_messages
            .consensus_queue
            .append(&mut batch.consensus_responses);

        self.observe_phase_duration(PHASE_INDUCTION, &since);

        let since = Instant::now();
        let execution_round_type = if batch.requires_full_state_hash {
            ExecutionRoundType::CheckpointRound
        } else {
            ExecutionRoundType::OrdinaryRound
        };

        // Process messages from the induction pool through the Scheduler.
        let round_summary = batch.batch_summary.map(|b| ExecutionRoundSummary {
            next_checkpoint_round: ExecutionRound::from(b.next_checkpoint_height.get()),
            current_interval_length: ExecutionRound::from(b.current_interval_length.get()),
        });
        let state_after_execution = self.scheduler.execute_round(
            state_with_messages,
            batch.randomness,
            batch.chain_key_data,
            &batch.replica_version,
            ExecutionRound::from(batch.batch_number.get()),
            round_summary,
            execution_round_type,
            registry_settings,
        );

        if !state_after_execution.consensus_queue.is_empty() {
            fatal!(
                self.log,
                "Consensus queue not empty at the end of round {:?}.",
                batch.batch_number
            )
        }

        self.observe_phase_duration(PHASE_EXECUTION, &since);

        let since = Instant::now();
        #[cfg(debug_assertions)]
        let balance_before_routing = state_after_execution.balance_with_messages();
        // Postprocess the state: route messages into streams.
        let mut state_after_stream_builder =
            self.stream_builder.build_streams(state_after_execution);
        self.observe_phase_duration(PHASE_MESSAGE_ROUTING, &since);

        let since = Instant::now();
        // Shed enough messages to stay below the best-effort message memory limit.
        state_after_stream_builder.enforce_best_effort_message_limit(
            self.best_effort_message_memory_capacity,
            &self.metrics,
        );
        #[cfg(debug_assertions)]
        state_after_stream_builder.assert_balance_with_messages(balance_before_routing);
        self.observe_phase_duration(PHASE_SHED_MESSAGES, &since);

        // Take out all refunds from the refund pool and observe them as lost cycles.
        //
        // Refunds are currently not routed to streams (this will be implemented in a
        // follow-up change). Therefore, we "lose" them here, so they don't accumulate
        // forever.
        if !state_after_stream_builder.refunds().is_empty() {
            let mut lost_cycles = Cycles::new(0);
            state_after_stream_builder.take_refunds(|refund| {
                lost_cycles += refund.amount();
                true
            });
            state_after_stream_builder.observe_lost_cycles_due_to_dropped_messages(lost_cycles);
        }

        state_after_stream_builder
    }
}
