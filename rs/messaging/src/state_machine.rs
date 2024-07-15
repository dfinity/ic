use crate::message_routing::{ApiBoundaryNodes, MessageRoutingMetrics, NodePublicKeys};
use crate::routing::{demux::Demux, stream_builder::StreamBuilder};
use ic_interfaces::execution_environment::{
    ExecutionRoundSummary, ExecutionRoundType, RegistryExecutionSettings, Scheduler,
};
use ic_logger::{fatal, ReplicaLogger};
use ic_query_stats::deliver_query_stats;
use ic_registry_subnet_features::SubnetFeatures;
use ic_replicated_state::{NetworkTopology, ReplicatedState};
use ic_types::{batch::Batch, ExecutionRound};
use std::time::Instant;

#[cfg(test)]
mod tests;

const PHASE_INDUCTION: &str = "induction";
const PHASE_EXECUTION: &str = "execution";
const PHASE_MESSAGE_ROUTING: &str = "message_routing";
const PHASE_TIME_OUT_REQUESTS: &str = "time_out_requests";

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
    log: ReplicaLogger,
    metrics: MessageRoutingMetrics,
}

impl StateMachineImpl {
    pub(crate) fn new(
        scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
        demux: Box<dyn Demux>,
        stream_builder: Box<dyn StreamBuilder>,
        log: ReplicaLogger,
        metrics: MessageRoutingMetrics,
    ) -> Self {
        Self {
            scheduler,
            demux,
            stream_builder,
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

        // Get query stats from blocks and add them to the state, so that they can be aggregated later.
        if let Some(query_stats) = &batch.messages.query_stats {
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

        // Time out requests.
        let timed_out_requests = state.time_out_requests();
        self.metrics
            .timed_out_requests_total
            .inc_by(timed_out_requests);
        self.observe_phase_duration(PHASE_TIME_OUT_REQUESTS, &since);

        // Preprocess messages and add messages to the induction pool through the Demux.
        let since = Instant::now();
        let mut state_with_messages = self.demux.process_payload(state, batch.messages);

        // Append additional responses to the consensus queue.
        state_with_messages
            .consensus_queue
            .append(&mut batch.consensus_responses);

        self.observe_phase_duration(PHASE_INDUCTION, &since);

        let execution_round_type = if batch.requires_full_state_hash {
            ExecutionRoundType::CheckpointRound
        } else {
            ExecutionRoundType::OrdinaryRound
        };

        let since = Instant::now();
        // Process messages from the induction pool through the Scheduler.
        let round_summary = batch.batch_summary.map(|b| ExecutionRoundSummary {
            next_checkpoint_round: ExecutionRound::from(b.next_checkpoint_height.get()),
            current_interval_length: ExecutionRound::from(b.current_interval_length.get()),
        });
        let state_after_execution = self.scheduler.execute_round(
            state_with_messages,
            batch.randomness,
            batch.idkg_subnet_public_keys,
            batch.idkg_pre_signature_ids,
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
        // Postprocess the state and consolidate the Streams.
        let state_after_stream_builder = self.stream_builder.build_streams(state_after_execution);
        self.observe_phase_duration(PHASE_MESSAGE_ROUTING, &since);

        state_after_stream_builder
    }
}
