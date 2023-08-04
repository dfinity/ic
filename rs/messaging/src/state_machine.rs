use crate::message_routing::{MessageRoutingMetrics, NodePublicKeys};
use crate::routing::{demux::Demux, stream_builder::StreamBuilder};
use ic_interfaces::execution_environment::{
    ExecutionRoundType, RegistryExecutionSettings, Scheduler,
};
use ic_logger::{fatal, ReplicaLogger};
use ic_metrics::Timer;
use ic_registry_subnet_features::SubnetFeatures;
use ic_replicated_state::{NetworkTopology, ReplicatedState};
use ic_types::{batch::Batch, ExecutionRound};
use std::sync::Arc;

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
    ) -> ReplicatedState;
}
pub(crate) struct StateMachineImpl {
    scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
    demux: Box<dyn Demux>,
    stream_builder: Box<dyn StreamBuilder>,
    log: ReplicaLogger,
    metrics: Arc<MessageRoutingMetrics>,
}

impl StateMachineImpl {
    pub(crate) fn new(
        scheduler: Box<dyn Scheduler<State = ReplicatedState>>,
        demux: Box<dyn Demux>,
        stream_builder: Box<dyn StreamBuilder>,
        log: ReplicaLogger,
        metrics: Arc<MessageRoutingMetrics>,
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
    fn observe_phase_duration(&self, phase: &str, timer: &Timer) {
        self.metrics
            .process_batch_phase_duration
            .with_label_values(&[phase])
            .observe(timer.elapsed());
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
    ) -> ReplicatedState {
        let phase_timer = Timer::start();

        state.metadata.batch_time = batch.time;
        state.metadata.network_topology = network_topology;
        state.metadata.own_subnet_features = subnet_features;
        state.metadata.node_public_keys = node_public_keys;
        if let Err(message) = state.metadata.init_allocation_ranges_if_empty() {
            self.metrics
                .observe_no_canister_allocation_range(&self.log, message);
        }

        if !state.consensus_queue.is_empty() {
            fatal!(
                self.log,
                "Consensus queue not empty at the beginning of round {:?}.",
                batch.batch_number
            )
        }

        // Time out requests.
        let timed_out_requests = state.time_out_requests(batch.time);
        self.metrics
            .timed_out_requests_total
            .inc_by(timed_out_requests);
        self.observe_phase_duration(PHASE_TIME_OUT_REQUESTS, &phase_timer);

        // Preprocess messages and add messages to the induction pool through the Demux.
        let phase_timer = Timer::start();
        let mut state_with_messages = self.demux.process_payload(state, batch.messages);

        // Append additional responses to the consensus queue.
        state_with_messages
            .consensus_queue
            .append(&mut batch.consensus_responses);

        self.observe_phase_duration(PHASE_INDUCTION, &phase_timer);

        let execution_round_type = if batch.requires_full_state_hash {
            ExecutionRoundType::CheckpointRound
        } else {
            ExecutionRoundType::OrdinaryRound
        };

        let phase_timer = Timer::start();
        // Process messages from the induction pool through the Scheduler.
        let state_after_execution = self.scheduler.execute_round(
            state_with_messages,
            batch.randomness,
            batch.ecdsa_subnet_public_keys,
            ExecutionRound::from(batch.batch_number.get()),
            execution_round_type,
            registry_settings,
        );
        self.observe_phase_duration(PHASE_EXECUTION, &phase_timer);

        let phase_timer = Timer::start();
        // Postprocess the state and consolidate the Streams.
        let state_after_stream_builder = self.stream_builder.build_streams(state_after_execution);
        self.observe_phase_duration(PHASE_MESSAGE_ROUTING, &phase_timer);

        state_after_stream_builder
    }
}
