use crate::message_routing::MessageRoutingMetrics;
use crate::routing::{demux::Demux, stream_builder::StreamBuilder};
use ic_interfaces::execution_environment::Scheduler;
use ic_logger::{fatal, ReplicaLogger};
use ic_metrics::Timer;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_features::SubnetFeatures;
use ic_replicated_state::{NetworkTopology, ReplicatedState};
use ic_types::{batch::Batch, ExecutionRound};
use std::sync::Arc;

#[cfg(test)]
mod tests;

const PHASE_INDUCTION: &str = "induction";
const PHASE_EXECUTION: &str = "execution";
const PHASE_MESSAGE_ROUTING: &str = "message_routing";

pub(crate) trait StateMachine: Send {
    fn execute_round(
        &self,
        state: ReplicatedState,
        network_topology: NetworkTopology,
        batch: Batch,
        provisional_whitelist: ProvisionalWhitelist,
        subnet_features: SubnetFeatures,
        max_number_of_canisters: u64,
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
    /// histgram for the given phase.
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
        batch: Batch,
        provisional_whitelist: ProvisionalWhitelist,
        subnet_features: SubnetFeatures,
        max_number_of_canisters: u64,
    ) -> ReplicatedState {
        let phase_timer = Timer::start();

        let mut metadata = state.system_metadata().clone();
        metadata.batch_time = batch.time;
        metadata.network_topology = network_topology;
        metadata.own_subnet_features = subnet_features;
        state.set_system_metadata(metadata);

        // Preprocess messages and add messages to the induction pool through the Demux.
        let mut state_with_messages = self.demux.process_payload(state, batch.payload);
        if !state_with_messages.consensus_queue.is_empty() {
            fatal!(
                self.log,
                "Consensus queue not empty at the beginning of round {:?}.",
                batch.batch_number
            )
        }
        state_with_messages.consensus_queue = batch.consensus_responses;
        self.observe_phase_duration(PHASE_INDUCTION, &phase_timer);

        let phase_timer = Timer::start();
        // Process messages from the induction pool through the Scheduler.
        let state_after_execution = self.scheduler.execute_round(
            state_with_messages,
            batch.randomness,
            batch.ecdsa_subnet_public_key,
            ExecutionRound::from(batch.batch_number.get()),
            provisional_whitelist,
            max_number_of_canisters,
        );
        self.observe_phase_duration(PHASE_EXECUTION, &phase_timer);

        let phase_timer = Timer::start();
        // Postprocess the state and consolidate the Streams.
        let state_after_stream_builder = self.stream_builder.build_streams(state_after_execution);
        self.observe_phase_duration(PHASE_MESSAGE_ROUTING, &phase_timer);

        state_after_stream_builder
    }
}
