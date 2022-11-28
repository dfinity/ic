use crate::message_routing::MessageRoutingMetrics;
use crate::routing::{demux::Demux, stream_builder::StreamBuilder};
use ic_ic00_types::CanisterStatusType;
use ic_interfaces::execution_environment::{
    ExecutionRoundType, RegistryExecutionSettings, Scheduler,
};
use ic_logger::{fatal, warn, ReplicaLogger};
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
const PHASE_REMOVE_CANISTERS: &str = "remove_canisters_not_in_rt";
const PHASE_TIME_OUT_REQUESTS: &str = "time_out_requests";

pub(crate) trait StateMachine: Send {
    fn execute_round(
        &self,
        state: ReplicatedState,
        network_topology: NetworkTopology,
        batch: Batch,
        subnet_features: SubnetFeatures,
        registry_settings: &RegistryExecutionSettings,
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

    /// Removes stopped canisters that are missing from the routing table.
    fn remove_canisters_not_in_routing_table(&self, state: &mut ReplicatedState) {
        let _timer = self
            .metrics
            .process_batch_phase_duration
            .with_label_values(&[PHASE_REMOVE_CANISTERS])
            .start_timer();

        let own_subnet_id = state.metadata.own_subnet_id;

        let ids_to_remove =
            ic_replicated_state::routing::find_canisters_to_remove(&self.log, state, own_subnet_id);

        if ids_to_remove.is_empty() {
            return;
        }

        for canister_id in ids_to_remove.iter() {
            if let Some(canister_state) = state.canister_state(canister_id) {
                if canister_state.status() != CanisterStatusType::Stopped {
                    warn!(
                        self.log,
                        "Skipped removing canister {} in state {} that is not in the routing table",
                        canister_id,
                        canister_state.status()
                    );
                    continue;
                }
            }

            warn!(
                self.log,
                "Removing canister {} that is not in the routing table", canister_id
            );

            state.canister_states.remove(canister_id);
        }
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
    ) -> ReplicatedState {
        let phase_timer = Timer::start();

        let mut metadata = state.system_metadata().clone();
        metadata.batch_time = batch.time;
        metadata.network_topology = network_topology;
        metadata.own_subnet_features = subnet_features;
        if let Err(message) = metadata.init_allocation_ranges_if_empty() {
            self.metrics
                .observe_no_canister_allocation_range(&self.log, message);
        }
        state.set_system_metadata(metadata);

        self.remove_canisters_not_in_routing_table(&mut state);

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
        let mut state_with_messages = self.demux.process_payload(state, batch.payload);

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
