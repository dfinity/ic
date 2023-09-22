use crossbeam_channel::{Receiver, Sender, TryRecvError, TrySendError};
use ic_interfaces::{
    batch_payload::{BatchPayloadBuilder, PastPayload},
    consensus::PayloadValidationError,
};
use ic_logger::{info, warn, ReplicaLogger};
use ic_types::{
    batch::{EpochStats, QueryStatsPayload, ValidationContext},
    CanisterId, Height, NumBytes, NumInstructions, QueryStatsEpoch,
};
use std::sync::{Mutex, RwLock};

pub fn init_query_stats(log: ReplicaLogger) -> (QueryStatsCollector, QueryStatsPayloadBuilderImpl) {
    let (tx, rx) = crossbeam_channel::bounded(1);
    (
        QueryStatsCollector {
            log: log.clone(),
            current_query_stats: Mutex::new(QueryStatsPayload::default()),
            current_epoch: None,
            sender: tx,
        },
        QueryStatsPayloadBuilderImpl {
            log,
            current_epoch: RwLock::new(None),
            receiver: rx,
        },
    )
}

/// A component that collects statistics for locally executed query calls.
///
/// It makes those stats available to be appended to consensus blocks via
/// the payload builder interface.
pub struct QueryStatsCollector {
    log: ReplicaLogger,
    current_query_stats: Mutex<QueryStatsPayload>,
    current_epoch: Option<QueryStatsEpoch>,
    sender: Sender<EpochStats>,
}

impl QueryStatsCollector {
    pub fn set_epoch(&mut self, new_epoch: QueryStatsEpoch) {
        let Some(previous_epoch) = self.current_epoch else {
            self.current_epoch = Some(new_epoch);
            return;
        };

        if previous_epoch == new_epoch {
            return;
        }

        // Reset locally observed stats for new epoch
        let mut state = self.current_query_stats.lock().unwrap();
        let previous_stats = std::mem::take(&mut *state);

        // Epoch changed, send stats from previous epoch to block maker
        match self.sender.try_send(EpochStats {
            epoch: previous_epoch,
            stats: previous_stats.canister_stats.into_iter().collect(),
        }) {
            Ok(()) => (),
            Err(TrySendError::Full(_)) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "QueryStatsPayloadBuilder has not been called for an entire epoch. \
                    Consensus is likely starving."
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "QueryStatsPayloadBuilder has been dropped. This is a bug"
                );
            }
        }
        self.current_epoch = Some(new_epoch);
    }

    pub fn register_query_statistics(
        &self,
        canister_id: CanisterId,
        num_instructions: NumInstructions,
        ingress_payload_size: u64,
        egress_payload_size: u64,
    ) {
        if self.current_epoch.is_none() {
            info!(
                every_n_seconds => 30,
                self.log,
                "QueryStatsCollector epoch not set - omitting stats for canister {} - num_instructions: {} - payload_size: {}:{}",
                canister_id, num_instructions, ingress_payload_size, egress_payload_size
            );
            return;
        }

        let mut state = self.current_query_stats.lock().unwrap();
        let stats_for_canister = state.canister_stats.entry(canister_id).or_default();

        stats_for_canister.num_calls = stats_for_canister.num_calls.saturating_add(1);
        stats_for_canister.num_instructions = stats_for_canister
            .num_instructions
            .saturating_add(num_instructions.get());
        stats_for_canister.ingress_payload_size = stats_for_canister
            .ingress_payload_size
            .saturating_add(ingress_payload_size);
        stats_for_canister.egress_payload_size = stats_for_canister
            .egress_payload_size
            .saturating_add(egress_payload_size);
    }
}

pub struct QueryStatsPayloadBuilderImpl {
    log: ReplicaLogger,
    current_epoch: RwLock<Option<EpochStats>>,
    receiver: Receiver<EpochStats>,
}

impl BatchPayloadBuilder for QueryStatsPayloadBuilderImpl {
    fn build_payload(
        &self,
        _height: Height,
        _max_size: NumBytes,
        _past_payloads: &[PastPayload],
        _context: &ValidationContext,
    ) -> Vec<u8> {
        match self.receiver.try_recv() {
            Ok(new_epoch) => {
                let mut epoch = self.current_epoch.write().unwrap();
                *epoch = Some(new_epoch);
            }
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => {
                warn!(
                    every_n_seconds => 5,
                    self.log,
                    "QueryStatsCollector has been dropped. This is a bug"
                );
                return vec![];
            }
        }

        let _epoch = self.current_epoch.read().unwrap();

        // TODO: Implement the actual streaming of the epoch stats
        vec![]
    }

    fn validate_payload(
        &self,
        _height: Height,
        _payload: &[u8],
        _past_payloads: &[PastPayload],
        _context: &ValidationContext,
    ) -> Result<(), PayloadValidationError> {
        Ok(())
    }
}
