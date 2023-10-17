use crossbeam_channel::{Sender, TrySendError};
use ic_logger::{info, warn, ReplicaLogger};
use ic_types::{
    batch::{CanisterQueryStats, LocalQueryStats, QueryStats},
    CanisterId, NumInstructions, QueryStatsEpoch,
};
use std::collections::BTreeMap;
use std::sync::Mutex;

mod payload_builder;
pub use self::payload_builder::{QueryStatsPayloadBuilderImpl, QueryStatsPayloadBuilderParams};

pub fn init_query_stats(
    log: ReplicaLogger,
) -> (QueryStatsCollector, QueryStatsPayloadBuilderParams) {
    let (tx, rx) = crossbeam_channel::bounded(1);
    (
        QueryStatsCollector {
            log: log.clone(),
            current_query_stats: Mutex::new(BTreeMap::new()),
            current_epoch: None,
            sender: tx,
        },
        QueryStatsPayloadBuilderParams(rx),
    )
}

/// A component that collects statistics for locally executed query calls.
///
/// It makes those stats available to be appended to consensus blocks via
/// the payload builder interface.
pub struct QueryStatsCollector {
    log: ReplicaLogger,
    current_query_stats: Mutex<BTreeMap<CanisterId, QueryStats>>,
    current_epoch: Option<QueryStatsEpoch>,
    sender: Sender<LocalQueryStats>,
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
        match self.sender.try_send(LocalQueryStats {
            epoch: previous_epoch,
            stats: previous_stats
                .into_iter()
                .map(|(canister_id, stats)| CanisterQueryStats { canister_id, stats })
                .collect(),
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
        let stats_for_canister = state.entry(canister_id).or_default();

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
