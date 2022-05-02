//! This module is responsible for the loading of DKG transcripts and DKG key
//! removals. It is invoked by the consensus and decides on every run if
//! there is something to do. On high-level, it's responsible of spawning
//! threads triggering long-running CSP operation and book-keeping of
//! thread-handles.
use crate::consensus::{
    pool_reader::PoolReader, prelude::threshold_sig::ni_dkg::NiDkgTranscript, prelude::*,
    ConsensusCrypto,
};
use ic_interfaces::crypto::{LoadTranscriptResult, NiDkgAlgorithm};
use ic_logger::{error, info, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_types::{
    consensus::{dkg::Summary, BlockPayload},
    crypto::threshold_sig::ni_dkg::{
        errors::load_transcript_error::DkgLoadTranscriptError, NiDkgId, NiDkgTag, NiDkgTargetSubnet,
    },
    Height,
};
use prometheus::{HistogramVec, IntCounterVec, IntGauge, IntGaugeVec};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        mpsc::{sync_channel, Receiver},
        Arc,
    },
};

struct Metrics {
    pub dkg_ops_duration: HistogramVec,
    pub dkg_instance_id: IntGaugeVec,
    pub current_committee_size: IntGaugeVec,
    pub consensus_membership_registry_version: IntGauge,
    pub failed_dkg_intervals: IntCounterVec,
}

impl Metrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            dkg_ops_duration: metrics_registry.histogram_vec(
                "consensus_dkg_ops_duration_seconds",
                "The time for the DKG relates operations, in seconds",
                // 0.1ms, 0.2ms, 0.5ms, 1ms, 2ms, 5ms, 10ms, 20ms, 50ms, 100ms, 200ms, 500ms,
                // 1s, 2s, 5s, 10s, 20s, 50s, 100s, 200s, 500s
                decimal_buckets(-4, 2),
                &["type"],
            ),
            dkg_instance_id: metrics_registry.int_gauge_vec(
                "consensus_dkg_instance_id",
                "The instance Id of the current transcript's DKG interval",
                &["tag"],
            ),
            current_committee_size: metrics_registry.int_gauge_vec(
                "consensus_dkg_current_committee_size",
                "The size of the threshold group committee",
                &["tag"],
            ),
            failed_dkg_intervals: metrics_registry.int_counter_vec(
                "consensus_dkg_intervals_failed",
                "The number of failed DKG intervals",
                &["tag"],
            ),
            consensus_membership_registry_version: metrics_registry.int_gauge(
                "consensus_membership_registry_version",
                "The registry version used by consensus for the subnet membership related information.",
            ),
        }
    }
}

/// The `DkgKeyManager` component is responsible for loading `DkgTranscripts` in
/// the background.
/// These variables are used for the book-keeping of transcript loads, according
/// to the following logic:
///  - If the CUP height or the new DKG summary height increases, we'd load the
///    summary' transcripts from the corresponding blocks and update the last
///    seen heights.
///  - Before we start loading a transcript, we check if it is being loaded
///    currently.
///  - On every `on_state_change` execution of the consensus we check the next
///    expected random beacon height and enforce the transcript loads if they
///    are needed.
pub struct DkgKeyManager {
    crypto: Arc<dyn ConsensusCrypto>,
    metrics: Metrics,
    logger: ReplicaLogger,
    last_dkg_summary_height: Option<Height>,
    last_cup_height: Option<Height>,
    pending_transcript_loads: HashMap<
        NiDkgId,
        (
            Height,
            Receiver<Result<LoadTranscriptResult, DkgLoadTranscriptError>>,
        ),
    >,
    // This is a thread handle used to keep track of asynchronous key removals.
    pending_key_removal: Option<std::thread::JoinHandle<()>>,
}

impl DkgKeyManager {
    /// Create a new `DkgKeyManager`
    pub fn new(
        metrics_registry: MetricsRegistry,
        crypto: Arc<dyn ConsensusCrypto>,
        logger: ReplicaLogger,
        pool_reader: &PoolReader<'_>,
    ) -> Self {
        let mut manager = Self {
            crypto,
            metrics: Metrics::new(&metrics_registry),
            logger,
            last_dkg_summary_height: Default::default(),
            last_cup_height: Default::default(),
            pending_transcript_loads: Default::default(),
            pending_key_removal: Default::default(),
        };

        // By calling on state change during initialization, we make sure, that the key store is
        // initialized. Otherwise, other consensus methods would initially fail, and generate warnings.
        manager.on_state_change(pool_reader);

        manager
    }

    pub(crate) fn on_state_change(&mut self, pool_reader: &PoolReader<'_>) {
        // Check and load new transcripts from the latest finalized DKG summary or from
        // a CUP. Note, we keep track of transcripts being loaded and do not
        // load them more than once.
        self.load_transcripts_if_necessary(pool_reader);

        // Checks if there are pending transcript loads, needed for the next random
        // beacon and enforces the loading if necessary.
        self.enforce_transcript_loading(pool_reader);
    }

    /// Checks, whether the transcript should have been loaded already by the
    /// key manager or not, based on the height and it's list of transcript
    /// loadings currently in progress.
    pub fn is_transcript_loaded(&mut self, id: &NiDkgId) -> bool {
        // If the height of the last cup rsp. last summary is smaller than the id, we
        // know for sure, that we have not loaded this transcript
        let last_height = match std::cmp::max(self.last_cup_height, self.last_dkg_summary_height) {
            Some(height) => height,
            None => {
                info!(
                    every_n_seconds => 5,
                    self.logger,
                    "No transcripts have been loaded yet"
                );
                return false;
            }
        };

        if id.start_block_height > last_height && id.target_subnet == NiDkgTargetSubnet::Local {
            info!(
                every_n_seconds => 5,
                self.logger,
                "Transcript can't be loaded yet, last height too low: {:?} {:?}", last_height, id
            );
            return false;
        }

        // Get the receiver
        let rx = match self.pending_transcript_loads.get(id) {
            Some(rx) => &rx.1,
            None => {
                return true;
            }
        };

        // Try to get the loaded transcript
        match rx.try_recv() {
            // NOTE: we don't need to check the LoadTranscriptResult, since returning false here
            // means that the caller will next invoke dealing::create_dealing, so if the
            // key is no longer available, we will find out by then
            Ok(Ok(_)) => {
                // Remove the handle of the loaded transcript
                self.pending_transcript_loads.remove(id);
                true
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => false,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("The dkg key manager thread panicked")
            }
            Ok(Err(err)) => panic!(
                "The DKG transcript with id={:?} couldn't be loaded: {:?}",
                id, err
            ),
        }
    }

    // Inspects the latest CUP height and the height of the latest finalized DKG
    // summary block. If they are newer than what we have seen, triggers the
    // loading of transcripts from corresponding summaries.
    fn load_transcripts_if_necessary(&mut self, pool_reader: &PoolReader<'_>) {
        let _timer = self
            .metrics
            .dkg_ops_duration
            .with_label_values(&["load_transcripts"])
            .start_timer();
        let cache = pool_reader.as_cache();

        // If the height of the latest CUP is higher than what we've seen before,
        // load its transcripts and update the latest seen height.
        let cup = cache.catch_up_package();
        let cup_height = Some(cup.height());
        if self.last_cup_height < cup_height {
            let summary = BlockPayload::from(cup.content.block.into_inner().payload).into_summary();
            self.load_transcripts_from_summary(Arc::new(summary.dkg));
            self.last_cup_height = cup_height;
        }

        // If the height of the latest finalized summary block is higher than what we
        // have seen before, we update the metrics, load the transcripts and update the
        // last seen height.
        let summary_block = cache.summary_block();
        if self.last_dkg_summary_height < Some(summary_block.height) {
            let summary = BlockPayload::from(summary_block.payload).into_summary();
            self.update_dkg_metrics(&summary.dkg);
            let dkg_summary = Arc::new(summary.dkg);
            // Note that the order of these two calls is critical. We remove DKG keys that
            // are no longer relevant by telling the CSP which transcripts are still
            // relevant. However, over time, we may load new transcripts that are relevant.
            // Since deletion blocks on the previous deletion, and we start loading after
            // deletion,  we know that the previous deletion must be completed, and
            // therefore newly loaded transcripts cannot be accidentally deleted.
            //
            // If we would switch the lines, we would start loading the new transcripts in
            // parallel with the previous removal and theoretically we could finish loading
            // the next transcript before the previous removal (which would consider the
            // next transcript key irrelevant and remove it).
            self.delete_inactive_keys(pool_reader);
            self.load_transcripts_from_summary(Arc::clone(&dkg_summary));
            self.last_dkg_summary_height = Some(summary_block.height);
        }
    }

    // Ensures that the pending transcripts are loaded BEFORE they are needed. For
    // that we take the next expected random beacon height and check for every
    // pending transcript load if we hit its deadline. If yes, we join on the
    // thread handle by enforcing its execution if it didn't happen yet or by
    // closing the thread otherwise.
    fn enforce_transcript_loading(&mut self, pool_reader: &PoolReader<'_>) {
        let _timer = self
            .metrics
            .dkg_ops_duration
            .with_label_values(&["enforce_transcripts"])
            .start_timer();
        let next_random_beacon_height = pool_reader.get_random_beacon_height().increment();
        // If there are no expired transcripts, which we expected in the most of rounds,
        // we're done.
        if self
            .pending_transcript_loads
            .iter()
            .all(|(_, (deadline, _))| *deadline > next_random_beacon_height)
        {
            return;
        }
        let (expired, pending): (Vec<_>, _) = self
            .pending_transcript_loads
            .drain()
            .partition(|(_, (deadline, _))| next_random_beacon_height >= *deadline);
        let number_of_transcripts = expired.len();
        info!(
            self.logger,
            "Waiting on {} transcripts to be loaded", number_of_transcripts
        );
        for (id, (_, handle)) in expired {
            match handle.recv() {
                Err(err) => panic!(
                    "Couldn't finish transcript loading with id={:?}: {:?}",
                    id, err
                ),
                Ok(Err(err)) => panic!(
                    "The DKG transcript with id={:?} couldn't be loaded: {:?}",
                    id, err
                ),
                _ => (),
            }
        }
        info!(
            self.logger,
            "Finished waiting on {} transcripts to be loaded", number_of_transcripts,
        );
        // Put the pending loads back.
        self.pending_transcript_loads = pending.into_iter().collect();
    }

    // Gets all available transcripts from a summary (current + next ones) and
    // spawns threads for every transcript load if it's not among transcripts
    // being loaded already. Note this functionality relies on the assumption,
    // that CSP does not re-load transcripts, which were succeffully loaded
    // before.
    fn load_transcripts_from_summary(&mut self, summary: Arc<Summary>) {
        let transcripts_to_load: Vec<_> = {
            let current_interval_start = summary.height;
            let next_interval_start = summary.get_next_start_height();
            // For current transcripts we take the current summary height as a deadline.
            let current_transcripts_with_load_deadlines = summary
                .current_transcripts()
                .iter()
                .filter(|(_, t)| !self.pending_transcript_loads.contains_key(&t.dkg_id))
                .map(|(_, t)| (current_interval_start, t.dkg_id));
            // For next transcripts, we take the start of the next interval as a deadline.
            let next_transcripts_with_load_deadlines = summary
                .next_transcripts()
                .iter()
                .filter(|(_, t)| !self.pending_transcript_loads.contains_key(&t.dkg_id))
                .map(|(_, t)| (next_interval_start, t.dkg_id));

            current_transcripts_with_load_deadlines
                .chain(next_transcripts_with_load_deadlines)
                .collect()
        };

        for (deadline, dkg_id) in transcripts_to_load.into_iter() {
            info!(
                self.logger,
                "Start asynchronously loading the DKG transcript with id={:?}", dkg_id,
            );
            let crypto = self.crypto.clone();
            let logger = self.logger.clone();
            let summary = summary.clone();
            let (tx, rx) = sync_channel(0);
            std::thread::spawn(move || {
                let transcript = summary
                    .current_transcripts()
                    .iter()
                    .chain(summary.next_transcripts().iter())
                    .find(|(_, t)| t.dkg_id == dkg_id)
                    .expect("No transcript was found")
                    .1;

                let result = NiDkgAlgorithm::load_transcript(&*crypto, transcript);
                match &result {
                    Ok(_) => info!(logger, "Finished loading transcript with id={:?}", dkg_id),
                    Err(err) => warn!(
                        logger,
                        "The DKG transcript with id={:?} couldn't be loaded: {:?}", dkg_id, err
                    ),
                }
                tx.send(result)
            });
            self.pending_transcript_loads.insert(dkg_id, (deadline, rx));
        }
    }

    // Ask the CSP to drop DKG key material related to transcripts that are no
    // longer relevant
    fn delete_inactive_keys(&mut self, pool_reader: &PoolReader<'_>) {
        if let Some(handle) = self.pending_key_removal.take() {
            // To make sure we delete all keys sequentially, we check if another key removal
            // is ongoing and if yes, we block until this thread is done. This
            // operation will only actually block, if the previous key removal
            // didn't finish yet. This should never happen in a normal operation
            // mode as we trigger the removal at the start of each DKG interval and
            // such an interval is expected to take significantly longer than the
            // key removal.
            handle
                .join()
                .unwrap_or_else(|err| panic!("Couldn't finish the DKG key removal: {:?}", err));
        }

        // Create list of transcripts that we need to retain, which is all DKG
        // transcripts in the latest CUP and in all subsequent finalized summary blocks.
        let mut transcripts_to_retain: HashSet<NiDkgTranscript> = HashSet::new();
        let mut dkg_summary = Some(
            BlockPayload::from(
                pool_reader
                    .cache
                    .catch_up_package()
                    .content
                    .block
                    .into_inner()
                    .payload,
            )
            .into_summary(),
        );

        while let Some(summary) = dkg_summary {
            let next_summary_height = summary.dkg.get_next_start_height();
            for transcript in summary.dkg.into_transcripts() {
                transcripts_to_retain.insert(transcript);
            }

            dkg_summary = pool_reader
                .get_finalized_block(next_summary_height)
                .map(|b| BlockPayload::from(b.payload).into_summary());
        }

        let crypto = self.crypto.clone();
        let logger = self.logger.clone();
        let handle = std::thread::spawn(move || {
            NiDkgAlgorithm::retain_only_active_keys(&*crypto, transcripts_to_retain)
                .unwrap_or_else(|err| error!(logger, "Could not delete DKG keys: {:?}", err));
        });
        self.pending_key_removal = Some(handle);
    }

    // Uses the provided summary to update the DKG metrics. Should only be used on
    // the summary for the last finalized DKG summary block.
    fn update_dkg_metrics(&self, summary: &Summary) {
        self.metrics
            .consensus_membership_registry_version
            .set(summary.registry_version.get() as i64);
        for tag in [NiDkgTag::LowThreshold, NiDkgTag::HighThreshold].iter() {
            let current_transcript = summary.current_transcript(tag);
            let metric_label = &format!("{:?}", tag);
            self.metrics
                .dkg_instance_id
                .with_label_values(&[metric_label])
                .set(current_transcript.dkg_id.start_block_height.get() as i64);
            self.metrics
                .current_committee_size
                .with_label_values(&[metric_label])
                .set(current_transcript.committee.count().get().into());
            if summary.next_transcript(tag).is_none() && summary.height > Height::from(0) {
                warn!(
                    self.logger,
                    "No new {:?} DKG transcript is available in summary at height {:?}.",
                    tag,
                    summary.height
                );
                self.metrics
                    .failed_dkg_intervals
                    .with_label_values(&[metric_label])
                    .inc();
            }
        }
    }

    /// Joins on all thread handles. It is supposed to be used in testing
    /// only to avoid race conditions and zombie threads.
    pub(crate) fn sync(&mut self) {
        self.pending_transcript_loads
            .drain()
            .for_each(move |(_, (_, handle))| {
                handle
                    .recv()
                    .expect("Failed to sync on the pending transcripts")
                    .expect("Loading of the pending transcripts failed");
            });
        if let Some(handle) = self.pending_key_removal.take() {
            handle.join().expect("Couldn't join on the thread handle.");
        }
    }
}

// We do not need the drop in production scenario, as the replica does not
// support a graceful shutdown, but we need it for tests where the components
// might be dropped.
impl Drop for DkgKeyManager {
    fn drop(&mut self) {
        self.sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::mocks::{dependencies_with_subnet_params, Dependencies};
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::{
        crypto::CryptoReturningOk,
        types::ids::{node_test_id, subnet_test_id},
        with_test_replica_logger,
    };
    use ic_test_utilities_registry::SubnetRecordBuilder;

    #[test]
    fn test_transcripts_get_loaded_and_retained() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let nodes: Vec<_> = (0..1).map(node_test_id).collect();
                let dkg_interval_len = 3;
                let Dependencies { mut pool, .. } = dependencies_with_subnet_params(
                    pool_config,
                    subnet_test_id(222),
                    vec![(
                        1,
                        SubnetRecordBuilder::from(&nodes)
                            .with_dkg_interval_length(dkg_interval_len)
                            .build(),
                    )],
                );
                let csp = Arc::new(CryptoReturningOk::default());
                let mut key_manager = DkgKeyManager::new(
                    MetricsRegistry::new(),
                    csp.clone(),
                    logger,
                    &PoolReader::new(&pool),
                );

                // Emulate the first invocation of the dkg key manager and make sure all
                // transcripts (exactly 2) were loaded from the genesis summary.
                let dkg_summary = BlockPayload::from(pool.get_cache().finalized_block().payload)
                    .into_summary()
                    .dkg;
                assert_eq!(dkg_summary.height, Height::from(0));
                key_manager.on_state_change(&PoolReader::new(&pool));
                key_manager.sync();
                let summary_0_transcripts = dkg_summary
                    .current_transcripts()
                    .values()
                    .chain(dkg_summary.next_transcripts().values())
                    .map(|t| t.dkg_id)
                    .collect::<HashSet<_>>();
                // We expect the genesis summary to contain exactly 2 current transcripts.
                assert_eq!(summary_0_transcripts.len(), 2);
                // All of them should be among the loaded transcripts.
                summary_0_transcripts.iter().for_each(|id| {
                    assert!(csp.loaded_transcripts.read().unwrap().contains(id));
                });
                // Also all of them should be submitted for a retention.
                assert_eq!(
                    csp.retained_transcripts.read().unwrap()[0],
                    summary_0_transcripts
                );

                // Fast-forward to the third summary block.
                // We skip the second block, because our mocked crypto would always return a
                // mocked transcript, even if there are not enough dealings. So in the second
                // block we would have next transcripts with the mocked crypto, but not with the
                // real crypto. Hence we skip this step and repeat the checks for the 3rd
                // summary. We first check in the situation where there is no CUP.
                pool.advance_round_normal_operation_no_cup_n(2 * (dkg_interval_len + 1));
                assert_eq!(
                    pool.get_cache().catch_up_package().height(),
                    Height::from(0)
                );

                let dkg_summary = BlockPayload::from(pool.get_cache().finalized_block().payload)
                    .into_summary()
                    .dkg;
                assert_eq!(dkg_summary.height, Height::from(2 * (dkg_interval_len + 1)));
                let summary_2_transcripts = dkg_summary
                    .current_transcripts()
                    .values()
                    .chain(dkg_summary.next_transcripts().values())
                    .map(|t| t.dkg_id)
                    .collect::<HashSet<_>>();
                // For the 3rd summary we expect 2 current and 2 next transcripts.
                assert_eq!(summary_2_transcripts.len(), 4);
                key_manager.on_state_change(&PoolReader::new(&pool));
                key_manager.sync();
                summary_2_transcripts.iter().for_each(|id| {
                    assert!(csp.loaded_transcripts.read().unwrap().contains(id));
                });
                let retained = csp.retained_transcripts.read().unwrap()[1].clone();
                assert_eq!(
                    retained,
                    summary_2_transcripts
                        .union(&summary_0_transcripts)
                        .cloned()
                        .collect()
                );

                pool.advance_round_normal_operation_n(dkg_interval_len + 1);
                assert_eq!(
                    pool.get_cache().catch_up_package().height(),
                    Height::from(3 * (dkg_interval_len + 1))
                );
                let dkg_summary = BlockPayload::from(pool.get_cache().finalized_block().payload)
                    .into_summary()
                    .dkg;
                assert_eq!(dkg_summary.height, Height::from(3 * (dkg_interval_len + 1)));
                let summary_3_transcripts = dkg_summary
                    .current_transcripts()
                    .values()
                    .chain(dkg_summary.next_transcripts().values())
                    .map(|t| t.dkg_id)
                    .collect::<HashSet<_>>();
                // For the 3rd summary we expect 2 current and 2 next transcripts.
                assert_eq!(summary_3_transcripts.len(), 4);
                key_manager.on_state_change(&PoolReader::new(&pool));
                key_manager.sync();
                summary_3_transcripts.iter().for_each(|id| {
                    assert!(csp.loaded_transcripts.read().unwrap().contains(id));
                });
                let retained = csp.retained_transcripts.read().unwrap()[2].clone();
                assert_eq!(retained, summary_3_transcripts);
            });
        });
    }
}
