//! This module is responsible for the loading of DKG transcripts and DKG key
//! removals. It is invoked by the consensus and decides on every run if
//! there is something to do. On high-level, it's responsible of spawning
//! threads triggering long-running CSP operation and book-keeping of
//! thread-handles.
use ic_consensus_utils::{crypto::ConsensusCrypto, pool_reader::PoolReader, subnet_splitting};
use ic_interfaces::crypto::{ErrorReproducibility, LoadTranscriptResult, NiDkgAlgorithm};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, error, info, warn};
use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use ic_types::{
    Height,
    consensus::{
        Block, HasHeight,
        dkg::{DkgSummary, SplittingArgs},
    },
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgTag, NiDkgTargetSubnet, NiDkgTranscript,
        errors::load_transcript_error::DkgLoadTranscriptError,
    },
    replica_config::ReplicaConfig,
};
use prometheus::{HistogramVec, IntCounterVec, IntGauge, IntGaugeVec};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        mpsc::{Receiver, sync_channel},
    },
    time::Instant,
};

use crate::payload_builder::get_post_split_dkg_summary;

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
    registry: Arc<dyn RegistryClient>,
    replica_config: ReplicaConfig,
}

impl DkgKeyManager {
    /// Create a new `DkgKeyManager`
    pub fn new(
        metrics_registry: MetricsRegistry,
        crypto: Arc<dyn ConsensusCrypto>,
        logger: ReplicaLogger,
        pool_reader: &PoolReader<'_>,
        registry: Arc<dyn RegistryClient>,
        replica_config: ReplicaConfig,
    ) -> Self {
        let mut manager = Self {
            crypto,
            metrics: Metrics::new(&metrics_registry),
            logger,
            last_dkg_summary_height: Default::default(),
            last_cup_height: Default::default(),
            pending_transcript_loads: Default::default(),
            pending_key_removal: Default::default(),
            registry,
            replica_config,
        };

        // By calling on state change during initialization, we make sure, that the key store is
        // initialized. Otherwise, other consensus methods would initially fail, and generate warnings.
        manager.on_state_change(pool_reader);

        manager
    }

    /// Check and load new transcripts from the latest finalized DKG summary or from a CUP.
    pub fn on_state_change(&mut self, pool_reader: &PoolReader<'_>) {
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

        if id.start_block_height > last_height && id.target_subnet.is_local() {
            info!(
                every_n_seconds => 5,
                self.logger,
                "Transcript {} can't be loaded yet, last height too low: {:?}", dkg_id_log_msg(id), last_height
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
                "The DKG transcript {} couldn't be loaded: {:?}",
                dkg_id_log_msg(id),
                err
            ),
        }
    }

    /// Inspects the latest CUP height and the height of the latest finalized DKG
    /// summary block. If they are newer than what we have seen, triggers the
    /// loading of transcripts from corresponding summaries.
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
            let block = cup.content.block.into_inner();
            let summary = block.payload.as_ref().as_summary();
            self.load_transcripts_from_summary(&summary.dkg);
            self.last_cup_height = cup_height;
        }

        // If the height of the latest finalized summary block is higher than what we
        // have seen before, we update the metrics, load the transcripts and update the
        // last seen height.
        let summary_block = cache.summary_block();
        if self.last_dkg_summary_height < Some(summary_block.height) {
            let summary = &summary_block.payload.as_ref().as_summary().dkg;

            // If a subnet split is in progress, we load the post-split summary's transcripts in
            // addition to the regular summary's below: they are needed to sign the post-split
            // CUP shares.
            let post_split_summary = match subnet_splitting::is_split_scheduled(&summary_block) {
                None => None,
                Some(scheduled) => match self.get_post_split_summary(&summary_block, scheduled) {
                    Ok(post_split_summary) => {
                        info!(
                            self.logger,
                            "Loading post-split DKG transcripts from summary at height {}",
                            post_split_summary.height
                        );

                        Some(post_split_summary)
                    }
                    Err(err) => {
                        warn!(
                            every_n_seconds => 5,
                            self.logger,
                            "Couldn't compute the post-split DKG summary for the new subnet after the split: {err}"
                        );
                        return;
                    }
                },
            };

            let mut summaries_to_load = vec![summary];
            if let Some(post_split_summary) = &post_split_summary {
                summaries_to_load.push(post_split_summary);
            }

            self.update_dkg_metrics(summary);

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
            //
            // Note that the removal we trigger here still runs in parallel with the loads
            // below, so it is only harmless as long as the set of transcripts it retains is a
            // superset of the ones we are about to load. This is why we hand `summaries_to_load`
            // to `delete_inactive_keys`: for a regular summary it is redundant, but the
            // post-split summary is computed locally and thus invisible to the removal
            // otherwise.
            self.delete_inactive_keys(pool_reader, &summaries_to_load);
            for summary in &summaries_to_load {
                self.load_transcripts_from_summary(summary);
            }

            // Even though we might have actually loaded a summary with higher height (the
            // post-split summary), we still drive the state machine consistently with the if-guard
            // above.
            self.last_dkg_summary_height = Some(summary_block.height);
        }
    }

    fn get_post_split_summary(
        &self,
        summary_block: &Block,
        scheduled: SplittingArgs,
    ) -> Result<DkgSummary, String> {
        let new_subnet_id = subnet_splitting::get_post_split_subnet_assignment(
            self.replica_config.node_id,
            summary_block,
            self.registry.as_ref(),
            scheduled,
        )
        .map_err(|err| {
            format!("Couldn't determine the post-split subnet assignment after the split: {err}")
        })?
        .new_subnet_id;

        get_post_split_dkg_summary(new_subnet_id, self.registry.as_ref(), summary_block)
    }

    /// Ensures that the pending transcripts are loaded BEFORE they are needed. For
    /// that we take the next expected random beacon height and check for every
    /// pending transcript load if we hit its deadline. If yes, we join on the
    /// thread handle by enforcing its execution if it didn't happen yet or by
    /// closing the thread otherwise.
    fn enforce_transcript_loading(&mut self, pool_reader: &PoolReader<'_>) {
        let _timer = self
            .metrics
            .dkg_ops_duration
            .with_label_values(&["enforce_transcripts"])
            .start_timer();
        let next_random_beacon_height = pool_reader.get_random_beacon_height().increment();

        // If there are no expired transcripts, which is expected in the most of the rounds,
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
            "Waiting on {} transcripts to be loaded for height {}",
            number_of_transcripts,
            next_random_beacon_height
        );

        for (id, (_, handle)) in expired {
            match handle.recv() {
                Err(err) => panic!(
                    "Couldn't finish loading transcript {}: {:?}",
                    dkg_id_log_msg(&id),
                    err
                ),
                Ok(Err(err)) => panic!(
                    "Couldn't finish loading transcript {}: {:?}",
                    dkg_id_log_msg(&id),
                    err
                ),
                _ => (),
            }
        }

        info!(
            self.logger,
            "Finished waiting on {} transcripts to be loaded for height {}",
            number_of_transcripts,
            next_random_beacon_height,
        );
        // Put the pending loads back.
        self.pending_transcript_loads = pending.into_iter().collect();
    }

    /// Gets all available transcripts from a summary (current + next ones) and
    /// spawns threads for every transcript load if it's not among transcripts
    /// being loaded already. Note this functionality relies on the assumption,
    /// that CSP does not reload transcripts, which were successfully loaded
    /// before.
    fn load_transcripts_from_summary(&mut self, summary: &DkgSummary) {
        let current_interval_start = summary.height;
        let next_interval_start = summary.get_next_start_height();

        let transcripts_to_load = {
            // For current transcripts we take the current summary height as a deadline.
            let current_transcripts_with_load_deadlines = summary
                .current_transcripts()
                .values()
                .map(|t| (current_interval_start, t));

            // For next transcripts, we take the start of the next interval as a deadline.
            let next_transcripts_with_load_deadlines = summary
                .next_transcripts()
                .values()
                .map(|t| (next_interval_start, t));

            current_transcripts_with_load_deadlines.chain(next_transcripts_with_load_deadlines)
        };

        for (deadline, transcript) in transcripts_to_load {
            if self
                .pending_transcript_loads
                .contains_key(&transcript.dkg_id)
            {
                continue;
            }

            let since = Instant::now();

            let crypto = self.crypto.clone();
            let logger = self.logger.clone();
            let transcript = transcript.clone();
            let (tx, rx) = sync_channel(0);
            self.pending_transcript_loads
                .insert(transcript.dkg_id.clone(), (deadline, rx));

            std::thread::spawn(move || {
                let result = loop {
                    let result = NiDkgAlgorithm::load_transcript(&*crypto, &transcript);
                    let elapsed = since.elapsed().as_secs_f64();

                    match &result {
                        // Key loaded successfully
                        Ok(LoadTranscriptResult::SigningKeyAvailable) => {
                            info!(
                                logger,
                                "Finished loading transcript {} after {}s",
                                dkg_id_log_msg(&transcript.dkg_id),
                                elapsed
                            );
                            break result;
                        }

                        Ok(LoadTranscriptResult::NodeNotInCommittee) => {
                            info!(
                                logger,
                                "Finished loading public parts of transcript {} after {}s\
                                (signing key unavailable since this node is not part of the committee)",
                                dkg_id_log_msg(&transcript.dkg_id),
                                elapsed
                            );
                            break result;
                        }

                        // Arguments passed to crypto are invalid, should never happen
                        Ok(val) => {
                            error!(
                                logger,
                                "Could only load public parts of transcript {} \
                                (signing key unavailable: {:?})",
                                dkg_id_log_msg(&transcript.dkg_id),
                                val
                            );
                            break result;
                        }

                        // Transient error in crypto, log warning and retry
                        Err(err) if !err.is_reproducible() => {
                            warn!(
                                every_n_seconds => 5,
                                logger,
                                "Transcript {} couldn't be loaded: {:?} Retrying...",
                                dkg_id_log_msg(&transcript.dkg_id),
                                err
                            );
                        }

                        // Permanent error in crypto, log error
                        Err(err) => {
                            error!(
                                logger,
                                "Transcript {} couldn't be loaded: {:?}",
                                dkg_id_log_msg(&transcript.dkg_id),
                                err
                            );
                            break result;
                        }
                    }
                };

                tx.send(result).expect("DKG key manager panicked");
            });
        }
    }

    /// Ask the CSP to drop DKG key material related to transcripts that are no
    /// longer relevant.
    ///
    /// The transcripts of `summaries_to_load`, i.e. the summaries whose transcripts the caller
    /// is about to load, are always retained.
    fn delete_inactive_keys(
        &mut self,
        pool_reader: &PoolReader<'_>,
        summaries_to_load: &[&DkgSummary],
    ) {
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
                .expect("Key removal thread panicked unexpectedly");
        }

        // Create list of transcripts that we need to retain, which is all DKG
        // transcripts in the latest CUP and in all subsequent finalized summary blocks.
        let mut transcripts_to_retain: HashSet<NiDkgTranscript> = HashSet::new();
        let mut next_summary_block = Some(
            pool_reader
                .as_cache()
                .catch_up_package()
                .content
                .block
                .into_inner(),
        );

        while let Some(summary_block) = next_summary_block {
            let summary = &summary_block.payload.as_ref().as_summary().dkg;
            insert_transcripts_of(&mut transcripts_to_retain, summary);

            next_summary_block = pool_reader.get_finalized_block(summary.get_next_start_height());
        }

        // The removal below runs concurrently with the loading of the `summaries_to_load`'s
        // transcripts, so they must be part of the retain set.
        for summary in summaries_to_load {
            insert_transcripts_of(&mut transcripts_to_retain, summary);
        }

        let crypto = self.crypto.clone();
        let logger = self.logger.clone();
        let handle = std::thread::spawn(move || {
            match NiDkgAlgorithm::retain_only_active_keys(&*crypto, transcripts_to_retain) {
                Ok(()) => (),
                // If we fail due to a transient error, we simply do nothing.
                // The next delete cycle will remove the keys.
                Err(err) if !err.is_reproducible() => {
                    warn!(
                        logger,
                        "Could not delete DKG keys (Crypto temporarily unavailable): {:?}", err
                    )
                }
                // On a replicated error, we need to log an error
                Err(err) => error!(logger, "Could not delete DKG keys: {:?}", err),
            }
        });
        self.pending_key_removal = Some(handle);
    }

    /// Uses the provided summary to update the DKG metrics. Should only be used on
    /// the summary for the last finalized DKG summary block.
    fn update_dkg_metrics(&self, summary: &DkgSummary) {
        self.metrics
            .consensus_membership_registry_version
            .set(summary.registry_version.get() as i64);

        for (tag, current_transcript) in summary.current_transcripts() {
            let metric_label = &format!("{tag:?}");

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

    /// Joins on all thread handles.
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

impl Drop for DkgKeyManager {
    fn drop(&mut self) {
        self.sync()
    }
}

/// Print the information about a [`NiDkgId`] in a concise way for logging
fn dkg_id_log_msg(id: &NiDkgId) -> String {
    let tag = match &id.dkg_tag {
        NiDkgTag::LowThreshold => "low".to_string(),
        NiDkgTag::HighThreshold => "high".to_string(),
        NiDkgTag::HighThresholdForKey(master_public_key_id) => {
            format!("highForKey({master_public_key_id})")
        }
    };

    // If the target is local (which it is usually), we don't log the target
    let remote = match id.target_subnet {
        NiDkgTargetSubnet::Local => String::from(""),
        NiDkgTargetSubnet::Remote(remote_id) => format!(", remote_target: {remote_id:?}"),
    };

    format!(
        "NiDkgId{{ start_height: {}, threshold: {}{} }}",
        id.start_block_height, tag, remote
    )
}

/// Inserts the current and next transcripts of the given summary into the set, cloning only the
/// transcripts that are not yet present.
///
/// [`HashSet::insert`] takes the value by ownership, so inserting from a reference requires
/// cloning up front — only to find out, after having paid for the clone of a (large)
/// [`NiDkgTranscript`], that an equal value was already present. Checking for presence first
/// avoids that, and duplicates are the common case when collecting the transcripts to retain:
/// the next transcripts of a summary are always the current transcripts of the following
/// summary. The price is that an actually inserted transcript is hashed twice: once by
/// `contains` and once by `insert`.
fn insert_transcripts_of(transcripts: &mut HashSet<NiDkgTranscript>, summary: &DkgSummary) {
    for transcript in summary
        .current_transcripts()
        .values()
        .chain(summary.next_transcripts().values())
    {
        if !transcripts.contains(transcript) {
            transcripts.insert(transcript.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_consensus_mocks::{Dependencies, DependenciesBuilder};
    use ic_crypto_test_utils_crypto_returning_ok::CryptoReturningOk;
    use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests_with_params;
    use ic_metrics::MetricsRegistry;
    use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, InitialNiDkgTranscriptRecord};
    use ic_registry_keys::make_catch_up_package_contents_key;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_registry::SubnetRecordBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id, test_replica_version};
    use ic_types::{
        NodeId, RegistryVersion, SubnetId,
        consensus::{
            BlockPayload, HashedBlock, Payload,
            dkg::{SplittingArgs, SubnetSplittingStatus},
        },
        crypto::crypto_hash,
    };
    use rstest::rstest;
    use std::collections::BTreeMap;

    #[test]
    fn test_transcripts_get_loaded_and_retained() {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let dkg_interval_len = 3;
                let Dependencies {
                    mut pool,
                    registry,
                    replica_config,
                    ..
                } = DependenciesBuilder::new(pool_config, 1)
                    .with_dkg_interval_length(dkg_interval_len)
                    .build();
                let csp = Arc::new(CryptoReturningOk::default());
                let mut key_manager = DkgKeyManager::new(
                    MetricsRegistry::new(),
                    csp.clone(),
                    logger,
                    &PoolReader::new(&pool),
                    registry,
                    replica_config,
                );

                // Emulate the first invocation of the dkg key manager and make sure all
                // transcripts (exactly 2) were loaded from the genesis summary.
                let block = pool.get_cache().finalized_block();
                let dkg_summary = &block.payload.as_ref().as_summary().dkg;
                assert_eq!(dkg_summary.height, Height::from(0));
                key_manager.on_state_change(&PoolReader::new(&pool));
                key_manager.sync();
                let summary_0_transcripts = dkg_summary
                    .current_transcripts()
                    .values()
                    .chain(dkg_summary.next_transcripts().values())
                    .map(|t| t.dkg_id.clone())
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

                let block = pool.get_cache().finalized_block();
                let dkg_summary = &block.payload.as_ref().as_summary().dkg;
                assert_eq!(dkg_summary.height, Height::from(2 * (dkg_interval_len + 1)));
                let summary_2_transcripts = dkg_summary
                    .current_transcripts()
                    .values()
                    .chain(dkg_summary.next_transcripts().values())
                    .map(|t| t.dkg_id.clone())
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
                let block = pool.get_cache().finalized_block();
                let dkg_summary = &block.payload.as_ref().as_summary().dkg;
                assert_eq!(dkg_summary.height, Height::from(3 * (dkg_interval_len + 1)));
                let summary_3_transcripts = dkg_summary
                    .current_transcripts()
                    .values()
                    .chain(dkg_summary.next_transcripts().values())
                    .map(|t| t.dkg_id.clone())
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

    /// Returns the ids of all the current and next transcripts of the given summary.
    fn transcript_ids(summary: &DkgSummary) -> HashSet<NiDkgId> {
        summary
            .current_transcripts()
            .values()
            .chain(summary.next_transcripts().values())
            .map(|transcript| transcript.dkg_id.clone())
            .collect()
    }

    /// The registry version at which the subnet split is scheduled, i.e. the version at which the
    /// CUP contents that the two halves of the split start from are registered.
    const SPLITTING_REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(2);

    /// Verifies that when a subnet split is in progress, the key manager loads the transcripts from
    /// the post-split DKG summary in addition to the current summary's.
    #[rstest]
    // Run the test twice, once with the local node in the source subnet and once with it in the
    // destination subnet.
    #[case::source(true)]
    #[case::destination(false)]
    fn test_subnet_splitting_loads_post_split_transcripts_in_addition(
        #[case] is_source_subnet: bool,
    ) {
        ic_test_utilities::artifact_pool_config::with_test_pool_config(|pool_config| {
            with_test_replica_logger(|logger| {
                let source_subnet_id = subnet_test_id(1);
                let destination_subnet_id = subnet_test_id(2);
                let source_nodes = (0..4).map(node_test_id).collect::<Vec<_>>();
                let destination_nodes = (4..8).map(node_test_id).collect::<Vec<_>>();
                let dkg_interval_len = 3;

                let (local_node_id, local_post_split_subnet_id) = if is_source_subnet {
                    (source_nodes[0], source_subnet_id)
                } else {
                    (destination_nodes[0], destination_subnet_id)
                };

                let Dependencies {
                    mut pool,
                    registry,
                    registry_data_provider,
                    replica_config,
                    ..
                } = DependenciesBuilder::multiple_subnets(
                    pool_config,
                    vec![
                        (
                            1,
                            source_subnet_id,
                            SubnetRecordBuilder::from(&source_nodes)
                                .with_dkg_interval_length(dkg_interval_len)
                                .build(),
                        ),
                        (
                            1,
                            destination_subnet_id,
                            SubnetRecordBuilder::from(&destination_nodes)
                                .with_dkg_interval_length(dkg_interval_len)
                                .build(),
                        ),
                    ],
                )
                .with_replica_config(ReplicaConfig {
                    node_id: local_node_id,
                    // The local node always starts in the source subnet.
                    subnet_id: source_subnet_id,
                    replica_version: test_replica_version(),
                })
                .build();

                // A subnet split registers the CUP contents each half of the split starts from at
                // the registry version at which the split is scheduled. Their transcripts are
                // freshly created for the split, i.e. they are *not* the initial ones registered at
                // genesis, which is what makes loading them observable below.
                let post_split_height = Height::from(2 * (dkg_interval_len + 1));
                let add_post_split_cup_contents = |subnet_id: SubnetId, committee: &[NodeId]| {
                    let transcript_record = |tag: NiDkgTag| {
                        let mut transcript = dummy_transcript_for_tests_with_params(
                            committee.to_vec(),
                            tag.clone(),
                            tag.threshold_for_subnet_of_size(committee.len()) as u32,
                            SPLITTING_REGISTRY_VERSION.get(),
                        );
                        // These are just dummy modifications to uniquely identify transcripts,
                        // they do not reflect how they would actually look like.
                        transcript.dkg_id.start_block_height = post_split_height;
                        transcript.dkg_id.dealer_subnet = subnet_id;
                        InitialNiDkgTranscriptRecord::from(transcript)
                    };

                    registry_data_provider
                        .add(
                            &make_catch_up_package_contents_key(subnet_id),
                            SPLITTING_REGISTRY_VERSION,
                            Some(CatchUpPackageContents {
                                initial_ni_dkg_transcript_low_threshold: Some(transcript_record(
                                    NiDkgTag::LowThreshold,
                                )),
                                initial_ni_dkg_transcript_high_threshold: Some(transcript_record(
                                    NiDkgTag::HighThreshold,
                                )),
                                ..Default::default()
                            }),
                        )
                        .expect("Failed to add the post-split CUP contents");
                };
                add_post_split_cup_contents(source_subnet_id, &source_nodes);
                add_post_split_cup_contents(destination_subnet_id, &destination_nodes);
                registry.update_to_latest_version();

                // Advance dkg_interval_len rounds so the finalized tip is at height
                // dkg_interval_len, stopping just before the next DKG interval boundary.
                pool.advance_round_normal_operation_no_cup_n(dkg_interval_len);

                // Build a DKG summary at the next interval boundary that signals a subnet split.
                let mut splitting_proposal = pool.make_next_block();
                let mut splitting_block = splitting_proposal.content.as_ref().clone();
                let splitting_height = splitting_block.height;
                // Safety-check: the summary block scheduling the split adopts the registry version
                // at which the split was registered, which is the version at which the key manager
                // looks up the post-split CUP contents.
                assert_eq!(
                    splitting_block.context.registry_version,
                    SPLITTING_REGISTRY_VERSION
                );
                let mut splitting_summary = splitting_block.payload.as_ref().as_summary().clone();
                // The current transcripts of this first summary are still the initial ones taken
                // from the registry, which are also the ones the key manager loads from the genesis
                // CUP. Give them a `NiDkgId` of their own, so that we can tell apart which of the
                // summaries the key manager loaded. The next transcripts are locally created, so
                // their ids are distinct already.
                let current_transcripts = splitting_summary
                    .dkg
                    .current_transcripts()
                    .iter()
                    .map(|(tag, transcript)| {
                        let mut transcript = transcript.clone();
                        transcript.dkg_id.start_block_height = splitting_height;
                        (tag.clone(), transcript)
                    })
                    .collect();
                splitting_summary.dkg = splitting_summary
                    .dkg
                    .with_current_transcripts(current_transcripts);

                splitting_summary.dkg.subnet_splitting_status =
                    SubnetSplittingStatus::Scheduled(SplittingArgs {
                        source_subnet_id,
                        destination_subnet_id,
                    });
                splitting_block.payload = Payload::new(
                    crypto_hash,
                    BlockPayload::Summary(splitting_summary.clone()),
                );
                splitting_proposal.content = HashedBlock::new(crypto_hash, splitting_block.clone());
                pool.advance_round_with_block(&splitting_proposal);

                // The local node keeps its registry membership across the split, so the subnet it
                // ends up on is the one it already runs.
                let post_split_summary = get_post_split_dkg_summary(
                    local_post_split_subnet_id,
                    registry.as_ref(),
                    &splitting_block,
                )
                .expect("Couldn't get the post-split summary");
                // Safety-check: the post-split summary should have been produced by the registry,
                // meaning `next_transcripts` should be empty
                assert!(
                    post_split_summary.next_transcripts().is_empty(),
                    "The post-split summary should not contain next transcripts"
                );

                let cup_block = pool
                    .get_cache()
                    .catch_up_package()
                    .content
                    .block
                    .into_inner();
                let genesis_ids = transcript_ids(&cup_block.payload.as_ref().as_summary().dkg);
                let splitting_ids = transcript_ids(&splitting_summary.dkg);
                let post_split_ids = transcript_ids(&post_split_summary);
                // Safety-check: the three sets of transcripts should be disjoint and non-empty,
                // otherwise we can't tell which ones the key manager loaded.
                assert!(
                    !genesis_ids.is_empty()
                        && !splitting_ids.is_empty()
                        && !post_split_ids.is_empty(),
                    "Each summary should reference transcripts of its own"
                );
                assert!(
                    genesis_ids.is_disjoint(&splitting_ids)
                        && genesis_ids.is_disjoint(&post_split_ids)
                        && splitting_ids.is_disjoint(&post_split_ids),
                    "The summaries should reference disjoint sets of transcripts"
                );

                let csp = Arc::new(CryptoReturningOk::default());
                let mut key_manager = DkgKeyManager::new(
                    MetricsRegistry::new(),
                    csp.clone(),
                    logger,
                    &PoolReader::new(&pool),
                    registry,
                    replica_config,
                );
                key_manager.sync();

                // The key manager should set its last seen summary height to the splitting one
                assert_eq!(key_manager.last_dkg_summary_height, Some(splitting_height));

                // The key manager should load the transcripts from the splitting summary as
                // usual, and additionally the transcripts from the post-split one.
                for ids in [&genesis_ids, &splitting_ids, &post_split_ids] {
                    for id in ids {
                        assert!(
                            csp.loaded_transcripts.read().unwrap().contains(id),
                            "Transcript {} should have been loaded",
                            dkg_id_log_msg(id),
                        );
                    }
                }

                // The key removal runs in parallel with the loading, so the transcripts of both
                // loaded summaries must be retained as well, otherwise the keys we just loaded
                // could be deleted right away.
                let retained_transcripts = csp.retained_transcripts.read().unwrap();
                let last_retained = retained_transcripts
                    .last()
                    .expect("The key manager should have asked for a key removal");
                for id in splitting_ids.iter().chain(post_split_ids.iter()) {
                    assert!(
                        last_retained.contains(id),
                        "Transcript {} should have been retained",
                        dkg_id_log_msg(id),
                    );
                }
            });
        });
    }

    #[test]
    fn test_insert_transcripts_of() {
        let transcript = |start_height: u64| {
            let committee = vec![node_test_id(0)];
            let mut transcript = dummy_transcript_for_tests_with_params(
                committee.clone(),
                NiDkgTag::LowThreshold,
                NiDkgTag::LowThreshold.threshold_for_subnet_of_size(committee.len()) as u32,
                /*registry_version=*/ 1,
            );
            // Make the transcripts distinguishable from each other.
            transcript.dkg_id.start_block_height = Height::from(start_height);
            transcript
        };
        let summary = |current: &NiDkgTranscript, next: &NiDkgTranscript| {
            DkgSummary::new(
                /*configs=*/ vec![],
                BTreeMap::from([(NiDkgTag::LowThreshold, current.clone())]),
                BTreeMap::from([(NiDkgTag::LowThreshold, next.clone())]),
                RegistryVersion::from(1),
                /*interval_length=*/ Height::from(0),
                /*next_interval_length=*/ Height::from(0),
                /*height=*/ Height::from(0),
                /*remote_dkg_attempts=*/ BTreeMap::new(),
                SubnetSplittingStatus::NotScheduled,
            )
        };

        let (a, b, c) = (transcript(0), transcript(1), transcript(2));
        let mut set = HashSet::new();

        insert_transcripts_of(&mut set, &summary(&a, &b));
        assert_eq!(set, HashSet::from([a.clone(), b.clone()]));

        // The next transcripts of a summary are the current transcripts of the following one,
        // so the second summary only contributes one new transcript.
        insert_transcripts_of(&mut set, &summary(&b, &c));
        assert_eq!(set, HashSet::from([a, b, c]));
    }
}
