#![allow(dead_code)]
use crate::consensus_pool::{
    InitializablePoolSection, MutablePoolSection, PoolSectionOp, PoolSectionOps,
};
use crate::rocksdb_iterator::{StandaloneIterator, StandaloneSnapshot};
use bincode::{deserialize, serialize};
use byteorder::{BigEndian, ReadBytesExt};
use ic_config::artifact_pool::RocksDBConfig;

use ic_consensus_message::ConsensusMessageHashable;
use ic_interfaces::artifact_pool::ValidatedArtifact;
use ic_interfaces::consensus_pool::{
    HeightIndexedPool, HeightRange, OnlyError, PoolSection, ValidatedConsensusArtifact,
};
use ic_interfaces::crypto::CryptoHashable;
use ic_logger::{info, warn, ReplicaLogger};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    artifact::ConsensusMessageId,
    batch::BatchPayload,
    consensus::{
        catchup::CUPWithOriginalProtobuf,
        certification::{Certification, CertificationMessage, CertificationShare},
        dkg::Dealings,
        BlockProposal, CatchUpPackage, CatchUpPackageShare, ConsensusMessage, ConsensusMessageHash,
        Finalization, FinalizationShare, HasHeight, Notarization, NotarizationShare, Payload,
        RandomBeacon, RandomBeaconShare, RandomTape, RandomTapeShare,
    },
    Height, Time,
};
use rocksdb::{
    compaction_filter::{CompactionFilterFn, Decision},
    ColumnFamilyDescriptor, DBCompressionType, Options, WriteBatch, DB,
};
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::thread::JoinHandle;
use std::{path::Path, sync::Arc};

// Macro that panics when result is not ok, printing the error.
macro_rules! check_ok {
    ($r:expr) => {
        let result = $r;
        assert!(
            result.is_ok(),
            "Fatal error in persistent artifact pool: {:?}",
            result.err().unwrap()
        );
    };
}

// Macro that panics when result is not ok, printing the error,
// and that unwraps the content otherwise.
macro_rules! check_ok_uw {
    ($r:expr) => {
        $r.expect("Fatal error in persistent artifact pool.")
    };
}

// Macro that panics when the option is None, and unwraps it
// otherwise.
macro_rules! check_not_none_uw {
    ($o:expr) => {
        $o.expect("Fatal error in persistent artifact pool. Unexpected None.")
    };
}

/// A shared mutable height, below which all artifacts are purged.
/// It has to be wrapped under Arc due to Send + 'static requirement.
type Watermark = Arc<RwLock<Height>>;

#[derive(Clone, Debug)]
struct PersistentHeightIndexedPoolConfig {
    skip_fsync_for_tests: bool,
    db_path: PathBuf,
    purge_interval: Height,
}

impl PersistentHeightIndexedPoolConfig {
    fn for_consensus(config: RocksDBConfig) -> Self {
        let mut db_path = config.persistent_pool_validated_persistent_db_path;
        db_path.push("consensus");
        Self {
            skip_fsync_for_tests: config.persistent_pool_validated_skip_fsync_for_tests,
            db_path,
            purge_interval: config.persistent_pool_validated_purge_interval,
        }
    }

    fn for_certification(config: RocksDBConfig) -> Self {
        let mut db_path = config.persistent_pool_validated_persistent_db_path;
        db_path.push("certification");
        Self {
            skip_fsync_for_tests: config.persistent_pool_validated_skip_fsync_for_tests,
            db_path,
            purge_interval: config.persistent_pool_validated_purge_interval,
        }
    }
}

/*
impl From<ArtifactPoolConfig> for PersistentHeightIndexedPoolConfig {
    fn from(artifact_pool_config: ArtifactPoolConfig) -> Self {
        Self {
            skip_fsync_for_tests: artifact_pool_config
                .consensus_pool_validated_skip_fsync_for_tests,
            db_path: artifact_pool_config.consensus_pool_validated_persistent_db_path,
            purge_interval: artifact_pool_config.consensus_pool_validated_purge_interval,
        }
    }
}
*/

/// A persistent implementation of PoolSection on RocksDB
/// See: https://docs.rs/crate/rocksdb/latest
///
/// Each artifact type maps to a single column family in RocksDB. Each
/// key is 40 bytes, in which:
/// bytes [0-8[  -> The height of the artifact
/// bytes [8-40[ -> The hash of the artifact
///
/// <<Height, Hash>, Value> entries are transformed to binary format and
/// stored in increasing order of height so that iteration sorted by height
/// and point lookups by height are very efficient.
///
/// Besides efficiency, the main goal of having keys laid out this way
/// and separate column families is to avoid having to perform compactions and
/// to have the ability to change the schema, per-type, later if required.
///
/// Compactions are expensive IO operations that periodically reduce the
/// throughput of the DB and need to be scheduled and monitored, thus making
/// operations harder. These are crucial to maintain performance on LSMT-based
/// stores when insertions/updates occur at random across the keyspace.
///
/// By having each type with it's own column family and storing keys
/// with height first, most of the time we'll be storing in increasing order,
/// meaning compactions won't be needed.
///
/// In the rare cases where we'll be inserting out of order (say inserting
/// two block proposals for the same height, but with different ranks) we
/// might still get away without increasing the level as insertions are
/// buffered in memory (where out-of-orders are unimpactful), before being
/// flushed.
///
/// To keep the ownership model simple, we keep a reference counted pointer
/// to the DB and each iterator over the data that is returned increases the
/// ref count. This allows for iterators to live independently of the pool
/// section they were created from, which makes sense since these iterators
/// are working on an snapshot of the state at the time of creation and
/// do not "see" any changes that happened since then.
pub struct PersistentHeightIndexedPool<T: HasCFInfos> {
    config: PersistentHeightIndexedPoolConfig,
    db: Arc<DB>,
    log: ReplicaLogger,
    // Artifacts below watermark height is obsolete and subject to purge.
    watermark: Watermark,
    // Artifacts below baseline are considered permanently purged. This is
    // to help implement periodical purge based on some height interval.
    baseline: Watermark,
    // compaction_thread holds the JoinHandle of any ongoing compaction work
    // (if any), such that we can wait for completion before dropping this struct.
    compaction_thread: Mutex<Option<JoinHandle<()>>>,
    pool_type: PhantomData<T>,
}

/// To instruct iterator to seek to start or end of a column family.
/// Similar to rocksdb::IteratorMode, but simpler.
enum SeekPos {
    Start,
    End,
}

impl<T: HasCFInfos> PersistentHeightIndexedPool<T> {
    fn new(
        config: PersistentHeightIndexedPoolConfig,
        log: ReplicaLogger,
    ) -> PersistentHeightIndexedPool<T> {
        // Initialize both baseline and watermark to 0.
        // It does not matter if we don't start purging or compaction
        // right away, because we'll get a PurgeBelow action at some point.
        let initial_height = Height::from(0);
        let watermark = Arc::new(RwLock::new(initial_height));
        let baseline = Arc::new(RwLock::new(initial_height));
        // Initialize db options
        let mut db_options = Options::default();
        set_common_db_options(&mut db_options);

        if config.skip_fsync_for_tests {
            db_options.set_use_fsync(false);
        }

        // TODO select compression, memtable format options, etc
        let cfs: Vec<ColumnFamilyDescriptor> = T::infos()
            .iter()
            .map(|cf_info| {
                let mut options = Options::default();
                set_common_db_options(&mut options);
                // Column families use compaction filter to implement purge
                options.set_compaction_filter(
                    "filter_outdated",
                    make_compaction_filter_fn(Arc::clone(&watermark)),
                );
                options.set_disable_auto_compactions(true);
                ColumnFamilyDescriptor::new(cf_info.name, options)
            })
            .collect();

        let path = Path::new(&config.db_path);
        let result = DB::open_cf_descriptors(&db_options, path, cfs);

        match result {
            Ok(db) => PersistentHeightIndexedPool {
                config: config.clone(),
                db: Arc::new(db),
                log,
                watermark,
                baseline,
                compaction_thread: Mutex::new(None),
                pool_type: PhantomData,
            },
            Err(err) => panic!(
                "Error creating persistent pool at: {:?}. Error: {}",
                path, err
            ),
        }
    }

    pub fn purge_below_height(&self, height: Height) {
        *self.watermark.write().unwrap() = height;
        self.check_and_start_compaction_if_needed();
    }

    /// Wait for any compaction work that we started to finish.
    pub fn wait_for_compaction_to_finish(&self) {
        let mut handle = self.compaction_thread.lock().unwrap();
        if let Some(thread) = handle.take() {
            thread
                .join()
                .expect("consensus persistent pool compaction failed.");
        }
    }

    /// Check to see if compactions should be started for column families, and
    /// if so, start them in a separate thread.
    ///
    /// RocksDB already ensures existing compactions have finished before it
    /// starts new ones, so this function does not have to use mutex to be
    /// reentrant. However, it is still desirable to have a big enough purge
    /// interval to avoid running compaction too often.
    fn check_and_start_compaction_if_needed(&self) {
        let baseline = Arc::clone(&self.baseline);
        let watermark = *self.watermark.read().unwrap();
        let baseline_read = *baseline.read().unwrap();
        // always trigger compaction on fresh start (when baseline is 0)
        if baseline_read.get() == 0 || watermark > baseline_read + self.config.purge_interval {
            // Wait to ensure any started compaction threads have finished. Note that we
            // expect this compaction to already have finished, meaning that we
            // do not actually spend any time waiting.
            self.wait_for_compaction_to_finish();

            // Update baseline to ensure this function is not entered again soon.
            *baseline.write().unwrap() = watermark;
            let db = Arc::clone(&self.db);
            let log = self.log.clone();
            let now = std::time::Instant::now();
            let child_thread = std::thread::spawn(move || {
                // Sync in-memory watermark with the persisted watermark
                info!(log, "Compaction has started");
                for info in T::infos().iter() {
                    let min_key = make_min_key(0);
                    let max_key = make_min_key(watermark.get());
                    let cf_handle = check_not_none_uw!(db.cf_handle(info.name));
                    db.compact_range_cf(cf_handle, Some(min_key), Some(max_key));
                }
                info!(
                    log,
                    "Compaction has finished in {}ms",
                    now.elapsed().as_secs_f32() * 1000.0
                );
            });
            // track the compaction thread such that we can ensure it finishes before
            // dropping this struct
            let mut handle = self.compaction_thread.lock().unwrap();
            handle.replace(child_thread);
        }
    }

    /// Returns the height of the first element returned by the iterator built
    /// with 'iterator_mode'.
    fn get_first_height(&self, info: &ArtifactCFInfo, pos: SeekPos) -> Option<Height> {
        let cf_handle = check_not_none_uw!(self.db.cf_handle(info.name));
        let mut read_options = rocksdb::ReadOptions::default();
        read_options.set_total_order_seek(true);
        // We use raw iterator in order to avoid having to memcpy both key and value.
        let mut iter = self.db.raw_iterator_cf_opt(cf_handle, read_options);

        match pos {
            SeekPos::Start => iter.seek_to_first(),
            SeekPos::End => iter.seek_to_last(),
        }

        iter.key().map(|key| {
            let (height, _) = decompose_key(key);
            Height::new(height)
        })
    }

    /// WARNING: USE ONLY WHEN NECESSARY
    /// Due to the internal implementation of RocksDB iterators, this function
    /// takes time proportional to the number of deleted but not flushed
    /// `Message`s. In practice, this means this function takes longer to
    /// complete as time goes on.
    pub fn min_height<Message: PerTypeCFInfo>(&self) -> Option<Height> {
        self.get_first_height(&Message::info(), SeekPos::Start)
            .map(|h| h.max(*self.watermark.read().unwrap()))
    }

    pub fn max_height<Message: PerTypeCFInfo>(&self) -> Option<Height> {
        self.get_first_height(&Message::info(), SeekPos::End)
            .and_then(|h| {
                if h < *self.watermark.read().unwrap() {
                    None
                } else {
                    Some(h)
                }
            })
    }

    /// Returns the key to use for looking up the given consensus message
    fn lookup_key(&self, msg_id: &ConsensusMessageId) -> Option<Vec<u8>> {
        let key = make_key(msg_id.height.get(), &msg_id.hash.digest().0);
        let watermark = make_min_key(self.watermark.read().unwrap().get());
        if key < watermark {
            // Skip read if key is below watermark
            None
        } else {
            Some(key)
        }
    }
}

impl<T: HasCFInfos> Drop for PersistentHeightIndexedPool<T> {
    fn drop(&mut self) {
        self.wait_for_compaction_to_finish();
    }
}

impl PersistentHeightIndexedPool<ConsensusMessage> {
    pub fn new_consensus_pool(
        config: RocksDBConfig,
        log: ReplicaLogger,
    ) -> PersistentHeightIndexedPool<ConsensusMessage> {
        PersistentHeightIndexedPool::new(
            PersistentHeightIndexedPoolConfig::for_consensus(config),
            log,
        )
    }

    /// Build an iterator that will iterate over the range [min_key, max_key],
    /// inclusive.
    ///
    /// Note that 'min_key', 'max_key' do not have to exists in the DB, they
    /// serve as lower and upper inclusive bounds, respectively.
    ///
    /// The returned iterator works on a snapshot of the DB, meaning it won't
    /// see any updates (insertions and/or removals), that happened to the DB
    /// after it was created.
    ///
    /// The returned iterator has a lifetime that is independent from the pool
    /// itself so that it can be passed around to perform big chunks of work
    /// asynchonously.
    pub fn iterate<Message: ConsensusMessageHashable + PerTypeCFInfo + 'static>(
        &self,
        min_key: &[u8],
        max_key: &[u8],
    ) -> Box<dyn Iterator<Item = Message>> {
        let watermark: &[u8] = &make_min_key(self.watermark.read().unwrap().get());
        if max_key < watermark {
            // Skip when the iterate range is below watermark
            return Box::new(std::iter::empty());
        }
        new_pool_snapshot_iterator(self.db.clone(), min_key.max(watermark), max_key)
    }
}

impl InitializablePoolSection for PersistentHeightIndexedPool<ConsensusMessage> {
    /// Insert a cup with the original bytes from which that cup was received.
    fn insert_cup_with_proto(&self, cup_with_proto: CUPWithOriginalProtobuf) {
        let height = cup_with_proto.cup.height();
        let info = &CATCH_UP_PACKAGE_CF_INFO;
        let key = make_key(height.get(), &cup_with_proto.cup.get_cm_hash().digest().0);
        let cf_handle = check_not_none_uw!(self.db.cf_handle(info.name));
        let artifact = ValidatedArtifact {
            msg: cup_with_proto.protobuf,
            timestamp: cup_with_proto.cup.content.block.as_ref().context.time,
        };
        check_ok_uw!(self
            .db
            .put_cf(cf_handle, key, check_ok_uw!(serialize(&artifact))));
    }
}

impl MutablePoolSection<ValidatedConsensusArtifact>
    for PersistentHeightIndexedPool<ConsensusMessage>
{
    fn mutate(&mut self, ops: PoolSectionOps<ValidatedConsensusArtifact>) {
        let mut batch = WriteBatch::default();
        for op in ops.ops {
            match op {
                PoolSectionOp::Insert(mut artifact) => {
                    let (info, height) = info_and_height_for_msg(&artifact.msg);
                    let key = make_key(height.get(), &artifact.msg.get_cm_hash().digest().0);
                    let cf_handle = check_not_none_uw!(self.db.cf_handle(info.name));
                    // Serialize payload separately. Payload is indexed by the same key
                    // as BlockProposal.
                    match artifact.msg {
                        ConsensusMessage::BlockProposal(mut proposal) => {
                            store_block_payload(self.db.as_ref(), &mut batch, &proposal);
                            // Then store altered proposal with just payload hash.
                            let block = proposal.content.as_mut();
                            let start_height = block.payload.as_ref().dkg_interval_start_height();
                            block.payload = Payload::new_with(
                                block.payload.get_hash().clone(),
                                block.payload.payload_type(),
                                Box::new(move || {
                                    (
                                        BatchPayload::default(),
                                        Dealings::new_empty(start_height),
                                        None,
                                    )
                                        .into()
                                }),
                            );
                            artifact.msg = proposal.into_message();
                            batch.put_cf(cf_handle, key, check_ok_uw!(serialize(&artifact)));
                        }
                        ConsensusMessage::CatchUpPackage(cup) => {
                            let artifact = ValidatedArtifact {
                                msg: pb::CatchUpPackage::from(&cup),
                                timestamp: artifact.timestamp,
                            };
                            batch.put_cf(cf_handle, key, check_ok_uw!(serialize(&artifact)));
                        }
                        _ => {
                            batch.put_cf(cf_handle, key, check_ok_uw!(serialize(&artifact)));
                        }
                    }
                }
                PoolSectionOp::Remove(msg_id) => {
                    let info = info_for_msg_id(&msg_id);
                    let height = msg_id.height.get();
                    let key = make_key(height, &msg_id.hash.digest().0);
                    let cf_handle = check_not_none_uw!(self.db.cf_handle(info.name));
                    match msg_id.hash {
                        ConsensusMessageHash::BlockProposal(_) => {
                            if let Some(bytes) = check_ok_uw!(self.db.get_cf(cf_handle, &key)) {
                                remove_block_payload(self.db.as_ref(), &mut batch, &bytes);
                                batch.delete_cf(cf_handle, key);
                            } else {
                                warn!(
                                    self.log,
                                    "Cannot remove from persistent pool: msg_id not found {:?}",
                                    msg_id
                                );
                            }
                        }
                        _ => {
                            batch.delete_cf(cf_handle, key);
                        }
                    }
                }
                PoolSectionOp::PurgeBelow(height) => self.purge_below_height(height),
            }
        }
        check_ok!(self.db.write(batch));
    }

    fn pool_section(&self) -> &dyn PoolSection<ValidatedConsensusArtifact> {
        self
    }
}

/// Store the payload of a 'BlockProposal' to the payload column family in the
/// DB as part of the given 'WriteBatch'.
fn store_block_payload(db: &DB, batch: &mut WriteBatch, proposal: &BlockProposal) {
    let height = proposal.height();
    let hash = proposal.as_ref().payload.get_hash();
    let uid = &hash.get_ref().0;
    let payload_key = make_key(height.get(), uid);
    let payload = proposal.as_ref().payload.as_ref();
    let cf_handle_payload = check_not_none_uw!(db.cf_handle(BLOCK_PAYLOAD_CF_INFO.name));
    batch.put_cf(
        cf_handle_payload,
        payload_key,
        check_ok_uw!(serialize(payload)),
    );
}

/// Remove the payload of a 'BlockProposal' from the payload column family in
/// the DB as part of the given "WriteBatch'. The 'bytes' parameter refers to
/// the serialized bytes of the 'BlockProposal' whose payload is to be removed.
fn remove_block_payload(db: &DB, batch: &mut WriteBatch, bytes: &[u8]) {
    let artifact: ValidatedConsensusArtifact = check_ok_uw!(deserialize(bytes));
    let proposal = check_not_none_uw!(BlockProposal::assert(&artifact.msg));
    let uid = &proposal.as_ref().payload.get_hash().get_ref().0;
    let payload_key = make_key(proposal.height().get(), uid);
    let cf_handle_payload = check_not_none_uw!(db.cf_handle(BLOCK_PAYLOAD_CF_INFO.name));
    batch.delete_cf(cf_handle_payload, payload_key);
}

fn deserialize_catch_up_package(bytes: &[u8]) -> Option<ValidatedArtifact<pb::CatchUpPackage>> {
    deserialize(bytes).ok()
}

fn deserialize_catch_up_package_fn(
    _: Arc<StandaloneSnapshot<'static>>,
    bytes: &[u8],
) -> Option<ValidatedArtifact<pb::CatchUpPackage>> {
    deserialize_catch_up_package(bytes)
}

/// Deserialize a consensus artifact from from binary bytes. It takes a DB
/// snapshot because additional DB lookup may be necessary (e.g., lazy payload
/// loading).
fn deserialize_consensus_artifact(
    snapshot: Arc<StandaloneSnapshot<'static>>,
    bytes: &[u8],
) -> Option<ValidatedConsensusArtifact> {
    let mut artifact: ValidatedConsensusArtifact = deserialize(bytes).ok().or_else(|| {
        deserialize_catch_up_package(bytes).map(|artifact| ValidatedConsensusArtifact {
            timestamp: artifact.timestamp,
            msg: ConsensusMessage::CatchUpPackage(
                CatchUpPackage::try_from(&artifact.msg)
                    .expect("Conversion from protobuf should not fail"),
            ),
        })
    })?;
    match artifact.msg {
        ConsensusMessage::BlockProposal(mut proposal) => {
            let block = proposal.content.as_mut();
            let hash = block.payload.get_hash();
            let uid = &hash.get_ref().0;
            let key = make_key(block.height().get(), uid);
            block.payload = Payload::new_with(
                hash.clone(),
                block.payload.payload_type(),
                Box::new(move || {
                    let cf_handle_payload =
                        check_not_none_uw!(snapshot.db.cf_handle(BLOCK_PAYLOAD_CF_INFO.name));
                    check_ok_uw!(snapshot.snapshot.get_cf(cf_handle_payload, &key))
                        .and_then(|bytes| deserialize(&bytes).ok())
                        .unwrap_or_else(|| panic!("Failed to deserialize payload: {:?}", key))
                }),
            );
            artifact.msg = proposal.into_message();
            Some(artifact)
        }
        _ => Some(artifact),
    }
}

impl PoolSection<ValidatedConsensusArtifact> for PersistentHeightIndexedPool<ConsensusMessage> {
    fn contains(&self, msg_id: &ConsensusMessageId) -> bool {
        self.lookup_key(msg_id).map_or(false, |key| {
            let info = info_for_msg_id(msg_id);
            let cf_handle = check_not_none_uw!(self.db.cf_handle(info.name));
            check_ok_uw!(self.db.get_pinned_cf(cf_handle, &key)).is_some()
        })
    }

    fn get(&self, msg_id: &ConsensusMessageId) -> Option<ConsensusMessage> {
        self.lookup_key(msg_id).and_then(|key| {
            let info = info_for_msg_id(msg_id);
            let cf_handle = check_not_none_uw!(self.db.cf_handle(info.name));
            let bytes = check_ok_uw!(self.db.get_cf(cf_handle, &key))?;
            deserialize_consensus_artifact(
                Arc::new(StandaloneSnapshot::new(self.db.clone())),
                &bytes,
            )
            .map(|x| x.msg)
        })
    }

    fn get_timestamp(&self, msg_id: &ConsensusMessageId) -> Option<Time> {
        self.lookup_key(msg_id).and_then(|key| {
            let info = info_for_msg_id(msg_id);
            let cf_handle = check_not_none_uw!(self.db.cf_handle(info.name));
            let bytes = check_ok_uw!(self.db.get_cf(cf_handle, &key))?;
            deserialize_consensus_artifact(
                Arc::new(StandaloneSnapshot::new(self.db.clone())),
                &bytes,
            )
            .map(|x| x.timestamp)
        })
    }

    fn random_beacon(&self) -> &dyn HeightIndexedPool<RandomBeacon> {
        self
    }

    fn block_proposal(&self) -> &dyn HeightIndexedPool<BlockProposal> {
        self
    }

    fn notarization(&self) -> &dyn HeightIndexedPool<Notarization> {
        self
    }

    fn finalization(&self) -> &dyn HeightIndexedPool<Finalization> {
        self
    }

    fn random_beacon_share(&self) -> &dyn HeightIndexedPool<RandomBeaconShare> {
        self
    }

    fn notarization_share(&self) -> &dyn HeightIndexedPool<NotarizationShare> {
        self
    }

    fn finalization_share(&self) -> &dyn HeightIndexedPool<FinalizationShare> {
        self
    }

    fn random_tape(&self) -> &dyn HeightIndexedPool<RandomTape> {
        self
    }

    fn random_tape_share(&self) -> &dyn HeightIndexedPool<RandomTapeShare> {
        self
    }

    fn catch_up_package(&self) -> &dyn HeightIndexedPool<CatchUpPackage> {
        self
    }

    fn catch_up_package_share(&self) -> &dyn HeightIndexedPool<CatchUpPackageShare> {
        self
    }

    fn highest_catch_up_package_proto(&self) -> pb::CatchUpPackage {
        let height_opt = self.max_height::<CatchUpPackage>().unwrap();
        let min_height_key = make_min_key(height_opt.get());
        let max_height_key = make_max_key(height_opt.get());
        let mut iter = check_ok_uw!(StandaloneIterator::new(
            self.db.clone(),
            CatchUpPackage::info().name,
            &min_height_key,
            &max_height_key,
            deserialize_catch_up_package_fn
        ));
        iter.next()
            .expect("There must be a catch up package in the pool")
            .msg
    }

    // TODO(CON-308): Implement size()
    fn size(&self) -> u64 {
        0
    }
}

impl<Message: ConsensusMessageHashable + PerTypeCFInfo + 'static> HeightIndexedPool<Message>
    for PersistentHeightIndexedPool<ConsensusMessage>
{
    fn height_range(&self) -> Option<HeightRange> {
        // Either min_height or max_height could be missing due to purging,
        // In this case we should just return None.
        let min_height = self.min_height::<Message>()?;
        let max_height = self.max_height::<Message>()?;
        Some(HeightRange::new(min_height, max_height))
    }

    fn max_height(&self) -> Option<Height> {
        self.max_height::<Message>()
    }

    fn get_all(&self) -> Box<dyn Iterator<Item = Message>> {
        self.iterate(&MIN_KEY, &MAX_KEY)
    }

    fn get_by_height(&self, h: Height) -> Box<dyn Iterator<Item = Message>> {
        self.iterate(&make_min_key(h.get()), &make_max_key(h.get()))
    }

    fn get_only_by_height(&self, h: Height) -> Result<Message, OnlyError> {
        let mut as_vec: Vec<Message> = self.get_by_height(h).collect();
        match as_vec.len() {
            0 => Err(OnlyError::NoneAvailable),
            1 => Ok(as_vec.remove(0)),
            _ => Err(OnlyError::MultipleValues),
        }
    }

    fn get_by_height_range(&self, range: HeightRange) -> Box<dyn Iterator<Item = Message>> {
        self.iterate(
            &make_min_key(range.min.get()),
            &make_max_key(range.max.get()),
        )
    }

    fn get_highest_iter(&self) -> Box<dyn Iterator<Item = Message>> {
        let height_opt = self.max_height::<Message>();
        match height_opt {
            Some(height) => self.get_by_height(height),
            None => Box::new(std::iter::empty()),
        }
    }

    fn get_highest(&self) -> Result<Message, OnlyError> {
        let mut as_vec: Vec<Message> = self.get_highest_iter().collect();
        match as_vec.len() {
            0 => Err(OnlyError::NoneAvailable),
            1 => Ok(as_vec.remove(0)),
            _ => Err(OnlyError::MultipleValues),
        }
    }
}

pub fn new_pool_snapshot_iterator<Message: ConsensusMessageHashable + PerTypeCFInfo>(
    db: Arc<DB>,
    min_key: &[u8],
    max_key: &[u8],
) -> Box<dyn Iterator<Item = Message>> {
    let info = Message::info();
    let iter = check_ok_uw!(StandaloneIterator::new(
        db,
        info.name,
        min_key,
        max_key,
        deserialize_consensus_artifact
    ));

    Box::new(
        iter.map(move |artifact| check_not_none_uw!(Message::assert(artifact.as_ref())).clone()),
    )
}

fn set_common_db_options(options: &mut Options) {
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    options.set_use_fsync(true);
    options.set_compression_type(DBCompressionType::None);
}

/// Make a compaction function that purges everything below the watermark.
fn make_compaction_filter_fn(watermark: Watermark) -> impl CompactionFilterFn + Send + 'static {
    Box::new(move |_level: u32, key: &[u8], _value: &[u8]| {
        let (h, _) = decompose_key(key);
        if h < watermark.read().unwrap().get() {
            Decision::Remove
        } else {
            Decision::Keep
        }
    })
}

/// Encapsulates the information needed to build a ColumnFamilyDescriptor,
/// per type.
#[derive(Clone)]
pub struct ArtifactCFInfo {
    name: &'static str,
}

impl ArtifactCFInfo {
    const fn new(name: &'static str) -> ArtifactCFInfo {
        ArtifactCFInfo { name }
    }
}

/// Trait allowing to specify ArtifactCFInfo per consensus message type, e.g.
/// RandomBeacon or BlockProposal.
pub trait PerTypeCFInfo {
    fn info() -> ArtifactCFInfo;
}

pub trait HasCFInfos {
    fn infos() -> &'static [ArtifactCFInfo];
}

// Initialize the consensus column family infos, one per type and store them in
// an array that is easy to iterate on.
const RANDOM_BEACON_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("RB");
const FINALIZATION_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("FZ");
const NOTARIZATION_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("NZ");
const BLOCK_PROPOSAL_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("BP");
const BLOCK_PAYLOAD_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("PL");
const RANDOM_BEACON_SHARE_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("RBS");
const NOTARIZATION_SHARE_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("NZS");
const FINALIZATION_SHARE_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("FZS");
const RANDOM_TAPE_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("RT");
const RANDOM_TAPE_SHARE_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("RTS");
const CATCH_UP_PACKAGE_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("CUP");
const CATCH_UP_PACKAGE_SHARE_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("CUS");

const CONSENSUS_CF_INFOS: [ArtifactCFInfo; 12] = [
    RANDOM_BEACON_CF_INFO,
    FINALIZATION_CF_INFO,
    NOTARIZATION_CF_INFO,
    BLOCK_PROPOSAL_CF_INFO,
    BLOCK_PAYLOAD_CF_INFO,
    RANDOM_BEACON_SHARE_CF_INFO,
    NOTARIZATION_SHARE_CF_INFO,
    FINALIZATION_SHARE_CF_INFO,
    RANDOM_TAPE_CF_INFO,
    RANDOM_TAPE_SHARE_CF_INFO,
    CATCH_UP_PACKAGE_CF_INFO,
    CATCH_UP_PACKAGE_SHARE_CF_INFO,
];

impl HasCFInfos for ConsensusMessage {
    fn infos() -> &'static [ArtifactCFInfo] {
        &CONSENSUS_CF_INFOS
    }
}

/// Returns the column family info and the height for an artifact
/// based on its type and content.
fn info_and_height_for_msg(msg: &ConsensusMessage) -> (&'static ArtifactCFInfo, Height) {
    match msg {
        ConsensusMessage::RandomBeacon(msg) => (&RANDOM_BEACON_CF_INFO, msg.height()),
        ConsensusMessage::Finalization(msg) => (&FINALIZATION_CF_INFO, msg.height()),
        ConsensusMessage::Notarization(msg) => (&NOTARIZATION_CF_INFO, msg.height()),
        ConsensusMessage::BlockProposal(msg) => (&BLOCK_PROPOSAL_CF_INFO, msg.height()),
        ConsensusMessage::RandomBeaconShare(msg) => (&RANDOM_BEACON_SHARE_CF_INFO, msg.height()),
        ConsensusMessage::NotarizationShare(msg) => (&NOTARIZATION_SHARE_CF_INFO, msg.height()),
        ConsensusMessage::FinalizationShare(msg) => (&FINALIZATION_SHARE_CF_INFO, msg.height()),
        ConsensusMessage::RandomTape(msg) => (&RANDOM_TAPE_CF_INFO, msg.height()),
        ConsensusMessage::RandomTapeShare(msg) => (&RANDOM_TAPE_SHARE_CF_INFO, msg.height()),
        ConsensusMessage::CatchUpPackage(msg) => (&CATCH_UP_PACKAGE_CF_INFO, msg.height()),
        ConsensusMessage::CatchUpPackageShare(msg) => {
            (&CATCH_UP_PACKAGE_SHARE_CF_INFO, msg.height())
        }
    }
}

/// Returns the column family info for a given 'msg_id' based on its type.
fn info_for_msg_id(msg_id: &ConsensusMessageId) -> &ArtifactCFInfo {
    match msg_id.hash {
        ConsensusMessageHash::RandomBeacon(_) => &RANDOM_BEACON_CF_INFO,
        ConsensusMessageHash::Finalization(_) => &FINALIZATION_CF_INFO,
        ConsensusMessageHash::Notarization(_) => &NOTARIZATION_CF_INFO,
        ConsensusMessageHash::BlockProposal(_) => &BLOCK_PROPOSAL_CF_INFO,
        ConsensusMessageHash::RandomBeaconShare(_) => &RANDOM_BEACON_SHARE_CF_INFO,
        ConsensusMessageHash::NotarizationShare(_) => &NOTARIZATION_SHARE_CF_INFO,
        ConsensusMessageHash::FinalizationShare(_) => &FINALIZATION_SHARE_CF_INFO,
        ConsensusMessageHash::RandomTape(_) => &RANDOM_TAPE_CF_INFO,
        ConsensusMessageHash::RandomTapeShare(_) => &RANDOM_TAPE_SHARE_CF_INFO,
        ConsensusMessageHash::CatchUpPackage(_) => &CATCH_UP_PACKAGE_CF_INFO,
        ConsensusMessageHash::CatchUpPackageShare(_) => &CATCH_UP_PACKAGE_SHARE_CF_INFO,
    }
}

impl PerTypeCFInfo for RandomBeacon {
    fn info() -> ArtifactCFInfo {
        RANDOM_BEACON_CF_INFO
    }
}

impl PerTypeCFInfo for Notarization {
    fn info() -> ArtifactCFInfo {
        NOTARIZATION_CF_INFO
    }
}

impl PerTypeCFInfo for Finalization {
    fn info() -> ArtifactCFInfo {
        FINALIZATION_CF_INFO
    }
}

impl PerTypeCFInfo for BlockProposal {
    fn info() -> ArtifactCFInfo {
        BLOCK_PROPOSAL_CF_INFO
    }
}

impl PerTypeCFInfo for RandomBeaconShare {
    fn info() -> ArtifactCFInfo {
        RANDOM_BEACON_SHARE_CF_INFO
    }
}

impl PerTypeCFInfo for NotarizationShare {
    fn info() -> ArtifactCFInfo {
        NOTARIZATION_SHARE_CF_INFO
    }
}

impl PerTypeCFInfo for FinalizationShare {
    fn info() -> ArtifactCFInfo {
        FINALIZATION_SHARE_CF_INFO
    }
}

impl PerTypeCFInfo for RandomTape {
    fn info() -> ArtifactCFInfo {
        RANDOM_TAPE_CF_INFO
    }
}

impl PerTypeCFInfo for RandomTapeShare {
    fn info() -> ArtifactCFInfo {
        RANDOM_TAPE_SHARE_CF_INFO
    }
}

impl PerTypeCFInfo for CatchUpPackage {
    fn info() -> ArtifactCFInfo {
        CATCH_UP_PACKAGE_CF_INFO
    }
}

impl PerTypeCFInfo for CatchUpPackageShare {
    fn info() -> ArtifactCFInfo {
        CATCH_UP_PACKAGE_SHARE_CF_INFO
    }
}

// Constants that indicate the size of the keys and the offsets that separate
// each component of the keys.
//
// Keys are made up of three components:
// - The height (64 bits, 8 bytes).
// - The hash (256 bits, 32 bytes).
//
// For a total of 40 bytes
//
// See: rustdoc on PersistentHeightIndexedPool for more information on keys.
const HASH_POS: usize = 8;
const KEY_SIZE: usize = 8 + 32;

/// MIN_ and MAX_ keys to facilitate building iterators.
const MIN_KEY: [u8; KEY_SIZE] = [0x00; KEY_SIZE];
const MAX_KEY: [u8; KEY_SIZE] = [0xff; KEY_SIZE];

/// Makes a key from a height and a hash (in Vec<u8> form).
fn make_key(height: u64, hash: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_SIZE);
    key.extend(&height.to_be_bytes());
    key.extend(hash);
    key
}

/// Decomposes 'key' into a height (u64) and a hash (Vec<u8>, 32 bytes).
fn decompose_key(key: &[u8]) -> (u64, Vec<u8>) {
    let (mut height, hash) = key.split_at(HASH_POS);
    (
        check_not_none_uw!(height.read_u64::<BigEndian>()),
        hash.to_vec(),
    )
}

/// Builds a key which is the lexicographical minimum for a given height and is
/// guaranteed to be less than or equal to any artifact at that height.
fn make_min_key(height: u64) -> Vec<u8> {
    make_key(height, check_not_none_uw!(&MIN_KEY.get(HASH_POS..KEY_SIZE)))
}

/// Builds a key which is the lexicographical maximum for a given height
/// and is guaranteed to be higher than or equal to all the artifacts at
/// height.
fn make_max_key(height: u64) -> Vec<u8> {
    make_key(height, check_not_none_uw!(&MAX_KEY.get(HASH_POS..KEY_SIZE)))
}

const CERTIFICATION_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("CE");
const CERTIFICATION_SHARE_CF_INFO: ArtifactCFInfo = ArtifactCFInfo::new("CES");

const CERTIFICATION_CF_INFOS: [ArtifactCFInfo; 2] =
    [CERTIFICATION_CF_INFO, CERTIFICATION_SHARE_CF_INFO];

impl HasCFInfos for CertificationMessage {
    fn infos() -> &'static [ArtifactCFInfo] {
        &CERTIFICATION_CF_INFOS
    }
}

impl PerTypeCFInfo for Certification {
    fn info() -> ArtifactCFInfo {
        CERTIFICATION_CF_INFO
    }
}

impl PerTypeCFInfo for CertificationShare {
    fn info() -> ArtifactCFInfo {
        CERTIFICATION_SHARE_CF_INFO
    }
}

fn deserialize_certification_artifact<T: CertificationType + 'static>(
    _: Arc<StandaloneSnapshot<'static>>,
    bytes: &[u8],
) -> Option<T> {
    T::extract(bytes)
}

pub trait CertificationType: Sized {
    fn extract(bytes: &[u8]) -> Option<Self>;
}

impl CertificationType for Certification {
    fn extract(bytes: &[u8]) -> Option<Self> {
        deserialize(bytes).ok()
    }
}

impl CertificationType for CertificationShare {
    fn extract(bytes: &[u8]) -> Option<Self> {
        deserialize(bytes).ok()
    }
}

impl PersistentHeightIndexedPool<CertificationMessage> {
    pub fn new_certification_pool(
        config: RocksDBConfig,
        log: ReplicaLogger,
    ) -> PersistentHeightIndexedPool<CertificationMessage> {
        PersistentHeightIndexedPool::new(
            PersistentHeightIndexedPoolConfig::for_certification(config),
            log,
        )
    }

    pub fn insert_message<
        T: serde::Serialize
            + PerTypeCFInfo
            + CertificationType
            + CryptoHashable
            + ic_types::consensus::HasHeight,
    >(
        &self,
        value: &T,
    ) {
        let info = T::info();
        let key = make_key(value.height().get(), &ic_crypto::crypto_hash(value).get().0);
        let cf_handle = check_not_none_uw!(self.db.cf_handle(info.name));
        check_ok!(self
            .db
            .put_cf(cf_handle, key, check_ok_uw!(serialize(value))));
    }

    pub fn iterate<Message: CertificationType + PerTypeCFInfo + 'static>(
        &self,
        min_key: &[u8],
        max_key: &[u8],
    ) -> Box<dyn Iterator<Item = Message>> {
        Box::new(check_ok_uw!(StandaloneIterator::new(
            self.db.clone(),
            Message::info().name,
            min_key,
            max_key,
            deserialize_certification_artifact
        )))
    }
}

impl crate::certification_pool::MutablePoolSection
    for PersistentHeightIndexedPool<CertificationMessage>
{
    fn insert(&self, message: CertificationMessage) {
        match message {
            CertificationMessage::Certification(value) => self.insert_message(&value),
            CertificationMessage::CertificationShare(value) => self.insert_message(&value),
        }
    }

    fn certifications(&self) -> &dyn HeightIndexedPool<Certification> {
        self
    }

    fn certification_shares(&self) -> &dyn HeightIndexedPool<CertificationShare> {
        self
    }

    fn purge_below(&self, height: Height) {
        self.purge_below_height(height)
    }
}

impl<Message: CertificationType + PerTypeCFInfo + 'static> HeightIndexedPool<Message>
    for PersistentHeightIndexedPool<CertificationMessage>
{
    fn height_range(&self) -> Option<HeightRange> {
        // Either min_height or max_height could be missing due to purging,
        // In this case we should just return None.
        let min_height = self.min_height::<Message>()?;
        let max_height = self.max_height::<Message>()?;
        Some(HeightRange::new(min_height, max_height))
    }

    fn max_height(&self) -> Option<Height> {
        self.max_height::<Message>()
    }

    fn get_all(&self) -> Box<dyn Iterator<Item = Message>> {
        self.iterate(&MIN_KEY, &MAX_KEY)
    }

    fn get_by_height(&self, h: Height) -> Box<dyn Iterator<Item = Message>> {
        self.iterate(&make_min_key(h.get()), &make_max_key(h.get()))
    }

    fn get_only_by_height(&self, h: Height) -> Result<Message, OnlyError> {
        let mut as_vec: Vec<Message> = self.get_by_height(h).collect();
        match as_vec.len() {
            0 => Err(OnlyError::NoneAvailable),
            1 => Ok(as_vec.remove(0)),
            _ => Err(OnlyError::MultipleValues),
        }
    }

    fn get_by_height_range(&self, range: HeightRange) -> Box<dyn Iterator<Item = Message>> {
        self.iterate(
            &make_min_key(range.min.get()),
            &make_max_key(range.max.get()),
        )
    }

    fn get_highest_iter(&self) -> Box<dyn Iterator<Item = Message>> {
        let height_opt = self.max_height::<Message>();
        match height_opt {
            Some(height) => self.get_by_height(height),
            None => Box::new(std::iter::empty()),
        }
    }

    fn get_highest(&self) -> Result<Message, OnlyError> {
        let mut as_vec: Vec<Message> = self.get_highest_iter().collect();
        match as_vec.len() {
            0 => Err(OnlyError::NoneAvailable),
            1 => Ok(as_vec.remove(0)),
            _ => Err(OnlyError::MultipleValues),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use ic_test_utilities::consensus::make_genesis;
    use slog::Drain;
    use std::panic;

    const SLOG_ASYNC_CHAN_SIZE: usize = 10000;

    #[test]
    fn test_encode_decode_key() {
        let height = Height::from(10);
        let genesis_beacon = make_genesis(make_summary(height))
            .content
            .random_beacon
            .into_inner();
        let msg = ConsensusMessage::RandomBeacon(genesis_beacon);
        let hash = msg.get_cm_hash().digest().clone();
        let rb_encoded_key = make_key(height.get(), &hash.0);
        let (rb_height, rb_hash) = decompose_key(&rb_encoded_key);
        assert_eq!(rb_height, 10, "height does not match");
        assert_eq!(&hash.0, &rb_hash, "Hash does not match");
    }

    fn make_logger() -> ReplicaLogger {
        let plain = slog_term::PlainSyncDecorator::new(std::io::stdout());
        let no_stamp = |_: &mut dyn std::io::Write| Ok(());
        let drain = slog_term::FullFormat::new(plain)
            .use_custom_timestamp(no_stamp)
            .build()
            .fuse();
        let drain = slog_async::AsyncCore::custom(slog_envlogger::new(drain))
            .chan_size(SLOG_ASYNC_CHAN_SIZE)
            .build()
            .fuse();
        slog::Logger::root(drain, slog::o!()).into()
    }

    fn destroy(config: &RocksDBConfig) {
        check_ok!(DB::destroy(
            &Options::default(),
            &config.persistent_pool_validated_persistent_db_path,
        ));
    }

    // TODO: Remove this after it is no longer needed
    // Helper to run the persistence tests below.
    // It creates the config and logger that is passed to the instances and then
    // makes sure that the the databases are destroyed before the test fails.
    fn run_persistent_pool_test<T>(_test_name: &str, test: T)
    where
        T: FnOnce(RocksDBConfig, ReplicaLogger) + panic::UnwindSafe,
    {
        ic_test_utilities::artifact_pool_config::with_test_rocksdb_pool_config(|config| {
            let result = panic::catch_unwind(|| test(config.clone(), make_logger()));
            destroy(&config);
            check_ok!(result);
        })
    }

    impl PoolTestHelper for RocksDBConfig {
        type PersistentHeightIndexedPool = PersistentHeightIndexedPool<ConsensusMessage>;

        fn run_persistent_pool_test<T, R>(_test_name: &str, test: T) -> R
        where
            T: FnOnce(RocksDBConfig, ReplicaLogger) -> R + panic::UnwindSafe,
        {
            ic_test_utilities::artifact_pool_config::with_test_rocksdb_pool_config(|config| {
                let result = panic::catch_unwind(|| test(config.clone(), make_logger()));
                destroy(&config);
                assert!(result.is_ok());
                result.unwrap()
            })
        }

        fn new_consensus_pool(self, log: ReplicaLogger) -> Self::PersistentHeightIndexedPool {
            PersistentHeightIndexedPool::new_consensus_pool(self, log)
        }

        fn persistent_pool_validated_persistent_db_path(&self) -> &PathBuf {
            &self.persistent_pool_validated_persistent_db_path
        }
    }

    #[test]
    fn test_as_pool_section() {
        crate::test_utils::test_as_pool_section::<RocksDBConfig>()
    }

    #[test]
    fn test_as_height_indexed_pool() {
        crate::test_utils::test_as_height_indexed_pool::<RocksDBConfig>()
    }

    #[test]
    fn test_block_proposal_and_payload_correspondence() {
        crate::test_utils::test_block_proposal_and_payload_correspondence::<RocksDBConfig>()
    }

    #[test]
    fn test_iterating_while_inserting_doesnt_see_new_updates() {
        crate::test_utils::test_iterating_while_inserting_doesnt_see_new_updates::<RocksDBConfig>()
    }

    #[test]
    fn test_iterator_can_outlive_the_pool() {
        crate::test_utils::test_iterator_can_outlive_the_pool::<RocksDBConfig>()
    }

    #[test]
    fn test_persistent_pool_path_is_cleanedup_after_tests() {
        crate::test_utils::test_persistent_pool_path_is_cleanedup_after_tests::<RocksDBConfig>()
    }

    // Test purge by compaction actually purges.
    // TODO CON-383: This test is currently disabled as it seem to fail on linux
    // sometimes with this error: `IO error: lock :
    // /build/ic_testsJ2Zq00/test_purge_by_compaction/LOCK: No locks available`.
    #[ignore]
    #[test]
    fn test_purge_by_compaction() {
        run_persistent_pool_test("test_purge_by_compaction", |mut config, log| {
            // set a small purge interval
            config.persistent_pool_validated_purge_interval = Height::from(8);
            let mut pool = PersistentHeightIndexedPool::new_consensus_pool(config, log);
            // insert a few things
            let rb_ops = random_beacon_ops();
            pool.mutate(rb_ops.clone());
            // check if read is ok after insertion
            let iter = pool.random_beacon().get_all();
            let msgs_from_pool: Vec<RandomBeacon> = iter.collect();
            assert_eq!(msgs_from_pool.len(), rb_ops.ops.len());
            let min_height = msgs_from_pool.iter().map(|x| x.height()).min().unwrap();
            // purge below height 5
            let mut purge_ops = PoolSectionOps::new();
            purge_ops.purge_below(Height::from(5));
            pool.mutate(purge_ops);
            let mut iter = pool.random_beacon().get_all();
            assert!(iter.all(|x| x.height() >= Height::from(5)));
            // range becomes (5, 18) after purge
            assert_eq!(
                pool.random_beacon().height_range().map(|r| r.min),
                Some(Height::from(5))
            );
            // But real min height is unchanged because compaction didn't happen
            assert_eq!(
                pool.get_first_height(&RANDOM_BEACON_CF_INFO, SeekPos::Start),
                Some(min_height)
            );
            // trigger compaction by purging again at height 10
            let mut purge_ops = PoolSectionOps::new();
            purge_ops.purge_below(Height::from(10));
            pool.mutate(purge_ops);
            assert_eq!(
                pool.random_beacon().height_range().map(|r| r.min),
                Some(Height::from(10))
            );
            // min height becomes 10 after compaction
            // Due to asynchrony, we'll wait at most 5s for this to happen.
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if pool.get_first_height(&RANDOM_BEACON_CF_INFO, SeekPos::Start)
                    == Some(Height::from(10))
                {
                    return;
                }
            }
            panic!("compaction did not purge")
        });
    }

    // Test if purge survives reboot.
    #[test]
    fn test_purge_survives_reboot() {
        run_persistent_pool_test("test_purge_survives_reboot", |mut config, log| {
            // set a small purge interval
            config.persistent_pool_validated_purge_interval = Height::from(8);
            // create a pool and purge at height 10
            {
                let mut pool =
                    PersistentHeightIndexedPool::new_consensus_pool(config.clone(), log.clone());
                // insert a few things
                let rb_ops = random_beacon_ops();
                pool.mutate(rb_ops.clone());
                let iter = pool.random_beacon().get_all();
                let msgs_from_pool = iter;
                assert_eq!(msgs_from_pool.count(), rb_ops.ops.len());
                // purge at height 10
                let mut purge_ops = PoolSectionOps::new();
                purge_ops.purge_below(Height::from(10));
                pool.mutate(purge_ops);
                assert_eq!(
                    pool.random_beacon().height_range().map(|r| r.min),
                    Some(Height::from(10))
                );
            }
            // wait 1s until it is fully closed
            std::thread::sleep(std::time::Duration::from_millis(1000));
            // create the same pool again, check if purge was persisted
            {
                let pool = PersistentHeightIndexedPool::new_consensus_pool(config, log);
                assert_eq!(
                    pool.random_beacon().height_range().map(|r| r.min),
                    Some(Height::from(10))
                );
            }
        });
    }

    #[test]
    fn test_timestamp_survives_reboot() {
        crate::test_utils::test_timestamp_survives_reboot::<RocksDBConfig>()
    }
}
