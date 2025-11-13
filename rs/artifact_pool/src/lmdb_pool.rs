use crate::consensus_pool::{InitializablePoolSection, PoolSectionOp, PoolSectionOps};
use crate::lmdb_iterator::{LMDBIDkgIterator, LMDBIterator};
use crate::metrics::IDkgPoolMetrics;
use ic_config::artifact_pool::LMDBConfig;
use ic_interfaces::consensus_pool::PurgeableArtifactType;
use ic_interfaces::{
    consensus_pool::{
        HeightIndexedPool, HeightRange, OnlyError, PoolSection, ValidatedConsensusArtifact,
    },
    idkg::{IDkgPoolSection, IDkgPoolSectionOp, IDkgPoolSectionOps, MutableIDkgPoolSection},
};
use ic_logger::{ReplicaLogger, error, info};
use ic_metrics::MetricsRegistry;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::types::v1 as pb;
use ic_types::consensus::dkg::DkgSummary;
use ic_types::{
    Height, Time,
    artifact::{CertificationMessageId, ConsensusMessageId, IDkgMessageId},
    batch::BatchPayload,
    consensus::{
        BlockPayload, BlockProposal, CatchUpPackage, CatchUpPackageShare, ConsensusMessage,
        ConsensusMessageHash, ConsensusMessageHashable, DataPayload, EquivocationProof,
        Finalization, FinalizationShare, HasHash, HasHeight, Notarization, NotarizationShare,
        Payload, PayloadType, RandomBeacon, RandomBeaconShare, RandomTape, RandomTapeShare,
        SummaryPayload,
        certification::{
            Certification, CertificationMessage, CertificationMessageHash, CertificationShare,
        },
        dkg::DkgDataPayload,
        idkg::{
            EcdsaSigShare, IDkgArtifactId, IDkgArtifactIdData, IDkgArtifactIdDataOf, IDkgMessage,
            IDkgMessageType, IDkgPrefix, IDkgPrefixOf, IterationPattern, SchnorrSigShare, SigShare,
            SigShareIdData, SigShareIdDataOf, SignedIDkgComplaint, SignedIDkgOpening,
            VetKdKeyShare,
        },
    },
    crypto::canister_threshold_sig::idkg::{
        IDkgDealingSupport, IDkgTranscriptId, SignedIDkgDealing,
    },
    crypto::{CryptoHash, CryptoHashOf, CryptoHashable},
};
use lmdb::{
    Cursor, Database, DatabaseFlags, Environment, EnvironmentFlags, RoTransaction, RwTransaction,
    Transaction, WriteFlags,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::{os::raw::c_uint, path::Path, sync::Arc};
use strum::{AsRefStr, FromRepr, IntoEnumIterator};

/// Implementation of a persistent, height indexed pool using LMDB.
///
/// Given an artifact, we calculate 3 keys: TypeKey, HeightKey and IdKey,
/// where TypeKey only depends on the type of an artifact, and IdKey
/// is prefixed by height value (in big endian), which makes them
/// ordered and can be purged by heights.
///
/// There are 3 kind of LMDB databases used:
///
/// 1. An "artifacts" database maps IdKey to bincode encoded bytes for fast
///    serialization and deserialization:
///
/// ```text
/// artifacts
/// --------------------------------------
/// | IdKey | (bincode serialized) Bytes |
/// --------------------------------------
/// ```
///
/// 2. A set of index databases, one for each message type. Each one of them
///    maps a HeightKey to a set of IdKeys:
///
/// ```text
/// --------------------------
/// | HeightKey | IdKey, ... |
/// --------------------------
/// ```
///
/// 3. A "meta" database maps each TypeKey to the metadata of this message type,
///    which at the moment is only the min and max height.
///
/// ```text
/// meta
/// ------------------
/// | TypeKey | Meta |
/// ------------------
/// ```
pub(crate) struct PersistentHeightIndexedPool<T> {
    pool_type: PhantomData<T>,
    db_env: Arc<Environment>,
    meta: Database,
    artifacts: Database,
    indices: Vec<(TypeKey, Database)>,
    log: ReplicaLogger,
}

/// A trait for loading/saving pool artifacts (of ArtifactKind). It allows a
/// flexible data schema to be used for pool objects. For example, objects may
/// be normalized and serialized into multiple data entries, and they are
/// re-constructed upon loading. This can be taken care of by the `save` and
/// `load_as` interface, subject to the actual implementation for each
/// ArtifactKind.
///
/// We differentiate between 3 types:
///
/// 1. Object that is serialized and stored in the pool. This can include
///    additional data such as timestamp.
///
/// 2. Artifact::Message is the message type (usually an enum) of each
///    ArtifactKind. It can be casted into individual messages using TryFrom.
///
/// 3. Individual message type.
pub(crate) trait PoolArtifact: Sized {
    /// The set of [`TypeKey`]s, one for each individual message type.
    const TYPE_KEYS: &'static [TypeKey];

    /// Type of the object to store.
    type ObjectType;
    type Id;

    /// Save an artifact to the database.
    // TODO: Consider using an internal error type, instead of `lmdb::Error`
    fn save(
        key: &IdKey,
        value: Self::ObjectType,
        artifacts: Database,
        tx: &mut RwTransaction,
        log: &ReplicaLogger,
    ) -> lmdb::Result<()>;

    /// Load an artifact from the database. This is parameterized
    /// by the individual message type T.
    // TODO: Consider using an internal error type, instead of `lmdb::Error`
    fn load_as<T: TryFrom<Self>>(
        key: &IdKey,
        db_env: Arc<Environment>,
        artifacts: Database,
        tx: &RoTransaction,
        log: &ReplicaLogger,
    ) -> lmdb::Result<T>
    where
        <T as TryFrom<Self>>::Error: Debug;
}

/// A unique representation for each type of supported message.
#[derive(Copy, Clone, Eq, PartialEq, Debug, AsRefStr, FromRepr)]
#[repr(u8)]
pub(crate) enum TypeKey {
    // Consensus messages
    RandomBeacon,
    Finalization,
    Notarization,
    BlockProposal,
    BlockPayload,
    RandomBeaconShare,
    NotarizationShare,
    FinalizationShare,
    RandomTape,
    RandomTapeShare,
    CatchUpPackage,
    CatchUpPackageShare,
    EquivocationProof,
    // Certification messages
    Certification,
    CertificationShare,
    // IDkg messages
    IDkgDealing,
    IDkgDealingSupport,
    EcdsaSigShare,
    SchnorrSigShare,
    VetKdKeyShare,
    IDkgComplaint,
    IDkgOpening,
}

impl TypeKey {
    fn name(&self) -> &str {
        self.as_ref()
    }
}

impl From<TypeKey> for u8 {
    fn from(value: TypeKey) -> u8 {
        value as u8
    }
}

impl TryFrom<u8> for TypeKey {
    type Error = String;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Self::from_repr(byte).ok_or(format!("Failed to convert byte {byte:#x} to TypeKey"))
    }
}

impl AsRef<[u8]> for TypeKey {
    fn as_ref(&self) -> &[u8] {
        self.name().as_bytes()
    }
}

/// Each support message gives a TypeKey.
trait HasTypeKey {
    fn type_key() -> TypeKey;
}

impl From<&ConsensusMessageId> for TypeKey {
    fn from(id: &ConsensusMessageId) -> Self {
        match id.hash {
            ConsensusMessageHash::RandomBeacon(_) => TypeKey::RandomBeacon,
            ConsensusMessageHash::Finalization(_) => TypeKey::Finalization,
            ConsensusMessageHash::Notarization(_) => TypeKey::Notarization,
            ConsensusMessageHash::BlockProposal(_) => TypeKey::BlockProposal,
            ConsensusMessageHash::RandomBeaconShare(_) => TypeKey::RandomBeaconShare,
            ConsensusMessageHash::NotarizationShare(_) => TypeKey::NotarizationShare,
            ConsensusMessageHash::FinalizationShare(_) => TypeKey::FinalizationShare,
            ConsensusMessageHash::RandomTape(_) => TypeKey::RandomTape,
            ConsensusMessageHash::RandomTapeShare(_) => TypeKey::RandomTapeShare,
            ConsensusMessageHash::CatchUpPackage(_) => TypeKey::CatchUpPackage,
            ConsensusMessageHash::CatchUpPackageShare(_) => TypeKey::CatchUpPackageShare,
            ConsensusMessageHash::EquivocationProof(_) => TypeKey::EquivocationProof,
        }
    }
}

impl From<&CertificationMessageId> for TypeKey {
    fn from(id: &CertificationMessageId) -> Self {
        match id.hash {
            CertificationMessageHash::Certification(_) => TypeKey::Certification,
            CertificationMessageHash::CertificationShare(_) => TypeKey::CertificationShare,
        }
    }
}

/// Message id as Key. The first 8 bytes is the big-endian representation
/// of the height, and the rest is hash.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct IdKey(Vec<u8>);

const HEIGHT_OFFSET: usize = 0;
const TYPE_OFFSET: usize = 8;
const HASH_OFFSET: usize = 9;

impl Debug for IdKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdKey")
            .field("height", &self.height())
            .field("type_key", &self.type_key())
            .field("hash", &self.hash())
            .finish()
    }
}

impl IdKey {
    fn new(height: Height, type_key: TypeKey, hash: &CryptoHash) -> Self {
        let hash_bytes = &hash.0;
        let len = hash_bytes.len() + 8 + 1;
        let mut bytes: Vec<u8> = vec![0; len];
        bytes[HEIGHT_OFFSET..TYPE_OFFSET].copy_from_slice(&u64::to_be_bytes(height.get()));
        bytes[TYPE_OFFSET] = type_key.into();
        bytes[HASH_OFFSET..].copy_from_slice(hash_bytes);

        Self(bytes)
    }

    fn height(&self) -> Height {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.0[HEIGHT_OFFSET..TYPE_OFFSET]);
        Height::from(u64::from_be_bytes(bytes))
    }

    fn type_key(&self) -> Result<TypeKey, String> {
        TypeKey::try_from(self.0[TYPE_OFFSET])
    }

    fn hash(&self) -> CryptoHash {
        CryptoHash(self.0[HASH_OFFSET..].to_vec())
    }

    fn with_type_key(&self, type_key: TypeKey) -> Self {
        let mut copy = self.clone();
        copy.0[TYPE_OFFSET] = type_key.into();

        copy
    }
}

impl AsRef<[u8]> for IdKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for IdKey {
    fn from(bytes: &[u8]) -> IdKey {
        IdKey(bytes.to_vec())
    }
}

impl<T> From<&T> for IdKey
where
    T: HasHeight + HasHash,
    for<'a> &'a T: Into<TypeKey>,
{
    fn from(id: &T) -> IdKey {
        IdKey::new(id.height(), id.into(), id.hash())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
pub(crate) struct HeightKey([u8; 8]);

impl AsRef<[u8]> for HeightKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for HeightKey {
    fn from(bytes: &[u8]) -> HeightKey {
        let mut bs: [u8; 8] = [0; 8];
        bs.copy_from_slice(bytes);
        HeightKey(bs)
    }
}

/// Use big-endian to ensure byte ordering.
impl From<Height> for HeightKey {
    fn from(height: Height) -> HeightKey {
        HeightKey(u64::to_be_bytes(height.get()))
    }
}

impl From<HeightKey> for Height {
    fn from(key: HeightKey) -> Height {
        Height::from(u64::from_be_bytes(key.0))
    }
}

/// DB Meta info about each message type is their min and max height
/// (inclusive).
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Meta {
    min: HeightKey,
    max: HeightKey,
}

/// Macro that logs the error when result is not Ok.
macro_rules! log_err {
    ($r:expr, $log:expr, $reason:expr) => {
        $r.map_err(|err| error!($log, "Error in DB operation {}: {:?}", $reason, err))
            .ok()
    };
}

/// Combination of type/height/id keys.
#[derive(Debug)]
struct ArtifactKey {
    type_key: TypeKey,
    height_key: HeightKey,
    id_key: IdKey,
}

/// Like log_err, but won't log the error if it matches the given error code.
macro_rules! log_err_except {
    ($r:expr, $log:expr, $code:pat, $reason:expr) => {
        $r.map_err(|err| match err {
            $code => {}
            _ => error!($log, "Error in DB operation {:?}: {:?}", $reason, err),
        })
        .ok()
    };
}

/// The max size (in bytes) of a persistent pool, also know as the LMDB map
/// size. It is a constant because it cannot be changed once DB is created.
const MAX_PERSISTENT_POOL_SIZE: usize = 0x0010_0000_0000; // 64GB

/// Max number of DB readers.
const MAX_READERS: c_uint = 2048;

fn create_db_env(path: &Path, read_only: bool, max_dbs: c_uint) -> Environment {
    let mut builder = Environment::new();
    let mut builder_flags = EnvironmentFlags::NO_TLS;
    let mut permission = 0o644;
    if read_only {
        builder_flags |= EnvironmentFlags::READ_ONLY;
        builder_flags |= EnvironmentFlags::NO_LOCK;
        permission = 0o444;
    }
    builder.set_flags(builder_flags);
    builder.set_max_readers(MAX_READERS);
    builder.set_max_dbs(max_dbs);
    builder.set_map_size(MAX_PERSISTENT_POOL_SIZE);
    let db_env = builder
        .open_with_permissions(path, permission)
        .unwrap_or_else(|err| {
            panic!("Error opening LMDB environment with permissions at {path:?}: {err:?}")
        });

    unsafe {
        // Mark fds created by lmdb as FD_CLOEXEC to prevent them from leaking into
        // canister sandbox process. Details in NODE-166
        let mut fd: lmdb_sys::mdb_filehandle_t = lmdb_sys::mdb_filehandle_t::default();
        lmdb_sys::mdb_env_get_fd(db_env.env(), &mut fd);
        nix::fcntl::fcntl(fd, nix::fcntl::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))
            .expect("Unable to mark FD_CLOEXEC");
    };
    db_env
}

///////////////////////////// Generic Pool /////////////////////////////

/// Collection of generic pool functions, indexed by Artifact type.
impl<Artifact: PoolArtifact> PersistentHeightIndexedPool<Artifact> {
    /// Return a persistent pool located the given directory path.
    /// Create the pool if it does not already exist.
    /// Panic if initialization fails.
    fn new(
        path: &Path,
        read_only: bool,
        log: ReplicaLogger,
    ) -> PersistentHeightIndexedPool<Artifact> {
        let db_env = create_db_env(path, read_only, (Artifact::TYPE_KEYS.len() + 2) as c_uint);

        // Create all databases.
        let meta = if read_only {
            db_env
                .open_db(Some("META"))
                .unwrap_or_else(|err| panic!("Error opening db for metadata: {err:?}"))
        } else {
            db_env
                .create_db(Some("META"), DatabaseFlags::empty())
                .unwrap_or_else(|err| panic!("Error creating db for metadata: {err:?}"))
        };
        let artifacts = if read_only {
            db_env
                .open_db(Some("ARTS"))
                .unwrap_or_else(|err| panic!("Error opening db for artifacts: {err:?}"))
        } else {
            db_env
                .create_db(Some("ARTS"), DatabaseFlags::empty())
                .unwrap_or_else(|err| panic!("Error creating db for artifacts: {err:?}"))
        };
        let indices = {
            Artifact::TYPE_KEYS
                .iter()
                .map(|type_key| {
                    // Use DUP_SORT to enable multi-value for each HeightKey.
                    let store = if read_only {
                        db_env.open_db(Some(type_key.name())).unwrap_or_else(|err| {
                            panic!("Error opening db {}: {:?}", type_key.name(), err)
                        })
                    } else {
                        db_env
                            .create_db(Some(type_key.name()), DatabaseFlags::DUP_SORT)
                            .unwrap_or_else(|err| {
                                panic!("Error creating db {}: {:?}", type_key.name(), err)
                            })
                    };
                    (*type_key, store)
                })
                .collect()
        };
        Self {
            pool_type: PhantomData,
            db_env: Arc::new(db_env),
            meta,
            artifacts,
            indices,
            log,
        }
    }

    /// Update the meta data of the given type_key.
    fn update_meta(
        &self,
        tx: &mut RwTransaction,
        type_key: &TypeKey,
        meta: &Meta,
    ) -> lmdb::Result<()> {
        if let Some(bytes) = log_err!(
            bincode::serialize::<Meta>(meta),
            self.log,
            "update_meta serialize"
        ) {
            tx.put(self.meta, &type_key, &bytes, WriteFlags::empty())
        } else {
            Err(lmdb::Error::Panic)
        }
    }

    /// Get the meta data of the given type_key.
    fn get_meta<Tx: Transaction>(&self, tx: &mut Tx, type_key: &TypeKey) -> Option<Meta> {
        log_err_except!(
            tx.get(self.meta, &type_key),
            self.log,
            lmdb::Error::NotFound,
            format!("get_meta {:?}", type_key)
        )
        .and_then(|bytes| bincode::deserialize::<Meta>(bytes).ok())
    }

    /// Get the index database of the given type_key.
    /// Each index database maps [`HeightKey`] to a list of [`IdKey`].
    fn get_index_db(&self, type_key: &TypeKey) -> Database {
        self.indices
            .iter()
            .find(|(key, _)| type_key == key)
            .unwrap_or_else(|| panic!("Error in get_index_db: {type_key:?} does not exist"))
            .1
    }

    /// Iterate messages between min and max HeightKey (inclusive).
    ///
    /// It is parameterized by an individual message type as long as it can be
    /// casted from the main `Artifact::Message` type.
    fn iterate<Message: TryFrom<Artifact> + HasTypeKey + 'static>(
        &self,
        min_key: HeightKey,
        max_key: HeightKey,
    ) -> Box<dyn Iterator<Item = Message>>
    where
        <Message as TryFrom<Artifact>>::Error: Debug,
    {
        let type_key = Message::type_key();
        let index_db = self.get_index_db(&type_key);
        let db_env = self.db_env.clone();
        let log = self.log.clone();
        let artifacts = self.artifacts;
        Box::new(LMDBIterator::new(
            db_env.clone(),
            index_db,
            min_key,
            max_key,
            move |tx: &RoTransaction<'_>, key: &[u8]| {
                Artifact::load_as::<Message>(&IdKey::from(key), db_env.clone(), artifacts, tx, &log)
            },
            self.log.clone(),
        ))
    }

    /// Insert a pool object under the given type/height/id key.
    fn tx_insert<PoolObject>(
        &self,
        tx: &mut RwTransaction,
        key: &ArtifactKey,
        value: PoolObject,
    ) -> lmdb::Result<()>
    where
        Artifact: PoolArtifact<ObjectType = PoolObject>,
    {
        self.tx_insert_prepare(tx, key)?;
        Artifact::save(&key.id_key, value, self.artifacts, tx, &self.log)
    }

    /// Prepares pool for artifact insertion, by checking index DB for duplicates and
    /// updating the metadata.
    fn tx_insert_prepare<PoolObject>(
        &self,
        tx: &mut RwTransaction,
        key: &ArtifactKey,
    ) -> lmdb::Result<()>
    where
        Artifact: PoolArtifact<ObjectType = PoolObject>,
    {
        // update index db first, because requiring NO_DUP_DATA may lead to
        // error when dup is detected. Insertion can be skipped in this case.
        let index_db = self.get_index_db(&key.type_key);
        tx.put(
            index_db,
            &key.height_key,
            &key.id_key,
            WriteFlags::NO_DUP_DATA,
        )?;
        // update meta
        let meta = self
            .get_meta(tx, &key.type_key)
            .map(|meta| Meta {
                min: meta.min.min(key.height_key),
                max: meta.max.max(key.height_key),
            })
            .unwrap_or(Meta {
                min: key.height_key,
                max: key.height_key,
            });
        self.update_meta(tx, &key.type_key, &meta)
    }

    /// Remove the pool object of the given type/height/id key.
    fn tx_remove(&self, tx: &mut RwTransaction, key: &ArtifactKey) -> lmdb::Result<()> {
        if let Err(err) = tx.del(self.artifacts, &key.id_key, None) {
            // skip the removal if it is not found in artifacts
            return if lmdb::Error::NotFound == err {
                Ok(())
            } else {
                Err(err)
            };
        }

        let index_db = self.get_index_db(&key.type_key);
        tx.del(index_db, &key.height_key, Some(&key.id_key.0))?;

        let min_height = tx_get_key(tx, index_db, GetOp::First)?;
        let max_height = tx_get_key(tx, index_db, GetOp::Last)?;

        match (min_height, max_height) {
            (Some(min), Some(max)) => self.update_meta(tx, &key.type_key, &Meta { min, max }),
            (Some(min), None) => self.update_meta(tx, &key.type_key, &Meta { min, max: min }),
            _ => tx.del(self.meta, &key.type_key, None),
        }
    }

    /// Remove all index entries for the given [`TypeKey`] with heights
    /// less than the given [`HeightKey`]. Update the type's meta table
    /// if necessary. Return the [`ArtifactKey`]s of deleted entries.
    fn tx_purge_index_below(
        &self,
        tx: &mut RwTransaction,
        type_key: TypeKey,
        height_key: HeightKey,
    ) -> lmdb::Result<Vec<ArtifactKey>> {
        let mut artifact_ids = Vec::new();
        // only delete if meta exists
        if let Some(meta) = self.get_meta(tx, &type_key) {
            // nothing to delete if min height is already higher
            if meta.min >= height_key {
                return Ok(artifact_ids);
            }

            let index_db = self.get_index_db(&type_key);
            {
                let mut cursor = tx.open_rw_cursor(index_db)?;

                while let Some((key, id)) = cursor.iter().next().transpose()? {
                    if HeightKey::from(key) >= height_key {
                        break;
                    }
                    artifact_ids.push(ArtifactKey {
                        type_key,
                        height_key: HeightKey::from(key),
                        id_key: IdKey::from(id),
                    });
                    cursor.del(WriteFlags::empty())?;
                }
            }

            // update meta
            let meta = if meta.max < height_key {
                None
            } else {
                tx_get_key(tx, index_db, GetOp::First)?.map(|key| Meta {
                    min: key,
                    max: meta.max,
                })
            };

            match meta {
                None => tx.del(self.meta, &type_key, None)?,
                Some(meta) => self.update_meta(tx, &type_key, &meta)?,
            }
        }

        Ok(artifact_ids)
    }

    /// Remove all artifacts with heights less than the given [`HeightKey`].
    /// Return [`ArtifactKey`]s of the removed artifacts.
    fn tx_purge_below(
        &self,
        tx: &mut RwTransaction,
        height_key: HeightKey,
    ) -> lmdb::Result<Vec<ArtifactKey>> {
        let mut purged = Vec::new();
        // delete from all index tables
        for &type_key in Artifact::TYPE_KEYS {
            purged.append(&mut self.tx_purge_index_below(tx, type_key, height_key)?);
        }

        // delete from artifacts table
        let mut cursor = tx.open_rw_cursor(self.artifacts)?;
        let height = Height::from(height_key);

        while let Some((key, _)) = cursor.iter().next().transpose()? {
            if IdKey::from(key).height() >= height {
                break;
            }
            cursor.del(WriteFlags::empty())?;
        }

        Ok(purged)
    }

    /// Remove all artifacts of the given [`TypeKey`] with heights less than the
    /// given [`HeightKey`]. Return [`ArtifactKey`]s of the removed artifacts.
    fn tx_purge_type_below(
        &self,
        tx: &mut RwTransaction,
        type_key: TypeKey,
        height_key: HeightKey,
    ) -> lmdb::Result<Vec<ArtifactKey>> {
        let artifact_keys = self.tx_purge_index_below(tx, type_key, height_key)?;
        // delete the corresponding artifacts, ignoring not found errors
        for key in &artifact_keys {
            if let Err(err) = tx.del(self.artifacts, &key.id_key, None) {
                // Ignore not found errors, although they should not appear in practice.
                if lmdb::Error::NotFound != err {
                    return Err(err);
                }
            }
        }
        Ok(artifact_keys)
    }
}

#[derive(Copy, Clone)]
enum GetOp {
    First,
    Last,
}

impl From<GetOp> for c_uint {
    fn from(op: GetOp) -> Self {
        match op {
            GetOp::First => lmdb_sys::MDB_FIRST,
            GetOp::Last => lmdb_sys::MDB_LAST,
        }
    }
}

/// Retrieves the first or the last key from the database.
fn tx_get_key(
    tx: &impl Transaction,
    database: Database,
    op: GetOp,
) -> lmdb::Result<Option<HeightKey>> {
    let cursor = tx.open_ro_cursor(database)?;
    match cursor.get(/*key=*/ None, /*data=*/ None, op.into()) {
        Ok((key, _value)) => Ok(key.map(HeightKey::from)),
        Err(lmdb::Error::NotFound) => Ok(None),
        Err(err) => Err(err),
    }
}

impl InitializablePoolSection for PersistentHeightIndexedPool<ConsensusMessage> {
    /// Insert a cup with the original bytes from which that cup was received.
    fn insert_cup_with_proto(&self, cup_proto: pb::CatchUpPackage) {
        let cup = CatchUpPackage::try_from(&cup_proto).expect("deserializing CUP failed");
        let mut tx = self
            .db_env
            .begin_rw_txn()
            .expect("Unable to begin transaction to initialize consensus pool");
        let key = ArtifactKey::from(&cup.get_id());

        // convert cup to bytes
        let bytes = &pb::ValidatedConsensusArtifact {
            msg: Some(pb::ConsensusMessage {
                msg: Some(pb::consensus_message::Msg::Cup(cup_proto)),
            }),
            timestamp: cup
                .content
                .block
                .as_ref()
                .context
                .time
                .as_nanos_since_unix_epoch(),
        }
        .encode_to_vec();

        // insert raw bytes
        self.tx_insert_prepare(&mut tx, &key)
            .expect("Insertion of metadata or updating index failed");
        tx.put(self.artifacts, &key.id_key, bytes, WriteFlags::empty())
            .expect("Insertion of CUP into initial consensus pool failed");
        tx.commit()
            .expect("Transaction inserting initial CUP into pool failed to commit");
    }
}

impl<Artifact: PoolArtifact, Message> HeightIndexedPool<Message>
    for PersistentHeightIndexedPool<Artifact>
where
    Message: TryFrom<Artifact> + HasTypeKey + 'static,
    <Message as TryFrom<Artifact>>::Error: Debug,
{
    fn height_range(&self) -> Option<HeightRange> {
        let mut tx = log_err!(self.db_env.begin_ro_txn(), self.log, "begin_ro_txn")?;
        self.get_meta(&mut tx, &Message::type_key())
            .map(|meta| HeightRange::new(Height::from(meta.min), Height::from(meta.max)))
    }

    fn max_height(&self) -> Option<Height> {
        <dyn HeightIndexedPool<Message>>::height_range(self).map(|range| range.max)
    }

    fn get_all(&self) -> Box<dyn Iterator<Item = Message>> {
        match <dyn HeightIndexedPool<Message>>::height_range(self) {
            None => Box::new(std::iter::empty()),
            Some(range) => self.iterate::<Message>(range.min.into(), range.max.into()),
        }
    }

    fn get_by_height(&self, h: Height) -> Box<dyn Iterator<Item = Message>> {
        let key = HeightKey::from(h);
        self.iterate(key, key)
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
        match <dyn HeightIndexedPool<Message>>::height_range(self) {
            None => Box::new(std::iter::empty()),
            Some(bounds) => self.iterate::<Message>(
                HeightKey::from(range.min.max(bounds.min)),
                HeightKey::from(range.max.min(bounds.max)),
            ),
        }
    }

    fn get_highest_iter(&self) -> Box<dyn Iterator<Item = Message>> {
        match <dyn HeightIndexedPool<Message>>::max_height(self) {
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

    fn size(&self) -> usize {
        let index_db = self.get_index_db(&Message::type_key());
        let Some(tx) = log_err!(self.db_env.begin_ro_txn(), &self.log, "begin_ro_txn") else {
            return 0;
        };
        let Some(mut cursor) = log_err!(tx.open_ro_cursor(index_db), &self.log, "open_ro_cursor")
        else {
            return 0;
        };

        cursor.iter().count()
    }
}

///////////////////////////// Consensus Pool /////////////////////////////
const CONSENSUS_KEYS: [TypeKey; 13] = [
    TypeKey::RandomBeacon,
    TypeKey::Finalization,
    TypeKey::Notarization,
    TypeKey::BlockProposal,
    TypeKey::BlockPayload,
    TypeKey::RandomBeaconShare,
    TypeKey::NotarizationShare,
    TypeKey::FinalizationShare,
    TypeKey::RandomTape,
    TypeKey::RandomTapeShare,
    TypeKey::CatchUpPackage,
    TypeKey::CatchUpPackageShare,
    TypeKey::EquivocationProof,
];

impl HasTypeKey for RandomBeacon {
    fn type_key() -> TypeKey {
        TypeKey::RandomBeacon
    }
}

impl HasTypeKey for Notarization {
    fn type_key() -> TypeKey {
        TypeKey::Notarization
    }
}

impl HasTypeKey for Finalization {
    fn type_key() -> TypeKey {
        TypeKey::Finalization
    }
}

impl HasTypeKey for BlockProposal {
    fn type_key() -> TypeKey {
        TypeKey::BlockProposal
    }
}

impl HasTypeKey for RandomBeaconShare {
    fn type_key() -> TypeKey {
        TypeKey::RandomBeaconShare
    }
}

impl HasTypeKey for NotarizationShare {
    fn type_key() -> TypeKey {
        TypeKey::NotarizationShare
    }
}

impl HasTypeKey for FinalizationShare {
    fn type_key() -> TypeKey {
        TypeKey::FinalizationShare
    }
}

impl HasTypeKey for RandomTape {
    fn type_key() -> TypeKey {
        TypeKey::RandomTape
    }
}

impl HasTypeKey for RandomTapeShare {
    fn type_key() -> TypeKey {
        TypeKey::RandomTapeShare
    }
}

impl HasTypeKey for CatchUpPackage {
    fn type_key() -> TypeKey {
        TypeKey::CatchUpPackage
    }
}

impl HasTypeKey for CatchUpPackageShare {
    fn type_key() -> TypeKey {
        TypeKey::CatchUpPackageShare
    }
}

impl HasTypeKey for EquivocationProof {
    fn type_key() -> TypeKey {
        TypeKey::EquivocationProof
    }
}

impl From<&ConsensusMessageId> for ArtifactKey {
    fn from(msg_id: &ConsensusMessageId) -> Self {
        Self {
            type_key: msg_id.into(),
            height_key: HeightKey::from(msg_id.height),
            id_key: IdKey::from(msg_id),
        }
    }
}

impl TryFrom<ArtifactKey> for ConsensusMessageId {
    type Error = String;
    fn try_from(key: ArtifactKey) -> Result<Self, Self::Error> {
        let h = key.id_key.hash();
        let hash = match key.type_key {
            TypeKey::RandomBeacon => ConsensusMessageHash::RandomBeacon(h.into()),
            TypeKey::Finalization => ConsensusMessageHash::Finalization(h.into()),
            TypeKey::Notarization => ConsensusMessageHash::Notarization(h.into()),
            TypeKey::BlockProposal => ConsensusMessageHash::BlockProposal(h.into()),
            TypeKey::RandomBeaconShare => ConsensusMessageHash::RandomBeaconShare(h.into()),
            TypeKey::NotarizationShare => ConsensusMessageHash::NotarizationShare(h.into()),
            TypeKey::FinalizationShare => ConsensusMessageHash::FinalizationShare(h.into()),
            TypeKey::RandomTape => ConsensusMessageHash::RandomTape(h.into()),
            TypeKey::RandomTapeShare => ConsensusMessageHash::RandomTapeShare(h.into()),
            TypeKey::CatchUpPackage => ConsensusMessageHash::CatchUpPackage(h.into()),
            TypeKey::CatchUpPackageShare => ConsensusMessageHash::CatchUpPackageShare(h.into()),
            TypeKey::EquivocationProof => ConsensusMessageHash::EquivocationProof(h.into()),
            TypeKey::BlockPayload => {
                return Err("Block payloads do not have a ConsensusMessageId".into());
            }
            other => {
                return Err(format!(
                    "{other:?} is not a valid ConsensusMessage TypeKey."
                ));
            }
        };
        Ok(ConsensusMessageId {
            hash,
            height: key.id_key.height(),
        })
    }
}

impl PoolArtifact for ConsensusMessage {
    // TODO: consider removing [`TypeKey::BlockPayload`] from here, as it's not necessary to create
    // an Index DB for this type of artifacts.
    const TYPE_KEYS: &'static [TypeKey] = &CONSENSUS_KEYS;

    type ObjectType = ValidatedConsensusArtifact;
    type Id = ConsensusMessageId;

    fn save(
        key: &IdKey,
        mut value: Self::ObjectType,
        artifacts: Database,
        tx: &mut RwTransaction,
        log: &ReplicaLogger,
    ) -> lmdb::Result<()> {
        // special handling for block proposal & its payload
        if let ConsensusMessage::BlockProposal(mut proposal) = value.msg {
            // store block payload separately
            let block = proposal.content.as_mut();
            let payload_hash = block.payload.get_hash().clone();
            let payload = block.payload.as_ref();
            let start_height = payload.dkg_interval_start_height();
            let payload_type = payload.payload_type();
            {
                let payload_key = key.with_type_key(TypeKey::BlockPayload);
                let bytes = log_err!(
                    bincode::serialize::<BlockPayload>(payload),
                    log,
                    "ConsensusArtifact::save serialize BlockPayload"
                )
                .ok_or(lmdb::Error::Panic)?;
                tx.put(artifacts, &payload_key, &bytes, WriteFlags::empty())?;
            }
            // replace block payload with an empty one
            block.payload = Payload::new_with(
                payload_hash,
                payload_type,
                // A dummy payload. Note that during deserialization, this dummy is
                // used to determine the payload type. So it's important that the
                // dummy has the SAME payload type as the real payload.
                Box::new(move || match payload_type {
                    PayloadType::Summary => BlockPayload::Summary(SummaryPayload {
                        dkg: DkgSummary::default(),
                        idkg: None,
                    }),
                    PayloadType::Data => BlockPayload::Data(DataPayload {
                        batch: BatchPayload::default(),
                        dkg: DkgDataPayload::new_empty(start_height),
                        idkg: None,
                    }),
                }),
            );
            value.msg = proposal.into_message();
        }
        let bytes = pb::ValidatedConsensusArtifact::from(&value).encode_to_vec();
        tx.put(artifacts, &key, &bytes, WriteFlags::empty())
    }

    fn load_as<T: TryFrom<Self>>(
        key: &IdKey,
        db_env: Arc<Environment>,
        artifacts: Database,
        tx: &RoTransaction,
        log: &ReplicaLogger,
    ) -> lmdb::Result<T>
    where
        <T as TryFrom<Self>>::Error: Debug,
    {
        let artifact = tx_get_validated_consensus_artifact(key, artifacts, tx, log)?;

        let msg = match artifact.msg {
            ConsensusMessage::BlockProposal(mut proposal) => {
                // Lazy loading of block proposal and its payload
                let block = proposal.content.as_mut();
                let payload_hash = block.payload.get_hash();
                let payload_key = key.with_type_key(TypeKey::BlockPayload);
                let log_clone = log.clone();
                block.payload = Payload::new_with(
                    payload_hash.clone(),
                    block.payload.payload_type(),
                    Box::new(move || {
                        log_err!(
                            load_block_payload(db_env, artifacts, &payload_key, &log_clone),
                            log_clone,
                            "ConsensusArtifact::load_as load_block_payload"
                        )
                        .unwrap()
                    }),
                );
                proposal.into_message()
            }
            consensus_message => consensus_message,
        };

        log_err!(
            T::try_from(msg),
            log,
            "ConsensusArtifact::load_as conversion"
        )
        .ok_or(lmdb::Error::Panic)
    }
}

fn tx_get_validated_consensus_artifact(
    key: &IdKey,
    artifacts: Database,
    tx: &impl Transaction,
    log: &ReplicaLogger,
) -> lmdb::Result<ValidatedConsensusArtifact> {
    let bytes = tx.get(artifacts, &key)?;
    let protobuf = log_err!(
        pb::ValidatedConsensusArtifact::decode(bytes),
        log,
        "tx_get_validated_consensus_artifact: protobuf decoding"
    )
    .ok_or(lmdb::Error::Panic)?;
    log_err!(
        ValidatedConsensusArtifact::try_from(protobuf),
        log,
        "tx_get_validated_consensus_artifact: protobuf conversion"
    )
    .ok_or(lmdb::Error::Panic)
}

/// Block payloads are loaded separately on demand.
fn load_block_payload(
    db_env: Arc<Environment>,
    artifacts: Database,
    payload_key: &IdKey,
    log: &ReplicaLogger,
) -> lmdb::Result<BlockPayload> {
    let tx = db_env.begin_ro_txn()?;
    let bytes = tx.get(artifacts, &payload_key)?;
    bincode::deserialize::<BlockPayload>(bytes).map_err(|err| {
        error!(log, "Error deserializing block payload: {:?}", err);
        lmdb::Error::Panic
    })
}

impl PersistentHeightIndexedPool<ConsensusMessage> {
    pub fn new_consensus_pool(
        config: LMDBConfig,
        read_only: bool,
        log: ReplicaLogger,
    ) -> PersistentHeightIndexedPool<ConsensusMessage> {
        let mut path = config.persistent_pool_validated_persistent_db_path;
        path.push("consensus");
        std::fs::create_dir_all(path.as_path()).ok();
        PersistentHeightIndexedPool::new(path.as_path(), read_only, log)
    }

    fn tx_mutate(
        &mut self,
        ops: PoolSectionOps<ValidatedConsensusArtifact>,
    ) -> lmdb::Result<Vec<ConsensusMessageId>> {
        let mut tx = self.db_env.begin_rw_txn()?;
        let mut purged = Vec::new();
        for op in ops.ops {
            match op {
                PoolSectionOp::Insert(artifact) => {
                    let msg_id = artifact.msg.get_id();
                    let key = ArtifactKey::from(&msg_id);
                    // Ignore KeyExist
                    match self.tx_insert(&mut tx, &key, artifact) {
                        Err(lmdb::Error::KeyExist) => Ok(()),
                        result => result,
                    }?
                }
                PoolSectionOp::Remove(msg_id) => {
                    let key = ArtifactKey::from(&msg_id);
                    self.tx_remove(&mut tx, &key)?;

                    // If we are removing a block proposal, remove its block payload as well
                    if key.type_key == TypeKey::BlockProposal {
                        tx.del(
                            self.artifacts,
                            &key.id_key.with_type_key(TypeKey::BlockPayload),
                            /*data=*/ None,
                        )?;
                    }

                    purged.push(msg_id);
                }
                PoolSectionOp::PurgeBelow(height) => {
                    let height_key = HeightKey::from(height);
                    purged.extend(
                        self.tx_purge_below(&mut tx, height_key)?
                            .into_iter()
                            .map(ConsensusMessageId::try_from)
                            .flat_map(|r| {
                                log_err!(r, self.log, "ConsensusMessage::tx_mutate PurgeBelow")
                            }),
                    );
                }
                PoolSectionOp::PurgeTypeBelow(artifact_type, height) => {
                    let height_key = HeightKey::from(height);
                    let type_key = match artifact_type {
                        PurgeableArtifactType::NotarizationShare => TypeKey::NotarizationShare,
                        PurgeableArtifactType::FinalizationShare => TypeKey::FinalizationShare,
                        PurgeableArtifactType::EquivocationProof => TypeKey::EquivocationProof,
                    };

                    purged.extend(
                        self.tx_purge_type_below(&mut tx, type_key, height_key)?
                            .into_iter()
                            .map(ConsensusMessageId::try_from)
                            .flat_map(|r| {
                                log_err!(
                                    r,
                                    self.log,
                                    "ConsensusMessage::tx_mutate PurgeSharesBelow"
                                )
                            }),
                    );
                }
            }
        }
        tx.commit()?;
        Ok(purged)
    }
}

impl crate::consensus_pool::MutablePoolSection<ValidatedConsensusArtifact>
    for PersistentHeightIndexedPool<ConsensusMessage>
{
    fn mutate(
        &mut self,
        ops: PoolSectionOps<ValidatedConsensusArtifact>,
    ) -> Vec<ConsensusMessageId> {
        match self.tx_mutate(ops) {
            Ok(purged) => purged,
            err => {
                log_err!(err, self.log, "ConsensusArtifact::mutate");
                Vec::new()
            }
        }
    }

    fn pool_section(&self) -> &dyn PoolSection<ValidatedConsensusArtifact> {
        self
    }
}

impl PoolSection<ValidatedConsensusArtifact> for PersistentHeightIndexedPool<ConsensusMessage> {
    fn contains(&self, msg_id: &ConsensusMessageId) -> bool {
        if let Some(tx) = log_err!(self.db_env.begin_ro_txn(), self.log, "begin_ro_txn") {
            let key = IdKey::from(msg_id);
            log_err_except!(
                tx.get(self.artifacts, &key),
                self.log,
                lmdb::Error::NotFound,
                format!("contains {:?}", msg_id)
            )
            .is_some()
        } else {
            false
        }
    }

    fn get(&self, msg_id: &ConsensusMessageId) -> Option<ConsensusMessage> {
        let tx = log_err!(self.db_env.begin_ro_txn(), self.log, "begin_ro_txn")?;
        let key = IdKey::from(msg_id);
        log_err_except!(
            ConsensusMessage::load_as::<ConsensusMessage>(
                &key,
                self.db_env.clone(),
                self.artifacts,
                &tx,
                &self.log
            ),
            self.log,
            lmdb::Error::NotFound,
            format!("get {:?}", msg_id)
        )
    }

    fn get_timestamp(&self, msg_id: &ConsensusMessageId) -> Option<Time> {
        let tx = log_err!(self.db_env.begin_ro_txn(), self.log, "begin_ro_txn")?;
        let key = IdKey::from(msg_id);
        let bytes = log_err_except!(
            tx.get(self.artifacts, &key),
            self.log,
            lmdb::Error::NotFound,
            format!("get_timestamp get {:?}", msg_id)
        )?;
        log_err!(
            pb::ValidatedConsensusArtifact::decode(bytes),
            self.log,
            "get_timestamp deserialize"
        )
        .map(|x| Time::from_nanos_since_unix_epoch(x.timestamp))
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

    fn equivocation_proof(&self) -> &dyn HeightIndexedPool<EquivocationProof> {
        self
    }

    fn highest_catch_up_package_proto(&self) -> pb::CatchUpPackage {
        let h = self
            .catch_up_package()
            .max_height()
            .expect("There should always be a CUP in the pool.");
        let key = HeightKey::from(h);
        let index_db = self.get_index_db(&CatchUpPackage::type_key());
        let log = self.log.clone();
        let artifacts = self.artifacts;
        LMDBIterator::new(
            self.db_env.clone(),
            index_db,
            key,
            key,
            move |tx: &RoTransaction<'_>, key: &[u8]| {
                let bytes = tx.get(artifacts, &key)?;
                let artifact = log_err!(
                    pb::ValidatedConsensusArtifact::decode(bytes),
                    log,
                    "CatchUpPackage protobuf deserialize"
                )
                .ok_or(lmdb::Error::Panic)?;
                match artifact.msg {
                    Some(pb::ConsensusMessage {
                        msg: Some(pb::consensus_message::Msg::Cup(cup_proto)),
                    }) => Ok(cup_proto),
                    Some(_) => panic!("unexpected artifact type when deserializing CUP"),
                    None => panic!("No consensus message found"),
                }
            },
            self.log.clone(),
        )
        .next()
        .unwrap_or_else(|| panic!("This should be impossible since we found a max height at {h:?}"))
    }

    /// Number of artifacts in the DB.
    fn size(&self) -> u64 {
        if let Some(tx) = log_err!(self.db_env.begin_ro_txn(), &self.log, "begin_ro_txn")
            && let Some(mut cursor) = log_err!(
                tx.open_ro_cursor(self.artifacts),
                &self.log,
                "open_ro_cursor"
            )
        {
            return cursor.iter().count() as u64;
        }
        0
    }
}

///////////////////////////// Certification Pool /////////////////////////////

const CERTIFICATION_KEYS: [TypeKey; 2] = [TypeKey::Certification, TypeKey::CertificationShare];

impl HasTypeKey for Certification {
    fn type_key() -> TypeKey {
        TypeKey::Certification
    }
}

impl HasTypeKey for CertificationShare {
    fn type_key() -> TypeKey {
        TypeKey::CertificationShare
    }
}

impl TryFrom<ArtifactKey> for CertificationMessageId {
    type Error = String;
    fn try_from(key: ArtifactKey) -> Result<Self, Self::Error> {
        let h = key.id_key.hash();
        let hash = match key.type_key {
            TypeKey::Certification => CertificationMessageHash::Certification(h.into()),
            TypeKey::CertificationShare => CertificationMessageHash::CertificationShare(h.into()),
            other => {
                return Err(format!(
                    "{other:?} is not a valid CertificationMessage TypeKey."
                ));
            }
        };
        Ok(CertificationMessageId {
            hash,
            height: key.id_key.height(),
        })
    }
}

impl PoolArtifact for CertificationMessage {
    const TYPE_KEYS: &'static [TypeKey] = &CERTIFICATION_KEYS;

    type ObjectType = CertificationMessage;
    type Id = CertificationMessageId;

    fn save(
        key: &IdKey,
        value: Self::ObjectType,
        artifacts: Database,
        tx: &mut RwTransaction,
        log: &ReplicaLogger,
    ) -> lmdb::Result<()> {
        let bytes = log_err!(
            bincode::serialize::<Self::ObjectType>(&value),
            log,
            "CertificationArtifact::save serialize"
        )
        .ok_or(lmdb::Error::Panic)?;
        tx.put(artifacts, &key, &bytes, WriteFlags::empty())
    }

    fn load_as<T: TryFrom<Self>>(
        key: &IdKey,
        _db_env: Arc<Environment>,
        artifacts: Database,
        tx: &RoTransaction,
        log: &ReplicaLogger,
    ) -> lmdb::Result<T> {
        let bytes = tx.get(artifacts, &key)?;
        let msg = log_err!(
            bincode::deserialize::<Self::ObjectType>(bytes),
            log,
            "CertificationArtifact::load_as deserialize"
        )
        .ok_or(lmdb::Error::Panic)?;
        log_err!(
            msg.try_into().map_err(|_| ()),
            log,
            "CertificationArtifact::load_as casting"
        )
        .ok_or(lmdb::Error::Panic)
    }
}

impl PersistentHeightIndexedPool<CertificationMessage> {
    pub fn new_certification_pool(
        config: LMDBConfig,
        read_only: bool,
        log: ReplicaLogger,
    ) -> PersistentHeightIndexedPool<CertificationMessage> {
        let mut path = config.persistent_pool_validated_persistent_db_path;
        path.push("certification");
        std::fs::create_dir_all(path.as_path()).ok();
        PersistentHeightIndexedPool::new(path.as_path(), read_only, log)
    }

    fn insert_message<T: HasTypeKey + Into<CertificationMessage> + CryptoHashable + HasHeight>(
        &self,
        hash: CryptoHashOf<T>,
        value: T,
    ) -> lmdb::Result<()> {
        let message: CertificationMessage = value.into();
        let message_id = CertificationMessageId::from(&message);
        let key = ArtifactKey {
            type_key: T::type_key(),
            id_key: IdKey::new(message_id.height(), T::type_key(), hash.get_ref()),
            height_key: HeightKey::from(message_id.height()),
        };
        let mut tx = self.db_env.begin_rw_txn()?;
        self.tx_insert(&mut tx, &key, message)?;
        tx.commit()
    }

    fn purge_below_height(&self, height: Height) -> lmdb::Result<Vec<CertificationMessageId>> {
        let mut tx = self.db_env.begin_rw_txn()?;
        let purged = self
            .tx_purge_below(&mut tx, HeightKey::from(height))?
            .into_iter()
            .map(CertificationMessageId::try_from)
            .flat_map(|r| log_err!(r, self.log, "CertificationMessage::purge_below_height"))
            .collect();
        tx.commit()?;
        Ok(purged)
    }
}

impl crate::certification_pool::MutablePoolSection
    for PersistentHeightIndexedPool<CertificationMessage>
{
    fn insert(&self, message: CertificationMessage) {
        match message {
            CertificationMessage::Certification(value) => log_err!(
                self.insert_message(ic_types::crypto::crypto_hash(&value), value),
                self.log,
                "CertificationMessage::Certification::insert"
            ),
            CertificationMessage::CertificationShare(value) => log_err!(
                self.insert_message(ic_types::crypto::crypto_hash(&value), value),
                self.log,
                "CertificationMessage::CertificationShare::insert"
            ),
        };
    }

    fn get(&self, msg_id: &CertificationMessageId) -> Option<CertificationMessage> {
        let tx = log_err!(self.db_env.begin_ro_txn(), self.log, "begin_ro_txn")?;
        let key = IdKey::from(msg_id);
        log_err_except!(
            CertificationMessage::load_as::<CertificationMessage>(
                &key,
                self.db_env.clone(),
                self.artifacts,
                &tx,
                &self.log
            ),
            self.log,
            lmdb::Error::NotFound,
            format!("get {:?}", msg_id)
        )
    }

    fn purge_below(&self, height: Height) -> Vec<CertificationMessageId> {
        match self.purge_below_height(height) {
            Ok(purged) => purged,
            err => {
                log_err!(err, self.log, "CertificationArtifact::purge_below");
                Vec::new()
            }
        }
    }

    fn certifications(&self) -> &dyn HeightIndexedPool<Certification> {
        self
    }

    fn certification_shares(&self) -> &dyn HeightIndexedPool<CertificationShare> {
        self
    }
}

///////////////////////////// IDKG Pool /////////////////////////////

/// The message id as a database key. The first 8 bytes are the big-endian representation
/// of the group tag (transcript ID / pre-signature ID). The next 8 bytes are a hash of meta
/// data (i.e. dealer ID, sig share sender, dealer ID + support sender, ...).
/// The remaining bytes are a proto encoding of additional ID data (height, message hash, [subnet Id]).
///
/// ```text
/// -----------------------------------------------------------------------------
/// |0   <group tag>   7|8   <meta hash>   15|16   <proto encoded ID data>   ...|
/// -----------------------------------------------------------------------------
/// ```
///
/// Two kinds of look up are possible with this:
/// 1. Look up by full key of <16 bytes prefix + id data>, which would return the matching
///    artifact if present.
/// 2. Look up by prefix match. This can return 0 or more entries, as several artifacts may share
///    the same prefix. The caller is expected to filter the returned entries as needed. The look up
///    by prefix makes some frequent queries more efficient (e.g) to know if a node has already
///    issued a support for a <transcript Id, dealer Id>, we could iterate through all the entries
///    in the support pool looking for a matching artifact. Instead, this implementation allows
///    us to issue a single prefix query for prefix = <transcript Id, dealer Id + support signer Id>.
#[derive(Debug)]
pub(crate) struct IDkgIdKey(Vec<u8>);

impl AsRef<[u8]> for IDkgIdKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for IDkgIdKey {
    fn from(bytes: &[u8]) -> IDkgIdKey {
        IDkgIdKey(bytes.to_vec())
    }
}

impl From<IDkgMessageId> for IDkgIdKey {
    fn from(msg_id: IDkgMessageId) -> IDkgIdKey {
        // Serialize the prefix
        let prefix = msg_id.prefix();
        let mut bytes = vec![];
        bytes.extend_from_slice(&u64::to_be_bytes(prefix.group_tag()));
        bytes.extend_from_slice(&u64::to_be_bytes(prefix.meta_hash()));

        // Serialize the ID data
        let id_data_bytes = match msg_id {
            IDkgArtifactId::Dealing(_, data) => {
                pb::IDkgArtifactIdData::from(data.get()).encode_to_vec()
            }
            IDkgArtifactId::DealingSupport(_, data) => {
                pb::IDkgArtifactIdData::from(data.get()).encode_to_vec()
            }
            IDkgArtifactId::EcdsaSigShare(_, data) => {
                pb::SigShareIdData::from(data.get()).encode_to_vec()
            }
            IDkgArtifactId::SchnorrSigShare(_, data) => {
                pb::SigShareIdData::from(data.get()).encode_to_vec()
            }
            IDkgArtifactId::VetKdKeyShare(_, data) => {
                pb::SigShareIdData::from(data.get()).encode_to_vec()
            }
            IDkgArtifactId::Complaint(_, data) => {
                pb::IDkgArtifactIdData::from(data.get()).encode_to_vec()
            }
            IDkgArtifactId::Opening(_, data) => {
                pb::IDkgArtifactIdData::from(data.get()).encode_to_vec()
            }
        };
        bytes.extend_from_slice(&id_data_bytes);
        IDkgIdKey(bytes)
    }
}

impl From<IterationPattern> for IDkgIdKey {
    fn from(pattern: IterationPattern) -> IDkgIdKey {
        let mut bytes = vec![];
        match pattern {
            IterationPattern::GroupTag(group_tag) => {
                bytes.extend_from_slice(&u64::to_be_bytes(group_tag));
            }
            IterationPattern::Prefix(prefix) => {
                bytes.extend_from_slice(&u64::to_be_bytes(prefix.group_tag()));
                bytes.extend_from_slice(&u64::to_be_bytes(prefix.meta_hash()));
            }
        }
        IDkgIdKey(bytes)
    }
}

fn deser_idkg_artifact_id_data(bytes: &[u8]) -> Result<IDkgArtifactIdData, ProxyDecodeError> {
    pb::IDkgArtifactIdData::decode(bytes)
        .map_err(ProxyDecodeError::DecodeError)
        .and_then(IDkgArtifactIdData::try_from)
}

fn deser_sig_share_id_data(bytes: &[u8]) -> Result<SigShareIdData, ProxyDecodeError> {
    pb::SigShareIdData::decode(bytes)
        .map_err(ProxyDecodeError::DecodeError)
        .and_then(SigShareIdData::try_from)
}

fn deser_idkg_message_id(
    message_type: IDkgMessageType,
    id_key: IDkgIdKey,
) -> Result<IDkgMessageId, ProxyDecodeError> {
    // Deserialize the prefix
    let mut group_tag_bytes = [0; 8];
    group_tag_bytes.copy_from_slice(&id_key.0[0..8]);

    let mut meta_hash_bytes = [0; 8];
    meta_hash_bytes.copy_from_slice(&id_key.0[8..16]);

    let prefix = IDkgPrefix::new_with_meta_hash(
        u64::from_be_bytes(group_tag_bytes),
        u64::from_be_bytes(meta_hash_bytes),
    );

    // Deserialize the remaining bytes as the ID data
    let id_data_bytes: &[u8] = &id_key.0[16..];

    let id = match message_type {
        IDkgMessageType::Dealing => IDkgArtifactId::Dealing(
            IDkgPrefixOf::new(prefix),
            IDkgArtifactIdDataOf::new(deser_idkg_artifact_id_data(id_data_bytes)?),
        ),
        IDkgMessageType::DealingSupport => IDkgArtifactId::DealingSupport(
            IDkgPrefixOf::new(prefix),
            IDkgArtifactIdDataOf::new(deser_idkg_artifact_id_data(id_data_bytes)?),
        ),
        IDkgMessageType::EcdsaSigShare => IDkgArtifactId::EcdsaSigShare(
            IDkgPrefixOf::new(prefix),
            SigShareIdDataOf::new(deser_sig_share_id_data(id_data_bytes)?),
        ),
        IDkgMessageType::SchnorrSigShare => IDkgArtifactId::SchnorrSigShare(
            IDkgPrefixOf::new(prefix),
            SigShareIdDataOf::new(deser_sig_share_id_data(id_data_bytes)?),
        ),
        IDkgMessageType::VetKdKeyShare => IDkgArtifactId::VetKdKeyShare(
            IDkgPrefixOf::new(prefix),
            SigShareIdDataOf::new(deser_sig_share_id_data(id_data_bytes)?),
        ),
        IDkgMessageType::Complaint => IDkgArtifactId::Complaint(
            IDkgPrefixOf::new(prefix),
            IDkgArtifactIdDataOf::new(deser_idkg_artifact_id_data(id_data_bytes)?),
        ),
        IDkgMessageType::Opening => IDkgArtifactId::Opening(
            IDkgPrefixOf::new(prefix),
            IDkgArtifactIdDataOf::new(deser_idkg_artifact_id_data(id_data_bytes)?),
        ),
    };
    Ok(id)
}

/// The per-message type DB
struct IDkgMessageDb {
    db_env: Arc<Environment>,
    db: Database,
    object_type: IDkgMessageType,
    metrics: IDkgPoolMetrics,
    log: ReplicaLogger,
}

impl IDkgMessageDb {
    fn new(
        db_env: Arc<Environment>,
        db: Database,
        object_type: IDkgMessageType,
        metrics: IDkgPoolMetrics,
        log: ReplicaLogger,
    ) -> Self {
        Self {
            db_env,
            db,
            object_type,
            metrics,
            log,
        }
    }

    /// Adds the serialized <key, vale> to be added to the transaction. Returns true on success,
    /// false otherwise.
    fn insert_txn(&self, message: IDkgMessage, tx: &mut RwTransaction) -> bool {
        assert_eq!(IDkgMessageType::from(&message), self.object_type);
        let key = IDkgIdKey::from(IDkgArtifactId::from(&message));
        let bytes = match bincode::serialize::<IDkgMessage>(&message) {
            Ok(bytes) => bytes,
            Err(err) => {
                error!(
                    self.log,
                    "IDkgMessageDb::insert_txn(): serialize(): {:?}/{:?}", key, err
                );
                self.metrics.persistence_error("insert_serialize");
                return false;
            }
        };

        if let Err(err) = tx.put(self.db, &key, &bytes, WriteFlags::empty()) {
            error!(
                self.log,
                "IDkgMessageDb::insert_txn(): tx.put(): {:?}/{:?}", key, err
            );
            self.metrics.persistence_error("insert_tx_put");
            return false;
        }

        true
    }

    fn get_object(&self, id: &IDkgMessageId) -> Option<IDkgMessage> {
        let key = IDkgIdKey::from(id.clone());
        let tx = match self.db_env.begin_ro_txn() {
            Ok(tx) => tx,
            Err(err) => {
                error!(
                    self.log,
                    "IDkgMessageDb::get(): begin_ro_txn(): {:?}/{:?}", key, err
                );
                self.metrics.persistence_error("get_begin_ro_txn");
                return None;
            }
        };

        let bytes = match tx.get(self.db, &key) {
            Ok(bytes) => bytes,
            Err(lmdb::Error::NotFound) => return None,
            Err(err) => {
                error!(
                    self.log,
                    "IDkgMessageDb::get(): tx.get(): {:?}/{:?}", key, err
                );
                self.metrics.persistence_error("get_tx_get");
                return None;
            }
        };

        match bincode::deserialize::<IDkgMessage>(bytes) {
            Ok(msg) => Some(msg),
            Err(err) => {
                error!(
                    self.log,
                    "IDkgMessageDb::get(): deserialize(): {:?}/{:?}", key, err
                );
                self.metrics.persistence_error("get_deserialize");
                None
            }
        }
    }

    /// Adds the serialized <key> to be removed to the transaction. Returns true on success,
    /// false otherwise.
    fn remove_txn(&self, id: IDkgMessageId, tx: &mut RwTransaction) -> bool {
        let key = IDkgIdKey::from(id);
        if let Err(err) = tx.del(self.db, &key, None) {
            error!(
                self.log,
                "IDkgMessageDb::remove_txn(): tx.del(): {:?}/{:?}", key, err
            );
            self.metrics.persistence_error("remove_tx_del");
            return false;
        }
        true
    }

    /// Iterate over the pool for a given optional pattern. Start at the first key that matches the
    /// pattern and stop at the first that does not. If no pattern is given, return all elements.
    fn iter<T: TryFrom<IDkgMessage>>(
        &self,
        pattern: Option<IterationPattern>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, T)> + '_>
    where
        <T as TryFrom<IDkgMessage>>::Error: Debug,
    {
        let message_type = self.object_type;
        let log = self.log.clone();
        let pattern_clone = pattern.clone();
        let deserialize_fn = move |key: &[u8], bytes: &[u8]| {
            // Convert key bytes to IDkgMessageId
            let mut key_bytes = Vec::<u8>::new();
            key_bytes.extend_from_slice(key);
            let id_key = IDkgIdKey(key_bytes);
            let id = match deser_idkg_message_id(message_type, id_key) {
                Ok(id) => id,
                Err(err) => {
                    error!(
                        log,
                        "IDkgMessageDb::iter(): deser_idkg_message_id() for key of length {} failed: {:?}",
                        key.len(),
                        err,
                    );
                    return None;
                }
            };

            // Stop iterating if we hit a different pattern.
            if pattern_clone.as_ref().is_some_and(|pattern| match pattern {
                IterationPattern::GroupTag(group_tag) => group_tag != &id.prefix().group_tag(),
                IterationPattern::Prefix(prefix) => prefix != &id.prefix(),
            }) {
                return None;
            }

            // Deserialize value bytes and convert to inner type
            let message = match bincode::deserialize::<IDkgMessage>(bytes) {
                Ok(message) => message,
                Err(err) => {
                    error!(
                        log,
                        "IDkgMessageDb::iter(): deserialize() failed: {:?}/{:?}/{}/{}",
                        id,
                        err,
                        key.len(),
                        bytes.len()
                    );
                    return None;
                }
            };

            match T::try_from(message) {
                Ok(inner) => Some((id, inner)),
                Err(err) => {
                    error!(
                        log,
                        "IDkgMessageDb::iter(): failed to convert to inner type: {:?}/{:?}/{}/{}",
                        id,
                        err,
                        key.len(),
                        bytes.len()
                    );
                    None
                }
            }
        };

        Box::new(LMDBIDkgIterator::new(
            self.db_env.clone(),
            self.db,
            deserialize_fn,
            pattern.map(IDkgIdKey::from),
            self.log.clone(),
        ))
    }
}

/// The PersistentIDkgPoolSection is just a collection of per-message type
/// backend DBs. The main role is to route the operations to the appropriate
/// backend DB.
pub(crate) struct PersistentIDkgPoolSection {
    // Per message type data base
    db_env: Arc<Environment>,
    message_dbs: Vec<(IDkgMessageType, IDkgMessageDb)>,
    metrics: IDkgPoolMetrics,
    log: ReplicaLogger,
}

impl PersistentIDkgPoolSection {
    pub(crate) fn new_idkg_pool(
        config: LMDBConfig,
        read_only: bool,
        log: ReplicaLogger,
        metrics_registry: MetricsRegistry,
        pool: &str,
        pool_type: &str,
    ) -> Self {
        let mut type_keys = Vec::new();
        for message_type in IDkgMessageType::iter() {
            type_keys.push((message_type, Self::get_type_key(message_type)));
        }

        let mut path = config.persistent_pool_validated_persistent_db_path;
        path.push("idkg");
        if let Err(err) = std::fs::create_dir_all(path.as_path()) {
            panic!("Error creating IDKG dir {path:?}: {err:?}")
        }
        let db_env = Arc::new(create_db_env(
            path.as_path(),
            read_only,
            type_keys.len() as c_uint,
        ));

        let mut message_dbs = Vec::new();
        let metrics = IDkgPoolMetrics::new(metrics_registry, pool, pool_type);
        for (message_type, type_key) in &type_keys {
            let db = if read_only {
                db_env.open_db(Some(type_key.name())).unwrap_or_else(|err| {
                    panic!("Error opening IDKG db {}: {:?}", type_key.name(), err)
                })
            } else {
                db_env
                    .create_db(Some(type_key.name()), DatabaseFlags::empty())
                    .unwrap_or_else(|err| {
                        panic!("Error creating IDKG db {}: {:?}", type_key.name(), err)
                    })
            };
            message_dbs.push((
                *message_type,
                IDkgMessageDb::new(
                    db_env.clone(),
                    db,
                    *message_type,
                    metrics.clone(),
                    log.clone(),
                ),
            ));
        }

        info!(
            log,
            "PersistentIDkgPoolSection::new_idkg_pool(): num_dbs = {}",
            type_keys.len()
        );

        Self {
            db_env,
            message_dbs,
            metrics,
            log,
        }
    }

    fn get_message_db(&self, message_type: IDkgMessageType) -> &IDkgMessageDb {
        self.message_dbs
            .iter()
            .find(|(db_type, _)| *db_type == message_type)
            .map(|(_, db)| db)
            .unwrap()
    }

    fn get_type_key(message_type: IDkgMessageType) -> TypeKey {
        match message_type {
            IDkgMessageType::Dealing => TypeKey::IDkgDealing,
            IDkgMessageType::DealingSupport => TypeKey::IDkgDealingSupport,
            IDkgMessageType::EcdsaSigShare => TypeKey::EcdsaSigShare,
            IDkgMessageType::SchnorrSigShare => TypeKey::SchnorrSigShare,
            IDkgMessageType::VetKdKeyShare => TypeKey::VetKdKeyShare,
            IDkgMessageType::Complaint => TypeKey::IDkgComplaint,
            IDkgMessageType::Opening => TypeKey::IDkgOpening,
        }
    }
}

impl IDkgPoolSection for PersistentIDkgPoolSection {
    fn contains(&self, msg_id: &IDkgMessageId) -> bool {
        self.get_message_db(IDkgMessageType::from(msg_id))
            .get_object(msg_id)
            .is_some()
    }

    fn get(&self, msg_id: &IDkgMessageId) -> Option<IDkgMessage> {
        self.get_message_db(IDkgMessageType::from(msg_id))
            .get_object(msg_id)
    }

    fn signed_dealings(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::Dealing);
        message_db.iter(None)
    }

    fn signed_dealings_by_prefix(
        &self,
        prefix: IDkgPrefixOf<SignedIDkgDealing>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::Dealing);
        message_db.iter(Some(IterationPattern::Prefix(prefix.get())))
    }

    fn signed_dealings_by_transcript_id(
        &self,
        transcript_id: &IDkgTranscriptId,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgDealing)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::Dealing);
        message_db.iter(Some(IterationPattern::GroupTag(transcript_id.id())))
    }

    fn dealing_support(
        &self,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, IDkgDealingSupport)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::DealingSupport);
        message_db.iter(None)
    }

    fn dealing_support_by_prefix(
        &self,
        prefix: IDkgPrefixOf<IDkgDealingSupport>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, IDkgDealingSupport)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::DealingSupport);
        message_db.iter(Some(IterationPattern::Prefix(prefix.get())))
    }

    fn dealing_support_by_transcript_id(
        &self,
        transcript_id: &IDkgTranscriptId,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, IDkgDealingSupport)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::DealingSupport);
        message_db.iter(Some(IterationPattern::GroupTag(transcript_id.id())))
    }

    fn ecdsa_signature_shares(
        &self,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaSigShare)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::EcdsaSigShare);
        message_db.iter(None)
    }

    fn ecdsa_signature_shares_by_prefix(
        &self,
        prefix: IDkgPrefixOf<EcdsaSigShare>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, EcdsaSigShare)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::EcdsaSigShare);
        message_db.iter(Some(IterationPattern::Prefix(prefix.get())))
    }

    fn schnorr_signature_shares(
        &self,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SchnorrSigShare)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::SchnorrSigShare);
        message_db.iter(None)
    }

    fn schnorr_signature_shares_by_prefix(
        &self,
        prefix: IDkgPrefixOf<SchnorrSigShare>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SchnorrSigShare)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::SchnorrSigShare);
        message_db.iter(Some(IterationPattern::Prefix(prefix.get())))
    }

    fn vetkd_key_shares(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, VetKdKeyShare)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::VetKdKeyShare);
        message_db.iter(None)
    }

    fn vetkd_key_shares_by_prefix(
        &self,
        prefix: IDkgPrefixOf<VetKdKeyShare>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, VetKdKeyShare)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::VetKdKeyShare);
        message_db.iter(Some(IterationPattern::Prefix(prefix.get())))
    }

    fn signature_shares(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SigShare)> + '_> {
        let ecdsa_db = self.get_message_db(IDkgMessageType::EcdsaSigShare);
        let schnorr_db = self.get_message_db(IDkgMessageType::SchnorrSigShare);
        let vetkd_db = self.get_message_db(IDkgMessageType::VetKdKeyShare);
        Box::new(
            ecdsa_db
                .iter(None)
                .map(|(id, share)| (id, SigShare::Ecdsa(share)))
                .chain(
                    schnorr_db
                        .iter(None)
                        .map(|(id, share)| (id, SigShare::Schnorr(share))),
                )
                .chain(
                    vetkd_db
                        .iter(None)
                        .map(|(id, share)| (id, SigShare::VetKd(share))),
                ),
        )
    }

    fn complaints(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgComplaint)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::Complaint);
        message_db.iter(None)
    }

    fn complaints_by_prefix(
        &self,
        prefix: IDkgPrefixOf<SignedIDkgComplaint>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgComplaint)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::Complaint);
        message_db.iter(Some(IterationPattern::Prefix(prefix.get())))
    }

    fn openings(&self) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgOpening)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::Opening);
        message_db.iter(None)
    }

    fn openings_by_prefix(
        &self,
        prefix: IDkgPrefixOf<SignedIDkgOpening>,
    ) -> Box<dyn Iterator<Item = (IDkgMessageId, SignedIDkgOpening)> + '_> {
        let message_db = self.get_message_db(IDkgMessageType::Opening);
        message_db.iter(Some(IterationPattern::Prefix(prefix.get())))
    }
}

impl MutableIDkgPoolSection for PersistentIDkgPoolSection {
    fn mutate(&mut self, ops: IDkgPoolSectionOps) {
        if ops.ops.is_empty() {
            return;
        }

        let mut tx = match self.db_env.begin_rw_txn() {
            Ok(tx) => tx,
            Err(err) => {
                error!(
                    self.log,
                    "MutableIDkgPoolSection::mutate(): begin_rw_txn(): {:?}", err
                );
                self.metrics.persistence_error("begin_rw_txn");
                return;
            }
        };

        for op in ops.ops {
            match op {
                IDkgPoolSectionOp::Insert(message) => {
                    let message_type = IDkgMessageType::from(&message);
                    let db = self.get_message_db(message_type);
                    if !db.insert_txn(message, &mut tx) {
                        return;
                    }
                    self.metrics.observe_insert(message_type.as_str());
                }
                IDkgPoolSectionOp::Remove(id) => {
                    let message_type = IDkgMessageType::from(&id);
                    let db = self.get_message_db(message_type);
                    if !db.remove_txn(id, &mut tx) {
                        return;
                    }
                    self.metrics.observe_remove(message_type.as_str())
                }
            }
        }

        match tx.commit() {
            Ok(()) => (),
            Err(lmdb::Error::NotFound) => {
                self.metrics.persistence_error("tx_commit_not_found");
            }
            Err(err) => {
                error!(
                    self.log,
                    "MutableIDkgPoolSection::mutate(): tx.commit(): {:?}", err
                );
                self.metrics.persistence_error("tx_commit");
            }
        }
    }

    fn as_pool_section(&self) -> &dyn IDkgPoolSection {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus_pool::MutablePoolSection,
        test_utils::{
            PoolTestHelper, block_proposal_ops, fake_block_proposal_with_rank, fake_random_beacon,
            finalization_share_ops, notarization_share_ops, random_beacon_ops,
        },
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_types::{PrincipalId, SubnetId, consensus::Rank};
    use std::{panic, path::PathBuf};

    #[test]
    fn test_encode_decode_key() {
        let height = Height::from(10);
        let beacon = fake_random_beacon(height);
        let msg = ConsensusMessage::RandomBeacon(beacon);
        let hash = msg.get_cm_hash();
        let height_key = HeightKey::from(height);
        let id_key = IdKey::new(height, TypeKey::BlockPayload, hash.digest());
        assert_eq!(Height::from(height_key), height, "height does not match");
        assert_eq!(id_key.height(), height, "Height of IdKey does not match");
        assert_eq!(
            &id_key.hash(),
            hash.digest(),
            "Hash of IdKey does not match"
        );
        assert_eq!(
            id_key.type_key().expect("Should deserialize the key"),
            TypeKey::BlockPayload
        );
    }

    #[test]
    fn test_encode_decode_idkg_key() {
        let data = [1u8; PrincipalId::MAX_LENGTH_IN_BYTES];
        let max_principal = PrincipalId::new(data.len(), data);
        let small_principal = PrincipalId::new(20, data);
        let one_byte_principal = PrincipalId::new(1, data);
        let empty_principal = PrincipalId::new(0, data);

        let subnet_ids = [
            SubnetId::new(max_principal),
            SubnetId::new(small_principal),
            SubnetId::new(one_byte_principal),
            SubnetId::new(empty_principal),
        ];

        let hashes = [
            CryptoHash(vec![]),
            CryptoHash(vec![2u8; 1]),
            CryptoHash(vec![2u8; 32]),
            CryptoHash(vec![2u8; 128]),
        ];

        let message_types = [IDkgMessageType::Dealing, IDkgMessageType::EcdsaSigShare];

        for message_type in &message_types {
            for subnet_id in &subnet_ids {
                for hash in &hashes {
                    let prefix = IDkgPrefix::new_with_meta_hash(1, 2);
                    let id = match message_type {
                        IDkgMessageType::Dealing => IDkgArtifactId::Dealing(
                            IDkgPrefixOf::new(prefix),
                            IDkgArtifactIdDataOf::new(IDkgArtifactIdData {
                                height: Height::from(3),
                                hash: hash.clone(),
                                subnet_id: *subnet_id,
                            }),
                        ),
                        IDkgMessageType::EcdsaSigShare => IDkgArtifactId::EcdsaSigShare(
                            IDkgPrefixOf::new(prefix),
                            SigShareIdDataOf::new(SigShareIdData {
                                height: Height::from(3),
                                hash: hash.clone(),
                            }),
                        ),
                        _ => panic!("Unexpected type: {message_type:?}"),
                    };
                    let id_key = IDkgIdKey::from(id.clone());
                    let deser_id = deser_idkg_message_id(*message_type, id_key).unwrap();
                    assert_eq!(id, deser_id);
                }
            }
        }
    }

    // TODO: Remove this after it is no longer needed
    // Helper to run the persistence tests below.
    // It creates the config and logger that is passed to the instances and then
    // makes sure that the the databases are destroyed before the test fails.
    fn run_persistent_pool_test<T>(_test_name: &str, test: T)
    where
        T: FnOnce(LMDBConfig, ReplicaLogger) + panic::UnwindSafe,
    {
        with_test_replica_logger(|log| {
            ic_test_utilities::artifact_pool_config::with_test_lmdb_pool_config(|config| {
                let result = panic::catch_unwind(|| test(config.clone(), log));
                assert!(result.is_ok());
            })
        })
    }

    impl PoolTestHelper for LMDBConfig {
        type PersistentHeightIndexedPool = PersistentHeightIndexedPool<ConsensusMessage>;

        fn run_persistent_pool_test<T, R>(_test_name: &str, test: T) -> R
        where
            T: FnOnce(LMDBConfig, ReplicaLogger) -> R + panic::UnwindSafe,
        {
            with_test_replica_logger(|log| {
                ic_test_utilities::artifact_pool_config::with_test_lmdb_pool_config(|config| {
                    let result = panic::catch_unwind(|| test(config.clone(), log));
                    assert!(result.is_ok());
                    result.unwrap()
                })
            })
        }

        fn new_consensus_pool(self, log: ReplicaLogger) -> Self::PersistentHeightIndexedPool {
            PersistentHeightIndexedPool::new_consensus_pool(self, false, log)
        }

        fn persistent_pool_validated_persistent_db_path(&self) -> &PathBuf {
            &self.persistent_pool_validated_persistent_db_path
        }
    }

    #[test]
    fn test_as_pool_section() {
        crate::test_utils::test_as_pool_section::<LMDBConfig>()
    }

    #[test]
    fn test_as_height_indexed_pool() {
        crate::test_utils::test_as_height_indexed_pool::<LMDBConfig>()
    }

    #[test]
    fn test_block_proposal_and_payload_correspondence() {
        crate::test_utils::test_block_proposal_and_payload_correspondence::<LMDBConfig>()
    }

    #[test]
    fn test_iterating_while_inserting_doesnt_see_new_updates() {
        crate::test_utils::test_iterating_while_inserting_doesnt_see_new_updates::<LMDBConfig>()
    }

    #[test]
    fn test_iterator_can_outlive_the_pool() {
        crate::test_utils::test_iterator_can_outlive_the_pool::<LMDBConfig>()
    }

    #[test]
    fn test_persistent_pool_path_is_cleanedup_after_tests() {
        crate::test_utils::test_persistent_pool_path_is_cleanedup_after_tests::<LMDBConfig>()
    }

    fn validated_block_proposal(height: Height, rank: Rank) -> ValidatedConsensusArtifact {
        ValidatedConsensusArtifact {
            msg: ConsensusMessage::BlockProposal(fake_block_proposal_with_rank(height, rank)),
            timestamp: ic_types::time::UNIX_EPOCH,
        }
    }

    #[test]
    fn block_proposals_consistency_test() {
        run_persistent_pool_test("block_proposals_consistency_test", |config, log| {
            let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                config, /*read_only=*/ false, log,
            );
            let mut ops = PoolSectionOps::new();
            // Note: all these proposals have exactly same payload
            ops.insert(validated_block_proposal(Height::new(1), Rank(0)));
            ops.insert(validated_block_proposal(Height::new(1), Rank(1)));
            ops.insert(validated_block_proposal(Height::new(2), Rank(1)));
            ops.insert(validated_block_proposal(Height::new(3), Rank(1)));
            ops.insert(validated_block_proposal(Height::new(3), Rank(2)));

            pool.mutate(ops);

            assert_consistency(&pool);
        });
    }

    #[test]
    fn remove_block_proposals_consistency_test() {
        run_persistent_pool_test("remove_block_proposals_consistency_test", |config, log| {
            let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                config, /*read_only=*/ false, log,
            );
            let block_proposal_1_0 = validated_block_proposal(Height::new(1), Rank(0));
            let block_proposal_1_1 = validated_block_proposal(Height::new(1), Rank(1));
            let block_proposal_2_1 = validated_block_proposal(Height::new(2), Rank(1));
            let block_proposal_3_1 = validated_block_proposal(Height::new(3), Rank(1));
            let block_proposal_3_2 = validated_block_proposal(Height::new(3), Rank(2));

            // Insert 5 block proposals
            let mut ops = PoolSectionOps::new();
            ops.insert(block_proposal_1_0.clone());
            ops.insert(block_proposal_1_1.clone());
            ops.insert(block_proposal_2_1.clone());
            ops.insert(block_proposal_3_1.clone());
            ops.insert(block_proposal_3_2.clone());
            pool.mutate(ops);

            // Remove 2 of them
            let mut removal_ops: PoolSectionOps<ValidatedConsensusArtifact> = PoolSectionOps::new();
            removal_ops.remove(block_proposal_1_0.msg.get_id());
            removal_ops.remove(block_proposal_2_1.msg.get_id());
            pool.mutate(removal_ops);

            assert_eq!(pool.block_proposal().size(), 3);
            assert_consistency(&pool);

            // Remove the remaining 3 of them
            let mut removal_ops: PoolSectionOps<ValidatedConsensusArtifact> = PoolSectionOps::new();
            removal_ops.remove(block_proposal_1_1.msg.get_id());
            removal_ops.remove(block_proposal_3_1.msg.get_id());
            removal_ops.remove(block_proposal_3_2.msg.get_id());
            pool.mutate(removal_ops);

            assert_eq!(pool.block_proposal().size(), 0);
            assert_consistency(&pool);
        });
    }

    #[test]
    fn remove_block_proposals_bounds_test() {
        run_persistent_pool_test("remove_block_proposals_bounds_test", |config, log| {
            let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                config, /*read_only=*/ false, log,
            );
            let block_proposal_1_0 = validated_block_proposal(Height::new(1), Rank(0));
            let block_proposal_1_1 = validated_block_proposal(Height::new(1), Rank(1));
            let block_proposal_2_1 = validated_block_proposal(Height::new(2), Rank(1));
            let block_proposal_3_1 = validated_block_proposal(Height::new(3), Rank(1));

            let mut ops = PoolSectionOps::new();
            ops.insert(block_proposal_1_0.clone());
            ops.insert(block_proposal_1_1.clone());
            ops.insert(block_proposal_2_1.clone());
            ops.insert(block_proposal_3_1.clone());
            pool.mutate(ops);

            // Remove a block at Height 1 - the height bounds shouldn't change
            let removal_ops = PoolSectionOps {
                ops: vec![PoolSectionOp::Remove(block_proposal_1_0.msg.get_id())],
            };

            pool.mutate(removal_ops);

            assert_eq!(
                pool.block_proposal().height_range(),
                Some(HeightRange::new(Height::new(1), Height::new(3))),
            );

            // Remove a block at Height 3 - the upper bound should change
            let removal_ops = PoolSectionOps {
                ops: vec![PoolSectionOp::Remove(block_proposal_3_1.msg.get_id())],
            };

            pool.mutate(removal_ops);

            assert_eq!(
                pool.block_proposal().height_range(),
                Some(HeightRange::new(Height::new(1), Height::new(2))),
            );

            // Remove a block at Height 1 - the lower bound should change
            let removal_ops = PoolSectionOps {
                ops: vec![PoolSectionOp::Remove(block_proposal_1_1.msg.get_id())],
            };

            pool.mutate(removal_ops);

            assert_eq!(
                pool.block_proposal().height_range(),
                Some(HeightRange::new(Height::new(2), Height::new(2))),
            );

            // Remove the remaining block, at Height 2 - `height_range` should be `None`
            let removal_ops = PoolSectionOps {
                ops: vec![PoolSectionOp::Remove(block_proposal_2_1.msg.get_id())],
            };

            pool.mutate(removal_ops);

            assert!(pool.block_proposal().height_range().is_none(),);
        });
    }

    #[test]
    fn test_purge_survives_reboot() {
        run_persistent_pool_test("test_purge_survives_reboot", |config, log| {
            // create a pool and purge at height 10
            const PURGE_HEIGHT: Height = Height::new(10);
            const RANDOM_BEACONS_INITIAL_MIN_HEIGHT: u64 = 6;
            const RANDOM_BEACONS_INITIAL_MAX_HEIGHT: u64 = 18;
            const BLOCK_PROPOSALS_INITIAL_MIN_HEIGHT: u64 = 8;
            const BLOCK_PROPOSALS_INITIAL_MAX_HEIGHT: u64 = 15;
            {
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                    config.clone(),
                    /*read_only=*/ false,
                    log.clone(),
                );
                // insert a few things
                // random beacons
                let rb_ops = random_beacon_ops(
                    RANDOM_BEACONS_INITIAL_MIN_HEIGHT..=RANDOM_BEACONS_INITIAL_MAX_HEIGHT,
                );
                pool.mutate(rb_ops.clone());
                assert_eq!(pool.random_beacon().size(), rb_ops.ops.len());
                // block proposals
                let block_proposal_ops = block_proposal_ops(
                    BLOCK_PROPOSALS_INITIAL_MIN_HEIGHT..=BLOCK_PROPOSALS_INITIAL_MAX_HEIGHT,
                );
                pool.mutate(block_proposal_ops.clone());
                assert_eq!(pool.block_proposal().size(), block_proposal_ops.ops.len());

                // purge at height 10
                let mut purge_ops = PoolSectionOps::new();
                purge_ops.purge_below(PURGE_HEIGHT);
                pool.mutate(purge_ops);

                // verify that the artifacts have been purged
                assert_eq!(
                    pool.random_beacon().height_range(),
                    Some(HeightRange {
                        min: PURGE_HEIGHT,
                        max: Height::new(RANDOM_BEACONS_INITIAL_MAX_HEIGHT)
                    })
                );
                assert_eq!(
                    pool.block_proposal().height_range(),
                    Some(HeightRange {
                        min: PURGE_HEIGHT,
                        max: Height::new(BLOCK_PROPOSALS_INITIAL_MAX_HEIGHT)
                    })
                );
                assert_consistency(&pool);
            }
            // create the same pool again, check if purge was persisted
            {
                let pool = PersistentHeightIndexedPool::new_consensus_pool(
                    config, /*read_only=*/ false, log,
                );
                assert_eq!(
                    pool.random_beacon().height_range(),
                    Some(HeightRange {
                        min: PURGE_HEIGHT,
                        max: Height::from(RANDOM_BEACONS_INITIAL_MAX_HEIGHT)
                    })
                );
                assert_eq!(
                    pool.block_proposal().height_range(),
                    Some(HeightRange {
                        min: PURGE_HEIGHT,
                        max: Height::from(BLOCK_PROPOSALS_INITIAL_MAX_HEIGHT)
                    })
                );
                assert_consistency(&pool);
            }
        });
    }

    #[test]
    fn test_purge_shares_survives_reboot() {
        run_persistent_pool_test("test_purge_shares_survives_reboot", |config, log| {
            // create a pool and purge finalization shares at height 10 and notarization shares at
            // height 13;
            let height10 = Height::from(10);
            let height13 = Height::from(13);
            {
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                    config.clone(),
                    false,
                    log.clone(),
                );
                // insert random beacons, notarization shares, and finalization shares
                let fs_ops = finalization_share_ops();
                pool.mutate(fs_ops.clone());
                let ns_ops = notarization_share_ops();
                pool.mutate(ns_ops.clone());
                pool.mutate(random_beacon_ops(/*heights=*/ 3..19));
                // min height of finalization shares should be less than 10
                assert!(pool.finalization_share().height_range().map(|r| r.min) < Some(height10));
                // min height of notarization shares should be less than 13
                assert!(pool.notarization_share().height_range().map(|r| r.min) < Some(height13));

                let iter = pool.finalization_share().get_all();
                let shares_from_pool = iter.count();
                assert_eq!(shares_from_pool, fs_ops.ops.len());
                let iter = pool.notarization_share().get_all();
                let shares_from_pool = iter.count();
                assert_eq!(shares_from_pool, ns_ops.ops.len());
                assert_consistency(&pool);
                let iter = pool.random_beacon().get_all();
                let messages_from_pool = iter.count();

                // purge finalization shares at height 10
                let mut purge_ops = PoolSectionOps::new();
                purge_ops.purge_type_below(PurgeableArtifactType::FinalizationShare, height10);
                // purge notarization shares at height 13
                purge_ops.purge_type_below(PurgeableArtifactType::NotarizationShare, height13);
                pool.mutate(purge_ops);
                // min height of finalization shares should be 10
                assert_eq!(
                    pool.finalization_share().height_range().map(|r| r.min),
                    Some(height10)
                );
                // min height of notarization shares should be 13
                assert_eq!(
                    pool.notarization_share().height_range().map(|r| r.min),
                    Some(height13)
                );
                // full beacon count should be unchanged
                assert_eq!(pool.random_beacon().get_all().count(), messages_from_pool);
                assert_consistency(&pool);
            }
            // create the same pool again, check if purge was persisted
            {
                let pool = PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                assert_eq!(
                    pool.finalization_share().height_range().map(|r| r.min),
                    Some(height10)
                );
                assert_eq!(
                    pool.notarization_share().height_range().map(|r| r.min),
                    Some(height13)
                );
                assert_consistency(&pool);
            }
        });
    }

    #[test]
    fn test_purge_below_maximum_element() {
        run_persistent_pool_test("test_purge_below_maximum_element", |config, log| {
            const MAX_HEIGHT: Height = Height::new(10);
            let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                config.clone(),
                /*read_only=*/ false,
                log.clone(),
            );
            let rb_ops = random_beacon_ops(1..=MAX_HEIGHT.get());
            pool.mutate(rb_ops.clone());
            assert_eq!(pool.random_beacon().size(), rb_ops.ops.len());

            // purge artifacts strictly below the maximum element (at height 10)
            let mut purge_ops = PoolSectionOps::new();
            purge_ops.purge_below(MAX_HEIGHT);
            pool.mutate(purge_ops);

            // verify that the artifacts have been purged
            assert_eq!(
                pool.random_beacon().height_range(),
                Some(HeightRange {
                    min: MAX_HEIGHT,
                    max: MAX_HEIGHT
                })
            );
            assert_consistency(&pool);
        });
    }

    fn assert_count_consistency_<T>(pool: &dyn HeightIndexedPool<T>) {
        assert_eq!(pool.size(), pool.get_all().count());
    }

    fn assert_count_consistency(pool: &PersistentHeightIndexedPool<ConsensusMessage>) {
        assert_count_consistency_(pool.random_beacon());
        assert_count_consistency_(pool.random_tape());
        assert_count_consistency_(pool.block_proposal());
        assert_count_consistency_(pool.notarization());
        assert_count_consistency_(pool.finalization());
        assert_count_consistency_(pool.random_beacon_share());
        assert_count_consistency_(pool.random_tape_share());
        assert_count_consistency_(pool.notarization_share());
        assert_count_consistency_(pool.finalization_share());
        assert_count_consistency_(pool.catch_up_package());
        assert_count_consistency_(pool.catch_up_package_share());
    }

    // Assert that entries in artifacts db are reflected by index db and vice versa.
    // Each entry should have a join partner when joining on IdKey.
    fn assert_consistency(pool: &PersistentHeightIndexedPool<ConsensusMessage>) {
        assert_count_consistency(pool);

        let tx = pool.db_env.begin_ro_txn().unwrap();
        // get all ids from all indices
        let ids_index = pool
            .indices
            .iter()
            .flat_map(|(_, db)| {
                let mut cursor = tx.open_ro_cursor(*db).unwrap();
                cursor
                    .iter()
                    .map(|res| {
                        let (_, id) = res.unwrap();
                        IdKey::from(id)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let block_proposal_ids_index = {
            let block_proposal_index_db = pool.get_index_db(&TypeKey::BlockProposal);
            let mut cursor = tx.open_ro_cursor(block_proposal_index_db).unwrap();
            cursor
                .iter()
                .map(|res| {
                    let (_, id_key) = res.unwrap();
                    IdKey::from(id_key)
                })
                .collect::<Vec<_>>()
        };

        let block_payload_ids_from_block_proposals = block_proposal_ids_index
            .iter()
            .map(|block_proposal_id| block_proposal_id.with_type_key(TypeKey::BlockPayload))
            .collect::<Vec<_>>();

        // get all ids from artifacts db
        let mut ids_artifacts = {
            let mut cursor = tx.open_ro_cursor(pool.artifacts).unwrap();
            cursor
                .iter()
                .map(|res| {
                    let (id, _) = res.unwrap();
                    IdKey::from(id)
                })
                .collect::<Vec<_>>()
        };
        tx.commit().unwrap();
        ids_artifacts.sort();

        // they should be equal
        assert_eq!(
            block_proposal_ids_index.len(),
            block_payload_ids_from_block_proposals.len()
        );
        assert_eq!(
            ids_index.len() + block_proposal_ids_index.len(),
            ids_artifacts.len()
        );

        let mut all_id_references = [ids_index, block_payload_ids_from_block_proposals].concat();
        all_id_references.sort();

        assert_eq!(all_id_references, ids_artifacts);
    }

    #[test]
    fn test_timestamp_survives_reboot() {
        crate::test_utils::test_timestamp_survives_reboot::<LMDBConfig>()
    }
}
