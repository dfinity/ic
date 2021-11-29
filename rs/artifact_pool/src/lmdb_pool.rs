use crate::consensus_pool::{InitializablePoolSection, PoolSectionOp, PoolSectionOps};
use crate::lmdb_iterator::LMDBIterator;
use ic_config::artifact_pool::LMDBConfig;
use ic_consensus_message::ConsensusMessageHashable;
use ic_interfaces::{
    artifact_pool::ValidatedArtifact,
    consensus_pool::{
        HeightIndexedPool, HeightRange, OnlyError, PoolSection, ValidatedConsensusArtifact,
    },
    crypto::CryptoHashable,
};
use ic_logger::{error, ReplicaLogger};
use ic_protobuf::types::v1 as pb;
use ic_types::{
    artifact::{CertificationMessageId, ConsensusMessageId},
    batch::BatchPayload,
    consensus::{
        catchup::CUPWithOriginalProtobuf,
        certification::{Certification, CertificationMessage, CertificationShare},
        dkg, BlockPayload, BlockProposal, CatchUpPackage, CatchUpPackageShare, ConsensusMessage,
        ConsensusMessageHash, Finalization, FinalizationShare, HasHeight, Notarization,
        NotarizationShare, Payload, RandomBeacon, RandomBeaconShare, RandomTape, RandomTapeShare,
    },
    crypto::{CryptoHash, CryptoHashOf},
    Height, Time,
};
use lmdb::{
    Cursor, Database, DatabaseFlags, Environment, EnvironmentFlags, RoTransaction, RwTransaction,
    Transaction, WriteFlags,
};
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;
use std::{os::raw::c_uint, path::Path, sync::Arc};

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
/// serialization and deserialization:
///
/// ```text
/// artifacts
/// --------------------------------------
/// | IdKey | (bincode serialized) Bytes |
/// --------------------------------------
/// ```
///
/// 2. A set of index databases, one for each message type. Each one of them
/// maps a HeightKey to a set of IdKeys:
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
pub struct PersistentHeightIndexedPool<T> {
    pool_type: PhantomData<T>,
    db_env: Arc<Environment>,
    meta: Database,
    artifacts: Database,
    indices: Vec<(TypeKey, Database)>,
    log: ReplicaLogger,
}

/// PersistedConsensusMessage exists to allow the direct persistence of protobuf
/// CUP Messages. This is important to ensure that we can properly serve a
/// version of the CUP whose signature can be verified by other nodes over HTTP.
/// Without directly persisting the original protobuf, it might become
/// impossible to verify the CUP signature across versions of the replica with
/// difference in the way the cup struct is structured.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum PersistedConsensusMessage {
    OriginalCUPBytes(pb::CatchUpPackage),
    ConsensusMessage(ConsensusMessage),
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
/// additional data such as timestamp.
///
/// 2. Artifact::Message is the message type (usually an enum) of each
/// ArtifactKind. It can be casted into individual messages using TryFrom.
///
/// 3. Individual message type.
pub trait PoolArtifact: Sized {
    /// Type of the object to store.
    type ObjectType;
    type Id;

    /// The set of TypeKeys, one for each individual message type.
    /// This should be a const function.
    fn type_keys() -> &'static [TypeKey];

    /// Save an artifact to the database.
    fn save<'a>(
        key: &IdKey,
        value: Self::ObjectType,
        artifacts: Database,
        tx: &mut RwTransaction<'a>,
        log: &ReplicaLogger,
    ) -> lmdb::Result<()>;

    /// Load an artifact from the database. This is parameterized
    /// by the individual message type T.
    fn load_as<'a, T: TryFrom<Self>>(
        key: &IdKey,
        db_env: Arc<Environment>,
        artifacts: Database,
        tx: &RoTransaction<'a>,
        log: &ReplicaLogger,
    ) -> lmdb::Result<T>;
}

/// A unique representation for each type of supported message.
/// Internally it is just a const string.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TypeKey {
    name: &'static str,
}

impl TypeKey {
    const fn new(name: &'static str) -> TypeKey {
        TypeKey { name }
    }
}

impl AsRef<[u8]> for TypeKey {
    fn as_ref(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

/// Each support message gives a TypeKey.
pub trait HasTypeKey {
    fn type_key() -> TypeKey;
}

/// Message id as Key. The first 8 bytes is the big-endian representation
/// of the height, and the rest is hash.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct IdKey(Vec<u8>);

impl IdKey {
    pub fn height(&self) -> Height {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.0[0..8]);
        Height::from(u64::from_be_bytes(bytes))
    }

    #[allow(unused)]
    pub fn hash(&self) -> CryptoHash {
        CryptoHash(self.0[8..].to_vec())
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

impl From<(Height, &CryptoHash)> for IdKey {
    fn from((height, hash): (Height, &CryptoHash)) -> IdKey {
        let hash_bytes = &hash.0;
        let len = hash_bytes.len() + 8;
        let mut bytes: Vec<u8> = vec![0; len];
        let (left, right) = bytes.split_at_mut(8);
        left.copy_from_slice(&u64::to_be_bytes(height.get()));
        right.copy_from_slice(hash_bytes);
        IdKey(bytes)
    }
}

// This conversion is lossy because height and type tag are not preserved.
// It is okay because we don't expect reverse conversion.
impl From<&ConsensusMessageId> for IdKey {
    fn from(id: &ConsensusMessageId) -> IdKey {
        IdKey::from((id.height, id.hash.digest()))
    }
}

/// Height key.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let type_keys = Artifact::type_keys();
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
        builder.set_max_dbs((type_keys.len() + 2) as c_uint);
        builder.set_map_size(MAX_PERSISTENT_POOL_SIZE);
        let db_env = builder
            .open_with_permissions(path, permission)
            .unwrap_or_else(|err| {
                panic!("Error opening LMDB environment at {:?}: {:?}", path, err)
            });

        unsafe {
            // Mark fds created by lmdb as FD_CLOEXEC to prevent them from leaking into
            // canister sandbox process. Details in NODE-166
            let mut fd: lmdb_sys::mdb_filehandle_t = lmdb_sys::mdb_filehandle_t::default();
            lmdb_sys::mdb_env_get_fd(db_env.env(), &mut fd);
            nix::fcntl::fcntl(fd, nix::fcntl::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))
                .expect("Unable to mark FD_CLOEXEC");
        };

        // Create all databases.
        let meta = if read_only {
            db_env
                .open_db(Some("META"))
                .unwrap_or_else(|err| panic!("Error opening db for metadata: {:?}", err))
        } else {
            db_env
                .create_db(Some("META"), DatabaseFlags::empty())
                .unwrap_or_else(|err| panic!("Error creating db for metadata: {:?}", err))
        };
        let artifacts = if read_only {
            db_env
                .open_db(Some("ARTS"))
                .unwrap_or_else(|err| panic!("Error opening db for artifacts: {:?}", err))
        } else {
            db_env
                .create_db(Some("ARTS"), DatabaseFlags::empty())
                .unwrap_or_else(|err| panic!("Error creating db for artifacts: {:?}", err))
        };
        let indices = {
            type_keys
                .iter()
                .map(|type_key| {
                    // Use DUP_SORT to enable multi-value for each HeightKey.
                    let store = if read_only {
                        db_env.open_db(Some(type_key.name)).unwrap_or_else(|err| {
                            panic!("Error opening db {}: {:?}", type_key.name, err)
                        })
                    } else {
                        db_env
                            .create_db(Some(type_key.name), DatabaseFlags::DUP_SORT)
                            .unwrap_or_else(|err| {
                                panic!("Error creating db {}: {:?}", type_key.name, err)
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
    fn update_meta<'a>(
        &self,
        tx: &mut RwTransaction<'a>,
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
    /// Each index database maps HeightKey to a list of IdKey.
    fn get_index_db(&self, type_key: &TypeKey) -> Database {
        self.indices
            .iter()
            .find(|(key, _)| type_key == key)
            .unwrap_or_else(|| panic!("Error in get_index_db: {:?} does not exist", type_key))
            .1
    }

    /// Iterate messages between min and max HeightKey (inclusive).
    ///
    /// It is parameteriazed by an individual message type as long as it can be
    /// casted from the main `Artifact::Message` type.
    fn iterate<Message: TryFrom<Artifact> + HasTypeKey + 'static>(
        &self,
        min_key: HeightKey,
        max_key: HeightKey,
    ) -> Box<dyn Iterator<Item = Message>> {
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
    fn tx_insert<'a, PoolObject>(
        &self,
        tx: &mut RwTransaction<'a>,
        key: &ArtifactKey,
        value: PoolObject,
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
        self.update_meta(tx, &key.type_key, &meta)?;
        // update artifacts (ignore KeyExists)
        Artifact::save(&key.id_key, value, self.artifacts, tx, &self.log)
    }

    /// Remove the pool object of the given type/height/id key.
    fn tx_remove<'a>(&self, tx: &mut RwTransaction<'a>, key: &ArtifactKey) -> lmdb::Result<()> {
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

        let min_height;
        let max_height;
        {
            let mut cursor = tx.open_ro_cursor(index_db)?;
            let mut iter = cursor.iter_start();
            min_height = iter
                .next()
                .transpose()?
                .map(|(key, _)| HeightKey::from(key));
            max_height = iter
                .last()
                .transpose()?
                .map(|(key, _)| HeightKey::from(key));
        }
        match (min_height, max_height) {
            (Some(min), Some(max)) => self.update_meta(tx, &key.type_key, &Meta { min, max }),
            (Some(min), None) => self.update_meta(tx, &key.type_key, &Meta { min, max: min }),
            _ => tx.del(self.meta, &key.type_key, None),
        }
    }

    /// Remove all artifacts with heights less than the given HeightKey.
    fn tx_purge_below<'a>(
        &self,
        tx: &mut RwTransaction<'a>,
        height_key: HeightKey,
    ) -> lmdb::Result<()> {
        // delete from all index tables
        for type_key in Artifact::type_keys() {
            // only delete if meta exists
            if let Some(meta) = self.get_meta(tx, type_key) {
                // skip to next db if min height is already higher
                if meta.min >= height_key {
                    continue;
                }
                let index_db = self.get_index_db(type_key);
                {
                    let mut cursor = tx.open_rw_cursor(index_db)?;
                    loop {
                        match cursor.iter().next().transpose()? {
                            None => break,
                            Some((key, _)) => {
                                if HeightKey::from(key) >= height_key {
                                    break;
                                }
                                cursor.del(WriteFlags::empty())?;
                            }
                        }
                    }
                }
                let meta = if meta.max <= height_key {
                    None
                } else {
                    let mut cursor = tx.open_rw_cursor(index_db)?;
                    cursor
                        .iter_start()
                        .next()
                        .transpose()?
                        .map(|(key, _)| Meta {
                            min: HeightKey::from(key),
                            max: meta.max,
                        })
                };
                match meta {
                    None => tx.del(self.meta, &type_key, None)?,
                    Some(meta) => self.update_meta(tx, type_key, &meta)?,
                }
            }
        }
        // delete from artifacts table
        let mut cursor = tx.open_rw_cursor(self.artifacts)?;
        let height = Height::from(height_key);
        loop {
            match cursor.iter().next().transpose()? {
                None => break,
                Some((key, _)) => {
                    let id_key = IdKey::from(key);
                    if id_key.height() >= height {
                        break;
                    }
                    cursor.del(WriteFlags::empty())?;
                }
            }
        }
        Ok(())
    }
}

impl InitializablePoolSection for PersistentHeightIndexedPool<ConsensusMessage> {
    /// Insert a cup with the original bytes from which that cup was received.
    fn insert_cup_with_proto(&self, cup_with_proto: CUPWithOriginalProtobuf) {
        let mut tx = self
            .db_env
            .begin_rw_txn()
            .expect("Unable to begin transation to initialize consensus pool");
        let key = ArtifactKey::from(cup_with_proto.cup.get_id());
        self.tx_insert(
            &mut tx,
            &key,
            ValidatedArtifact {
                msg: PersistedConsensusMessage::OriginalCUPBytes(cup_with_proto.protobuf),
                timestamp: cup_with_proto.cup.content.block.as_ref().context.time,
            },
        )
        .expect("Insertion of CUP into initial consensus pool failed");
        tx.commit()
            .expect("Transaction inserting initial CUP into pool failed to commit");
    }
}

impl<Artifact: PoolArtifact, Message> HeightIndexedPool<Message>
    for PersistentHeightIndexedPool<Artifact>
where
    Message: TryFrom<Artifact> + HasTypeKey + 'static,
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
}

///////////////////////////// Consensus Pool /////////////////////////////

const RANDOM_BEACON_KEY: TypeKey = TypeKey::new("RB");
const FINALIZATION_KEY: TypeKey = TypeKey::new("FZ");
const NOTARIZATION_KEY: TypeKey = TypeKey::new("NZ");
const BLOCK_PROPOSAL_KEY: TypeKey = TypeKey::new("BP");
const BLOCK_PAYLOAD_KEY: TypeKey = TypeKey::new("PL");
const RANDOM_BEACON_SHARE_KEY: TypeKey = TypeKey::new("RBS");
const NOTARIZATION_SHARE_KEY: TypeKey = TypeKey::new("NZS");
const FINALIZATION_SHARE_KEY: TypeKey = TypeKey::new("FZS");
const RANDOM_TAPE_KEY: TypeKey = TypeKey::new("RT");
const RANDOM_TAPE_SHARE_KEY: TypeKey = TypeKey::new("RTS");
const CATCH_UP_PACKAGE_KEY: TypeKey = TypeKey::new("CUP");
const CATCH_UP_PACKAGE_SHARE_KEY: TypeKey = TypeKey::new("CUS");

const CONSENSUS_KEYS: [TypeKey; 12] = [
    RANDOM_BEACON_KEY,
    FINALIZATION_KEY,
    NOTARIZATION_KEY,
    BLOCK_PROPOSAL_KEY,
    BLOCK_PAYLOAD_KEY,
    RANDOM_BEACON_SHARE_KEY,
    NOTARIZATION_SHARE_KEY,
    FINALIZATION_SHARE_KEY,
    RANDOM_TAPE_KEY,
    RANDOM_TAPE_SHARE_KEY,
    CATCH_UP_PACKAGE_KEY,
    CATCH_UP_PACKAGE_SHARE_KEY,
];

impl HasTypeKey for RandomBeacon {
    fn type_key() -> TypeKey {
        RANDOM_BEACON_KEY
    }
}

impl HasTypeKey for Notarization {
    fn type_key() -> TypeKey {
        NOTARIZATION_KEY
    }
}

impl HasTypeKey for Finalization {
    fn type_key() -> TypeKey {
        FINALIZATION_KEY
    }
}

impl HasTypeKey for BlockProposal {
    fn type_key() -> TypeKey {
        BLOCK_PROPOSAL_KEY
    }
}

impl HasTypeKey for RandomBeaconShare {
    fn type_key() -> TypeKey {
        RANDOM_BEACON_SHARE_KEY
    }
}

impl HasTypeKey for NotarizationShare {
    fn type_key() -> TypeKey {
        NOTARIZATION_SHARE_KEY
    }
}

impl HasTypeKey for FinalizationShare {
    fn type_key() -> TypeKey {
        FINALIZATION_SHARE_KEY
    }
}

impl HasTypeKey for RandomTape {
    fn type_key() -> TypeKey {
        RANDOM_TAPE_KEY
    }
}

impl HasTypeKey for RandomTapeShare {
    fn type_key() -> TypeKey {
        RANDOM_TAPE_SHARE_KEY
    }
}

impl HasTypeKey for CatchUpPackage {
    fn type_key() -> TypeKey {
        CATCH_UP_PACKAGE_KEY
    }
}

impl HasTypeKey for CatchUpPackageShare {
    fn type_key() -> TypeKey {
        CATCH_UP_PACKAGE_SHARE_KEY
    }
}

impl From<ConsensusMessageId> for ArtifactKey {
    fn from(msg_id: ConsensusMessageId) -> Self {
        let type_key = match msg_id.hash {
            ConsensusMessageHash::RandomBeacon(_) => RANDOM_BEACON_KEY,
            ConsensusMessageHash::Finalization(_) => FINALIZATION_KEY,
            ConsensusMessageHash::Notarization(_) => NOTARIZATION_KEY,
            ConsensusMessageHash::BlockProposal(_) => BLOCK_PROPOSAL_KEY,
            ConsensusMessageHash::RandomBeaconShare(_) => RANDOM_BEACON_SHARE_KEY,
            ConsensusMessageHash::NotarizationShare(_) => NOTARIZATION_SHARE_KEY,
            ConsensusMessageHash::FinalizationShare(_) => FINALIZATION_SHARE_KEY,
            ConsensusMessageHash::RandomTape(_) => RANDOM_TAPE_KEY,
            ConsensusMessageHash::RandomTapeShare(_) => RANDOM_TAPE_SHARE_KEY,
            ConsensusMessageHash::CatchUpPackage(_) => CATCH_UP_PACKAGE_KEY,
            ConsensusMessageHash::CatchUpPackageShare(_) => CATCH_UP_PACKAGE_SHARE_KEY,
        };
        Self {
            type_key,
            height_key: HeightKey::from(msg_id.height),
            id_key: IdKey::from((msg_id.height, msg_id.hash.digest())),
        }
    }
}

impl From<ConsensusMessage> for PersistedConsensusMessage {
    fn from(message: ConsensusMessage) -> PersistedConsensusMessage {
        PersistedConsensusMessage::ConsensusMessage(message)
    }
}

impl TryFrom<PersistedConsensusMessage> for ConsensusMessage {
    type Error = String;
    fn try_from(message: PersistedConsensusMessage) -> Result<Self, Self::Error> {
        match message {
            PersistedConsensusMessage::OriginalCUPBytes(protobuf) => {
                CatchUpPackage::try_from(&protobuf).map(ConsensusMessage::CatchUpPackage)
            }
            PersistedConsensusMessage::ConsensusMessage(message) => Ok(message),
        }
    }
}

impl PoolArtifact for ConsensusMessage {
    type ObjectType = ValidatedArtifact<PersistedConsensusMessage>;
    type Id = ConsensusMessageId;

    fn type_keys() -> &'static [TypeKey] {
        &CONSENSUS_KEYS
    }

    fn save<'a>(
        key: &IdKey,
        mut value: Self::ObjectType,
        artifacts: Database,
        tx: &mut RwTransaction<'a>,
        log: &ReplicaLogger,
    ) -> lmdb::Result<()> {
        // special handling for block proposal & its payload
        if let PersistedConsensusMessage::ConsensusMessage(ConsensusMessage::BlockProposal(
            mut proposal,
        )) = value.msg
        {
            // store block payload separately
            let block = proposal.content.as_mut();
            let payload_hash = block.payload.get_hash().clone();
            let payload = block.payload.as_ref();
            let start_height = payload.dkg_interval_start_height();
            let payload_type = payload.payload_type();
            {
                let payload_key = IdKey::from((block.height(), payload_hash.get_ref()));
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
                Box::new(move || {
                    (
                        BatchPayload::default(),
                        dkg::Dealings::new_empty(start_height),
                    )
                        .into()
                }),
            );
            value.msg = PersistedConsensusMessage::from(proposal.into_message());
        }
        let bytes = log_err!(
            bincode::serialize::<Self::ObjectType>(&value),
            log,
            "ConsensusArtifact::save serialize"
        )
        .ok_or(lmdb::Error::Panic)?;
        tx.put(artifacts, &key, &bytes, WriteFlags::empty())
    }

    fn load_as<'a, T: TryFrom<Self>>(
        key: &IdKey,
        db_env: Arc<Environment>,
        artifacts: Database,
        tx: &RoTransaction<'a>,
        log: &ReplicaLogger,
    ) -> lmdb::Result<T> {
        let bytes = tx.get(artifacts, &key)?;
        let mut artifact = log_err!(
            bincode::deserialize::<Self::ObjectType>(bytes),
            log,
            "ConsensusArtifact::load_as deserialize"
        )
        .ok_or(lmdb::Error::Panic)?;
        // Lazy loading of block proposal and its payload
        if let PersistedConsensusMessage::ConsensusMessage(ConsensusMessage::BlockProposal(
            mut proposal,
        )) = artifact.msg
        {
            let block = proposal.content.as_mut();
            let payload_hash = block.payload.get_hash();
            let payload_key = IdKey::from((block.height(), payload_hash.get_ref()));
            let log = log.clone();
            block.payload = Payload::new_with(
                payload_hash.clone(),
                block.payload.payload_type(),
                Box::new(move || {
                    log_err!(
                        load_block_payload(db_env, artifacts, &payload_key, &log),
                        log,
                        "ConsensusArtifact::load_as load_block_payload"
                    )
                    .unwrap()
                }),
            );
            artifact.msg = PersistedConsensusMessage::from(proposal.into_message());
        }
        log_err!(
            ConsensusMessage::try_from(artifact.msg)
                .map_err(|_| ())
                .and_then(|msg| msg.try_into().map_err(|_| ())),
            log,
            "ConsensusArtifact::load_as casting"
        )
        .ok_or(lmdb::Error::Panic)
    }
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

    fn tx_mutate(&mut self, ops: PoolSectionOps<ValidatedConsensusArtifact>) -> lmdb::Result<()> {
        let mut tx = self.db_env.begin_rw_txn()?;
        for op in ops.ops {
            match op {
                PoolSectionOp::Insert(artifact) => {
                    let msg_id = artifact.msg.get_id();
                    let key = ArtifactKey::from(msg_id);
                    // Ignore KeyExist
                    match self.tx_insert(
                        &mut tx,
                        &key,
                        artifact.map(PersistedConsensusMessage::ConsensusMessage),
                    ) {
                        Err(lmdb::Error::KeyExist) => Ok(()),
                        result => result,
                    }?
                }
                PoolSectionOp::Remove(msg_id) => {
                    let key = ArtifactKey::from(msg_id);
                    // Note: We do not remove block payloads here, but leave it to purging.
                    self.tx_remove(&mut tx, &key)?
                }
                PoolSectionOp::PurgeBelow(height) => {
                    let height_key = HeightKey::from(height);
                    self.tx_purge_below(&mut tx, height_key)?
                }
            }
        }
        tx.commit()
    }
}

impl crate::consensus_pool::MutablePoolSection<ValidatedConsensusArtifact>
    for PersistentHeightIndexedPool<ConsensusMessage>
{
    fn mutate(&mut self, ops: PoolSectionOps<ValidatedConsensusArtifact>) {
        log_err!(self.tx_mutate(ops), self.log, "ConsensusArtifact::mutate");
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
            bincode::deserialize::<ValidatedArtifact<PersistedConsensusMessage>>(bytes),
            self.log,
            "get_timestamp deserialize"
        )
        .map(|x| x.timestamp)
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
                    bincode::deserialize::<PersistedConsensusMessage>(bytes),
                    log,
                    "CatchUpPackage protobuf deserialize"
                )
                .ok_or(lmdb::Error::Panic)?;
                match artifact {
                    PersistedConsensusMessage::OriginalCUPBytes(protobuf) => Ok(protobuf),
                    PersistedConsensusMessage::ConsensusMessage(
                        ConsensusMessage::CatchUpPackage(cup),
                    ) => Ok(pb::CatchUpPackage::from(&cup)),
                    _ => panic!("Unexpected artifact type when deserializing CUP"),
                }
            },
            self.log.clone(),
        )
        .next()
        .unwrap_or_else(|| {
            panic!(
                "This should be impossible since we found a max height at {:?}",
                h
            )
        })
    }

    /// Number of artifacts in the DB.
    fn size(&self) -> u64 {
        if let Some(tx) = log_err!(self.db_env.begin_ro_txn(), &self.log, "begin_ro_txn") {
            if let Some(mut cursor) = log_err!(
                tx.open_ro_cursor(self.artifacts),
                &self.log,
                "open_ro_cursor"
            ) {
                return cursor.iter().count() as u64;
            }
        }
        0
    }
}

///////////////////////////// Certification Pool /////////////////////////////

const CERTIFICATION_KEY: TypeKey = TypeKey::new("CE");
const CERTIFICATION_SHARE_KEY: TypeKey = TypeKey::new("CES");

const CERTIFICATION_KEYS: [TypeKey; 2] = [CERTIFICATION_KEY, CERTIFICATION_SHARE_KEY];

impl HasTypeKey for Certification {
    fn type_key() -> TypeKey {
        CERTIFICATION_KEY
    }
}

impl HasTypeKey for CertificationShare {
    fn type_key() -> TypeKey {
        CERTIFICATION_SHARE_KEY
    }
}

impl PoolArtifact for CertificationMessage {
    type ObjectType = CertificationMessage;
    type Id = CertificationMessageId;

    fn type_keys() -> &'static [TypeKey] {
        &CERTIFICATION_KEYS
    }

    fn save<'a>(
        key: &IdKey,
        value: Self::ObjectType,
        artifacts: Database,
        tx: &mut RwTransaction<'a>,
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

    fn load_as<'a, T: TryFrom<Self>>(
        key: &IdKey,
        _db_env: Arc<Environment>,
        artifacts: Database,
        tx: &RoTransaction<'a>,
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
        let key = ArtifactKey {
            type_key: T::type_key(),
            id_key: IdKey::from((value.height(), hash.get_ref())),
            height_key: HeightKey::from(value.height()),
        };
        let mut tx = self.db_env.begin_rw_txn()?;
        self.tx_insert(&mut tx, &key, value.into())?;
        tx.commit()
    }

    fn purge_below_height(&self, height: Height) -> lmdb::Result<()> {
        let mut tx = self.db_env.begin_rw_txn()?;
        self.tx_purge_below(&mut tx, HeightKey::from(height))?;
        tx.commit()
    }
}

impl crate::certification_pool::MutablePoolSection
    for PersistentHeightIndexedPool<CertificationMessage>
{
    fn insert(&self, message: CertificationMessage) {
        match message {
            CertificationMessage::Certification(value) => log_err!(
                self.insert_message(ic_crypto::crypto_hash(&value), value),
                self.log,
                "CertificationMessage::Certification::insert"
            ),
            CertificationMessage::CertificationShare(value) => log_err!(
                self.insert_message(ic_crypto::crypto_hash(&value), value),
                self.log,
                "CertificationMessage::CertificationShare::insert"
            ),
        };
    }

    fn purge_below(&self, height: Height) {
        log_err!(
            self.purge_below_height(height),
            self.log,
            "CertificationArtifact::purge_below"
        );
    }

    fn certifications(&self) -> &dyn HeightIndexedPool<Certification> {
        self
    }

    fn certification_shares(&self) -> &dyn HeightIndexedPool<CertificationShare> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_pool::MutablePoolSection;
    use crate::test_utils::*;
    use ic_test_utilities::{mock_time, with_test_replica_logger};
    use ic_types::consensus::BlockProposal;
    use std::panic;
    use std::path::Path;
    use std::time::Duration;

    // We test if the binding links to the required LMDB version.
    #[test]
    fn test_lmdb_version() {
        println!(
            "LMDB VERSION {}.{}.{}",
            lmdb_sys::MDB_VERSION_MAJOR,
            lmdb_sys::MDB_VERSION_MINOR,
            lmdb_sys::MDB_VERSION_PATCH
        );
        assert_eq!(lmdb_sys::MDB_VERSION_MAJOR, 0);
        assert_eq!(lmdb_sys::MDB_VERSION_MINOR, 9);
        assert_eq!(lmdb_sys::MDB_VERSION_PATCH, 70);
    }

    #[test]
    fn test_encode_decode_key() {
        let height = Height::from(10);
        let beacon = fake_random_beacon(height);
        let msg = ConsensusMessage::RandomBeacon(beacon);
        let hash = msg.get_cm_hash();
        let height_key = HeightKey::from(height);
        let id_key = IdKey::from((height, hash.digest()));
        assert_eq!(Height::from(height_key), height, "height does not match");
        assert_eq!(id_key.height(), height, "Height of IdKey does not match");
        assert_eq!(
            &id_key.hash(),
            hash.digest(),
            "Hash of IdKey does not match"
        );
    }

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

    // Tests the pool though the PoolSection trait, including inserting
    // and rebooting.
    #[test]
    fn test_as_pool_section() {
        run_persistent_pool_test("test_as_pool_section", |config, log| {
            let height = Height::from(11);
            let block_proposal = fake_block_proposal(Height::from(11));
            let msg = ConsensusMessage::BlockProposal(block_proposal);
            let msg_expected = msg.clone();
            let hash = msg_expected.get_cm_hash();
            let msg_id = ConsensusMessageId { hash, height };
            // Create a pool and insert an item.
            {
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                    config.clone(),
                    false,
                    log.clone(),
                );
                let mut ops = PoolSectionOps::new();
                ops.insert(ValidatedConsensusArtifact {
                    msg,
                    timestamp: mock_time(),
                });
                pool.mutate(ops);
            }
            // Test that we can get the item after rebuilding the pool.
            {
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                    config.clone(),
                    false,
                    log.clone(),
                );
                assert!(pool.contains(&msg_id));
                let get_result = pool.get(&msg_id);
                match get_result {
                    Some(artifact_result) => {
                        assert_eq!(artifact_result, msg_expected);
                    }
                    None => {
                        panic!("Get failed");
                    }
                }
                let mut ops = PoolSectionOps::new();
                ops.remove(msg_id.clone());
                pool.mutate(ops);
            }
            // Test that the item's removal survived a reboot.
            {
                let pool = PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                assert!(!pool.contains(&msg_id));
                assert!(pool.get(&msg_id).is_none());
            }
        })
    }

    // Tests the pool through the HeightIndexedPool trait.
    //
    // This is the most comprehensive functional test. It directly tests all
    // of the HeightIndexedPool methods, it also indirectly tests whether
    // reference counting is working properly. This because if we have
    // reference count leak and some instance of DB is alive, the destroy()
    // call in run_persistent_pool_test() will fail as it requires exclusive
    // access to the DB directory.
    #[test]
    fn test_as_height_indexed_pool() {
        run_persistent_pool_test("test_as_height_indexed_pool", |config, log| {
            let rb_ops = random_beacon_ops();
            let fz_ops = finalization_ops();
            let nz_ops = notarization_ops();
            let bp_ops = block_proposal_ops();
            let rbs_ops = random_beacon_share_ops();
            let nzs_ops = notarization_share_ops();
            let fzs_ops = finalization_share_ops();
            let rt_ops = random_tape_ops();
            let rts_ops = random_tape_share_ops();

            // Insert a bunch of items and test that the pool returns them
            {
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                    config.clone(),
                    false,
                    log.clone(),
                );

                pool.mutate(rb_ops.clone());
                match_ops_to_results(&rb_ops, pool.random_beacon(), false);

                pool.mutate(fz_ops.clone());
                match_ops_to_results(&fz_ops, pool.finalization(), false);

                pool.mutate(nz_ops.clone());
                match_ops_to_results(&nz_ops, pool.notarization(), false);

                pool.mutate(bp_ops.clone());
                match_ops_to_results(&bp_ops, pool.block_proposal(), false);

                pool.mutate(rbs_ops.clone());
                match_ops_to_results(&rbs_ops, pool.random_beacon_share(), true);

                pool.mutate(nzs_ops.clone());
                match_ops_to_results(&nzs_ops, pool.notarization_share(), true);

                pool.mutate(fzs_ops.clone());
                match_ops_to_results(&fzs_ops, pool.finalization_share(), true);

                pool.mutate(rt_ops.clone());
                match_ops_to_results(&rt_ops, pool.random_tape(), false);

                pool.mutate(rts_ops.clone());
                match_ops_to_results(&rts_ops, pool.random_tape_share(), true);
            }

            // Test the matching after a reboot.
            {
                let pool = PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                match_ops_to_results(&rb_ops, pool.random_beacon(), false);
                match_ops_to_results(&fz_ops, pool.finalization(), false);
                match_ops_to_results(&nz_ops, pool.notarization(), false);
                match_ops_to_results(&bp_ops, pool.block_proposal(), false);
                match_ops_to_results(&rbs_ops, pool.random_beacon_share(), true);
                match_ops_to_results(&nzs_ops, pool.notarization_share(), true);
                match_ops_to_results(&fzs_ops, pool.finalization_share(), true);
                match_ops_to_results(&rt_ops, pool.random_tape(), false);
                match_ops_to_results(&rts_ops, pool.random_tape_share(), true);
            }
        })
    }

    fn make_random_beacon_at_height(i: u64) -> ValidatedConsensusArtifact {
        let random_beacon = fake_random_beacon(Height::from(i));
        ValidatedConsensusArtifact {
            msg: ConsensusMessage::RandomBeacon(random_beacon),
            timestamp: mock_time(),
        }
    }

    fn make_random_beacon_msg_id_at_height(i: u64) -> ConsensusMessageId {
        let hash = make_random_beacon_at_height(i).msg.get_cm_hash();
        let height = Height::from(i);
        ConsensusMessageId { hash, height }
    }

    fn check_iter_original(iter: Box<dyn Iterator<Item = RandomBeacon>>) {
        // Now make sure the iterator still sees the old values
        // and doesn't see the new ones.
        let msgs_from_pool: Vec<RandomBeacon> = iter.collect();
        assert_eq!(msgs_from_pool.len(), 16);
        for i in 3..15 {
            let msg = &msgs_from_pool[i - 3];
            assert_eq!(msg.content.height, Height::from(i as u64));
        }
    }

    fn check_iter_mutated(iter: Box<dyn Iterator<Item = RandomBeacon>>) {
        let msgs_from_pool: Vec<RandomBeacon> = iter.collect();
        assert_eq!(msgs_from_pool.len(), 3);
        assert_eq!(msgs_from_pool[0].content.height, Height::from(1));
        assert_eq!(msgs_from_pool[1].content.height, Height::from(2));
        assert_eq!(msgs_from_pool[2].content.height, Height::from(20));
    }

    // Tests if payloads are persisted and removed correctly together with block
    // proposals.
    #[test]
    fn test_block_proposal_and_payload_correspondence() {
        run_persistent_pool_test(
            "test_block_proposal_and_payload_correspondence",
            |config, log| {
                let insert_ops = block_proposal_ops();
                let msgs = insert_ops
                    .ops
                    .iter()
                    .map(|op| {
                        if let PoolSectionOp::Insert(artifact) = op {
                            &artifact.msg
                        } else {
                            panic!("Expect Insert but found {:?}", op)
                        }
                    })
                    .collect::<Vec<_>>();
                let mut remove_ops = msgs
                    .iter()
                    .map(|msg| PoolSectionOp::Remove(msg.get_id()))
                    .collect::<Vec<_>>();
                let mut payloads: Vec<BlockPayload> = msgs
                    .iter()
                    .map(|msg| {
                        BlockProposal::assert(msg)
                            .unwrap()
                            .as_ref()
                            .payload
                            .as_ref()
                            .clone()
                    })
                    .collect::<Vec<_>>();
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                pool.mutate(insert_ops);
                let proposals = pool.block_proposal().get_all().collect::<Vec<_>>();
                assert!(proposals.iter().all(|proposal| proposal.check_integrity()));
                assert_eq!(
                    payloads,
                    proposals
                        .iter()
                        .map(|proposal| proposal.as_ref().payload.as_ref().clone())
                        .collect::<Vec<_>>()
                );

                // Remove the first 5 block proposals
                let _ = payloads.split_off(5);
                let remove_first_5 = remove_ops.split_off(5);
                pool.mutate(PoolSectionOps {
                    ops: remove_first_5,
                });
                let iter = pool.block_proposal().get_all();
                assert_eq!(
                    payloads,
                    iter.map(|proposal| proposal.as_ref().payload.as_ref().clone())
                        .collect::<Vec<_>>()
                );

                // check integrity
                pool.block_proposal()
                    .get_all()
                    .for_each(|proposal| assert!(proposal.check_integrity()));

                // Remove all
                pool.mutate(PoolSectionOps { ops: remove_ops });
                let mut iter = pool.block_proposal().get_all();
                assert!(iter.next().is_none());
            },
        )
    }

    // Tests that iterators are created on snapshots of the pool and that
    // the returned values do not reflect any updates after the iterator
    // was created.
    //
    // This also illustrates passing iterators by value when the pool is
    // left behind, emulating how iterators might be used to perform
    // async work.
    #[test]
    fn test_iterating_while_inserting_doesnt_see_new_updates() {
        run_persistent_pool_test(
            "test_iterating_while_inserting_doesnt_see_new_updates",
            |config, log| {
                let rb_ops = random_beacon_ops();
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                pool.mutate(rb_ops);
                let iter = pool.random_beacon().get_all();

                // Before we go through the iterator values we'll remove all of
                // of the values in the current range and add values before and after
                // the iterator's initial range (3..15).
                let mut ops = PoolSectionOps::new();
                ops.insert(make_random_beacon_at_height(1));
                ops.insert(make_random_beacon_at_height(2));
                ops.insert(make_random_beacon_at_height(20));
                for i in 3..20 {
                    ops.remove(make_random_beacon_msg_id_at_height(i));
                }
                pool.mutate(ops);

                // The original iterator shouldn't observe the changes
                // we made above
                check_iter_original(iter);

                // A new iterator should see the new values.
                check_iter_mutated(pool.random_beacon().get_all());
            },
        );
    }

    // Tests that iterators obtained from the pool can outlive it, meaning it's
    // safe to pass them around without the pool itself. Even though it isn't
    // likely that the iterator will outlive the pool, ever, it is necessary
    // to make make sure it can to guarantee the safety of passing it as an
    // argument without the pool.
    #[test]
    fn test_iterator_can_outlive_the_pool() {
        run_persistent_pool_test("test_iterator_can_outlive_the_pool", |config, log| {
            let rb_ops = random_beacon_ops();
            let iter;

            // Create a pool in this inner scope, which will be destroyed
            // before the iterator is used.
            {
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                pool.mutate(rb_ops.clone());
                iter = pool.random_beacon().get_all();
            }

            let msgs_from_pool: Vec<RandomBeacon> = iter.collect();
            assert_eq!(msgs_from_pool.len(), rb_ops.ops.len());
            for (i, op) in rb_ops.ops.iter().enumerate() {
                if let PoolSectionOp::Insert(artifact) = &op {
                    assert_eq!(
                        RandomBeacon::assert(&artifact.msg).unwrap(),
                        &msgs_from_pool[i]
                    );
                }
            }
        });
    }

    // Tests that, if configured to do so, the pool will delete the data
    // directories on drop. This is useful to cleanup after running
    // tests.
    #[test]
    fn test_persistent_pool_path_is_cleanedup_after_tests() {
        with_test_replica_logger(|log| {
            let tmp =
                ic_test_utilities::artifact_pool_config::with_test_lmdb_pool_config(|config| {
                    let path = config.persistent_pool_validated_persistent_db_path.clone();
                    let rb_ops = random_beacon_ops();
                    {
                        let mut pool =
                            PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                        pool.mutate(rb_ops);
                    }
                    path
                });
            assert!(!Path::new(&tmp).exists());
        })
    }

    // Test if purge survives reboot.
    #[test]
    fn test_purge_survives_reboot() {
        run_persistent_pool_test("test_purge_survives_reboot", |config, log| {
            // create a pool and purge at height 10
            {
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                    config.clone(),
                    false,
                    log.clone(),
                );
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
            // create the same pool again, check if purge was persisted
            {
                let pool = PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                assert_eq!(
                    pool.random_beacon().height_range().map(|r| r.min),
                    Some(Height::from(10))
                );
            }
        });
    }

    // Test if timestamp survives reboot.
    #[test]
    fn test_timestamp_survives_reboot() {
        run_persistent_pool_test("test_purge_survives_reboot", |config, log| {
            let time_0 = mock_time() + Duration::from_secs(1234);
            // create a pool and insert an artifact
            {
                let mut pool = PersistentHeightIndexedPool::new_consensus_pool(
                    config.clone(),
                    false,
                    log.clone(),
                );
                // insert a few things
                let mut ops = PoolSectionOps::new();
                let random_beacon = fake_random_beacon(Height::from(10));
                let msg = ConsensusMessage::RandomBeacon(random_beacon);
                let msg_id = msg.get_id();
                ops.insert(ValidatedConsensusArtifact {
                    msg,
                    timestamp: time_0,
                });
                pool.mutate(ops);

                assert_eq!(pool.get_timestamp(&msg_id), Some(time_0));
            }

            // create the same pool again, check if timestamp was preserved
            {
                let pool = PersistentHeightIndexedPool::new_consensus_pool(config, false, log);
                let random_beacon = pool
                    .random_beacon()
                    .get_by_height(Height::from(10))
                    .next()
                    .unwrap();
                let msg_id = random_beacon.get_id();
                assert_eq!(pool.get_timestamp(&msg_id), Some(time_0));
            }
        });
    }
}
