//! Store headers received from p2p network.

use crate::common::{BlockHeight, BlockchainHeader};
use bitcoin::{
    block::Header as PureHeader,
    consensus::{encode, Decodable, Encodable},
    io, BlockHash, Work,
};
use ic_btc_validation::ValidateHeaderError;
use ic_logger::{error, ReplicaLogger};
use lmdb::{
    Cursor, Database, DatabaseFlags, Environment, EnvironmentFlags, RoTransaction, RwTransaction,
    Transaction, WriteFlags,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use thiserror::Error;

/// The max size (in bytes) of a LMDB cache, also know as the LMDB map
/// size. It is a constant because it cannot be changed once DB is created.
const MAX_LMDB_CACHE_SIZE: usize = 0x2_0000_0000; // 8GB

/// Block header with its height in the blockchain and other info.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct HeaderData<Header> {
    /// Block header.
    pub header: Header,
    /// Height of the header.
    pub height: BlockHeight,
    /// Total work of the blockchain leading up to this header.
    /// That is, this field is the sum of work of this header and all its ancestors.
    pub work: Work,
}

/// Header node contains both header data and children hash.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct HeaderNode<Header> {
    /// Header data.
    pub data: HeaderData<Header>,
    /// Headers of the the successors of this node.
    pub children: Vec<BlockHash>,
}

impl<Header> From<HeaderData<Header>> for HeaderNode<Header> {
    fn from(data: HeaderData<Header>) -> Self {
        Self {
            data,
            children: Default::default(),
        }
    }
}

/// Tip is the same as [HeaderData].
pub type Tip<Header> = HeaderData<Header>;

impl<Header: Encodable> Encodable for HeaderData<Header> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let header_size = self.header.consensus_encode(writer)?;
        let height_size = self.height.consensus_encode(writer)?;
        let work_bytes = self.work.to_be_bytes();
        let work_size = work_bytes.consensus_encode(writer)?;
        Ok(header_size + height_size + work_size)
    }
}

impl<Header: Decodable> Decodable for HeaderData<Header> {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        let header = Header::consensus_decode(reader)?;
        let height = BlockHeight::consensus_decode(reader)?;
        let work_bytes = <[u8; 32]>::consensus_decode(reader)?;
        Ok(Self {
            header,
            height,
            work: Work::from_be_bytes(work_bytes),
        })
    }
}

/// The result when `add_header(...)` is called.
#[derive(Debug)]
pub enum AddHeaderResult {
    /// When the input header is added to the header_cache.
    HeaderAdded(BlockHash),
    /// When the input header already exists in the header_cache.
    HeaderAlreadyExists,
}

#[derive(Debug, Error)]
pub enum AddHeaderError {
    /// When the received header is invalid (eg: not of the right format).
    #[error("Received an invalid block header: {0}")]
    InvalidHeader(BlockHash, ValidateHeaderError),
    /// When the predecessor of the input header is not part of header_cache.
    #[error("Received a block header where we do not have the previous header in the cache: {0}")]
    PrevHeaderNotCached(BlockHash),
    /// When there is internal error writing to the cache.
    #[error("Internal error: {0}")]
    Internal(String),
}

pub struct InMemoryHeaderCache<Header> {
    /// The starting point of the blockchain.
    genesis: PureHeader,

    /// Maps block hash to [HeaderNode].
    cache: HashMap<BlockHash, HeaderNode<Header>>,

    /// Known tips.
    tips: Vec<Tip<Header>>,
}

pub trait HeaderCache: Send + Sync {
    type Header;

    /// Return the genesis header.
    fn get_genesis(&self) -> PureHeader;

    /// Return the header for the given block hash.
    fn get_header(&self, hash: &BlockHash) -> Option<HeaderNode<Self::Header>>;

    /// Add the input header to cache.
    fn add_header(
        &self,
        block_hash: BlockHash,
        header: Self::Header,
    ) -> Result<AddHeaderResult, AddHeaderError>;

    /// Return the tip header with the highest cumulative work.
    fn get_active_chain_tip(&self) -> Tip<Self::Header>;

    /// Return the number of tips.
    fn get_num_tips(&self) -> usize;

    #[cfg(test)]
    /// Return all tips.
    fn get_tips(&self) -> Vec<Tip<Self::Header>>;
}

impl<Header: BlockchainHeader> InMemoryHeaderCache<Header> {
    /// Creates a new cache with a genesis header
    pub fn new(genesis: Header) -> RwLock<Self> {
        let tips = vec![Tip {
            header: genesis.clone(),
            height: 0,
            work: genesis.work(),
        }];
        let data = HeaderData {
            header: genesis.clone(),
            height: 0,
            work: genesis.work(),
        };
        let mut cache = HashMap::new();
        cache.insert(genesis.block_hash(), data.into());

        RwLock::new(InMemoryHeaderCache {
            genesis: genesis.into_pure_header(),
            cache,
            tips,
        })
    }
}

impl<Header: BlockchainHeader + Send + Sync> HeaderCache for RwLock<InMemoryHeaderCache<Header>> {
    type Header = Header;

    fn get_genesis(&self) -> PureHeader {
        self.read().unwrap().genesis
    }

    fn get_header(&self, hash: &BlockHash) -> Option<HeaderNode<Header>> {
        self.read().unwrap().cache.get(hash).cloned()
    }

    fn add_header(
        &self,
        block_hash: BlockHash,
        header: Header,
    ) -> Result<AddHeaderResult, AddHeaderError> {
        let mut this = self.write().unwrap();
        let parent_hash = header.prev_block_hash();
        let parent = this
            .cache
            .get_mut(&parent_hash)
            .ok_or(AddHeaderError::PrevHeaderNotCached(parent_hash))?;

        let tip = HeaderData {
            header: header.clone(),
            height: parent.data.height + 1,
            work: parent.data.work + header.work(),
        };
        parent.children.push(block_hash);

        // Update the tip headers.
        // If the previous header already exists in `tips`, then update it with the new tip.
        let maybe_node_idx = this
            .tips
            .iter()
            .position(|tip| tip.header.block_hash() == parent_hash);

        match maybe_node_idx {
            Some(idx) => {
                this.tips[idx] = tip.clone();
            }
            None => {
                // If the previous header is not a tip, then add the `cached_header` as a tip.
                this.tips.push(tip.clone())
            }
        };

        this.cache.insert(block_hash, tip.into());

        Ok(AddHeaderResult::HeaderAdded(block_hash))
    }

    fn get_active_chain_tip(&self) -> Tip<Header> {
        self.read()
            .unwrap()
            .tips
            .iter()
            .max_by(|x, y| x.work.cmp(&y.work))
            .cloned()
            .unwrap_or_else(|| panic!("Impossible: failed to find active_chain_tip"))
    }

    fn get_num_tips(&self) -> usize {
        self.read().unwrap().tips.len()
    }

    #[cfg(test)]
    fn get_tips(&self) -> Vec<Tip<Header>> {
        self.read().unwrap().tips.clone()
    }
}

fn create_db_env(path: &Path) -> Environment {
    let mut builder = Environment::new();
    let builder_flags = EnvironmentFlags::NO_TLS;
    let permission = 0o644;
    builder.set_flags(builder_flags);
    // 3 databases: 1 for headers, 1 for tips, 1 for parent-child relation.
    builder.set_max_dbs(3);
    builder.set_map_size(MAX_LMDB_CACHE_SIZE);

    let db_env = builder
        .open_with_permissions(path, permission)
        .unwrap_or_else(|err| {
            panic!(
                "Error opening LMDB environment with permissions at {:?}: {:?}",
                path, err
            )
        });
    db_env
}

#[derive(Error, Debug)]
pub enum LMDBCacheError {
    #[error("LMDB error {0}")]
    Lmdb(lmdb::Error),
    #[error("Decoding error {0}")]
    Decode(#[from] encode::Error),
    #[error("Encoding error {0}")]
    Encode(#[from] io::Error),
}

impl From<lmdb::Error> for LMDBCacheError {
    fn from(err: lmdb::Error) -> Self {
        Self::Lmdb(err)
    }
}

/// Macro that logs the error when result is not Ok.
macro_rules! log_err {
    ($r:expr, $log:expr, $reason:expr) => {
        $r.map_err(|err| {
            error!($log, "Error in DB operation {}: {:?}", $reason, err);
            err
        })
    };
}

/// Like log_err, but won't log the error if it matches the given error code.
macro_rules! log_err_except {
    ($r:expr, $log:expr, $code:pat, $reason:expr) => {
        $r.map_err(|err| match err {
            $code => {}
            _ => error!($log, "Error in DB operation {}: {:?}", $reason, err),
        })
        .ok()
    };
}

pub struct LMDBHeaderCache<Header> {
    genesis: Header,
    db_env: Environment,
    // Map BlockHash to HeaderData.
    headers: Database,
    // Map BlockHash to Tip.
    tips: Database,
    // Map parent's BlockHash to child's BlockHash, duplicated key (parent's hash) allowed.
    children: Database,
    log: ReplicaLogger,
}

impl<Header: BlockchainHeader> LMDBHeaderCache<Header> {
    /// Load the cache with a genesis header and cache directory.
    pub fn new(genesis: Header, cache_dir: &str, log: ReplicaLogger) -> Self {
        let mut path = PathBuf::from(cache_dir);
        path.push("headers");
        let path = path.as_path();
        std::fs::create_dir_all(path).ok();
        let db_env = create_db_env(path);
        let headers = db_env
            .create_db(Some("HEADERS"), DatabaseFlags::empty())
            .unwrap_or_else(|err| panic!("Error creating db for metadata: {:?}", err));
        let tips = db_env
            .create_db(Some("TIPS"), DatabaseFlags::empty())
            .unwrap_or_else(|err| panic!("Error creating db for metadata: {:?}", err));
        let children = db_env
            .create_db(Some("CHILDREN"), DatabaseFlags::DUP_SORT)
            .unwrap_or_else(|err| panic!("Error creating db for metadata: {:?}", err));

        let cache = LMDBHeaderCache {
            genesis: genesis.clone(),
            db_env,
            headers,
            tips,
            children,
            log,
        };

        cache
            .run_rw_txn(|tx| cache.tx_add_header(tx, None, genesis.block_hash(), genesis))
            .unwrap();

        cache
    }

    fn tx_get_tips<Tx: Transaction>(
        &self,
        tx: &mut Tx,
    ) -> Result<Vec<Tip<Header>>, LMDBCacheError> {
        let mut cursor = tx.open_ro_cursor(self.tips)?;
        cursor
            .iter_start()
            .map(|row| {
                let (_, mut value) = row?;
                let tip = <Tip<Header>>::consensus_decode(&mut value)?;
                Ok(tip)
            })
            .collect::<Result<_, _>>()
    }

    fn tx_get_num_tips<Tx: Transaction>(&self, tx: &mut Tx) -> Result<usize, LMDBCacheError> {
        let mut cursor = tx.open_ro_cursor(self.tips)?;
        Ok(cursor.iter_start().count())
    }

    fn tx_get_children<Tx: Transaction>(
        &self,
        tx: &mut Tx,
        hash: &BlockHash,
    ) -> Result<Vec<BlockHash>, LMDBCacheError> {
        let mut cursor = tx.open_ro_cursor(self.children)?;
        let children = cursor
            .iter_dup_of(hash)
            .map(|row| {
                let (_key, mut value) = row?;
                let child_hash = BlockHash::consensus_decode(&mut value)?;
                Ok(child_hash)
            })
            .collect::<Result<Vec<_>, LMDBCacheError>>()?;
        Ok(children)
    }

    fn tx_get_header<Tx: Transaction>(
        &self,
        tx: &mut Tx,
        hash: &BlockHash,
    ) -> Result<HeaderNode<Header>, LMDBCacheError> {
        let mut bytes = tx.get(self.headers, hash)?;
        let data = <HeaderData<Header>>::consensus_decode(&mut bytes)?;
        let children = self.tx_get_children(tx, hash)?;
        Ok(HeaderNode { data, children })
    }

    fn tx_add_child(
        &self,
        tx: &mut RwTransaction,
        parent: &BlockHash,
        child: &BlockHash,
    ) -> Result<(), LMDBCacheError> {
        Ok(tx.put(self.children, parent, child, WriteFlags::empty())?)
    }

    fn tx_add_header(
        &self,
        tx: &mut RwTransaction,
        parent: Option<&HeaderNode<Header>>,
        block_hash: BlockHash,
        header: Header,
    ) -> Result<AddHeaderResult, LMDBCacheError> {
        let tip = Tip {
            header: header.clone(),
            height: parent.map(|p| p.data.height + 1).unwrap_or_default(),
            work: parent
                .map(|p| p.data.work + header.work())
                .unwrap_or(header.work()),
        };
        let mut bytes = Vec::new();
        tip.consensus_encode(&mut bytes)?;
        tx.put(self.headers, &block_hash, &bytes, WriteFlags::empty())?;
        tx.put(self.tips, &block_hash, &bytes, WriteFlags::empty())?;

        if let Some(parent) = parent {
            let parent_hash = parent.data.header.block_hash();
            self.tx_add_child(tx, &parent_hash, &block_hash)?;
            // If the previous header already exists in `tips`, then remove it
            for tip in self.tx_get_tips(tx)?.iter() {
                let block_hash = tip.header.block_hash();
                if block_hash == parent_hash {
                    tx.del(self.tips, &block_hash, None)?;
                }
            }
        }
        Ok(AddHeaderResult::HeaderAdded(block_hash))
    }

    fn run_ro_txn<'a, R, F>(&'a self, f: F) -> Result<R, LMDBCacheError>
    where
        F: FnOnce(&mut RoTransaction<'a>) -> Result<R, LMDBCacheError>,
    {
        let mut tx = self.db_env.begin_ro_txn()?;
        let result = f(&mut tx)?;
        tx.commit()?;
        Ok(result)
    }

    fn run_rw_txn<'a, R, F>(&'a self, f: F) -> Result<R, LMDBCacheError>
    where
        F: FnOnce(&mut RwTransaction<'a>) -> Result<R, LMDBCacheError>,
    {
        let mut tx = self.db_env.begin_rw_txn()?;
        let result = f(&mut tx)?;
        tx.commit()?;
        Ok(result)
    }
}

impl<Header: BlockchainHeader + Send + Sync> HeaderCache for LMDBHeaderCache<Header> {
    type Header = Header;

    fn get_genesis(&self) -> PureHeader {
        self.genesis.clone().into_pure_header()
    }

    fn get_header(&self, hash: &BlockHash) -> Option<HeaderNode<Header>> {
        log_err_except!(
            self.run_ro_txn(|tx| self.tx_get_header(tx, hash)),
            self.log,
            LMDBCacheError::Lmdb(lmdb::Error::NotFound),
            format!("tx_get_header({hash})")
        )
    }

    fn add_header(
        &self,
        block_hash: BlockHash,
        header: Header,
    ) -> Result<AddHeaderResult, AddHeaderError> {
        let parent_hash = header.prev_block_hash();
        let parent = self
            .get_header(&parent_hash)
            .ok_or(AddHeaderError::PrevHeaderNotCached(parent_hash))?;

        log_err!(
            self.run_rw_txn(move |tx| self.tx_add_header(tx, Some(&parent), block_hash, header)),
            self.log,
            format!("tx_add_header({block_hash})")
        )
        .map_err(|err| AddHeaderError::Internal(format!("{err:?}")))
    }

    /// This method returns the tip header with the highest cumulative work.
    fn get_active_chain_tip(&self) -> Tip<Header> {
        let tips = log_err!(
            self.run_ro_txn(|tx| self.tx_get_tips(tx)),
            self.log,
            "tx_get_tips"
        )
        .unwrap_or_else(|err| panic!("Failed to get tips {:?}", err));
        tips.into_iter()
            .max_by(|x, y| x.work.cmp(&y.work))
            .unwrap_or_else(|| panic!("Impossible: failed to find active_chain_tip"))
    }

    fn get_num_tips(&self) -> usize {
        log_err!(
            self.run_ro_txn(|tx| self.tx_get_num_tips(tx)),
            self.log,
            "tx_get_tips"
        )
        .unwrap_or_else(|err| panic!("Failed to get_num_tips {:?}", err))
    }

    #[cfg(test)]
    fn get_tips(&self) -> Vec<Tip<Header>> {
        log_err!(
            self.run_ro_txn(|tx| self.tx_get_tips(tx)),
            self.log,
            "get_tips"
        )
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::BlockchainNetwork;
    use ic_btc_adapter_test_utils::generate_headers;
    use ic_logger::no_op_logger;
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    #[test]
    fn test_in_memory_header_cache() {
        let network = bitcoin::Network::Bitcoin;
        let genesis_block_header = network.genesis_block_header();
        let genesis_block_hash = genesis_block_header.block_hash();
        {
            let cache = <InMemoryHeaderCache<bitcoin::block::Header>>::new(genesis_block_header);
            assert!(cache.get_header(&genesis_block_hash).is_some());
            let node = cache.get_header(&genesis_block_hash).unwrap();
            assert_eq!(node.data.height, 0);
            assert_eq!(node.data.header, genesis_block_header);
            assert_eq!(cache.get_active_chain_tip().header, genesis_block_header);

            // Make a few new header
            let mut next_headers = BTreeSet::new();
            for i in 1..4 {
                for header in
                    generate_headers(genesis_block_hash, genesis_block_header.time, i, &[])
                {
                    eprintln!(
                        "add_header {} prev = {}",
                        header.block_hash(),
                        header.prev_block_hash()
                    );
                    cache.add_header(header.block_hash(), header).unwrap();
                    let next_node = cache.get_header(&header.block_hash()).unwrap();
                    assert_eq!(next_node.data.header, header);
                    next_headers.insert(header);
                }
            }
            let tip = cache.get_active_chain_tip();
            assert!(next_headers.contains(&tip.header));
            assert_eq!(
                next_headers
                    .iter()
                    .map(|x| cache.get_header(&x.block_hash()).unwrap().data.work)
                    .max(),
                Some(tip.work)
            );
        }
    }

    fn get_tips_of<Header: Ord>(
        cache: &impl HeaderCache<Header = Header>,
        block_hash: &BlockHash,
    ) -> BTreeSet<HeaderNode<Header>> {
        let mut set = BTreeSet::new();
        let node = cache.get_header(block_hash).unwrap();
        if node.children.is_empty() {
            set.insert(node);
        } else {
            for hash in node.children {
                set.append(&mut get_tips_of(cache, &hash))
            }
        }
        set
    }

    #[test]
    fn test_lmdb_header_cache() {
        let dir = tempdir().unwrap();
        let network = bitcoin::Network::Bitcoin;
        let genesis_block_header = network.genesis_block_header();
        let genesis_block_hash = genesis_block_header.block_hash();
        {
            let cache = <LMDBHeaderCache<bitcoin::block::Header>>::new(
                genesis_block_header,
                dir.path().to_str().unwrap(),
                no_op_logger(),
            );
            assert!(cache.get_header(&genesis_block_hash).is_some());
            let node = cache.get_header(&genesis_block_hash).unwrap();
            assert_eq!(node.data.height, 0);
            assert_eq!(node.data.header, genesis_block_header);
            assert_eq!(cache.get_active_chain_tip().header, genesis_block_header);

            // Make a few new header
            let mut next_headers = BTreeSet::new();
            for i in 1..4 {
                for header in
                    generate_headers(genesis_block_hash, genesis_block_header.time, i, &[])
                {
                    eprintln!(
                        "add_header {} prev = {}",
                        header.block_hash(),
                        header.prev_block_hash()
                    );
                    cache.add_header(header.block_hash(), header).unwrap();
                    let next_node = cache.get_header(&header.block_hash()).unwrap();
                    assert_eq!(next_node.data.header, header);
                    next_headers.insert(header);
                }
            }
            let tip = cache.get_active_chain_tip();
            assert!(next_headers.contains(&tip.header));
            assert_eq!(
                next_headers
                    .iter()
                    .map(|x| cache.get_header(&x.block_hash()).unwrap().data.work)
                    .max(),
                Some(tip.work)
            );
        }

        // Re-open the cache and check to see if data still exists
        {
            let cache = <LMDBHeaderCache<bitcoin::block::Header>>::new(
                genesis_block_header,
                dir.path().to_str().unwrap(),
                no_op_logger(),
            );
            assert!(cache.get_header(&genesis_block_hash).is_some());
            let node = cache.get_header(&genesis_block_hash).unwrap();
            assert_eq!(node.data.height, 0);
            assert_eq!(node.data.header, genesis_block_header);
            assert_eq!(node.children.len(), 3);
            let tips = get_tips_of(&cache, &genesis_block_hash)
                .iter()
                .map(|node| node.data.header.block_hash())
                .collect::<BTreeSet<_>>();
            let tip = cache.get_active_chain_tip();
            assert!(tips.contains(&tip.header.block_hash()));
            for hash in tips.iter() {
                assert!(cache.get_header(hash).is_some());
            }
        }
    }
}
