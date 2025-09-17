//! Store headers received from p2p network.

use crate::common::{BlockHeight, BlockchainHeader};
use bitcoin::{
    BlockHash, Work,
    block::Header as PureHeader,
    consensus::{Decodable, Encodable, encode},
    io,
};
use ic_btc_validation::ValidateHeaderError;
use ic_logger::{ReplicaLogger, error, info};
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
    /// Headers of the successors of this node.
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
    fn get_header(&self, hash: BlockHash) -> Option<HeaderNode<Self::Header>>;

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

    /// Return all tips.
    fn get_tips(&self) -> Vec<Tip<Self::Header>>;

    /// Return the anchor height and headers to prune given the anchor's block hash.
    fn get_headers_to_prune(&self, anchor: BlockHash) -> (BlockHeight, Vec<BlockHash>);

    /// Prune headers from the cache
    fn prune_headers(&self, anchor_height: BlockHeight, to_prune: Vec<BlockHash>);
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

    fn get_header(&self, hash: BlockHash) -> Option<HeaderNode<Header>> {
        self.read().unwrap().cache.get(&hash).cloned()
    }

    fn add_header(
        &self,
        block_hash: BlockHash,
        header: Header,
    ) -> Result<AddHeaderResult, AddHeaderError> {
        let mut this = self.write().unwrap();
        let prev_hash = header.prev_block_hash();
        let prev_node = this
            .cache
            .get_mut(&prev_hash)
            .ok_or(AddHeaderError::PrevHeaderNotCached(prev_hash))?;

        let tip = HeaderData {
            header: header.clone(),
            height: prev_node.data.height + 1,
            work: prev_node.data.work + header.work(),
        };
        prev_node.children.push(block_hash);

        // Update the tip headers.
        // If the previous header already exists in `tips`, then update it with the new tip.
        let maybe_node_idx = this
            .tips
            .iter()
            .position(|tip| tip.header.block_hash() == prev_hash);

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

    fn get_tips(&self) -> Vec<Tip<Header>> {
        self.read().unwrap().tips.clone()
    }

    fn get_headers_to_prune(&self, anchor: BlockHash) -> (BlockHeight, Vec<BlockHash>) {
        // Not implemented
        (self.get_header(anchor).unwrap().data.height, Vec::new())
    }

    fn prune_headers(&self, _anchor_height: BlockHeight, _to_prune: Vec<BlockHash>) {
        // Not implemented
    }
}

fn create_db_env(path: &Path) -> Environment {
    let mut builder = Environment::new();
    let builder_flags = EnvironmentFlags::NO_TLS;
    let permission = 0o644;
    builder.set_flags(builder_flags);
    // 5 databases
    builder.set_max_dbs(5);
    builder.set_map_size(MAX_LMDB_CACHE_SIZE);
    builder
        .open_with_permissions(path, permission)
        .unwrap_or_else(|err| {
            panic!(
                "Error opening LMDB environment with permissions at {:?}: {:?}",
                path, err
            )
        })
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

/// Ignore an error if it matches the given pattern.
macro_rules! ignore_err {
    ($r:expr, $code:pat) => {
        match $r {
            Ok(_) | Err($code) => Ok(()),
            Err(err) => Err(err),
        }
    };
}

pub struct LMDBHeaderCache<Header> {
    genesis: Header,
    db_env: Environment,
    log: ReplicaLogger,
    // Map BlockHash to HeaderData.
    headers: Database,
    // Map BlockHash to Tip.
    tips: Database,
    // Map parent's BlockHash to child's BlockHash, duplicated key (parent's hash) allowed.
    children: Database,
    // Map height to header hashes, used for pruning
    heights: Database,
    // Last pruned height
    last_pruned_height: Database,
}

impl<Header: BlockchainHeader> LMDBHeaderCache<Header> {
    /// Load the cache with a genesis header and cache directory.
    pub fn new(genesis: Header, mut cache_dir: PathBuf, log: ReplicaLogger) -> Self {
        cache_dir.push("headers");
        let path = cache_dir.as_path();
        std::fs::create_dir_all(path).unwrap_or_else(|err| {
            panic!("Error creating DB directory {}: {}", path.display(), err)
        });
        let db_env = create_db_env(path);
        let headers = db_env
            .create_db(Some("HEADERS"), DatabaseFlags::empty())
            .unwrap_or_else(|err| panic!("Error creating db for headers: {:?}", err));
        let tips = db_env
            .create_db(Some("TIPS"), DatabaseFlags::empty())
            .unwrap_or_else(|err| panic!("Error creating db for tips: {:?}", err));
        let children = db_env
            .create_db(Some("CHILDREN"), DatabaseFlags::DUP_SORT)
            .unwrap_or_else(|err| panic!("Error creating db for children: {:?}", err));
        let heights = db_env
            .create_db(Some("HEIGHTS"), DatabaseFlags::DUP_SORT)
            .unwrap_or_else(|err| panic!("Error creating db for heights: {:?}", err));
        let last_pruned_height = db_env
            .create_db(Some("LAST_PRUNED_HEIGHT"), DatabaseFlags::DUP_SORT)
            .unwrap_or_else(|err| panic!("Error creating db for last_pruned_height: {:?}", err));

        let cache = LMDBHeaderCache {
            genesis: genesis.clone(),
            db_env,
            log,
            headers,
            tips,
            children,
            heights,
            last_pruned_height,
        };

        cache
            .run_rw_txn(|tx| cache.tx_add_header(tx, None, genesis.block_hash(), genesis))
            .unwrap();

        cache
    }

    fn tx_is_tip<Tx: Transaction>(
        &self,
        tx: &Tx,
        block_hash: BlockHash,
    ) -> Result<bool, LMDBCacheError> {
        match tx.get(self.tips, &block_hash) {
            Ok(_) => Ok(true),
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    fn tx_get_tips<Tx: Transaction>(&self, tx: &Tx) -> Result<Vec<Tip<Header>>, LMDBCacheError> {
        let mut cursor = tx.open_ro_cursor(self.tips)?;
        cursor
            .iter_start()
            .map(|row| {
                let (mut key, _) = row?;
                let hash = <BlockHash>::consensus_decode(&mut key)?;
                let mut bytes = tx.get(self.headers, &hash)?;
                let tip = <Tip<Header>>::consensus_decode(&mut bytes)?;
                Ok(tip)
            })
            .collect::<Result<_, _>>()
    }

    fn tx_get_num_tips<Tx: Transaction>(&self, tx: &Tx) -> Result<usize, LMDBCacheError> {
        let mut cursor = tx.open_ro_cursor(self.tips)?;
        Ok(cursor.iter_start().count())
    }

    fn tx_get_children<Tx: Transaction>(
        &self,
        tx: &Tx,
        hash: BlockHash,
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
        tx: &Tx,
        hash: BlockHash,
    ) -> Result<HeaderNode<Header>, LMDBCacheError> {
        let mut bytes = tx.get(self.headers, &hash)?;
        let data = <HeaderData<Header>>::consensus_decode(&mut bytes)?;
        let children = self.tx_get_children(tx, hash)?;
        Ok(HeaderNode { data, children })
    }

    fn tx_get_last_pruned_height<Tx: Transaction>(
        &self,
        tx: &Tx,
    ) -> Result<BlockHeight, LMDBCacheError> {
        let mut bytes = tx.get(self.last_pruned_height, b"height")?;
        Ok(<BlockHeight>::consensus_decode(&mut bytes)?)
    }

    // Return (hashes of) nodes that have a height less than or equal to the given node
    // (of the given hash), and not one of its ancestors.
    fn tx_get_headers_to_prune<Tx: Transaction>(
        &self,
        tx: &Tx,
        mut hash: BlockHash,
    ) -> Result<(BlockHeight, Vec<BlockHash>), LMDBCacheError> {
        let last_pruned_height = log_err_except!(
            self.tx_get_last_pruned_height(tx),
            self.log,
            LMDBCacheError::Lmdb(lmdb::Error::NotFound),
            "tx_get_last_pruned_height".to_string()
        )
        .unwrap_or(0);
        let mut to_prune = Vec::new();
        let mut starting_height = None;
        loop {
            let node = log_err!(
                self.tx_get_header(tx, hash),
                self.log,
                format!("tx_get_header({hash})")
            )?;
            let height = node.data.height;
            if starting_height.is_none() {
                starting_height = Some(height);
            }
            if height <= last_pruned_height {
                break;
            }
            let mut cursor = tx.open_ro_cursor(self.heights)?;
            let mut height_bytes = Vec::new();
            height.consensus_encode(&mut height_bytes)?;
            for row in cursor.iter_dup_of(&height_bytes) {
                let (_, mut value) = row?;
                let block_hash = <BlockHash>::consensus_decode(&mut value)?;
                if block_hash != hash {
                    to_prune.push(block_hash);
                }
            }
            hash = node.data.header.prev_block_hash();
        }
        Ok((starting_height.unwrap(), to_prune))
    }

    fn tx_prune_headers(
        &self,
        tx: &mut RwTransaction,
        height: BlockHeight,
        to_prune: Vec<BlockHash>,
    ) -> Result<(), LMDBCacheError> {
        for hash in to_prune {
            let mut bytes = tx.get(self.headers, &hash)?;
            let data = <HeaderData<Header>>::consensus_decode(&mut bytes)?;
            let prev_hash = data.header.prev_block_hash();
            let mut height_bytes = Vec::new();
            data.height.consensus_encode(&mut height_bytes)?;
            tx.del(self.headers, &hash, None)?;
            tx.del(self.heights, &height_bytes, Some(hash.as_ref()))?;
            // Note that we only remove (prev_hash, hash) from the children table,
            // while keeping (hash, *) entries, which will be removed eventually
            // when its children are pruned.
            tx.del(self.children, &prev_hash, Some(hash.as_ref()))?;
            ignore_err!(tx.del(self.tips, &hash, None), lmdb::Error::NotFound)?;
        }
        let mut bytes = Vec::new();
        height.consensus_encode(&mut bytes)?;
        tx.put(
            self.last_pruned_height,
            b"height",
            &bytes,
            WriteFlags::empty(),
        )?;
        Ok(())
    }

    fn tx_add_header(
        &self,
        tx: &mut RwTransaction,
        prev_node: Option<&HeaderNode<Header>>,
        block_hash: BlockHash,
        header: Header,
    ) -> Result<AddHeaderResult, LMDBCacheError> {
        let height = prev_node.map(|p| p.data.height + 1).unwrap_or_default();
        let work = prev_node
            .map(|p| p.data.work + header.work())
            .unwrap_or(header.work());
        let tip = Tip {
            header: header.clone(),
            height,
            work,
        };
        let mut height_bytes = Vec::new();
        let mut tip_bytes = Vec::new();
        height.consensus_encode(&mut height_bytes)?;
        tip.consensus_encode(&mut tip_bytes)?;
        tx.put(self.headers, &block_hash, &tip_bytes, WriteFlags::empty())?;
        tx.put(self.tips, &block_hash, &[], WriteFlags::empty())?;
        tx.put(
            self.heights,
            &height_bytes,
            &block_hash,
            WriteFlags::empty(),
        )?;
        if let Some(prev_node) = prev_node {
            let prev_hash = prev_node.data.header.block_hash();
            tx.put(self.children, &prev_hash, &block_hash, WriteFlags::empty())?;
            // If the previous header already exists in `tips`, then remove it
            if self.tx_is_tip(tx, prev_hash)? {
                tx.del(self.tips, &prev_hash, None)?;
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

    fn get_header(&self, hash: BlockHash) -> Option<HeaderNode<Header>> {
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
        let prev_hash = header.prev_block_hash();
        let prev_node = self
            .get_header(prev_hash)
            .ok_or(AddHeaderError::PrevHeaderNotCached(prev_hash))?;

        log_err!(
            self.run_rw_txn(move |tx| self.tx_add_header(tx, Some(&prev_node), block_hash, header)),
            self.log,
            format!("tx_add_header({block_hash})")
        )
        .map_err(|err| AddHeaderError::Internal(format!("{err:?}")))
    }

    /// This method returns the tip header with the highest cumulative work.
    fn get_active_chain_tip(&self) -> Tip<Header> {
        self.get_tips()
            .into_iter()
            .max_by(|x, y| x.work.cmp(&y.work))
            .unwrap_or_else(|| panic!("Impossible: failed to find active_chain_tip"))
    }

    fn get_num_tips(&self) -> usize {
        log_err!(
            self.run_ro_txn(|tx| self.tx_get_num_tips(tx)),
            self.log,
            "tx_num_tips"
        )
        .unwrap_or_else(|err| panic!("Failed to get_num_tips {:?}", err))
    }

    fn get_tips(&self) -> Vec<Tip<Header>> {
        log_err!(
            self.run_ro_txn(|tx| self.tx_get_tips(tx)),
            self.log,
            "tx_get_tips"
        )
        .unwrap_or_else(|err| panic!("Failed to get tips {:?}", err))
    }

    fn get_headers_to_prune(&self, anchor: BlockHash) -> (BlockHeight, Vec<BlockHash>) {
        log_err!(
            self.run_ro_txn(|tx| self.tx_get_headers_to_prune(tx, anchor)),
            self.log,
            "tx_get_headers_to_prune({anchor})"
        )
        .unwrap_or_else(|err| panic!("Failed to get headers to prune {:?}", err))
    }

    fn prune_headers(&self, anchor_height: BlockHeight, to_prune: Vec<BlockHash>) {
        let num = to_prune.len();
        log_err!(
            self.run_rw_txn(|tx| self.tx_prune_headers(tx, anchor_height, to_prune)),
            self.log,
            "tx_prune_headers()"
        )
        .unwrap_or_else(|err| panic!("Failed to prune headers {:?}", err));
        info!(self.log, "Pruned {num} headers from LMDBHeaderCache");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::BlockchainNetwork;
    use ic_btc_adapter_test_utils::generate_headers;
    use ic_test_utilities_logger::with_test_replica_logger;
    use std::collections::{BTreeMap, BTreeSet};
    use tempfile::tempdir;

    #[test]
    fn test_in_memory_header_cache() {
        let network = bitcoin::Network::Bitcoin;
        let genesis_block_header = network.genesis_block_header();
        let genesis_block_hash = genesis_block_header.block_hash();
        {
            let cache = <InMemoryHeaderCache<bitcoin::block::Header>>::new(genesis_block_header);
            assert!(cache.get_header(genesis_block_hash).is_some());
            let node = cache.get_header(genesis_block_hash).unwrap();
            assert_eq!(node.data.height, 0);
            assert_eq!(node.data.header, genesis_block_header);
            assert_eq!(cache.get_active_chain_tip().header, genesis_block_header);

            // Make a few new header
            let mut next_headers = BTreeSet::new();
            for i in 1..4 {
                for header in
                    generate_headers(genesis_block_hash, genesis_block_header.time, i, &[])
                {
                    cache.add_header(header.block_hash(), header).unwrap();
                    let next_node = cache.get_header(header.block_hash()).unwrap();
                    assert_eq!(next_node.data.header, header);
                    next_headers.insert(header);
                }
            }
            let tip = cache.get_active_chain_tip();
            assert!(next_headers.contains(&tip.header));
            assert_eq!(
                next_headers
                    .iter()
                    .map(|x| cache.get_header(x.block_hash()).unwrap().data.work)
                    .max(),
                Some(tip.work)
            );
        }
    }

    fn get_tips_of<Header: Ord>(
        cache: &impl HeaderCache<Header = Header>,
        block_hash: BlockHash,
    ) -> BTreeSet<HeaderNode<Header>> {
        let mut set = BTreeSet::new();
        let node = cache.get_header(block_hash).unwrap();
        if node.children.is_empty() {
            set.insert(node);
        } else {
            for hash in node.children {
                set.append(&mut get_tips_of(cache, hash))
            }
        }
        set
    }

    fn check_lmdb_cache_consistency<Header: BlockchainHeader>(cache: &LMDBHeaderCache<Header>) {
        let tx = cache.db_env.begin_ro_txn().unwrap();

        // Num of entries in headers and heights tables are equal
        assert_eq!(
            tx.open_ro_cursor(cache.headers)
                .unwrap()
                .iter_start()
                .count(),
            tx.open_ro_cursor(cache.heights)
                .unwrap()
                .iter_start()
                .count()
        );

        // Check headers table
        let mut headers = BTreeMap::new();
        for row in tx.open_ro_cursor(cache.headers).unwrap().iter_start() {
            let (mut key, mut val) = row.unwrap();
            let hash = <BlockHash>::consensus_decode(&mut key).unwrap();
            let data = <HeaderData<Header>>::consensus_decode(&mut val).unwrap();
            assert_eq!(hash, data.header.block_hash());
            headers.insert(
                hash,
                HeaderNode {
                    data,
                    children: vec![],
                },
            );
        }

        // Check children table
        let mut tips = headers.keys().cloned().collect::<BTreeSet<_>>();
        for row in tx.open_ro_cursor(cache.children).unwrap().iter_start() {
            let (mut key, mut val) = row.unwrap();
            let parent = <BlockHash>::consensus_decode(&mut key).unwrap();
            let child = <BlockHash>::consensus_decode(&mut val).unwrap();
            // Skip this assert because parent may have already been removed due to pruning.
            // assert!(headers.get(&parent).is_some());
            assert!(headers.get(&child).is_some());
            headers
                .entry(parent)
                .and_modify(|node| node.children.push(child));
            tips.remove(&parent);
        }

        // Check tips table
        for row in tx.open_ro_cursor(cache.tips).unwrap().iter_start() {
            let (mut key, _) = row.unwrap();
            let hash = <BlockHash>::consensus_decode(&mut key).unwrap();
            assert!(tips.contains(&hash));
            tips.remove(&hash);
        }
        assert!(tips.is_empty());

        // Check heights table
        let last_pruned = cache.tx_get_last_pruned_height(&tx).unwrap_or_default();
        let mut heights = BTreeSet::new();
        for row in tx.open_ro_cursor(cache.heights).unwrap().iter_start() {
            let (mut key, mut val) = row.unwrap();
            let height = <BlockHeight>::consensus_decode(&mut key).unwrap();
            let hash = <BlockHash>::consensus_decode(&mut val).unwrap();
            let node = headers.get(&hash).unwrap();
            assert_eq!(node.data.height, height);
            if height < last_pruned {
                assert_eq!(node.children.len(), 1);
            }
            heights.insert(height);
        }
        let max_height = heights.iter().max().cloned().unwrap_or_default();
        assert_eq!(heights, (0u32..=max_height).collect::<BTreeSet<_>>());
    }

    #[test]
    fn test_lmdb_header_cache() {
        let dir = tempdir().unwrap();
        let network = bitcoin::Network::Bitcoin;
        let genesis_block_header = network.genesis_block_header();
        let genesis_block_hash = genesis_block_header.block_hash();
        with_test_replica_logger(|logger| {
            let cache = <LMDBHeaderCache<bitcoin::block::Header>>::new(
                genesis_block_header,
                dir.path().to_path_buf(),
                logger,
            );
            assert!(cache.get_header(genesis_block_hash).is_some());
            let node = cache.get_header(genesis_block_hash).unwrap();
            assert_eq!(node.data.height, 0);
            assert_eq!(node.data.header, genesis_block_header);
            assert_eq!(cache.get_active_chain_tip().header, genesis_block_header);

            // Make a few new header
            let mut next_headers = BTreeSet::new();
            for i in 1..4 {
                for header in
                    generate_headers(genesis_block_hash, genesis_block_header.time, i, &[])
                {
                    cache.add_header(header.block_hash(), header).unwrap();
                    let next_node = cache.get_header(header.block_hash()).unwrap();
                    assert_eq!(next_node.data.header, header);
                    next_headers.insert(header);
                }
            }
            let tip = cache.get_active_chain_tip();
            assert!(next_headers.contains(&tip.header));
            assert_eq!(
                next_headers
                    .iter()
                    .map(|x| cache.get_header(x.block_hash()).unwrap().data.work)
                    .max(),
                Some(tip.work)
            );
        });

        // Re-open the cache and check to see if data still exists
        with_test_replica_logger(|logger| {
            let cache = <LMDBHeaderCache<bitcoin::block::Header>>::new(
                genesis_block_header,
                dir.path().to_path_buf(),
                logger,
            );
            assert!(cache.get_header(genesis_block_hash).is_some());
            let node = cache.get_header(genesis_block_hash).unwrap();
            assert_eq!(node.data.height, 0);
            assert_eq!(node.data.header, genesis_block_header);
            assert_eq!(node.children.len(), 3);
            let tips = get_tips_of(&cache, genesis_block_hash)
                .iter()
                .map(|node| node.data.header.block_hash())
                .collect::<BTreeSet<_>>();
            let tip = cache.get_active_chain_tip();
            assert!(tips.contains(&tip.header.block_hash()));
            for hash in tips.iter() {
                assert!(cache.get_header(*hash).is_some());
            }
        });
    }

    #[test]
    fn test_lmdb_header_cache_pruning() {
        let dir = tempdir().unwrap();
        let network = bitcoin::Network::Bitcoin;
        let genesis_block_header = network.genesis_block_header();
        let genesis_block_hash = genesis_block_header.block_hash();
        with_test_replica_logger(|logger| {
            let cache = <LMDBHeaderCache<bitcoin::block::Header>>::new(
                genesis_block_header,
                dir.path().to_path_buf(),
                logger,
            );
            assert_eq!(cache.get_headers_to_prune(genesis_block_hash), (0, vec![]));

            // Make a few new header
            let mut next_headers = Vec::new();
            for i in 1..4 {
                for header in
                    generate_headers(genesis_block_hash, genesis_block_header.time, i, &[])
                {
                    cache.add_header(header.block_hash(), header).unwrap();
                    check_lmdb_cache_consistency(&cache);
                    let next_node = cache.get_header(header.block_hash()).unwrap();
                    assert_eq!(next_node.data.header, header);
                    next_headers.push(header);
                }
            }
            let intermediate = cache.get_active_chain_tip();
            // Extend one of the intermediate node again
            for i in 1..4 {
                for header in generate_headers(
                    intermediate.header.block_hash(),
                    genesis_block_header.time,
                    i,
                    &[],
                ) {
                    cache.add_header(header.block_hash(), header).unwrap();
                    check_lmdb_cache_consistency(&cache);
                    let next_node = cache.get_header(header.block_hash()).unwrap();
                    assert_eq!(next_node.data.header, header);
                    next_headers.push(header);
                }
            }
            let tip = cache.get_active_chain_tip();

            // Prune from intermediate
            let (anchor_height, to_prune) =
                cache.get_headers_to_prune(intermediate.header.block_hash());
            assert_eq!(anchor_height, 3);
            // for <= height 3, there are 1 + 2 + 3 - 3 = 3 nodes to be pruned
            assert_eq!(to_prune.len(), 3);
            cache.prune_headers(anchor_height, to_prune);
            check_lmdb_cache_consistency(&cache);
            assert_eq!(
                cache.get_headers_to_prune(intermediate.header.block_hash()),
                (3, vec![])
            );

            // Prune from tip
            let (anchor_height, to_prune) = cache.get_headers_to_prune(tip.header.block_hash());
            assert_eq!(anchor_height, 6);
            // for <= height 6, there are 1 + 2 + 3 - 3 = 3 nodes to be pruned
            assert_eq!(to_prune.len(), 3);
            cache.prune_headers(anchor_height, to_prune);
            check_lmdb_cache_consistency(&cache);
            assert_eq!(
                cache.get_headers_to_prune(tip.header.block_hash()),
                (6, vec![])
            )
        });
    }
}
