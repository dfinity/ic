//! Store headers received from p2p network.

use crate::{
    common::{BlockHeight, BlockchainHeader},
    metrics::HeaderCacheMetrics,
};
use bitcoin::{
    BlockHash, Work,
    block::Header as PureHeader,
    consensus::{Decodable, Encodable, encode},
    io,
};
use ic_logger::{ReplicaLogger, error, info};
use ic_metrics::MetricsRegistry;
use lmdb::{
    Database, DatabaseFlags, Environment, EnvironmentFlags, RoTransaction, RwTransaction,
    Transaction, WriteFlags,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use thiserror::Error;

/// The max size (in bytes) of the LMDB cache, also known as the LMDB map size.
const MAX_LMDB_CACHE_SIZE: usize = 0x4_0000_0000; // 16GB

/// Database key used to store tip header.
const TIP_KEY: &str = "TIP";

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

impl<Header: Encodable> Encodable for HeaderNode<Header> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let data_size = self.data.consensus_encode(writer)?;
        let children_size = self.children.consensus_encode(writer)?;
        Ok(data_size + children_size)
    }
}

impl<Header: Decodable> Decodable for HeaderNode<Header> {
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        let data = <HeaderData<Header>>::consensus_decode(reader)?;
        let children = <Vec<BlockHash>>::consensus_decode(reader)?;
        Ok(Self { data, children })
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
pub enum AddHeaderCacheError {
    /// When the predecessor of the input header is not part of header_cache.
    #[error("Received a block header where we do not have the previous header in the cache: {0}")]
    PrevHeaderNotCached(BlockHash),
    /// When there is internal error writing to the cache.
    #[error("Internal error: {0}")]
    Internal(String),
}

pub struct InMemoryHeaderCache<Header> {
    /// Maps block hash to [HeaderNode].
    cache: HashMap<BlockHash, HeaderNode<Header>>,

    /// Known tips.
    tips: Vec<Tip<Header>>,
}

pub trait HeaderCache: Send + Sync {
    type Header;

    /// Return the header for the given block hash.
    fn get_header(&self, hash: BlockHash) -> Option<HeaderNode<Self::Header>>;

    /// Add the input header to cache.
    fn add_header(
        &self,
        block_hash: BlockHash,
        header: Self::Header,
    ) -> Result<AddHeaderResult, AddHeaderCacheError>;

    /// Return the tip header with the highest cumulative work.
    fn get_active_chain_tip(&self) -> Tip<Self::Header>;

    /// Return the number of tips.
    fn get_num_tips(&self) -> usize;

    /// Return the number of headers.
    fn get_num_headers(&self) -> usize;

    /// Return the ancestor from the given block hash to the current anchor in the
    /// in-memory cache as a chain of headers, where each element is the only child
    /// of the next, and the first element (tip) has no child.
    fn get_ancestor_chain(&self, from: BlockHash) -> Vec<(BlockHash, HeaderNode<Self::Header>)>;

    /// Prune headers below the anchor_height.
    fn prune_headers_below_height(&self, anchor_height: BlockHeight);
}

impl<Header: BlockchainHeader> InMemoryHeaderCache<Header> {
    /// Creates a new cache with a genesis header
    pub fn new_with_anchor(anchor: Tip<Header>) -> Self {
        let tips = vec![anchor.clone()];
        let mut cache = HashMap::new();
        cache.insert(anchor.header.block_hash(), anchor.into());
        InMemoryHeaderCache { cache, tips }
    }
}

impl<Header: BlockchainHeader + Send + Sync> HeaderCache for RwLock<InMemoryHeaderCache<Header>> {
    type Header = Header;

    fn get_header(&self, hash: BlockHash) -> Option<HeaderNode<Header>> {
        self.read().unwrap().cache.get(&hash).cloned()
    }

    fn add_header(
        &self,
        block_hash: BlockHash,
        header: Header,
    ) -> Result<AddHeaderResult, AddHeaderCacheError> {
        let mut this = self.write().unwrap();
        let prev_hash = header.prev_block_hash();
        let prev_node = this
            .cache
            .get_mut(&prev_hash)
            .ok_or(AddHeaderCacheError::PrevHeaderNotCached(prev_hash))?;

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

    fn get_num_headers(&self) -> usize {
        self.read().unwrap().cache.len()
    }

    fn get_ancestor_chain(&self, from: BlockHash) -> Vec<(BlockHash, HeaderNode<Header>)> {
        let mut hash = from;
        let mut to_persist = Vec::new();
        let mut next_hash = None;
        while let Some(mut node) = self.get_header(hash) {
            // The tip in the returned chain will have no child, and the rest have a single child.
            node.children = next_hash.into_iter().collect::<Vec<_>>();
            let prev_hash = node.data.header.prev_block_hash();
            to_persist.push((hash, node));
            next_hash = Some(hash);
            hash = prev_hash;
        }
        to_persist
    }

    fn prune_headers_below_height(&self, anchor_height: BlockHeight) {
        let mut this = self.write().unwrap();
        this.cache
            .retain(|_, node| node.data.height >= anchor_height);
        this.tips.retain(|tip| tip.height >= anchor_height);
    }
}

fn create_db_env(path: &Path, map_size: usize) -> Environment {
    let mut builder = Environment::new();
    let builder_flags = EnvironmentFlags::NO_TLS;
    let permission = 0o644;
    builder.set_flags(builder_flags);
    builder.set_max_dbs(1);
    builder.set_map_size(map_size);
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
    #[error("JoinError")]
    TaskJoin(#[from] tokio::task::JoinError),
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

pub struct LMDBHeaderCache {
    log: ReplicaLogger,
    db_env: Environment,
    // Map BlockHash to HeaderData
    headers: Database,
}

impl LMDBHeaderCache {
    /// Load the cache with a genesis header and cache directory.
    pub fn new_with_genesis<Header: BlockchainHeader>(
        mut cache_dir: PathBuf,
        log: ReplicaLogger,
        genesis: Tip<Header>,
    ) -> Result<Self, LMDBCacheError> {
        cache_dir.push("headers");
        let path = cache_dir.as_path();
        std::fs::create_dir_all(path).unwrap_or_else(|err| {
            panic!("Error creating DB directory {}: {}", path.display(), err)
        });
        let db_env = create_db_env(path, MAX_LMDB_CACHE_SIZE);
        let headers = db_env
            .create_db(Some("HEADERS"), DatabaseFlags::empty())
            .unwrap_or_else(|err| panic!("Error creating db for metadata: {:?}", err));
        let cache = LMDBHeaderCache {
            log,
            db_env,
            headers,
        };
        // Initialize DB with genesis if there is no tip yet
        log_err!(
            cache.run_rw_txn(|tx| match cache.tx_get_tip_hash(tx) {
                Ok(_) => Ok(()),
                Err(LMDBCacheError::Lmdb(lmdb::Error::NotFound)) => {
                    let hash = genesis.header.block_hash();
                    cache.tx_add_header(tx, hash, genesis.clone().into())?;
                    cache.tx_update_tip(tx, hash)?;
                    Ok(())
                }
                Err(err) => Err(err),
            }),
            cache.log,
            "initialize genesis"
        )?;
        let start = std::time::Instant::now();
        let (key_bytes, val_bytes) = cache.total_header_bytes()?;
        info!(
            cache.log,
            "LMDB header scanned ({} ms), key_bytes = {} val_bytes = {}",
            start.elapsed().as_millis(),
            key_bytes,
            val_bytes
        );
        Ok(cache)
    }

    fn tx_get_header<Tx: Transaction, Header: BlockchainHeader>(
        &self,
        tx: &Tx,
        hash: BlockHash,
    ) -> Result<HeaderNode<Header>, LMDBCacheError> {
        let mut bytes = tx.get(self.headers, &hash)?;
        let node = <HeaderNode<Header>>::consensus_decode(&mut bytes)?;
        Ok(node)
    }

    fn tx_get_num_headers<Tx: Transaction>(&self, tx: &Tx) -> Result<usize, LMDBCacheError> {
        let num = tx
            .stat(self.headers)
            .map(|stat| stat.entries())
            .map_err(LMDBCacheError::Lmdb)?;
        assert!(
            num > 0,
            "BUG: LMDBHeaderCache::new_with_genesis adds the tip header key '{TIP_KEY}'"
        );
        Ok(num - 1)
    }

    fn tx_add_header<Header: BlockchainHeader>(
        &self,
        tx: &mut RwTransaction,
        block_hash: BlockHash,
        node: HeaderNode<Header>,
    ) -> Result<(), LMDBCacheError> {
        let mut bytes = Vec::new();
        node.consensus_encode(&mut bytes)?;
        tx.put(self.headers, &block_hash, &bytes, WriteFlags::empty())?;
        Ok(())
    }

    fn tx_get_tip_hash<Tx: Transaction>(&self, tx: &Tx) -> Result<BlockHash, LMDBCacheError> {
        let mut bytes = tx.get(self.headers, &TIP_KEY)?;
        let hash = <BlockHash>::consensus_decode(&mut bytes)?;
        Ok(hash)
    }

    fn tx_get_tip<Tx: Transaction, Header: BlockchainHeader>(
        &self,
        tx: &Tx,
    ) -> Result<Tip<Header>, LMDBCacheError> {
        let hash = self.tx_get_tip_hash(tx)?;
        self.tx_get_header(tx, hash).map(|node| node.data)
    }

    fn tx_update_tip(
        &self,
        tx: &mut RwTransaction,
        tip_hash: BlockHash,
    ) -> Result<(), LMDBCacheError> {
        tx.put(self.headers, &TIP_KEY, &tip_hash, WriteFlags::empty())?;
        Ok(())
    }

    fn run_ro_txn<'a, R, F>(&'a self, f: F) -> Result<R, LMDBCacheError>
    where
        F: FnOnce(&RoTransaction<'a>) -> Result<R, LMDBCacheError>,
    {
        let tx = self.db_env.begin_ro_txn()?;
        let result = f(&tx)?;
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

    fn used_size(&self) -> Result<usize, LMDBCacheError> {
        let info = self.db_env.info()?;
        let stat = self.db_env.stat()?;
        let freelist = self.db_env.freelist()?;

        let page_size = stat.page_size();
        let last_page = info.last_pgno() + 1; // page number is 0-based
        let used_pages = last_page - freelist;
        Ok(used_pages * page_size as usize)
    }

    fn total_header_bytes(&self) -> Result<(usize, usize), LMDBCacheError> {
        use lmdb::Cursor;

        let mut key_bytes = 0;
        let mut val_bytes = 0;
        self.run_ro_txn(|tx| {
            let mut cursor = tx.open_ro_cursor(self.headers)?;
            let mut iter = cursor.iter_start();
            while let Some(Ok((key, val))) = iter.next() {
                key_bytes += key.len();
                val_bytes += val.len();
            }
            Ok((key_bytes, val_bytes))
        })
    }
}

/// A 2-tier header cache consisting of an in-memory cache, and optionally
/// an on-disk cache. It maintains the following invariants:
///
/// 1. The on-disk cache contains headers from genesis to the header at an anchor point.
///
/// 2. The in-memory cache contains headers from the anchor to latest.
///
/// 3. The on-disk headers form a linear chain with no forks, where the anchor is the tip and has no child.
///
/// 4. The two caches would overlap only at the anchor header, in which case
///    [get_header] would always return the header stored at in-memory cache.
///
/// It would behave as only an in-memory cache when on-disk cache is not enabled,
/// and pruning operation would be a no-op.
pub struct HybridHeaderCache<Header> {
    in_memory: RwLock<InMemoryHeaderCache<Header>>,
    on_disk: Option<LMDBHeaderCache>,
    genesis_hash: BlockHash,
    metrics: HeaderCacheMetrics,
}

impl<Header: BlockchainHeader> HybridHeaderCache<Header> {
    pub fn new(
        genesis_header: Header,
        cache_dir: Option<PathBuf>,
        metrics_registry: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let genesis_hash = genesis_header.block_hash();
        let genesis = HeaderData {
            work: genesis_header.work(),
            header: genesis_header,
            height: 0,
        };
        let metrics = HeaderCacheMetrics::new(metrics_registry);
        let on_disk = cache_dir.map(|dir| {
            LMDBHeaderCache::new_with_genesis(dir, log, genesis.clone())
                .and_then(|cache| {
                    metrics.on_disk_db_size.set(cache.used_size()? as i64);
                    Ok(cache)
                })
                .expect("Error initializing LMDBHeaderCache")
        });
        // Try reading the anchor (tip of the chain) from disk.
        // If it doesn't exist, use genesis header.
        let anchor = on_disk
            .as_ref()
            .map(|cache| {
                log_err!(
                    cache.run_ro_txn(|tx| cache.tx_get_tip(tx)),
                    cache.log,
                    "tx_get_tip()"
                )
                .inspect(|anchor| {
                    metrics.anchor_height_on_disk.set(anchor.height as i64);
                    metrics.on_disk_elements.set(1 + anchor.height as i64);
                })
                .expect("LMDBHeaderCache contains no tip")
            })
            .unwrap_or(genesis);
        let in_memory = RwLock::new(InMemoryHeaderCache::new_with_anchor(anchor));
        metrics.in_memory_elements.set(1);
        Self {
            in_memory,
            on_disk,
            genesis_hash,
            metrics,
        }
    }
}

impl<Header: BlockchainHeader + Send + Sync + 'static> HybridHeaderCache<Header> {
    /// Get the genesis header.
    pub fn get_genesis(&self) -> PureHeader {
        // The unwrap below is safe because:
        // - if the on-disk cache is configured and has persisted data, it should
        //   contain the genesis header;
        // - otherwise the in-memory cache hasn't been pruned, and should contain
        //   the genesis header.
        self.get_header(self.genesis_hash)
            .unwrap()
            .data
            .header
            .into_pure_header()
    }

    // Lookup header from the on-disk cache. Return None if it is not found or
    // the on-disk cache is not enabled.
    fn get_header_from_disk(&self, hash: BlockHash) -> Option<HeaderNode<Header>> {
        self.on_disk.as_ref().and_then(|cache| {
            log_err_except!(
                cache.run_ro_txn(|tx| cache.tx_get_header(tx, hash)),
                cache.log,
                LMDBCacheError::Lmdb(lmdb::Error::NotFound),
                format!("tx_get_header({hash})")
            )
        })
    }

    /// Number of headers stored.
    ///
    /// Return a pair where
    /// 1. Number of headers stored on disk
    /// 2. Number of headers stored in memory
    pub fn get_num_headers(&self) -> Result<(usize, usize), LMDBCacheError> {
        let num_headers_in_memory = self.in_memory.get_num_headers();
        if self.on_disk.is_none() {
            return Ok((0, num_headers_in_memory));
        }

        let cache = self.on_disk.as_ref().unwrap();
        let num_headers_on_disk = log_err!(
            cache.run_ro_txn(|tx| cache.tx_get_num_headers(tx)),
            cache.log,
            "get_num_headers"
        )?;

        Ok((num_headers_on_disk, num_headers_in_memory))
    }

    /// Get a header by hash.
    pub fn get_header(&self, hash: BlockHash) -> Option<HeaderNode<Header>> {
        self.in_memory
            .get_header(hash)
            .or_else(|| self.get_header_from_disk(hash))
    }

    /// Add a new header.
    pub fn add_header(
        &self,
        block_hash: BlockHash,
        header: Header,
    ) -> Result<AddHeaderResult, AddHeaderCacheError> {
        self.in_memory
            .add_header(block_hash, header)
            .inspect(|_| self.metrics.in_memory_elements.inc())
    }

    /// Returns the tip header with the highest cumulative work.
    pub fn get_active_chain_tip(&self) -> Tip<Header> {
        self.in_memory.get_active_chain_tip()
    }

    /// Returns the number of tip headers.
    pub fn get_num_tips(&self) -> usize {
        self.in_memory.get_num_tips()
    }

    /// Persist headers below the anchor (as headers) and the anchor (as tip) on to disk, and
    /// Prune headers below the anchor from the in-memory cache.
    /// It is a no-op if the on-disk cache is not configured.
    pub fn persist_and_prune_headers_below_anchor(
        &self,
        anchor: BlockHash,
    ) -> Result<(), LMDBCacheError> {
        if let Some(on_disk) = &self.on_disk {
            let to_persist = self.in_memory.get_ancestor_chain(anchor);
            self.metrics
                .headers_pruned_from_memory
                .observe(to_persist.len() as f64);
            // Only persist when there are more than 1 header because
            // get_ancestor_chain always returns at least 1 header.
            if to_persist.len() > 1 {
                let (_, node) = &to_persist[0];

                let anchor_height = node.data.height;
                on_disk.run_rw_txn(|tx| {
                    for (hash, node) in to_persist {
                        on_disk.tx_add_header(tx, hash, node)?;
                    }
                    on_disk.tx_update_tip(tx, anchor).inspect(|_| {
                        self.metrics.anchor_height_on_disk.set(anchor_height as i64);
                        self.metrics.on_disk_elements.set(1 + anchor_height as i64);
                    })?;
                    Ok(())
                })?;
                self.in_memory.prune_headers_below_height(anchor_height);
                self.metrics
                    .in_memory_elements
                    .set(self.in_memory.read().unwrap().cache.len() as i64);
                self.metrics
                    .on_disk_db_size
                    .set(on_disk.used_size()? as i64);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::BlockchainNetwork;
    use ic_btc_adapter_test_utils::generate_headers;
    use ic_test_utilities_logger::with_test_replica_logger;
    use std::collections::{BTreeMap, BTreeSet};
    use tempfile::tempdir;

    /// Creates an empty new cache.
    pub fn new_in_memory_cache_with_genesis<Header: BlockchainHeader>(
        genesis: Header,
    ) -> InMemoryHeaderCache<Header> {
        let data = HeaderData {
            header: genesis.clone(),
            height: 0,
            work: genesis.work(),
        };
        InMemoryHeaderCache::new_with_anchor(data)
    }

    #[test]
    fn test_in_memory_header_cache() {
        let network = bitcoin::Network::Bitcoin;
        let genesis_block_header = network.genesis_block_header();
        let genesis_block_hash = genesis_block_header.block_hash();
        {
            let cache = RwLock::new(new_in_memory_cache_with_genesis(genesis_block_header));
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

    // get all tips whose ancestors include given block hash.
    fn get_tips_of<Header: BlockchainHeader + Sync + Send + Ord + 'static>(
        cache: &HybridHeaderCache<Header>,
        block_hash: BlockHash,
    ) -> Vec<Tip<Header>> {
        let mut tips = Vec::new();
        let node = cache.get_header(block_hash).unwrap();
        if node.children.is_empty() {
            tips.push(node.data);
        } else {
            for hash in node.children {
                tips.append(&mut get_tips_of(cache, hash))
            }
        }
        tips
    }

    // get all tips that extends the node of the given block hash.
    pub(crate) fn get_tips<Header: BlockchainHeader + Sync + Send + Ord + 'static>(
        cache: &HybridHeaderCache<Header>,
    ) -> Vec<Tip<Header>> {
        get_tips_of(cache, cache.get_genesis().block_hash())
    }

    #[test]
    fn test_hybrid_header_cache() {
        type Header = bitcoin::block::Header;

        let dir = tempdir().unwrap();
        let network = bitcoin::Network::Bitcoin;
        let genesis_block_header = network.genesis_block_header();
        let genesis_block_hash = genesis_block_header.block_hash();
        with_test_replica_logger(|logger| {
            let cache = <HybridHeaderCache<Header>>::new(
                genesis_block_header,
                Some(dir.path().to_path_buf()),
                &MetricsRegistry::default(),
                logger,
            );
            assert!(cache.get_header(genesis_block_hash).is_some());
            let node = cache.get_header(genesis_block_hash).unwrap();
            assert_eq!(node.data.height, 0);
            assert_eq!(node.data.header, genesis_block_header);
            assert_eq!(cache.get_active_chain_tip().header, genesis_block_header);

            // key_bytes = 35 = 32 + 3
            //     where 3 is key "TIP", 32 is the genesis hash len.
            // val_bytes = 149, obtained after running this test.
            assert!(matches!(
                cache.on_disk.as_ref().unwrap().total_header_bytes(),
                Ok((35, 149))
            ));
            // Check initial metrics
            assert_eq!(cache.metrics.in_memory_elements.get(), 1);
            assert_eq!(cache.metrics.on_disk_elements.get(), 1);

            // Make a few new headers
            let mut next_headers = BTreeMap::new();
            for i in 1..4 {
                for header in
                    generate_headers(genesis_block_hash, genesis_block_header.time, i, &[])
                {
                    cache.add_header(header.block_hash(), header).unwrap();
                    let next_node = cache.get_header(header.block_hash()).unwrap();
                    assert_eq!(next_node.data.header, header);
                    next_headers.insert(header.block_hash(), header);
                }
            }
            assert_eq!(cache.metrics.in_memory_elements.get(), 7);
            assert_eq!(cache.metrics.on_disk_elements.get(), 1);

            // Add more headers
            let intermediate = cache.get_active_chain_tip();
            let intermediate_hash = intermediate.header.block_hash();
            for i in 1..4 {
                for header in generate_headers(intermediate_hash, intermediate.header.time, i, &[])
                {
                    cache.add_header(header.block_hash(), header).unwrap();
                    let next_node = cache.get_header(header.block_hash()).unwrap();
                    assert_eq!(next_node.data.header, header);
                    next_headers.insert(header.block_hash(), header);
                }
            }
            assert_eq!(cache.metrics.in_memory_elements.get(), 13);
            assert_eq!(cache.metrics.on_disk_elements.get(), 1);
            let tip = cache.get_active_chain_tip();
            assert!(next_headers.contains_key(&tip.header.block_hash()));
            assert_eq!(
                next_headers
                    .values()
                    .map(|x| cache.get_header(x.block_hash()).unwrap().data.work)
                    .max(),
                Some(tip.work)
            );
            assert!(cache.get_header(genesis_block_hash).is_some());
            let mut hash = tip.header.block_hash();
            while hash != genesis_block_hash {
                let header = *next_headers.get(&hash).unwrap();
                assert_eq!(Some(header), cache.get_header(hash).map(|x| x.data.header));
                hash = header.prev_block_hash();
            }
            let tips = get_tips(&cache);
            assert_eq!(tips.len(), 5);
            // Test pruning below genesis, should be no-op
            cache
                .persist_and_prune_headers_below_anchor(genesis_block_hash)
                .unwrap();
            let tips = get_tips(&cache);
            assert_eq!(tips.len(), 5);
            cache
                .persist_and_prune_headers_below_anchor(intermediate_hash)
                .unwrap();
            assert_eq!(cache.metrics.anchor_height_on_disk.get(), 3);
            assert_eq!(cache.metrics.on_disk_elements.get(), 4);
            assert_eq!(cache.metrics.in_memory_elements.get(), 7);

            // Check if the chain from genesis to tip can still be found
            assert!(cache.get_header(genesis_block_hash).is_some());
            let mut hash = tip.header.block_hash();
            while hash != genesis_block_hash {
                let header = *next_headers.get(&hash).unwrap();
                let node = cache.get_header(hash).unwrap();
                assert_eq!(header, node.data.header);
                // If height <= anchor, it can be found on-disk
                if node.data.height <= intermediate.height {
                    assert!(cache.get_header_from_disk(hash).is_some());
                }
                // If height >= anchor, it can be found in-memory
                if node.data.height >= intermediate.height {
                    assert!(cache.in_memory.get_header(hash).is_some())
                }
                hash = header.prev_block_hash();
            }

            // Check if all tip ancestors can be found.
            let tips = get_tips(&cache);
            assert_eq!(tips.len(), 3);
            for mut tip in tips {
                while tip.header.block_hash() != genesis_block_hash {
                    let prev_hash = tip.header.prev_block_hash();
                    let node = cache.get_header(prev_hash).unwrap();
                    assert_eq!(node.data.height + 1, tip.height);
                    assert!(node.children.contains(&tip.header.block_hash()));
                    tip = node.data;
                }
            }
        });

        // Re-open the cache and check to see if headers were persisted
        with_test_replica_logger(|logger| {
            let cache = <HybridHeaderCache<bitcoin::block::Header>>::new(
                genesis_block_header,
                Some(dir.path().to_path_buf()),
                &MetricsRegistry::default(),
                logger,
            );
            assert_eq!(cache.metrics.anchor_height_on_disk.get(), 3);
            assert_eq!(cache.metrics.on_disk_elements.get(), 4);
            assert_eq!(cache.metrics.in_memory_elements.get(), 1);

            // key_bytes = 131 = 32 * 4 + 3
            //     where 3 is key "TIP", and 4 is on_disk_elements.
            // val_bytes = 596, obtained after running this test.
            assert!(matches!(
                cache.on_disk.as_ref().unwrap().total_header_bytes(),
                Ok((131, 596))
            ));

            assert!(cache.get_header(genesis_block_hash).is_some());
            let tips = get_tips_of(&cache, genesis_block_hash);
            assert_eq!(tips.len(), 1);
            assert_eq!(tips[0], cache.get_active_chain_tip());
            assert_eq!(tips[0].height, 3);
        });
    }

    #[test]
    fn test_db_size_limit_increase() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        std::fs::create_dir_all(path).unwrap_or_else(|err| {
            panic!("Error creating DB directory {}: {}", path.display(), err)
        });
        // 1. Create a DB and write to it until MapFull error.
        let idx = {
            let env = create_db_env(path, 30000);
            let db = env
                .create_db(Some("DB"), DatabaseFlags::empty())
                .unwrap_or_else(|err| panic!("Error creating db for metadata: {:?}", err));
            let mut i = 0u8;
            let err = loop {
                let mut tx = env.begin_rw_txn().unwrap();
                let bytes = [i; 32];
                if let Err(err) = tx
                    .put(db, &bytes, &bytes, WriteFlags::empty())
                    .and_then(|_| tx.commit())
                {
                    break err;
                };
                i += 1;
            };
            assert_eq!(err, lmdb::Error::MapFull);
            i
        };

        // 2. Open the same DB and read it, no error. Write additional data, got MapFull.
        {
            let env = create_db_env(path, 30000);
            let db = env
                .create_db(Some("DB"), DatabaseFlags::empty())
                .unwrap_or_else(|err| panic!("Error creating db for metadata: {:?}", err));
            let mut tx = env.begin_rw_txn().unwrap();
            let mut bytes = [0; 32];
            assert_eq!(tx.get(db, &bytes).unwrap(), bytes);
            bytes = [idx; 32];
            assert_eq!(
                tx.put(db, &bytes, &bytes, WriteFlags::empty()),
                Err(lmdb::Error::MapFull)
            );
        }

        // 3. Open the same DB with bigger size limit, no problem writing more data to it.
        {
            let env = create_db_env(path, 60000);
            let db = env
                .create_db(Some("DB"), DatabaseFlags::empty())
                .unwrap_or_else(|err| panic!("Error creating db for metadata: {:?}", err));
            let mut i = idx;
            let err = loop {
                let mut tx = env.begin_rw_txn().unwrap();
                let bytes = [i; 32];
                if let Err(err) = tx
                    .put(db, &bytes, &bytes, WriteFlags::empty())
                    .and_then(|_| tx.commit())
                {
                    break err;
                };
                i += 1;
            };
            assert_eq!(err, lmdb::Error::MapFull);
            assert!(i > idx);
        }
    }
}
