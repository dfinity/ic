//! The module is responsible for keeping track of the blockchain state.
//!
use crate::common::BlockchainHeaderValidator;
use crate::{
    common::{BlockHeight, BlockchainBlock, BlockchainHeader, BlockchainNetwork},
    header_cache::{
        AddHeaderCacheError, AddHeaderResult, HeaderCache, HeaderNode, InMemoryHeaderCache,
        LMDBHeaderCache, Tip,
    },
    metrics::BlockchainStateMetrics,
};
use bitcoin::{BlockHash, block::Header, consensus::Encodable};
use ic_btc_validation::HeaderStore;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use thiserror::Error;

/// The limit at which we should stop making additional requests for new blocks as the block cache
/// becomes too large. Inflight `getdata` messages will remain active, but new `getdata` messages will
/// not be created.
const BLOCK_CACHE_THRESHOLD_BYTES: usize = 10 * ONE_MB;
const ONE_MB: usize = 1_024 * 1_024;

#[derive(Debug, Error)]
pub enum AddHeaderError<V: BlockchainHeaderValidator> {
    /// When the received header is invalid (e.g., not in the right format).
    #[error("Received an invalid block header: {0}")]
    InvalidHeader(BlockHash, V::HeaderValidationError),
    /// When there is an error writing the header to the cache.
    #[error("Error writing the header to the cache: {0}")]
    CacheError(AddHeaderCacheError),
}

impl<V: BlockchainHeaderValidator> From<AddHeaderCacheError> for AddHeaderError<V> {
    fn from(err: AddHeaderCacheError) -> Self {
        AddHeaderError::CacheError(err)
    }
}

#[derive(Debug, Error)]
pub enum AddBlockError<V: BlockchainHeaderValidator> {
    /// Used to indicate that the merkle root of the block is invalid.
    #[error("Received a block with an invalid merkle root: {0}")]
    InvalidMerkleRoot(BlockHash),
    /// Used to indicate when the header causes an error while adding a block to the state.
    #[error("Block's header caused an error: {0}")]
    Header(AddHeaderError<V>),
    /// Used to indicate that the block could not be serialized.
    #[error("Serialization error for block {0} with error {1}")]
    CouldNotSerialize(BlockHash, String),
}

pub type SerializedBlock = Vec<u8>;

/// This struct is a cache of Bitcoin blockchain.
/// The BlockChainState caches all the Bitcoin headers, some of the Bitcoin blocks.
/// The BlockChainState also maintains the child relationhips between the headers.
pub struct BlockchainState<Network: BlockchainNetwork> {
    /// This field stores all the Bitcoin headers using a HashMap containing BlockHash and the corresponding header.
    header_cache: Box<dyn HeaderCache<Header = Network::Header> + Send>,

    /// This field stores a hashmap containing BlockHash and the corresponding SerializedBlock.
    block_cache: HashMap<BlockHash, Arc<SerializedBlock>>,

    /// Used to determine how validation should be handled with `validate_header`.
    network: Network,
    metrics: BlockchainStateMetrics,
}

impl<Network: BlockchainNetwork> BlockchainState<Network>
where
    Network::Header: Send + Sync,
{
    /// Create a new BlockChainState object with in-memory cache.
    pub fn new(network: Network, metrics_registry: &MetricsRegistry) -> Self {
        let genesis_block_header = network.genesis_block_header();
        let header_cache = Box::new(InMemoryHeaderCache::new(genesis_block_header));
        let block_cache = HashMap::new();
        BlockchainState {
            header_cache,
            block_cache,
            network,
            metrics: BlockchainStateMetrics::new(metrics_registry),
        }
    }

    /// Create a new BlockChainState with on-disk cache.
    pub fn new_with_cache_dir(
        network: Network,
        cache_dir: PathBuf,
        metrics_registry: &MetricsRegistry,
        logger: ReplicaLogger,
    ) -> Self {
        let genesis_block_header = network.genesis_block_header();
        let header_cache = Box::new(LMDBHeaderCache::new(
            genesis_block_header,
            cache_dir,
            logger,
        ));
        let block_cache = HashMap::new();
        BlockchainState {
            header_cache,
            block_cache,
            network,
            metrics: BlockchainStateMetrics::new(metrics_registry),
        }
    }

    /// Returns the genesis header that the store is initialized with.
    pub fn genesis(&self) -> Header {
        self.header_cache.get_genesis()
    }

    /// Returns the header for the given block hash.
    pub fn get_cached_header(&self, hash: &BlockHash) -> Option<HeaderNode<Network::Header>> {
        self.header_cache.get_header(*hash)
    }

    /// Returns the hashes of all cached blocks.
    pub(crate) fn get_cached_blocks(&self) -> Vec<BlockHash> {
        self.block_cache.keys().copied().collect()
    }

    /// Processes the `headers` message received from Bitcoin nodes by adding them to the state.
    /// Headers are expected to be sorted. If they are not, the headers will be likely be rejected
    /// with a [AddHeaderError::PrevHeaderNotCached](AddHeaderError::PrevHeaderNotCached) error.
    /// If the header has been added to the cache, it will be returned in a vector alongside
    /// a possible error that may have occurred while adding the headers.
    pub fn add_headers(
        &mut self,
        headers: &[Network::Header],
    ) -> (
        Vec<BlockHash>,
        Option<AddHeaderError<Network::HeaderValidator>>,
    ) {
        let mut block_hashes_of_added_headers = vec![];

        let err = headers
            .iter()
            .try_for_each(|header| match self.add_header(header.clone()) {
                Ok(AddHeaderResult::HeaderAdded(block_hash)) => {
                    block_hashes_of_added_headers.push(block_hash);
                    Ok(())
                }
                Ok(AddHeaderResult::HeaderAlreadyExists) => Ok(()),
                Err(err) => Err(err),
            })
            .err();

        let num_tips = self.header_cache.get_num_tips();
        self.metrics.tips.set(num_tips as i64);
        self.metrics
            .tip_height
            .set(self.get_active_chain_tip().height.into());

        (block_hashes_of_added_headers, err)
    }

    /// This method adds the input header to the `header_cache`.
    fn add_header(
        &mut self,
        header: Network::Header,
    ) -> Result<AddHeaderResult, AddHeaderError<Network::HeaderValidator>> {
        let block_hash = header.block_hash();

        // If the header already exists in the cache,
        // then don't insert the header again, and return HeaderAlreadyExistsError
        if self.header_cache.get_header(block_hash).is_some() {
            return Ok(AddHeaderResult::HeaderAlreadyExists);
        }

        // Validate the header using the network-specific validator
        let validator = self.network.get_header_validator();
        validator
            .validate_header(&self.network, self, &header)
            .map_err(|err| AddHeaderError::InvalidHeader(block_hash, err))?;

        self.header_cache
            .add_header(block_hash, header)
            .inspect(|_| {
                self.metrics.header_cache_size.inc();
            })
            .map_err(AddHeaderError::from)
    }

    /// This method adds a new block to the `block_cache`
    pub fn add_block(
        &mut self,
        block: Network::Block,
    ) -> Result<(), AddBlockError<Network::HeaderValidator>> {
        let block_hash = block.block_hash();

        if block.compute_merkle_root().is_some() && !block.check_merkle_root() {
            return Err(AddBlockError::InvalidMerkleRoot(block_hash));
        }

        // If the block's header is not added before, then add the header into the `header_cache` first.
        let _ = self
            .add_header(block.header().clone())
            .map_err(AddBlockError::Header)?;

        let mut serialized_block = vec![];
        block
            .consensus_encode(&mut serialized_block)
            .map_err(|e| AddBlockError::CouldNotSerialize(block_hash, e.to_string()))?;

        self.block_cache
            .insert(block_hash, Arc::new(serialized_block));

        self.metrics
            .block_cache_size
            .set(self.get_block_cache_size() as i64);
        self.metrics
            .block_cache_elements
            .set(self.block_cache.len() as i64);
        Ok(())
    }

    /// This method returns the tip header with the highest cumulative work.
    pub fn get_active_chain_tip(&self) -> Tip<Network::Header> {
        self.header_cache.get_active_chain_tip()
    }

    /// This method is used to remove blocks in the `header_cache` that are found in the given
    /// block hashes.
    pub fn prune_blocks(&mut self, block_hashes: &[BlockHash]) {
        for block_hash in block_hashes {
            self.block_cache.remove(block_hash);
        }
    }

    /// Removes blocks that are below a given height from the block cache.
    pub fn prune_blocks_below_height(&mut self, height: BlockHeight) {
        let hashes_below_height = self
            .block_cache
            .keys()
            .filter(|b| height > self.get_cached_header(b).map_or(0, |c| c.data.height))
            .copied()
            .collect::<Vec<_>>();
        self.prune_blocks(&hashes_below_height);
    }

    /// Get the locator hashes for the active chain (the chain with the highest amount of work).
    /// Returns the block hashes corresponding to  tip, tip - 1, tip - 2, tip - 3, tip - 4, tip - 5, tip - 6, tip - 7, tip - 8,
    /// tip - (8 + 2), tip - (8 + 2 + 4), tip - (8 + 2 + 4 + 8), tip - (8 + 2 + 4 + 8 + 16) ..., tip - (8 + 2 + 4 + 8 + ... + 4096), adapter_gensis_hash
    pub fn locator_hashes(&self) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        let tip = self.get_active_chain_tip();
        let mut current_header = tip.header.clone();
        let mut current_hash = current_header.block_hash();
        let mut step: u32 = 1;
        let mut last_hash = current_hash;
        let genesis_hash = self.genesis().block_hash();
        // Push the most recent 8 block hashes start from the tip of the active chain.
        for i in 0..22 {
            current_hash = current_header.block_hash();
            last_hash = current_hash;
            hashes.push(current_hash);
            for _j in 0..step {
                let prev_hash = current_header.prev_block_hash();
                //If the prev header does not exist, then simply return the `hashes` vector.
                if let Some(cached) = self.header_cache.get_header(prev_hash) {
                    current_header = cached.data.header.clone();
                } else {
                    if last_hash != genesis_hash {
                        hashes.push(genesis_hash);
                    }
                    return hashes;
                }
            }
            if i >= 7 {
                step = step.saturating_mul(2);
            }
        }

        if last_hash != genesis_hash {
            hashes.push(genesis_hash);
        }
        hashes
    }

    /// This method takes a block hash
    /// If the corresponding block is stored in the `block_cache`, the cached block is returned.
    pub fn get_block(&self, block_hash: &BlockHash) -> Option<Arc<SerializedBlock>> {
        self.block_cache.get(block_hash).cloned()
    }

    /// Used when the adapter is shutdown and no longer requires holding on to blocks.
    pub fn clear_blocks(&mut self) {
        self.block_cache = HashMap::new();
    }

    pub(crate) fn is_block_cache_full(&self) -> bool {
        self.get_block_cache_size() >= BLOCK_CACHE_THRESHOLD_BYTES
    }

    /// Returns the current size of the block cache.
    pub fn get_block_cache_size(&self) -> usize {
        self.block_cache.values().map(|block| block.len()).sum()
    }
}

impl<Network: BlockchainNetwork> HeaderStore for BlockchainState<Network> {
    fn get_header(&self, hash: &BlockHash) -> Option<(Header, BlockHeight)> {
        self.get_cached_header(hash).map(|cached| {
            (
                cached.data.header.clone().into_pure_header(),
                cached.data.height,
            )
        })
    }

    fn get_initial_hash(&self) -> BlockHash {
        self.genesis().block_hash()
    }

    fn get_height(&self) -> BlockHeight {
        self.get_active_chain_tip().height
    }
}

#[cfg(test)]
mod test {
    use bitcoin::{Block, Network, TxMerkleNode, consensus::Decodable};
    use ic_btc_validation::ValidateHeaderError;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use tempfile::tempdir;

    use super::*;
    use crate::common::test_common::TestState;
    use ic_btc_adapter_test_utils::{block_1, block_2, generate_header, generate_headers};
    use std::collections::HashSet;

    fn run_in_memory(network: Network, test_fn: impl Fn(BlockchainState<Network>)) {
        test_fn(BlockchainState::new(network, &MetricsRegistry::default()))
    }

    fn run_with_cache_dir(network: Network, test_fn: impl Fn(BlockchainState<Network>)) {
        let dir = tempdir().unwrap();
        test_fn(BlockchainState::new_with_cache_dir(
            network,
            dir.path().to_path_buf(),
            &MetricsRegistry::default(),
            no_op_logger(),
        ))
    }

    fn test_get_block(mut state: BlockchainState<Network>) {
        let test_state = TestState::setup();

        state
            .add_block(test_state.block_1.clone())
            .expect("should be able to add block 1");
        let block_1_hash = test_state.block_1.block_hash();
        let block_2_hash = test_state.block_2.block_hash();
        let block_hashes: HashSet<_> = vec![block_1_hash, block_2_hash].into_iter().collect();

        let mut cached_blocks = vec![];
        for hash in &block_hashes {
            if let Some(block) = state.get_block(hash) {
                cached_blocks.push((*hash, block));
            }
        }

        assert_eq!(cached_blocks.len(), 1);
        let (block_hash, serialized_block) = cached_blocks.first().expect("there should be 1");
        let block = Block::consensus_decode(&mut (*serialized_block).as_slice()).unwrap();
        assert_eq!(*block_hash, block_1_hash);
        assert_eq!(block.block_hash(), block_1_hash);
    }

    #[test]
    fn test_get_block_in_memory() {
        run_in_memory(Network::Bitcoin, test_get_block)
    }

    #[test]
    fn test_get_block_on_disk() {
        run_with_cache_dir(Network::Bitcoin, test_get_block)
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers to the cache
    /// successfully.
    fn test_adding_headers_successfully(mut state: BlockchainState<Network>) {
        let initial_header = state.genesis();
        let chain = generate_headers(initial_header.block_hash(), initial_header.time, 16, &[]);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();
        let last_hash = *chain_hashes.last().unwrap();

        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert!(maybe_err.is_none());

        let last_block_hashes = added_headers.last().unwrap();
        assert_eq!(*last_block_hashes, last_hash);
        let tip = state.get_active_chain_tip();
        assert_eq!(tip.height, 16);
        assert_eq!(tip.header.block_hash(), last_hash);
    }

    #[test]
    fn test_adding_headers_successfully_in_memory() {
        run_in_memory(Network::Regtest, test_adding_headers_successfully)
    }

    #[test]
    fn test_adding_headers_successfully_on_disk() {
        run_with_cache_dir(Network::Regtest, test_adding_headers_successfully)
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add 2500 mainnet headers to the cache
    /// successfully. After ~2000 headers there is difficulty adjustment so 2500 headers make sure that we test
    /// at least one header validation with difficulty adjustment.
    /// This is a regression test for incident at btc height 799_498.
    fn test_adding_mainnet_headers_successfully(mut state: BlockchainState<Network>) {
        let headers_json = include_str!("../test_data/first_2500_mainnet_headers.json");
        let headers: Vec<_> = serde_json::from_str(headers_json).unwrap();

        let (added_headers, maybe_err) = state.add_headers(&headers);
        assert!(
            maybe_err.is_none(),
            "Error when adding valid mainnet headers."
        );

        // The last block header has height 2499 because the genesis block header has height 0.
        assert_eq!(added_headers.len(), 2499);
        let tip = state.get_active_chain_tip();
        assert_eq!(tip.height, 2499);
    }

    #[test]
    fn test_adding_mainnet_headers_successfully_in_memory() {
        run_in_memory(Network::Bitcoin, test_adding_mainnet_headers_successfully)
    }

    #[test]
    fn test_adding_mainnet_headers_successfully_on_disk() {
        run_with_cache_dir(Network::Bitcoin, test_adding_mainnet_headers_successfully)
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add 2500 testnet headers to the cache
    /// successfully. After ~2000 headers there is difficulty adjustment so 2500 headers make sure that we test
    /// at least one header validation with difficulty adjustment.
    fn test_adding_testnet_headers_successfully(mut state: BlockchainState<Network>) {
        let headers_json = include_str!("../test_data/first_2500_testnet_headers.json");
        let headers: Vec<_> = serde_json::from_str(headers_json).unwrap();

        let (added_headers, maybe_err) = state.add_headers(&headers);
        assert!(
            maybe_err.is_none(),
            "Error when adding valid testnet headers."
        );

        // The last block header has height 2499 because the genesis block header has height 0.
        assert_eq!(added_headers.len(), 2499);
        let tip = state.get_active_chain_tip();
        assert_eq!(tip.height, 2499);
    }

    #[test]
    fn test_adding_testnet_headers_successfully_in_memory() {
        run_in_memory(Network::Testnet, test_adding_testnet_headers_successfully)
    }

    #[test]
    fn test_adding_testnet_headers_successfully_on_disk() {
        run_with_cache_dir(Network::Testnet, test_adding_testnet_headers_successfully)
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers that
    /// cause 2 forks in the chain. The state should be able to determine what is the active tip.
    fn test_forks_when_adding_headers(mut state: BlockchainState<Network>) {
        let initial_header = state.genesis();

        // Create an arbitrary chain and adding to the BlockchainState
        let chain = generate_headers(initial_header.block_hash(), initial_header.time, 16, &[]);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();
        let last_chain_hash = chain_hashes.last().expect("missing last hash");

        let (_, maybe_err) = state.add_headers(&chain);
        assert!(
            maybe_err.is_none(),
            "unsuccessfully added first chain: {maybe_err:?}"
        );

        // Create a fork chain forking from chain_hashes[10] and adding to the BlockchainState.
        let fork_chain = generate_headers(chain_hashes[10], chain[10].time, 16, &chain_hashes);
        let fork_hashes: Vec<BlockHash> = fork_chain
            .iter()
            .map(|header| header.block_hash())
            .collect();
        let last_fork_hash = fork_hashes.last().expect("missing last hash");

        let (_, maybe_err) = state.add_headers(&fork_chain);
        assert!(
            maybe_err.is_none(),
            "unsuccessfully added fork chain: {maybe_err:?}"
        );

        let mut tips = state.header_cache.get_tips();
        tips.sort_by(|x, y| y.work.cmp(&x.work));
        assert_eq!(tips.len(), 2);
        assert_eq!(tips[0].header.block_hash(), *last_fork_hash);
        assert_eq!(tips[1].header.block_hash(), *last_chain_hash);
        assert_eq!(state.get_active_chain_tip().height, 27);
    }

    #[test]
    fn test_forks_when_adding_headers_in_memory() {
        run_in_memory(Network::Regtest, test_forks_when_adding_headers)
    }

    #[test]
    fn test_forks_when_adding_headers_on_disk() {
        run_with_cache_dir(Network::Regtest, test_forks_when_adding_headers)
    }

    /// Tests `BlockchainState::add_headers(...)` with an empty set of headers.
    fn test_adding_an_empty_headers_vector(mut state: BlockchainState<Network>) {
        let chain = vec![];
        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert!(maybe_err.is_none());
        assert!(added_headers.is_empty());
        assert_eq!(state.get_active_chain_tip().height, 0);
    }

    #[test]
    fn test_adding_an_empty_headers_vector_in_memory() {
        run_in_memory(Network::Bitcoin, test_adding_an_empty_headers_vector)
    }

    #[test]
    fn test_adding_an_empty_headers_vector_on_disk() {
        run_with_cache_dir(Network::Bitcoin, test_adding_an_empty_headers_vector)
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can handle adding already known
    /// headers in the state.
    fn test_adding_headers_that_already_exist(mut state: BlockchainState<Network>) {
        let initial_header = state.genesis();
        let chain = generate_headers(initial_header.block_hash(), initial_header.time, 16, &[]);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();
        let last_hash = *chain_hashes.last().unwrap();

        let (last_block_hashes, maybe_err) = state.add_headers(&chain);
        assert!(maybe_err.is_none());
        assert_eq!(last_block_hashes.len(), 16);

        let last_block_hash = last_block_hashes.last().unwrap();
        assert_eq!(*last_block_hash, last_hash);

        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert!(maybe_err.is_none());
        assert!(added_headers.is_empty());
    }
    #[test]
    fn test_adding_headers_that_already_exist_in_memory() {
        run_in_memory(Network::Regtest, test_adding_headers_that_already_exist)
    }

    #[test]
    fn test_adding_headers_that_already_exist_on_disk() {
        run_with_cache_dir(Network::Regtest, test_adding_headers_that_already_exist)
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers while avoiding
    /// adding a header that is invalid.
    fn test_adding_headers_with_an_invalid_header(mut state: BlockchainState<Network>) {
        let initial_header = state.genesis();
        let mut chain = generate_headers(initial_header.block_hash(), initial_header.time, 16, &[]);
        let last_header = chain.get_mut(10).unwrap();
        last_header.prev_blockhash = BlockHash::from_raw_hash(bitcoin::hashes::Hash::all_zeros());

        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();
        let last_hash = chain_hashes[10];

        let (added_headers, maybe_err) = state.add_headers(&chain);

        assert_eq!(added_headers.len(), 10);
        assert!(
            matches!(maybe_err, Some(AddHeaderError::InvalidHeader(block_hash, err)) if block_hash == last_hash && matches!(err, ValidateHeaderError::PrevHeaderNotFound))
        );

        let tip = state.get_active_chain_tip();
        assert_eq!(tip.height, 10);
    }

    #[test]
    fn test_adding_headers_with_an_invalid_header_in_memory() {
        run_in_memory(Network::Regtest, test_adding_headers_with_an_invalid_header)
    }

    #[test]
    fn test_adding_headers_with_an_invalid_header_on_disk() {
        run_with_cache_dir(Network::Regtest, test_adding_headers_with_an_invalid_header)
    }

    /// Tests the functionality of `BlockchainState::add_block(...)` to push it through the add_header
    /// validation and adding the block to the cache.
    fn test_adding_blocks_to_the_cache(mut state: BlockchainState<Network>) {
        let block_1 = block_1();
        let mut block_2 = block_2();

        // Attempt to add block 2 to the cache before block 1's header has been added.
        let block_2_hash = block_2.header.block_hash();
        let result = state.add_block(block_2.clone());
        assert!(
            matches!(result, Err(AddBlockError::Header(AddHeaderError::InvalidHeader(stop_hash, err))) if stop_hash == block_2_hash && matches!(err, ValidateHeaderError::PrevHeaderNotFound)),
        );

        let result = state.add_block(block_1);
        assert!(matches!(result, Ok(())));

        // Make a block 2's merkle root invalid and try to add the block to the cache.
        block_2.header.merkle_root =
            TxMerkleNode::from_raw_hash(bitcoin::hashes::Hash::all_zeros());
        // Block 2's hash will now be changed because of the merkle root change.
        let block_2_hash = block_2.block_hash();
        let result = state.add_block(block_2);
        assert!(
            matches!(result, Err(AddBlockError::InvalidMerkleRoot(stop_hash)) if stop_hash == block_2_hash),
        );
    }

    #[test]
    fn test_adding_blocks_to_the_cache_in_memory() {
        run_in_memory(Network::Bitcoin, test_adding_blocks_to_the_cache)
    }

    #[test]
    fn test_adding_blocks_to_the_cache_on_disk() {
        run_with_cache_dir(Network::Bitcoin, test_adding_blocks_to_the_cache)
    }

    /// Tests the functionality of `BlockchainState::prune_blocks(...)` to ensure
    /// blocks are removed from the cache.
    fn test_pruning_blocks_from_the_cache(mut state: BlockchainState<Network>) {
        let test_state = TestState::setup();
        let block_1_hash = test_state.block_1.block_hash();
        let block_2_hash = test_state.block_2.block_hash();
        state.add_block(test_state.block_1).unwrap();
        state.add_block(test_state.block_2).unwrap();

        state.prune_blocks(&[block_2_hash]);
        assert!(state.block_cache.contains_key(&block_1_hash));
        assert!(!state.block_cache.contains_key(&block_2_hash));
    }

    #[test]
    fn test_pruning_blocks_from_the_cache_in_memory() {
        run_in_memory(Network::Bitcoin, test_pruning_blocks_from_the_cache)
    }

    #[test]
    fn test_pruning_blocks_from_the_cache_on_disk() {
        run_with_cache_dir(Network::Bitcoin, test_pruning_blocks_from_the_cache)
    }

    /// Tests the functionality of `BlockchainState::prune_blocks_below_height(...)` to ensure
    /// blocks are removed from the cache that are below a given height.
    fn test_pruning_blocks_below_a_given_height_from_the_cache(
        mut state: BlockchainState<Network>,
    ) {
        let test_state = TestState::setup();
        let block_1_hash = test_state.block_1.block_hash();
        let block_2_hash = test_state.block_2.block_hash();
        state.add_block(test_state.block_1).unwrap();
        state.add_block(test_state.block_2).unwrap();

        state.prune_blocks_below_height(2);
        assert!(!state.block_cache.contains_key(&block_1_hash));
        assert!(state.block_cache.contains_key(&block_2_hash));
    }

    #[test]
    fn test_pruning_blocks_below_a_given_height_from_the_cache_in_memory() {
        run_in_memory(
            Network::Bitcoin,
            test_pruning_blocks_below_a_given_height_from_the_cache,
        )
    }

    #[test]
    fn test_pruning_blocks_below_a_given_height_from_the_cache_on_disk() {
        run_with_cache_dir(
            Network::Bitcoin,
            test_pruning_blocks_below_a_given_height_from_the_cache,
        )
    }

    /// Simple test to verify that `BlockchainState::block_cache_size()` returns the total
    /// number of bytes in the block cache.
    fn test_block_cache_size(mut state: BlockchainState<Network>) {
        let test_state = TestState::setup();

        let block_cache_size = state.get_block_cache_size();
        assert_eq!(block_cache_size, 0);

        state.add_block(test_state.block_1.clone()).unwrap();
        state.add_block(test_state.block_2.clone()).unwrap();

        let expected_cache_size = test_state.block_1.total_size() + test_state.block_2.total_size();
        let block_cache_size = state.get_block_cache_size();

        assert_eq!(expected_cache_size, block_cache_size);
    }

    #[test]
    fn test_block_cache_size_in_memory() {
        run_in_memory(Network::Bitcoin, test_block_cache_size)
    }

    #[test]
    fn test_block_cache_size_on_disk() {
        run_with_cache_dir(Network::Bitcoin, test_block_cache_size)
    }

    /// Test that verifies that the tip is always correctly sorted in case of forks and blocks
    /// with unknown headers.
    fn test_sorted_tip(mut state: BlockchainState<Network>) {
        let h1 = state.genesis();
        // h1 - h2
        let h2 = generate_header(h1.block_hash(), h1.time, 0);
        state.add_headers(&[h2]);
        assert_eq!(state.get_active_chain_tip().header, h2);

        // Create a fork with 3 headers where the last one is invalid and check that h3f is the tip.
        //      h2f - h3f
        //    /
        // h1 - h2

        let h2f = generate_header(h1.block_hash(), h1.time, 1);
        let h3f = generate_header(h2f.block_hash(), h2f.time, 0);
        // Set time to zero to make header invalid
        let h4f_invalid = generate_header(h2f.block_hash(), 0, 0);
        state.add_headers(&[h2f, h3f, h4f_invalid]);
        assert_eq!(state.get_active_chain_tip().header, h3f);

        // Extend non fork chain with blocks (with unknown headers) and make sure h4 is tip.
        //      h2f - h3f
        //    /
        // h1 - h2  - h3  - h4
        let h3 = generate_header(h2.block_hash(), h2.time, 0);
        let h4 = generate_header(h3.block_hash(), h3.time, 0);
        state
            .add_block(Block {
                header: h3,
                txdata: Vec::new(),
            })
            .unwrap();
        state
            .add_block(Block {
                header: h4,
                txdata: Vec::new(),
            })
            .unwrap();
        assert_eq!(state.get_active_chain_tip().header, h4);
    }

    #[test]
    fn test_sorted_tip_in_memory() {
        run_in_memory(Network::Regtest, test_sorted_tip)
    }

    #[test]
    fn test_sorted_tip_on_disk() {
        run_with_cache_dir(Network::Regtest, test_sorted_tip)
    }

    /// Test header store `get_header` function.
    fn test_headerstore_get_cached_header(mut state: BlockchainState<Network>) {
        let initial_header = state.genesis();
        let chain = generate_headers(initial_header.block_hash(), initial_header.time, 2500, &[]);

        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert_eq!(added_headers.len(), 2500);
        assert!(maybe_err.is_none());

        for (h, header) in chain.iter().enumerate() {
            if h == 0 {
                assert_eq!(state.get_initial_hash(), state.genesis().block_hash(),);
            } else {
                let header_node = state.get_cached_header(&header.block_hash()).unwrap();
                assert_eq!(
                    (header_node.data.header, header_node.data.height),
                    (chain[h], (h + 1) as u32)
                );
            }
        }
    }

    #[test]
    fn test_headerstore_get_cached_header_in_memory() {
        run_in_memory(Network::Regtest, test_headerstore_get_cached_header)
    }

    #[test]
    fn test_headerstore_get_cached_header_on_disk() {
        run_with_cache_dir(Network::Regtest, test_headerstore_get_cached_header)
    }
}
