//! The module is responsible for keeping track of the blockchain state.
//!
use crate::{common::BlockHeight, config::Config, metrics::BlockchainStateMetrics};
use bitcoin::{blockdata::constants::genesis_block, Block, BlockHash, BlockHeader, Network};
use ic_btc_validation::{validate_header, HeaderStore, ValidateHeaderError};
use ic_metrics::MetricsRegistry;
use std::collections::HashMap;
use thiserror::Error;

/// This field contains the datatype used to store "work" of a Bitcoin blockchain
pub type Work = bitcoin::util::uint::Uint256;

/// Contains the necessary information about a tip.
#[derive(Clone, Debug)]
pub struct Tip {
    /// This field stores a Bitcoin header.
    pub header: BlockHeader,
    /// This field stores the height of the Bitcoin header stored in the field `header`.
    pub height: BlockHeight,
    /// This field stores the work of the Blockchain leading up to this tip.
    /// That is, this field is the sum of work of the above header and all its ancestors.
    pub work: Work,
}

/// Creates a new cache with a set genesis header determined by the
/// provided network.
fn init_cache_with_genesis(genesis_block_header: BlockHeader) -> HashMap<BlockHash, HeaderNode> {
    let cached_header = HeaderNode {
        header: genesis_block_header,
        height: 0,
        work: genesis_block_header.work(),
        children: vec![],
    };
    let mut headers = HashMap::new();
    headers.insert(genesis_block_header.block_hash(), cached_header);
    headers
}

/// This struct stores a BlockHeader along with its height in the Bitcoin Blockchain.
#[derive(Debug)]
pub struct HeaderNode {
    /// This field stores a Bitcoin header.
    pub header: BlockHeader,
    /// This field stores the height of a Bitcoin header
    pub height: BlockHeight,
    /// This field stores the work of the Blockchain leading up to this header.
    /// That is, this field is the sum of work of the above header and all its ancestors.
    pub work: Work,
    /// This field contains this node's successor headers.
    pub children: Vec<BlockHash>,
}

/// The result when `BlockchainState::add_header(...)` is called.
#[derive(Debug)]
enum AddHeaderResult {
    /// This variant is used when the input header is added to the header_cache.
    HeaderAdded(BlockHash),
    /// This variant is used when the input header already exists in the header_cache.
    HeaderAlreadyExists,
}

#[derive(Debug, Error)]
pub enum AddHeaderError {
    /// This variant is used when the input header is invalid
    /// (eg: not of the right format)
    #[error("Received an invalid block header: {0}")]
    InvalidHeader(BlockHash, ValidateHeaderError),
    /// This variant is used when the predecessor of the input header is not part of header_cache.
    #[error("Received a block header where we do not have the previous header in the cache: {0}")]
    PrevHeaderNotCached(BlockHash),
}

#[derive(Debug, Error)]
pub enum AddBlockError {
    /// Used to indicate that the merkle root of the block is invalid.
    #[error("Received a block with an invalid merkle root: {0}")]
    InvalidMerkleRoot(BlockHash),
    // Used to indicate when the header causes an error while adding a block to the state.
    #[error("Block's header caused an error: {0}")]
    Header(AddHeaderError),
}

/// This struct is a cache of Bitcoin blockchain.
/// The BlockChainState caches all the Bitcoin headers, some of the Bitcoin blocks.
/// The BlockChainState also maintains the child relationhips between the headers.
#[derive(Debug)]
pub struct BlockchainState {
    /// The starting point of the blockchain
    genesis_block_header: BlockHeader,

    /// This field stores all the Bitcoin headers using a HashMap containining BlockHash and the corresponding header.
    header_cache: HashMap<BlockHash, HeaderNode>,

    /// This field stores a hashmap containing BlockHash and the corresponding Block.
    block_cache: HashMap<BlockHash, Block>,

    /// This field contains the known tips of the header cache.
    tips: Vec<Tip>,

    /// Used to determine how validation should be handled with `validate_header`.
    network: Network,
    metrics: BlockchainStateMetrics,
}

impl BlockchainState {
    /// This function is used to create a new BlockChainState object.  
    pub fn new(config: &Config, metrics_registry: &MetricsRegistry) -> Self {
        // Create a header cache and inserting dummy header corresponding the `adapter_genesis_hash`.
        let genesis_block_header = genesis_block(config.network).header;
        let header_cache = init_cache_with_genesis(genesis_block_header);
        let block_cache = HashMap::new();
        let tips = vec![Tip {
            header: genesis_block_header,
            height: 0,
            work: genesis_block_header.work(),
        }];

        BlockchainState {
            genesis_block_header,
            header_cache,
            block_cache,
            tips,
            network: config.network,
            metrics: BlockchainStateMetrics::new(metrics_registry),
        }
    }

    /// Returns the genesis header that the store is initialized with.
    pub fn genesis(&self) -> &BlockHeader {
        &self.genesis_block_header
    }

    /// Returns the header for the given block hash.
    pub fn get_cached_header(&self, hash: &BlockHash) -> Option<&HeaderNode> {
        self.header_cache.get(hash)
    }

    /// Processes the `headers` message received from Bitcoin nodes by adding them to the state.
    /// Headers are expected to be sorted. If they are not, the headers will be likely be rejected
    /// with a [AddHeaderError::PrevHeaderNotCached](AddHeaderError::PrevHeaderNotCached) error.
    /// If the header has been added to the cache, it will be returned in a vector alongside
    /// a possible error that may have occurred while adding the headers.
    pub fn add_headers(
        &mut self,
        headers: &[BlockHeader],
    ) -> (Vec<BlockHash>, Option<AddHeaderError>) {
        let mut block_hashes_of_added_headers = vec![];

        let err = headers
            .iter()
            .try_for_each(|header| match self.add_header(*header) {
                Ok(AddHeaderResult::HeaderAdded(block_hash)) => {
                    block_hashes_of_added_headers.push(block_hash);
                    Ok(())
                }
                Ok(AddHeaderResult::HeaderAlreadyExists) => Ok(()),
                Err(err) => Err(err),
            })
            .err();

        // Sort the tips by the total work
        self.tips.sort_unstable_by(|a, b| b.work.cmp(&a.work));
        self.metrics.tips.set(self.tips.len() as i64);
        self.metrics
            .tip_height
            .set(self.get_active_chain_tip().height.into());

        (block_hashes_of_added_headers, err)
    }

    /// This method adds the input header to the `header_cache`.
    #[allow(clippy::indexing_slicing)]
    fn add_header(&mut self, header: BlockHeader) -> Result<AddHeaderResult, AddHeaderError> {
        let block_hash = header.block_hash();

        // If the header already exists in the cache,
        // then don't insert the header again, and return HeaderAlreadyExistsError
        if self.get_cached_header(&block_hash).is_some() {
            return Ok(AddHeaderResult::HeaderAlreadyExists);
        }

        if let Err(err) = validate_header(&self.network, self, &header) {
            return Err(AddHeaderError::InvalidHeader(block_hash, err));
        }

        let parent = self
            .header_cache
            .get_mut(&header.prev_blockhash)
            .ok_or(AddHeaderError::PrevHeaderNotCached(header.prev_blockhash))?;

        let cached_header = HeaderNode {
            header,
            height: parent.height + 1,
            work: parent.work + header.work(),
            children: vec![],
        };
        parent.children.push(header.block_hash());

        // Update the tip headers.
        // If the previous header already exists in `tips`, then update it with the new tip.
        let prev_hash = header.prev_blockhash;
        let maybe_cached_header_idx = self
            .tips
            .iter()
            .position(|tip| tip.header.block_hash() == prev_hash);
        let tip = Tip {
            header,
            height: cached_header.height,
            work: cached_header.work,
        };

        match maybe_cached_header_idx {
            Some(idx) => {
                self.tips[idx] = tip;
            }
            None => {
                // If the previous header is not a tip, then add the `cached_header` as a tip.
                self.tips.push(tip);
            }
        };

        self.header_cache.insert(block_hash, cached_header);

        self.metrics.header_cache_size.inc();
        Ok(AddHeaderResult::HeaderAdded(header.block_hash()))
    }

    /// This method adds a new block to the `block_cache`
    pub fn add_block(&mut self, block: Block) -> Result<(), AddBlockError> {
        let block_hash = block.block_hash();

        if block.compute_merkle_root().is_some() && !block.check_merkle_root() {
            return Err(AddBlockError::InvalidMerkleRoot(block_hash));
        }

        // If the block's header is not added before, then add the header into the `header_cache` first.
        let _ = self
            .add_header(block.header)
            .map_err(AddBlockError::Header)?;
        self.tips.sort_unstable_by(|a, b| b.work.cmp(&a.work));
        self.block_cache.insert(block_hash, block);
        self.metrics
            .block_cache_size
            .set(self.get_block_cache_size() as i64);
        self.metrics
            .block_cache_elements
            .set(self.block_cache.len() as i64);
        Ok(())
    }

    /// This method returns the tip header with the highest cumulative work.
    #[allow(clippy::indexing_slicing)]
    pub fn get_active_chain_tip(&self) -> &Tip {
        // `self.tips` is initialized in the new() method with the initial header.
        // `add_headers` sorts the tips by total work. The zero index will always be
        // the active tip.
        &self.tips[0]
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
            .filter(|b| height > self.get_cached_header(b).map_or(0, |c| c.height))
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
        let mut current_header = tip.header;
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
                let prev_hash = current_header.prev_blockhash;
                //If the prev header does not exist, then simply return the `hashes` vector.
                if let Some(cached) = self.header_cache.get(&prev_hash) {
                    current_header = cached.header;
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

    /// This method takes a list of block hashes as input.
    /// For each block hash, if the corresponding block is stored in the `block_cache`, the cached block is returned.
    pub fn get_block(&self, block_hash: &BlockHash) -> Option<&Block> {
        self.block_cache.get(block_hash)
    }

    /// Used when the adapter is shutdown and no longer requires holding on to blocks.
    pub fn clear_blocks(&mut self) {
        self.block_cache = HashMap::new();
    }

    /// Returns the current size of the block cache.
    pub fn get_block_cache_size(&self) -> usize {
        self.block_cache.values().fold(0, |sum, b| b.size() + sum)
    }
}

impl HeaderStore for BlockchainState {
    fn get_header(&self, hash: &BlockHash) -> Option<(BlockHeader, BlockHeight)> {
        self.get_cached_header(hash)
            .map(|cached| (cached.header, cached.height))
    }

    fn get_height(&self) -> BlockHeight {
        self.get_active_chain_tip().height
    }

    fn get_initial_hash(&self) -> BlockHash {
        self.genesis().block_hash()
    }
}

#[cfg(test)]
mod test {
    use bitcoin::TxMerkleNode;
    use ic_metrics::MetricsRegistry;

    use super::*;
    use crate::{common::test_common::TestState, config::test::ConfigBuilder};
    use ic_btc_adapter_test_utils::{block_1, block_2, generate_header, generate_headers};
    use std::collections::HashSet;

    #[test]
    fn test_get_block() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

        state
            .add_block(test_state.block_1.clone())
            .expect("should be able to add block 1");
        let block_1_hash = test_state.block_1.block_hash();
        let block_2_hash = test_state.block_2.block_hash();
        let block_hashes: HashSet<_> = vec![block_1_hash, block_2_hash].into_iter().collect();

        let mut cached_blocks = vec![];
        for hash in &block_hashes {
            if let Some(block) = state.get_block(hash) {
                cached_blocks.push(block);
            }
        }

        assert_eq!(cached_blocks.len(), 1);
        let block = cached_blocks.first().expect("there should be 1");
        assert_eq!(block.block_hash(), block_1_hash);
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers to the cache
    /// successfully.
    #[test]
    fn test_adding_headers_successfully() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

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

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add 2500 mainnet headers to the cache
    /// successfully. After ~2000 headers there is difficulty adjustment so 2500 headers make sure that we test
    /// at least one header validation with difficulty adjustment.
    /// This is a regression test for incident at btc height 799_498.
    #[test]
    fn test_adding_mainnet_headers_successfully() {
        let config = ConfigBuilder::new().with_network(Network::Bitcoin).build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

        let headers_json = include_str!("../test_data/first_2500_mainnet_headers.json");
        let headers: Vec<BlockHeader> = serde_json::from_str(headers_json).unwrap();

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

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add 2500 testnet headers to the cache
    /// successfully. After ~2000 headers there is difficulty adjustment so 2500 headers make sure that we test
    /// at least one header validation with difficulty adjustment.
    #[test]
    fn test_adding_testnet_headers_successfully() {
        let config = ConfigBuilder::new().with_network(Network::Testnet).build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

        let headers_json = include_str!("../test_data/first_2500_testnet_headers.json");
        let headers: Vec<BlockHeader> = serde_json::from_str(headers_json).unwrap();

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
    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers that
    /// cause 2 forks in the chain. The state should be able to determine what is the active tip.
    fn test_forks_when_adding_headers() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());
        let initial_header = state.genesis();

        // Create an arbitrary chain and adding to the BlockchainState
        let chain = generate_headers(initial_header.block_hash(), initial_header.time, 16, &[]);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();
        let last_chain_hash = chain_hashes.last().expect("missing last hash");

        let (_, maybe_err) = state.add_headers(&chain);
        assert!(
            maybe_err.is_none(),
            "unsuccessfully added first chain: {:?}",
            maybe_err
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
            "unsuccessfully added fork chain: {:?}",
            maybe_err
        );

        assert_eq!(state.tips.len(), 2);
        assert_eq!(state.tips[0].header.block_hash(), *last_fork_hash);
        assert_eq!(state.tips[1].header.block_hash(), *last_chain_hash);
        assert_eq!(state.get_active_chain_tip().height, 27);
    }

    /// Tests `BlockchainState::add_headers(...)` with an empty set of headers.
    #[test]
    fn test_adding_an_empty_headers_vector() {
        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());
        let chain = vec![];
        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert!(maybe_err.is_none());
        assert!(added_headers.is_empty());
        assert_eq!(state.get_active_chain_tip().height, 0);
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can handle adding already known
    /// headers in the state.
    #[test]
    fn test_adding_headers_that_already_exist() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

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

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers while avoiding
    /// adding a header that is invalid.
    #[test]
    fn test_adding_headers_with_an_invalid_header() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

        let initial_header = state.genesis();
        let mut chain = generate_headers(initial_header.block_hash(), initial_header.time, 16, &[]);
        let last_header = chain.get_mut(10).unwrap();
        last_header.prev_blockhash = BlockHash::default();

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

    /// Tests the functionality of `BlockchainState::add_block(...)` to push it through the add_header
    /// validation and adding the block to the cache.
    #[test]
    fn test_adding_blocks_to_the_cache() {
        let block_1 = block_1();
        let mut block_2 = block_2();

        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

        // Attempt to add block 2 to the cache before block 1's header has been added.
        let block_2_hash = block_2.header.block_hash();
        let result = state.add_block(block_2.clone());
        assert!(
            matches!(result, Err(AddBlockError::Header(AddHeaderError::InvalidHeader(stop_hash, err))) if stop_hash == block_2_hash && matches!(err, ValidateHeaderError::PrevHeaderNotFound)),
        );

        let result = state.add_block(block_1);
        assert!(matches!(result, Ok(())));

        // Make a block 2's merkle root invalid and try to add the block to the cache.
        block_2.header.merkle_root = TxMerkleNode::default();
        // Block 2's hash will now be changed because of the merkle root change.
        let block_2_hash = block_2.block_hash();
        let result = state.add_block(block_2);
        assert!(
            matches!(result, Err(AddBlockError::InvalidMerkleRoot(stop_hash)) if stop_hash == block_2_hash),
        );
    }

    /// Tests the functionality of `BlockchainState::prune_blocks(...)` to ensure
    /// blocks are removed from the cache.
    #[test]
    fn test_pruning_blocks_from_the_cache() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());
        let block_1_hash = test_state.block_1.block_hash();
        let block_2_hash = test_state.block_2.block_hash();
        state.add_block(test_state.block_1).unwrap();
        state.add_block(test_state.block_2).unwrap();

        state.prune_blocks(&[block_2_hash]);
        assert!(state.block_cache.contains_key(&block_1_hash));
        assert!(!state.block_cache.contains_key(&block_2_hash));
    }

    /// Tests the functionality of `BlockchainState::prune_blocks_below_height(...)` to ensure
    /// blocks are removed from the cache that are below a given height.
    #[test]
    fn test_pruning_blocks_below_a_given_height_from_the_cache() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());
        let block_1_hash = test_state.block_1.block_hash();
        let block_2_hash = test_state.block_2.block_hash();
        state.add_block(test_state.block_1).unwrap();
        state.add_block(test_state.block_2).unwrap();

        state.prune_blocks_below_height(2);
        assert!(!state.block_cache.contains_key(&block_1_hash));
        assert!(state.block_cache.contains_key(&block_2_hash));
    }

    /// Simple test to verify that `BlockchainState::block_cache_size()` returns the total
    /// number of bytes in the block cache.
    #[test]
    fn test_block_cache_size() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

        let block_cache_size = state.get_block_cache_size();
        assert_eq!(block_cache_size, 0);

        state.add_block(test_state.block_1.clone()).unwrap();
        state.add_block(test_state.block_2.clone()).unwrap();

        let expected_cache_size = test_state.block_1.size() + test_state.block_2.size();
        let block_cache_size = state.get_block_cache_size();

        assert_eq!(expected_cache_size, block_cache_size);
    }

    /// Test that verifies that the tip is always correctly sorted in case of forks and blocks
    /// with unknown headers.
    #[test]
    fn test_sorted_tip() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());
        let h1 = *state.genesis();
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

    /// Test header store `get_header` function.
    #[test]
    fn test_headerstore_get_header() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config, &MetricsRegistry::default());

        let initial_header = state.genesis();
        let chain = generate_headers(initial_header.block_hash(), initial_header.time, 2500, &[]);

        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert_eq!(added_headers.len(), 2500);
        assert!(maybe_err.is_none());

        for (h, header) in chain.iter().enumerate() {
            if h == 0 {
                assert_eq!(state.get_initial_hash(), state.genesis().block_hash(),);
            } else {
                assert_eq!(
                    state.get_header(&header.block_hash()).unwrap(),
                    (chain[h], (h + 1) as u32),
                );
            }
        }
    }
}
