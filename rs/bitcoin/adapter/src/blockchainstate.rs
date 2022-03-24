use crate::{common::BlockHeight, config::Config};
use bitcoin::{blockdata::constants::genesis_block, Block, BlockHash, BlockHeader, Network};
use ic_btc_validation::{validate_header, HeaderStore, ValidateHeaderError};
use std::collections::HashMap;
use thiserror::Error;

/// This field contains the datatype used to store "work" of a Bitcoin blockchain
pub type Work = bitcoin::util::uint::Uint256;

/// Contains the necessary information about a tip.
#[derive(Debug, Clone)]
pub struct Tip {
    /// This field stores a Bitcoin header.
    pub header: BlockHeader,
    /// This field stores the height of the Bitcoin header stored in the field `header`.
    pub height: BlockHeight,
    /// This field stores the work of the Blockchain leading up to this tip.
    /// That is, this field is the sum of work of the above header and all its ancestors.
    pub work: Work,
}

/// This struct stores a BlockHeader along with its height in the Bitcoin Blockchain.
#[derive(Debug, Clone)]
pub struct CachedHeader {
    /// This field stores a Bitcoin header.
    pub header: BlockHeader,
    /// This field stores the height of a Bitcoin header
    pub height: BlockHeight,
    /// This field stores the work of the Blockchain leading up to this header.
    /// That is, this field is the sum of work of the above header and all its ancestors.
    pub work: Work,
}

/// The result when `BlockchainState::add_header(...)` is called.
#[derive(Debug)]
enum AddHeaderResult {
    /// This variant is used when the input header is added to the header_cache.
    HeaderAdded(CachedHeader),
    /// This variant is used when the input header already exists in the header_cache.
    HeaderAlreadyExists(CachedHeader),
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
    // TODO: ER-1548: Block headers must be persisted in storage and the adapter must be able
    // to resume from the stored state.
    /// This field stores all the Bitcoin headers using a HashMap containining BlockHash and the corresponding header.
    header_cache: HashMap<BlockHash, CachedHeader>,

    /// This field stores a hashmap containing BlockHash and the corresponding Block.
    block_cache: HashMap<BlockHash, Block>,

    /// This field maps a block hash to the block hashes of all its children.
    children: HashMap<BlockHash, Vec<BlockHash>>,

    /// Contains the cached genesis header.
    cached_genesis: CachedHeader,

    /// This field contains the known tips of the header cache.
    tips: Vec<Tip>,

    /// Used to determine how validation should be handled with `validate_header`.
    network: Network,
}

impl BlockchainState {
    /// This function is used to create a new BlockChainState object.  
    pub fn new(config: &Config) -> Self {
        // Create a header cache and inserting dummy header corresponding the `adapter_genesis_hash`.
        let mut header_cache = HashMap::new();

        let cached_genesis = {
            let header = genesis_block(config.network).header;
            CachedHeader {
                header,
                height: 0,
                work: header.work(),
            }
        };
        header_cache.insert(cached_genesis.header.block_hash(), cached_genesis.clone());

        let block_cache = HashMap::new();
        let children = HashMap::new();
        let tips = vec![Tip {
            header: cached_genesis.header,
            height: 0,
            work: cached_genesis.work,
        }];

        BlockchainState {
            header_cache,
            block_cache,
            children,
            cached_genesis,
            tips,
            network: config.network,
        }
    }

    /// Returns the genesis header that the store is initialized with.
    pub fn genesis(&self) -> &CachedHeader {
        &self.cached_genesis
    }

    /// Returns the header for the given block hash.
    pub fn get_cached_header(&self, hash: &BlockHash) -> Option<&CachedHeader> {
        self.header_cache.get(hash)
    }

    /// This method retrieves the children for the given block hash.
    pub fn get_children(&self, hash: &BlockHash) -> Vec<BlockHash> {
        self.children.get(hash).cloned().unwrap_or_default()
    }

    /// Processes the `headers` message received from Bitcoin nodes by adding them to the state.
    /// Headers are expected to be sorted. If they are not, the headers will be likely be rejected
    /// with a [AddHeaderError::PrevHeaderNotCached](AddHeaderError::PrevHeaderNotCached) error.
    /// If the header has been added to the cache, it will be returned in a vector alongside
    /// a possible error that may have occurred while adding the headers.
    pub fn add_headers(
        &mut self,
        headers: &[BlockHeader],
    ) -> (Vec<CachedHeader>, Option<AddHeaderError>) {
        let mut added_headers = vec![];

        for header in headers {
            match self.add_header(*header) {
                Ok(AddHeaderResult::HeaderAdded(cached_header)) => {
                    added_headers.push(cached_header);
                }
                Ok(AddHeaderResult::HeaderAlreadyExists(_)) => {}
                Err(err) => return (added_headers, Some(err)),
            }
        }

        // Sort the tips by the total work
        self.tips.sort_unstable_by(|a, b| b.work.cmp(&a.work));

        (added_headers, None)
    }

    /// This method adds the input header to the `header_cache`.
    #[allow(clippy::indexing_slicing)]
    fn add_header(&mut self, header: BlockHeader) -> Result<AddHeaderResult, AddHeaderError> {
        let block_hash = header.block_hash();

        // If the header already exists in the cache,
        // then don't insert the header again, and return HeaderAlreadyExistsError
        if let Some(cached_header) = self.get_cached_header(&block_hash) {
            return Ok(AddHeaderResult::HeaderAlreadyExists(cached_header.clone()));
        }

        if let Err(err) = validate_header(&self.network, self, &header) {
            return Err(AddHeaderError::InvalidHeader(block_hash, err));
        }

        // Compute prev_hash in the header. Check if it is present in the `header_cache`.
        let prev_hash = header.prev_blockhash;
        let prev_header = self
            .header_cache
            .get(&prev_hash)
            .ok_or(AddHeaderError::PrevHeaderNotCached(block_hash))?;

        // Insert the header into `header_cache`.
        // Height is currently u32, this should be sufficient for a long while
        #[allow(clippy::integer_arithmetic)]
        let height = prev_header.height + 1;
        let work = prev_header.work + header.work();
        let cached_header = CachedHeader {
            header,
            height,
            work,
        };
        self.header_cache.insert(block_hash, cached_header.clone());

        // Insert the header into `children`.
        self.children
            .entry(prev_hash)
            .or_insert_with(Vec::new)
            .push(block_hash);

        // Update the tip headers.
        // If the previous header already exists in `tips`, then update it with the new tip.
        let maybe_cached_header_idx = self
            .tips
            .iter()
            .position(|tip| tip.header.block_hash() == prev_hash);
        let tip = Tip {
            header,
            height,
            work,
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

        Ok(AddHeaderResult::HeaderAdded(cached_header))
    }

    /// This method adds a new block to the `block_cache`
    pub fn add_block(&mut self, block: Block) -> Result<BlockHeight, AddBlockError> {
        let block_hash = block.block_hash();

        if !block.check_merkle_root() {
            return Err(AddBlockError::InvalidMerkleRoot(block_hash));
        }

        // If the block's header is not added before, then add the header into the `header_cache` first.
        let result = self
            .add_header(block.header)
            .map_err(AddBlockError::Header)?;
        self.block_cache.insert(block_hash, block);
        Ok(match result {
            AddHeaderResult::HeaderAdded(cached) => cached.height,
            AddHeaderResult::HeaderAlreadyExists(cached) => cached.height,
        })
    }

    /// This method returns the tip header with the highest cumulative work.
    #[allow(clippy::indexing_slicing)]
    pub fn get_active_chain_tip(&self) -> &Tip {
        // `self.tips` is initialized in the new() method with the initial header.
        // `add_headers` sorts the tips by total work. The zero index will always be
        // the active tip.
        &self.tips[0]
    }

    /// This method is used to remove old blocks in the `header_cache`
    pub fn prune_old_blocks(&mut self, block_hashes: &[BlockHash]) {
        for block_hash in block_hashes {
            self.block_cache.remove(block_hash);
        }
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
        let genesis_hash = self.genesis().header.block_hash();
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

    /// Check whether a block hash is known i.e., stored in the `header_cache`.
    pub fn is_block_hash_known(&self, block_hash: &BlockHash) -> bool {
        self.header_cache.contains_key(block_hash)
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
        self.block_cache
            .values()
            .fold(0, |sum, b| b.get_size() + sum)
    }
}

impl HeaderStore for BlockchainState {
    fn get_header(&self, hash: &BlockHash) -> Option<(&BlockHeader, BlockHeight)> {
        self.get_cached_header(hash)
            .map(|cached| (&cached.header, cached.height))
    }

    fn get_height(&self) -> BlockHeight {
        self.get_active_chain_tip().height
    }

    fn get_initial_hash(&self) -> BlockHash {
        self.genesis().header.block_hash()
    }
}

#[cfg(test)]
mod test {
    use bitcoin::TxMerkleNode;

    use super::*;
    use crate::{
        common::test_common::{block_1, block_2, generate_headers, TestState},
        config::test::ConfigBuilder,
    };
    use std::collections::HashSet;

    #[test]
    fn test_get_block() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config);

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
        let block = cached_blocks.get(0).expect("there should be 1");
        assert_eq!(block.block_hash(), block_1_hash);
    }
    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers to the cache
    /// successfully.
    #[test]
    fn test_adding_headers_successfully() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config);

        let initial_header = state.genesis();
        let chain = generate_headers(
            initial_header.header.block_hash(),
            initial_header.header.time,
            16,
            &[],
        );
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();
        let last_hash = *chain_hashes.last().unwrap();

        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert!(maybe_err.is_none());

        let last_cached = added_headers.last().unwrap();
        assert_eq!(last_cached.header.block_hash(), last_hash);
        assert_eq!(last_cached.height, 16);
        let tip = state.get_active_chain_tip();
        assert_eq!(tip.height, 16);
        assert_eq!(tip.header.block_hash(), last_hash);
    }

    #[test]
    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers that
    /// cause 2 forks in the chain. The state should be able to determine what is the active tip.
    fn test_forks_when_adding_headers() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config);
        let initial_header = state.genesis();

        // Create an arbitrary chain and adding to the BlockchainState
        let chain = generate_headers(
            initial_header.header.block_hash(),
            initial_header.header.time,
            16,
            &[],
        );
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
        let mut state = BlockchainState::new(&config);
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
        let mut state = BlockchainState::new(&config);

        let initial_header = state.genesis();
        let chain = generate_headers(
            initial_header.header.block_hash(),
            initial_header.header.time,
            16,
            &[],
        );
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();
        let last_hash = *chain_hashes.last().unwrap();

        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert!(maybe_err.is_none());
        assert_eq!(added_headers.len(), 16);

        let last_cached = added_headers.last().unwrap();
        assert_eq!(last_cached.header.block_hash(), last_hash);
        assert_eq!(last_cached.height, 16);

        let (added_headers, maybe_err) = state.add_headers(&chain);
        assert!(maybe_err.is_none());
        assert!(added_headers.is_empty());
    }

    /// Tests whether or not the `BlockchainState::add_headers(...)` function can add headers while avoiding
    /// adding a header that is invalid.
    #[test]
    fn test_adding_headers_with_an_invalid_header() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut state = BlockchainState::new(&config);

        let initial_header = state.genesis();
        let mut chain = generate_headers(
            initial_header.header.block_hash(),
            initial_header.header.time,
            16,
            &[],
        );
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
        let mut state = BlockchainState::new(&config);

        // Attempt to add block 2 to the cache before block 1's header has been added.
        let block_2_hash = block_2.header.block_hash();
        let result = state.add_block(block_2.clone());
        assert!(
            matches!(result, Err(AddBlockError::Header(AddHeaderError::InvalidHeader(stop_hash, err))) if stop_hash == block_2_hash && matches!(err, ValidateHeaderError::PrevHeaderNotFound)),
        );

        let result = state.add_block(block_1);
        assert!(matches!(result, Ok(height) if height == 1));

        // Make a block 2's merkle root invalid and try to add the block to the cache.
        block_2.header.merkle_root = TxMerkleNode::default();
        // Block 2's hash will now be changed because of the merkle root change.
        let block_2_hash = block_2.block_hash();
        let result = state.add_block(block_2);
        assert!(
            matches!(result, Err(AddBlockError::InvalidMerkleRoot(stop_hash)) if stop_hash == block_2_hash),
        );
    }

    /// Tests the functionality of `BlockchainState::prune_old_blocks(...)` to ensure
    /// blocks are removed from the cache.
    #[test]
    fn test_pruning_old_blocks_from_the_cache() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config);
        let block_2_hash = test_state.block_2.block_hash();
        state.add_block(test_state.block_1).unwrap();
        state.add_block(test_state.block_2).unwrap();

        state.prune_old_blocks(&[block_2_hash]);
        assert!(!state.block_cache.contains_key(&block_2_hash));
    }

    /// Simple test to verify that `BlockchainState::block_cache_size()` returns the total
    /// number of bytes in the block cache.
    #[test]
    fn test_block_cache_size() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut state = BlockchainState::new(&config);

        let block_cache_size = state.get_block_cache_size();
        assert_eq!(block_cache_size, 0);

        state.add_block(test_state.block_1.clone()).unwrap();
        state.add_block(test_state.block_2.clone()).unwrap();

        let expected_cache_size = test_state.block_1.get_size() + test_state.block_2.get_size();
        let block_cache_size = state.get_block_cache_size();

        assert_eq!(expected_cache_size, block_cache_size);
    }
}
