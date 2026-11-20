use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, Mutex},
};

use bitcoin::{BlockHash, consensus::Encodable};
use ic_metrics::MetricsRegistry;
use static_assertions::const_assert_eq;
use tokio::sync::mpsc::Sender;
use tonic::Status;

use crate::{
    BlockchainManagerRequest, BlockchainState,
    blockchainstate::SerializedBlock,
    common::{BlockHeight, BlockchainHeader, BlockchainNetwork},
    metrics::GetSuccessorMetrics,
};

// Max size of the `GetSuccessorsResponse` message.
// This number is slightly less than the maximum payload size a canister can send (2MiB)
// to leave a small buffer for the additional space that candid encoding may need.
//
// NOTE: Should be = the `MAX_RESPONSE_SIZE` defined in `replicated_state/bitcoin.rs`
// for pagination on the replica side to work as expected.
const MAX_RESPONSE_SIZE: usize = 2_000_000;

// Lower than mainnet's response size. The main reason is large serialization time
// for large blocks.
const TESTNET4_MAX_RESPONSE_SIZE: usize = 1_000_000;

// Max number of next block headers that can be returned in the `GetSuccessorsResponse`.
const MAX_NEXT_BLOCK_HEADERS_LENGTH: usize = 100;

// Max number of blocks that can be returned in the `GetSuccessorsResponse`.
// We limit the number of blocks because serializing many blocks to pb can take some time.
const MAX_BLOCKS_LENGTH: usize = 100;

// The maximum number of get blocks requests that can be in-flight at any given time.
pub(crate) const MAX_IN_FLIGHT_BLOCKS: usize = 100;

// The maximum number of get blocks requests that can be in-flight at any given time.
// The number of blocks outside of the main chain easily exceeds 100 currently on testnet4.
// Setting this to 100 would prevent the adapter from making progress,
// as it gets stuck on these blocks, whose requests timeout indefinitely.
pub(crate) const TESTNET4_MAX_IN_FLIGHT_BLOCKS: usize = 1000;

const BLOCK_HEADER_SIZE: usize = 80;

// The maximum number of bytes the `next` field in a response can take.
const MAX_NEXT_BYTES: usize = MAX_NEXT_BLOCK_HEADERS_LENGTH * BLOCK_HEADER_SIZE;

// The maximum number of bytes the `blocks` in a response can take.
// NOTE: This is a soft limit, and is only honored if there's > 1 blocks already in the response.
// Having this as a soft limit as necessary to prevent large blocks from stalling consensus.
pub(crate) const MAX_BLOCKS_BYTES: usize = MAX_RESPONSE_SIZE - MAX_NEXT_BYTES;

pub(crate) const TESTNET4_MAX_BLOCKS_BYTES: usize = TESTNET4_MAX_RESPONSE_SIZE - MAX_NEXT_BYTES;

const_assert_eq!(MAX_NEXT_BYTES + MAX_BLOCKS_BYTES, MAX_RESPONSE_SIZE);
const_assert_eq!(
    MAX_NEXT_BYTES + TESTNET4_MAX_BLOCKS_BYTES,
    TESTNET4_MAX_RESPONSE_SIZE
);

// Max height for sending multiple blocks when connecting the Bitcoin mainnet.
pub(crate) const BTC_MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT: BlockHeight = 750_000;

// Max height for sending multiple blocks when connecting the Dogecoin mainnet.
pub(crate) const DOGE_MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT: BlockHeight = 5_000_000;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct GetSuccessorsRequest {
    /// Hash of the most recent stable block in the Bitcoin canister.
    pub anchor: BlockHash,
    /// Most recent block hashes that have been processed by the canister.
    pub processed_block_hashes: Vec<BlockHash>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct GetSuccessorsResponse<Header> {
    /// Blocks found in the block cache.
    pub blocks: Vec<Arc<SerializedBlock>>,
    /// Next set of headers to be sent to the canister.
    pub next: Vec<Header>,
}
/// Contains the functionality to respond to GetSuccessorsRequests via the RPC
/// server.
pub struct GetSuccessorsHandler<Network: BlockchainNetwork> {
    state: Arc<BlockchainState<Network>>,
    blockchain_manager_tx: Sender<BlockchainManagerRequest>,
    network: Network,
    metrics: GetSuccessorMetrics,
    pruning_task_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    most_work_chain: Mutex<MostWorkChain>,
}

impl<Network: BlockchainNetwork + Send + Sync> GetSuccessorsHandler<Network> {
    /// Creates a GetSuccessorsHandler to be used to access the blockchain state
    /// inside of the adapter when a `GetSuccessorsRequest` is received.
    pub fn new(
        network: Network,
        state: Arc<BlockchainState<Network>>,
        blockchain_manager_tx: Sender<BlockchainManagerRequest>,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            state,
            blockchain_manager_tx,
            network,
            metrics: GetSuccessorMetrics::new(metrics_registry),
            pruning_task_handle: Mutex::new(None),
            most_work_chain: Mutex::new(MostWorkChain::default()),
        }
    }

    // TODO: ER-2157: GetSuccessors should only sync after the adapter is synced past the
    // highest checkpoint.
    // TODO: ER-2479: Pruning blocks from the cache should also consider the height of the anchor hash.
    /// Handles a request for get successors. The response will contain the blocks that the adapter
    /// currently contains in its cache as well as the headers for the next blocks.
    /// If the channels are full, PruneOldBlocks and EnqueueNewBlocksToDownload will not be executed.
    pub async fn get_successors(
        &self,
        request: GetSuccessorsRequest,
    ) -> Result<GetSuccessorsResponse<Network::Header>, Status> {
        let start_time = std::time::Instant::now();

        self.metrics
            .processed_block_hashes
            .observe(request.processed_block_hashes.len() as f64);

        let anchor_header = self.state.get_cached_header(&request.anchor);
        let anchor_height = anchor_header
            .as_ref()
            .map_or(0, |cached| cached.data.height);

        // Spawn persist-to-disk task without waiting for it to finish, and make sure there
        // is only one task running at a time.
        let mut handle = self.pruning_task_handle.lock().unwrap();
        let is_finished = handle
            .as_ref()
            .map(|handle| handle.is_finished())
            .unwrap_or(true);
        if is_finished {
            self.metrics
                .prune_headers_anchor_height
                .set(anchor_height as i64);
            *handle = Some(
                self.state
                    .persist_and_prune_headers_below_anchor(request.anchor),
            );
        }

        let (blocks, next, obsolete_blocks) = {
            let allow_multiple_blocks = self.network.are_multiple_blocks_allowed(anchor_height);
            let blocks = get_successor_blocks(
                &self.state,
                &request.anchor,
                &request.processed_block_hashes,
                allow_multiple_blocks,
                &self.network,
            );
            let mut most_work_chain = self.most_work_chain.lock().unwrap();
            let most_work_chain_above_anchor = anchor_header
                .is_some()
                .then(|| {
                    most_work_chain.hashes_above_anchor(&self.state, &request.anchor, anchor_height)
                })
                .into_iter()
                .flatten();
            let next = get_next_headers(
                &self.state,
                &request.anchor,
                &request.processed_block_hashes,
                &blocks,
                most_work_chain_above_anchor,
                &self.network,
            );
            drop(most_work_chain);
            // If no blocks are returned, this means that nothing that is in the cache could be reached from the anchor.
            // We can safely remove everything that is in the cache then, as those blocks are no longer needed.
            // There is a chance that these blocks are above the anchor height (but they were forked below it),
            // meaning that the regular "pruning anything below anchor" will not affect them.
            // There is also a chance that they are reachable from the anchor, just not through the cache.
            // Meaning that we still need to download some other blocks first. (hence we need to free the cache).
            let mut obsolete_blocks = request.processed_block_hashes;
            if blocks.is_empty() && self.state.is_block_cache_full() {
                obsolete_blocks.extend(self.state.get_cached_blocks())
            }
            (blocks, next, obsolete_blocks)
        };
        // Because Dogecoin headers can have variable length, we must choose
        // next headers that can fit within MAX_NEXT_BYTES.
        // TODO(XC-478): add tests for auxpow headers
        let mut response_next = Vec::with_capacity(MAX_NEXT_BLOCK_HEADERS_LENGTH);
        let mut response_next_bytes = 0;
        let mut bytes = Vec::with_capacity(MAX_NEXT_BYTES);
        for header in next.iter() {
            match header.consensus_encode(&mut bytes) {
                Ok(size) => {
                    response_next_bytes += size;
                    if response_next_bytes <= MAX_NEXT_BYTES {
                        response_next.push(header.clone())
                    } else {
                        break;
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
        let response = GetSuccessorsResponse {
            blocks: blocks.into_iter().map(|(_, block)| block).collect(),
            next: response_next.to_vec(),
        };
        self.metrics
            .response_blocks
            .observe(response.blocks.len() as f64);

        if !next.is_empty() {
            // TODO: better handling of full channel as the receivers are never closed.
            self.blockchain_manager_tx
                .try_send(BlockchainManagerRequest::EnqueueNewBlocksToDownload(
                    next.into_iter().map(|x| x.into_pure_header()).collect(),
                ))
                .ok();
        }
        // TODO: better handling of full channel as the receivers are never closed.
        self.blockchain_manager_tx
            .try_send(BlockchainManagerRequest::PruneBlocks(
                request.anchor,
                obsolete_blocks,
            ))
            .ok();

        // Record response metrics
        let blocks_size: usize = response.blocks.iter().map(|b| b.len()).sum();
        self.metrics
            .response_blocks_size
            .observe(blocks_size as f64);
        let empty_label = match response.blocks.is_empty() {
            true => "true",
            false => "false",
        };
        self.metrics
            .response_build_duration
            .with_label_values(&[empty_label])
            .observe(start_time.elapsed().as_secs_f64());

        Ok(response)
    }
}

// Performs a breadth-first search to retrieve blocks from the block cache.
//
// If blocks are available and `allow_multiple_blocks` is `true`, then as many blocks are returned
// as possible that fit in the `MAX_BLOCKS_BYTES` limit, with a minimum of one block.  Otherwise, a
// single block is returned.
fn get_successor_blocks<Network: BlockchainNetwork>(
    state: &BlockchainState<Network>,
    anchor: &BlockHash,
    processed_block_hashes: &[BlockHash],
    allow_multiple_blocks: bool,
    network: &Network,
) -> Vec<(BlockHash, Arc<SerializedBlock>)> {
    let seen: HashSet<BlockHash> = processed_block_hashes.iter().copied().collect();

    let mut successor_blocks = vec![];
    // Block hashes that should be looked at in subsequent breadth-first searches.
    let mut response_block_size: usize = 0;
    let mut queue: VecDeque<BlockHash> = state
        .get_cached_header(anchor)
        .map(|c| c.children.into_iter().collect())
        .unwrap_or_default();

    let max_blocks_bytes = network.max_blocks_bytes();

    let max_blocks_length = if allow_multiple_blocks {
        MAX_BLOCKS_LENGTH
    } else {
        1
    };

    // Compute the blocks by starting a breadth-first search.
    while let Some(block_hash) = queue.pop_front() {
        if !seen.contains(&block_hash) {
            // Retrieve the block from the cache.
            let Some(block) = state.get_block(&block_hash) else {
                // If the block is not in the cache, we skip it and all its subtree.
                // We don't want to return orphaned blocks to the canister.
                continue;
            };
            let block_size = block.len();
            // If we have at least one block in the response, and we can't fit another block, we stop.
            if response_block_size > 0
                && (response_block_size + block_size > max_blocks_bytes
                    || successor_blocks.len() + 1 > max_blocks_length)
            {
                break;
            }
            successor_blocks.push((block_hash, block));
            response_block_size += block_size;
        }

        queue.extend(
            state
                .get_cached_header(&block_hash)
                .map(|header| header.children.into_iter())
                .unwrap_or_default(),
        );
    }

    successor_blocks
}

/// Block hashes of the chain ending in the tip with the most accumulated work, where the first
/// hash is at `base_height`. It is kept across requests so that the chain only needs to be
/// walked from the tip down to the first header it shares with the previously known chain.
#[derive(Default)]
struct MostWorkChain {
    base_height: BlockHeight,
    hashes: VecDeque<BlockHash>,
}

impl MostWorkChain {
    fn hash_at(&self, height: BlockHeight) -> Option<&BlockHash> {
        let index = height.checked_sub(self.base_height)?;
        self.hashes.get(index as usize)
    }

    /// Brings the chain up to date with the current most-work tip, drops the hashes below the
    /// anchor, and returns the hashes above the anchor in ascending order of height.
    /// Returns nothing if the anchor is not on the most-work chain.
    fn hashes_above_anchor<Network: BlockchainNetwork>(
        &mut self,
        state: &BlockchainState<Network>,
        anchor: &BlockHash,
        anchor_height: BlockHeight,
    ) -> impl Iterator<Item = BlockHash> + '_ {
        if self.base_height > anchor_height {
            self.hashes.clear();
        }
        while self.base_height < anchor_height && self.hashes.pop_front().is_some() {
            self.base_height += 1;
        }

        let tip = state.get_active_chain_tip();
        let tip_hash = tip.header.block_hash();
        if self.hashes.back() != Some(&tip_hash) {
            let mut new_hashes = vec![];
            let mut shared_height = None;
            let mut current = Some((tip_hash, tip.height, tip.header.prev_block_hash()));
            while let Some((hash, height, prev_hash)) = current {
                if self.hash_at(height) == Some(&hash) {
                    shared_height = Some(height);
                    break;
                }
                new_hashes.push(hash);
                if height <= anchor_height {
                    break;
                }
                current = state.get_cached_header(&prev_hash).map(|node| {
                    (
                        prev_hash,
                        node.data.height,
                        node.data.header.prev_block_hash(),
                    )
                });
            }
            match shared_height {
                Some(height) => self
                    .hashes
                    .truncate((height - self.base_height) as usize + 1),
                None => {
                    self.hashes.clear();
                    self.base_height = (tip.height + 1).saturating_sub(new_hashes.len() as u32);
                }
            }
            self.hashes.extend(new_hashes.into_iter().rev());
        }

        let skip = if self.hash_at(anchor_height) == Some(anchor) {
            (anchor_height - self.base_height) as usize + 1
        } else {
            self.hashes.len()
        };
        self.hashes.iter().skip(skip).copied()
    }
}

/// Get the next headers for blocks that may possibly be sent in upcoming GetSuccessor responses.
/// This returns up to MAX_IN_FLIGHT_BLOCKS / TESTNET4_MAX_IN_FLIGHT_BLOCKS headers which are not
/// in processed nor are they in the current response. Essentially representing the blocks that
/// should be returned in the next response.
///
/// The headers on the most-work chain above the anchor come first, so that headers of other
/// branches cannot prevent the blocks of the most-work chain from being downloaded. The
/// remaining slots are filled with the other headers reachable from the anchor in BFS fashion.
fn get_next_headers<Network: BlockchainNetwork>(
    state: &BlockchainState<Network>,
    anchor: &BlockHash,
    processed_block_hashes: &[BlockHash],
    blocks: &[(BlockHash, Arc<SerializedBlock>)],
    most_work_chain_above_anchor: impl Iterator<Item = BlockHash>,
    network: &Network,
) -> Vec<Network::Header> {
    let seen: HashSet<BlockHash> = processed_block_hashes
        .iter()
        .copied()
        .chain(blocks.iter().map(|(hash, _)| *hash))
        .collect();

    let max_in_flight_blocks = network.max_in_flight_blocks();
    let mut next_headers = vec![];
    let mut selected = HashSet::new();

    for block_hash in most_work_chain_above_anchor {
        if next_headers.len() >= max_in_flight_blocks {
            break;
        }
        if seen.contains(&block_hash) {
            continue;
        }
        let Some(header_node) = state.get_cached_header(&block_hash) else {
            break;
        };
        next_headers.push(header_node.data.header);
        selected.insert(block_hash);
    }

    let mut queue: VecDeque<BlockHash> = state
        .get_cached_header(anchor)
        .map(|c| c.children.into_iter().collect())
        .unwrap_or_default();

    while let Some(block_hash) = queue.pop_front() {
        if next_headers.len() >= max_in_flight_blocks {
            break;
        }

        if let Some(header_node) = state.get_cached_header(&block_hash) {
            if !seen.contains(&block_hash) && !selected.contains(&block_hash) {
                next_headers.push(header_node.data.header.clone());
            }
            queue.extend(header_node.children.iter());
        }
    }
    next_headers
}

// TODO(XC-478): add tests for auxpow headers
#[cfg(test)]
mod test {
    use super::*;

    use bitcoin::{Block, consensus::Decodable};
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use tokio::sync::mpsc::channel;

    use ic_btc_adapter_test_utils::{
        generate_headers, generate_large_block_blockchain, headers_to_hashes,
    };

    fn decode_block(serialized_block: &Arc<SerializedBlock>) -> Block {
        Block::consensus_decode(&mut (*serialized_block).as_slice()).unwrap()
    }

    fn new_blockchain_state<Network: BlockchainNetwork>(
        network: Network,
    ) -> BlockchainState<Network> {
        BlockchainState::new(network, None, &MetricsRegistry::default(), no_op_logger())
    }

    /// This tests ensures that `BlockchainManager::get_successors(...)` will return relevant blocks
    /// with the next headers of many forks and enqueue missing block hashes.
    #[tokio::test]
    async fn test_get_successors() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );
        // Set up the following chain:
        // |--> 1'---> 2'
        // 0 -> 1 ---> 2 ---> 3 -> 4
        // |--> 1'' -> 2'' -> 3''
        let mut previous_hashes = vec![];
        let main_chain = generate_headers(genesis_hash, genesis.time, 4, &[]);
        previous_hashes.extend(
            main_chain
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<_>>(),
        );
        let side_chain = generate_headers(genesis_hash, genesis.time, 2, &previous_hashes);
        previous_hashes.extend(
            side_chain
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<_>>(),
        );
        let side_chain_2 = generate_headers(genesis_hash, genesis.time, 3, &previous_hashes);

        let main_block_2 = Block {
            header: main_chain[1],
            txdata: vec![],
        };
        let side_1 = side_chain.first().cloned().expect("Should have 1 header");
        let side_block_1 = Block {
            header: side_1,
            txdata: vec![],
        };

        // Create a request with the anchor block as the block 0 and processed block hashes contain
        // block 1 and 2.
        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![main_chain[0].block_hash(), main_chain[1].block_hash()],
        };

        {
            let blockchain = &handler.state;
            blockchain.add_headers(&main_chain).await;
            blockchain.add_headers(&side_chain).await;
            blockchain.add_headers(&side_chain_2).await;

            // Add main block 2
            blockchain
                .add_block(main_block_2)
                .await
                .expect("invalid block");
            // Add side block 1
            blockchain
                .add_block(side_block_1.clone())
                .await
                .expect("invalid block");
        }

        let response = handler.get_successors(request).await.unwrap();

        // Check that blocks contain block 1.
        assert_eq!(response.blocks.len(), 1);
        assert!(
            matches!(response.blocks.first(), Some(block) if decode_block(block).block_hash() == side_block_1.block_hash())
        );

        assert_eq!(response.next.len(), 6);

        let next_hashes = response
            .next
            .iter()
            .map(|h| h.block_hash())
            .collect::<Vec<BlockHash>>();

        assert_eq!(
            next_hashes,
            vec![
                main_chain[2].block_hash(),   // 3
                main_chain[3].block_hash(),   // 4
                side_chain_2[0].block_hash(), // 1''
                side_chain[1].block_hash(),   // 2'
                side_chain_2[1].block_hash(), // 2''
                side_chain_2[2].block_hash(), // 3''
            ],
            "main = {:#?}, side = {:#?}, side 2 = {:#?}, next hashes = {:#?}",
            main_chain
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<BlockHash>>(),
            side_chain
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<BlockHash>>(),
            side_chain_2
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<BlockHash>>(),
            next_hashes
        );
    }

    #[tokio::test]
    async fn test_get_successors_wait_header_sync_regtest() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );

        // Set up the following chain:
        // 0 -> 1 -> 2 -> 3 -> 4 -> 5
        let main_chain = generate_headers(genesis_hash, genesis.time, 5, &[]);
        let main_block_1 = Block {
            header: main_chain[0],
            txdata: vec![],
        };
        let main_block_2 = Block {
            header: main_chain[1],
            txdata: vec![],
        };
        {
            let blockchain = &handler.state;
            blockchain.add_headers(&main_chain).await;
            blockchain
                .add_block(main_block_1.clone())
                .await
                .expect("invalid block");
            blockchain
                .add_block(main_block_2.clone())
                .await
                .expect("invalid block");
        }
        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![],
        };
        let response = handler.get_successors(request).await.unwrap();

        // Response should be contain the blocks and next headers since the regtest network does not have checkpoints.
        assert_eq!(response.blocks.len(), 2);
        assert_eq!(response.next.len(), 3);
    }

    /// This tests ensures that `BlockchainManager::handle_client_request(...)` returns multiple
    /// blocks from the main chain and a fork. Order should be preserved.
    #[tokio::test]
    async fn test_get_successors_multiple_blocks() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );
        // Set up the following chain:
        // |-> 1'
        // 0 -> 1 -> 2
        let main_chain = generate_headers(genesis_hash, genesis.time, 2, &[]);
        let main_block_1 = Block {
            header: main_chain[0],
            txdata: vec![],
        };
        let main_block_2 = Block {
            header: main_chain[1],
            txdata: vec![],
        };

        let side_chain = generate_headers(
            genesis_hash,
            genesis.time,
            1,
            &headers_to_hashes(&main_chain),
        );
        let side_1 = side_chain.first().cloned().expect("Should have 1 header");
        let side_block_1 = Block {
            header: side_1,
            txdata: vec![],
        };
        {
            let blockchain = &handler.state;
            blockchain.add_headers(&main_chain).await;
            blockchain.add_headers(&side_chain).await;
            blockchain
                .add_block(main_block_1.clone())
                .await
                .expect("invalid block");
            blockchain
                .add_block(main_block_2.clone())
                .await
                .expect("invalid block");
            blockchain
                .add_block(side_block_1.clone())
                .await
                .expect("invalid block");
        }
        //             |-> 1'
        // If chain is 0 -> 1 -> 2 and block hashes are {0}  then {1, 1', 2} should be returned in that order.
        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![],
        };
        let response = handler.get_successors(request).await.unwrap();
        assert_eq!(response.blocks.len(), 3);
        assert!(
            matches!(response.blocks.first(), Some(block) if decode_block(block).block_hash() == main_block_1.block_hash())
        );
        assert!(
            matches!(response.blocks.get(1), Some(block) if decode_block(block).block_hash() == side_block_1.block_hash())
        );
        assert!(
            matches!(response.blocks.get(2), Some(block) if decode_block(block).block_hash() == main_block_2.block_hash())
        );
    }

    /// This tests ensures that `get_successor` returns no more than MAX_BLOCKS_LENGTH blocks.
    #[tokio::test]
    async fn test_get_successors_max_num_blocks() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );
        let main_chain = generate_headers(genesis_hash, genesis.time, 120, &[]);
        {
            let blockchain = &handler.state;
            blockchain.add_headers(&main_chain).await;
            for header in main_chain {
                let block = Block {
                    header,
                    txdata: vec![],
                };
                blockchain.add_block(block).await.expect("invalid block");
            }
        }

        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![],
        };
        let response = handler.get_successors(request).await.unwrap();
        assert_eq!(response.blocks.len(), MAX_BLOCKS_LENGTH);
    }

    /// This tests ensures that `BlockchainManager::get_successors(...)` returns multiple
    /// blocks from the main chain and a fork. Order should be preserved.
    #[tokio::test]
    async fn test_get_successors_multiple_blocks_out_of_order() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );
        // Set up the following chain:
        // |-> 1'
        // 0 -> 1 -> 2
        let main_chain = generate_headers(genesis_hash, genesis.time, 2, &[]);
        let main_block_2 = Block {
            header: main_chain[1],
            txdata: vec![],
        };

        let side_chain = generate_headers(
            genesis_hash,
            genesis.time,
            1,
            &headers_to_hashes(&main_chain),
        );
        let side_1 = side_chain.first().cloned().expect("Should have 1 header");
        let side_block_1 = Block {
            header: side_1,
            txdata: vec![],
        };
        {
            let blockchain = &handler.state;
            let (_, maybe_err) = blockchain.add_headers(&main_chain).await;
            assert!(
                maybe_err.is_none(),
                "Error was found in main chain: {maybe_err:#?}"
            );

            let (_, maybe_err) = blockchain.add_headers(&side_chain).await;
            assert!(
                maybe_err.is_none(),
                "Error was found in side chain: {maybe_err:#?}"
            );
            blockchain
                .add_block(main_block_2)
                .await
                .expect("invalid block");

            blockchain
                .add_block(side_block_1.clone())
                .await
                .expect("invalid block");
        }

        //             |-> 1'
        // If chain is 0 -> 1 -> 2 and block hashes are {0}  then {1, 1', 2} would be the successor blocks.
        // Block 1 is not in the cache yet. The Bitcoin virtual canister requires that the blocks
        // are received in order.
        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![],
        };
        let response = handler.get_successors(request).await.unwrap();
        assert_eq!(
            response.blocks.len(),
            1,
            "main_chain = {:#?}, side_chain = {:#?}, blocks = {:#?}",
            headers_to_hashes(&main_chain),
            headers_to_hashes(&side_chain),
            response
                .blocks
                .iter()
                .map(|b| decode_block(b).block_hash())
                .collect::<Vec<BlockHash>>()
        );
        assert!(
            matches!(response.blocks.first(), Some(block) if decode_block(block).block_hash() == side_block_1.block_hash())
        );
        assert_eq!(
            response.next.len(),
            2,
            "main_chain = {:#?}, side_chain = {:#?}, next = {:#?}",
            headers_to_hashes(&main_chain),
            headers_to_hashes(&side_chain),
            headers_to_hashes(&response.next)
        );
        assert_eq!(response.next[0].block_hash(), main_chain[0].block_hash());
        assert_eq!(response.next[1].block_hash(), main_chain[1].block_hash());
    }

    /// This test ensures that the 2MB limit is enforced by `BlockchainManager.get_successors(...)`.
    #[tokio::test]
    async fn test_get_successors_large_block() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );
        // Generate a blockchain with one large block.
        let large_blocks = generate_large_block_blockchain(genesis_hash, genesis.time, 1);
        let large_block = large_blocks.first().cloned().unwrap();
        let headers: Vec<_> = large_blocks.iter().map(|b| b.header).collect();

        let previous_hashes = headers.iter().map(|h| h.block_hash()).collect::<Vec<_>>();
        let additional_headers = generate_headers(
            large_block.block_hash(),
            large_block.header.time,
            1,
            &previous_hashes,
        );
        // Add an additional smaller block to the chain.
        let small_block = Block {
            header: additional_headers[0],
            txdata: vec![],
        };

        {
            let blockchain = &handler.state;
            let (added_headers, _) = blockchain.add_headers(&headers).await;
            assert_eq!(added_headers.len(), 1);
            let (added_headers, _) = blockchain.add_headers(&additional_headers).await;
            assert_eq!(added_headers.len(), 1);

            blockchain
                .add_block(large_block.clone())
                .await
                .expect("invalid block");
            blockchain
                .add_block(small_block)
                .await
                .expect("invalid block");
        };

        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![],
        };
        let response = handler.get_successors(request).await.unwrap();
        // There are 2 blocks in the chain: {large, small}.
        // Only the large block should be returned in this response.
        assert_eq!(response.blocks.len(), 1);
        assert!(
            matches!(response.blocks.first(), Some(block) if decode_block(block).block_hash() == large_block.block_hash() && decode_block(block).txdata.len() == large_block.txdata.len())
        );
        // The smaller block's header should be in the next field.
        assert!(
            matches!(response.next.first(), Some(header) if header.block_hash() == additional_headers[0].block_hash())
        );
    }

    /// This test ensures that `BlockchainManager::get_successors(...)` sends blocks up to the cap limit.
    #[tokio::test]
    async fn test_get_successors_many_blocks_until_size_cap_is_met() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );

        let main_chain = generate_headers(genesis_hash, genesis.time, 5, &[]);
        let large_blocks =
            generate_large_block_blockchain(main_chain[4].block_hash(), main_chain[4].time, 1);

        {
            let blockchain = &handler.state;
            let (added_headers, _) = blockchain.add_headers(&main_chain).await;
            assert_eq!(added_headers.len(), 5);
            let main_blocks = main_chain
                .iter()
                .map(|h| Block {
                    header: *h,
                    txdata: vec![],
                })
                .collect::<Vec<_>>();
            for block in main_blocks {
                blockchain.add_block(block).await.unwrap();
            }

            for block in &large_blocks {
                blockchain.add_block(block.clone()).await.unwrap();
            }
        };

        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![],
        };
        let response = handler.get_successors(request).await.unwrap();

        // Six blocks in the chain. First 5 are small blocks and the last block is large.
        // Should return the first 5 blocks as the total size is below the cap.
        assert_eq!(response.blocks.len(), 5);
        assert!(
            matches!(response.blocks.last(), Some(block) if decode_block(block).block_hash() == main_chain.last().unwrap().block_hash())
        );

        // The next field should contain the large block header as it is too large for the request.
        assert_eq!(response.next.len(), 1);
        assert!(
            matches!(response.next.first(), Some(header) if large_blocks[0].block_hash() == header.block_hash())
        );
    }

    fn generate_single_header_forks(
        parent: &bitcoin::block::Header,
        count: usize,
    ) -> Vec<bitcoin::block::Header> {
        let mut forks: Vec<bitcoin::block::Header> = vec![];
        for _ in 0..count {
            let fork = generate_headers(
                parent.block_hash(),
                parent.time,
                1,
                &headers_to_hashes(&forks),
            );
            forks.extend(fork);
        }
        forks
    }

    fn take_enqueued_hashes(
        receiver: &mut tokio::sync::mpsc::Receiver<BlockchainManagerRequest>,
    ) -> Vec<BlockHash> {
        let mut enqueued = vec![];
        while let Ok(request) = receiver.try_recv() {
            if let BlockchainManagerRequest::EnqueueNewBlocksToDownload(headers) = request {
                enqueued.extend(headers.iter().map(|h| h.block_hash()));
            }
        }
        enqueued
    }

    /// Ensures that the headers of the most-work chain are included in `next` and enqueued for
    /// download even when more than `MAX_IN_FLIGHT_BLOCKS` other headers that come earlier in
    /// BFS order are reachable from the anchor.
    #[tokio::test]
    async fn test_next_headers_prioritise_most_work_chain() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, mut blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );

        // Set up the following chain, where the forks 1', 1'', ... are added before the main chain:
        // |--> 1' (x MAX_IN_FLIGHT_BLOCKS + 50)
        // 0 -> 1 -> 2 -> 3
        let forks = generate_single_header_forks(&genesis, MAX_IN_FLIGHT_BLOCKS + 50);
        let main_chain =
            generate_headers(genesis_hash, genesis.time, 3, &headers_to_hashes(&forks));
        {
            let blockchain = &handler.state;
            let (added, err) = blockchain.add_headers(&forks).await;
            assert_eq!(added.len(), forks.len(), "{err:?}");
            let (added, err) = blockchain.add_headers(&main_chain).await;
            assert_eq!(added.len(), main_chain.len(), "{err:?}");
        }

        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![],
        };
        let response = handler.get_successors(request).await.unwrap();

        assert!(response.blocks.is_empty());
        assert_eq!(response.next.len(), MAX_NEXT_BLOCK_HEADERS_LENGTH);
        assert_eq!(
            headers_to_hashes(&response.next[..3]),
            headers_to_hashes(&main_chain)
        );

        let enqueued = take_enqueued_hashes(&mut blockchain_manager_rx);
        assert_eq!(enqueued.len(), MAX_IN_FLIGHT_BLOCKS);
        assert_eq!(enqueued[..3], headers_to_hashes(&main_chain));
    }

    /// Ensures that `next` follows the most-work chain as the anchor advances, the chain is
    /// extended, and another branch overtakes it.
    #[tokio::test]
    async fn test_next_headers_follow_most_work_chain_as_it_changes() {
        let network = bitcoin::Network::Regtest;
        let blockchain_state = new_blockchain_state(network);
        let genesis = blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, mut blockchain_manager_rx) = channel(10);
        let handler = GetSuccessorsHandler::new(
            network,
            Arc::new(blockchain_state),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );

        // 0 -> a1 -> a2
        let chain_a = generate_headers(genesis_hash, genesis.time, 2, &[]);
        handler.state.add_headers(&chain_a).await;
        let response = handler
            .get_successors(GetSuccessorsRequest {
                anchor: genesis_hash,
                processed_block_hashes: vec![],
            })
            .await
            .unwrap();
        assert_eq!(
            headers_to_hashes(&response.next),
            headers_to_hashes(&chain_a)
        );

        // 0 -> a1 -> a2 -> a3 -> a4, with the anchor moved to a1.
        let a1_hash = chain_a[0].block_hash();
        let extension = generate_headers(chain_a[1].block_hash(), chain_a[1].time, 2, &[]);
        handler.state.add_headers(&extension).await;
        let response = handler
            .get_successors(GetSuccessorsRequest {
                anchor: a1_hash,
                processed_block_hashes: vec![],
            })
            .await
            .unwrap();
        assert_eq!(
            headers_to_hashes(&response.next),
            vec![
                chain_a[1].block_hash(),
                extension[0].block_hash(),
                extension[1].block_hash()
            ]
        );

        //        |--> a2' (x MAX_IN_FLIGHT_BLOCKS + 50)
        // 0 -> a1 -> a2 -> a3 -> a4
        //        |--> b2 -> b3 -> b4 -> b5 -> b6
        let forks = generate_single_header_forks(&chain_a[0], MAX_IN_FLIGHT_BLOCKS + 50);
        handler.state.add_headers(&forks).await;
        let mut known_hashes = headers_to_hashes(&forks);
        known_hashes.push(chain_a[1].block_hash());
        let chain_b = generate_headers(a1_hash, chain_a[0].time, 5, &known_hashes);
        let (added, err) = handler.state.add_headers(&chain_b).await;
        assert_eq!(added.len(), chain_b.len(), "{err:?}");
        take_enqueued_hashes(&mut blockchain_manager_rx);

        let response = handler
            .get_successors(GetSuccessorsRequest {
                anchor: a1_hash,
                processed_block_hashes: vec![chain_b[0].block_hash()],
            })
            .await
            .unwrap();
        assert_eq!(response.next.len(), MAX_NEXT_BLOCK_HEADERS_LENGTH);
        assert_eq!(
            headers_to_hashes(&response.next[..4]),
            headers_to_hashes(&chain_b[1..])
        );
        let enqueued = take_enqueued_hashes(&mut blockchain_manager_rx);
        assert_eq!(enqueued[..4], headers_to_hashes(&chain_b[1..]));
    }

    #[test]
    fn test_are_multiple_blocks_allowed() {
        // Mainnet
        assert!(
            bitcoin::Network::Bitcoin.are_multiple_blocks_allowed(100_500),
            "Multiple blocks are allowed at 100_500"
        );
        assert!(
            bitcoin::Network::Bitcoin
                .are_multiple_blocks_allowed(BTC_MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT),
            "Multiple blocks are allowed at {BTC_MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT}"
        );
        assert!(
            !bitcoin::Network::Bitcoin.are_multiple_blocks_allowed(900_000),
            "Multiple blocks are not allowed at 900_000"
        );

        // Testnet
        assert!(
            bitcoin::Network::Testnet.are_multiple_blocks_allowed(1_000_000),
            "Multiple blocks are allowed at 1_000_000"
        );
        assert!(
            bitcoin::Network::Testnet.are_multiple_blocks_allowed(u32::MAX),
            "Multiple blocks are allowed at {}",
            u32::MAX
        );

        // Regtest
        assert!(
            bitcoin::Network::Regtest.are_multiple_blocks_allowed(1),
            "Multiple blocks are allowed at 1"
        );
        assert!(
            bitcoin::Network::Regtest.are_multiple_blocks_allowed(u32::MAX),
            "Multiple blocks are allowed at {}",
            u32::MAX
        );
    }
}
