use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use bitcoin::{Block, BlockHash, BlockHeader, Network};
use ic_btc_validation::is_beyond_last_checkpoint;
use ic_metrics::MetricsRegistry;
use tokio::sync::{mpsc::Sender, Mutex};
use tonic::{Code, Status};

use crate::{
    common::BlockHeight, config::Config, metrics::GetSuccessorMetrics, BlockchainManagerRequest,
    BlockchainState,
};

// Max size of the `GetSuccessorsResponse` message.
// This number is slightly less than the maximum payload size a canister can send (2MiB)
// to leave a small buffer for the additional space that candid encoding may need.
//
// NOTE: Should be = the `MAX_RESPONSE_SIZE` defined in `replicated_state/bitcoin.rs`
// for pagination on the replica side to work as expected.
const MAX_RESPONSE_SIZE: usize = 2_000_000;

// Max number of next block headers that can be returned in the `GetSuccessorsResponse`.
const MAX_NEXT_BLOCK_HEADERS_LENGTH: usize = 100;

// Max number of blocks that can be returned in the `GetSuccessorsResponse`.
// We limit the number of blocks because serializing many blocks to pb can take some time.
const MAX_BLOCKS_LENGTH: usize = 100;

const BLOCK_HEADER_SIZE: usize = 80;

// The maximum number of bytes the `next` field in a response can take.
const MAX_NEXT_BYTES: usize = MAX_NEXT_BLOCK_HEADERS_LENGTH * BLOCK_HEADER_SIZE;

// The maximum number of bytes the `blocks` in a response can take.
// NOTE: This is a soft limit, and is only honored if there's > 1 blocks already in the response.
// Having this as a soft limit as necessary to prevent large blocks from stalling consensus.
const MAX_BLOCKS_BYTES: usize = MAX_RESPONSE_SIZE - MAX_NEXT_BYTES;

// Max height for sending multiple blocks when connecting the Bitcoin mainnet.
const MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT: BlockHeight = 750_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSuccessorsRequest {
    /// Hash of the most recent stable block in the Bitcoin canister.
    pub anchor: BlockHash,
    /// Most recent block hashes that have been processed by the canister.
    pub processed_block_hashes: Vec<BlockHash>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSuccessorsResponse {
    /// Blocks found in the block cache.
    pub blocks: Vec<Block>,
    /// Next set of headers to be sent to the canister.
    pub next: Vec<BlockHeader>,
}
/// Contains the functionality to respond to GetSuccessorsRequests via the RPC
/// server.
pub struct GetSuccessorsHandler {
    state: Arc<Mutex<BlockchainState>>,
    blockchain_manager_tx: Sender<BlockchainManagerRequest>,
    network: Network,
    metrics: GetSuccessorMetrics,
}

impl GetSuccessorsHandler {
    /// Creates a GetSuccessorsHandler to be used to access the blockchain state
    /// inside of the adapter when a `GetSuccessorsRequest` is received.
    pub fn new(
        config: &Config,
        state: Arc<Mutex<BlockchainState>>,
        blockchain_manager_tx: Sender<BlockchainManagerRequest>,
        metrics_registry: &MetricsRegistry,
    ) -> Self {
        Self {
            state,
            blockchain_manager_tx,
            network: config.network,
            metrics: GetSuccessorMetrics::new(metrics_registry),
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
    ) -> Result<GetSuccessorsResponse, Status> {
        self.metrics
            .processed_block_hashes
            .observe(request.processed_block_hashes.len() as f64);

        let response = {
            let state = self.state.lock().await;
            let anchor_height = state
                .get_cached_header(&request.anchor)
                .map_or(0, |cached| cached.height);

            // Wait with downloading blocks until we synced the header chain above the last checkpoint
            // to make sure we are following the correct chain.
            if !is_beyond_last_checkpoint(&self.network, state.get_active_chain_tip().height) {
                return Err(Status::new(
                    Code::Unavailable,
                    "Header chain not yet synced past last checkpoint",
                ));
            }

            let allow_multiple_blocks = are_multiple_blocks_allowed(self.network, anchor_height);
            let blocks = get_successor_blocks(
                &state,
                &request.anchor,
                &request.processed_block_hashes,
                allow_multiple_blocks,
            );
            let next = get_next_headers(
                &state,
                &request.anchor,
                &request.processed_block_hashes,
                &blocks,
            );
            GetSuccessorsResponse { blocks, next }
        };
        self.metrics
            .response_blocks
            .observe(response.blocks.len() as f64);

        if !response.next.is_empty() {
            // TODO: better handling of full channel as the receivers are never closed.
            self.blockchain_manager_tx
                .try_send(BlockchainManagerRequest::EnqueueNewBlocksToDownload(
                    response.next.clone(),
                ))
                .ok();
        }
        // TODO: better handling of full channel as the receivers are never closed.
        self.blockchain_manager_tx
            .try_send(BlockchainManagerRequest::PruneBlocks(
                request.anchor,
                request.processed_block_hashes,
            ))
            .ok();

        Ok(response)
    }
}

// Performs a breadth-first search to retrieve blocks from the block cache.
//
// If blocks are available and `allow_multiple_blocks` is `true`, then as many blocks are returned
// as possible that fit in the `MAX_BLOCKS_BYTES` limit, with a minimum of one block.  Otherwise, a
// single block is returned.
fn get_successor_blocks(
    state: &BlockchainState,
    anchor: &BlockHash,
    processed_block_hashes: &[BlockHash],
    allow_multiple_blocks: bool,
) -> Vec<Block> {
    let seen: HashSet<BlockHash> = processed_block_hashes.iter().copied().collect();

    let mut successor_blocks = vec![];
    // Block hashes that should be looked at in subsequent breadth-first searches.
    let mut response_block_size: usize = 0;
    let mut queue: VecDeque<BlockHash> = state
        .get_cached_header(anchor)
        .map(|c| c.children.clone())
        .unwrap_or_default()
        .into_iter()
        .collect();

    // Compute the blocks by starting a breadth-first search.
    while let Some(block_hash) = queue.pop_front() {
        if !seen.contains(&block_hash) {
            // Retrieve the block from the cache.
            match state.get_block(&block_hash) {
                Some(block) => {
                    let block_size = block.size();
                    if response_block_size == 0
                        || (response_block_size + block_size <= MAX_BLOCKS_BYTES
                            && successor_blocks.len() < MAX_BLOCKS_LENGTH
                            && allow_multiple_blocks)
                    {
                        successor_blocks.push(block.clone());
                        response_block_size += block_size;
                    } else {
                        break;
                    }
                }
                None => {
                    // Cache miss has occurred. This block or any of its successors cannot
                    // be returned. Discarding this subtree from the BFS.
                    continue;
                }
            }
        }

        queue.extend(
            state
                .get_cached_header(&block_hash)
                .map(|header| header.children.clone())
                .unwrap_or_default(),
        );
    }

    successor_blocks
}

/// Get the next headers for blocks that may possibly be sent in upcoming GetSuccessor responses.
fn get_next_headers(
    state: &BlockchainState,
    anchor: &BlockHash,
    processed_block_hashes: &[BlockHash],
    blocks: &[Block],
) -> Vec<BlockHeader> {
    let seen: HashSet<BlockHash> = processed_block_hashes
        .iter()
        .copied()
        .chain(blocks.iter().map(|b| b.block_hash()))
        .collect();
    let mut queue: VecDeque<BlockHash> = state
        .get_cached_header(anchor)
        .map(|c| c.children.clone())
        .unwrap_or_default()
        .into_iter()
        .collect();
    let mut next_headers = vec![];
    while let Some(block_hash) = queue.pop_front() {
        if next_headers.len() >= MAX_NEXT_BLOCK_HEADERS_LENGTH {
            break;
        }

        if let Some(header_node) = state.get_cached_header(&block_hash) {
            if !seen.contains(&block_hash) {
                next_headers.push(header_node.header);
            }
            queue.extend(header_node.children.clone());
        }
    }
    next_headers
}

/// Helper used to determine if multiple blocks should be returned.
fn are_multiple_blocks_allowed(network: Network, anchor_height: BlockHeight) -> bool {
    match network {
        Network::Bitcoin => anchor_height <= MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT,
        Network::Testnet | Network::Signet | Network::Regtest => true,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::sync::Arc;

    use bitcoin::Network;
    use ic_metrics::MetricsRegistry;
    use tokio::sync::{mpsc::channel, Mutex};

    use crate::config::test::ConfigBuilder;
    use ic_btc_adapter_test_utils::{
        generate_headers, generate_large_block_blockchain, headers_to_hashes,
    };

    /// This tests ensures that `BlockchainManager::get_successors(...)` will return relevant blocks
    /// with the next headers of many forks and enqueue missing block hashes.
    #[tokio::test]
    async fn test_get_successors() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = *blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) =
            channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
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
            let mut blockchain = handler.state.lock().await;
            blockchain.add_headers(&main_chain);
            blockchain.add_headers(&side_chain);
            blockchain.add_headers(&side_chain_2);

            // Add main block 2
            blockchain.add_block(main_block_2).expect("invalid block");
            // Add side block 1
            blockchain
                .add_block(side_block_1.clone())
                .expect("invalid block");
        }

        let response = handler.get_successors(request).await.unwrap();

        // Check that blocks contain block 1.
        assert_eq!(response.blocks.len(), 1);
        assert!(
            matches!(response.blocks.first(), Some(block) if block.block_hash() == side_block_1.block_hash())
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
                side_chain_2[0].block_hash(), // 1''
                side_chain[1].block_hash(),   // 2'
                side_chain_2[1].block_hash(), // 2''
                main_chain[2].block_hash(),   // 3
                side_chain_2[2].block_hash(), // 3'
                main_chain[3].block_hash(),   // 4
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
    async fn test_get_successors_wait_header_sync_testnet() {
        let config = ConfigBuilder::new().with_network(Network::Testnet).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = *blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );
        // Set up the following chain:
        // 0 -> 1 ---> 2 ---> 3 -> 4
        let mut previous_hashes = vec![];
        let main_chain = generate_headers(genesis_hash, genesis.time, 4, &[]);
        previous_hashes.extend(
            main_chain
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<_>>(),
        );

        // Create a request with the anchor block as the block 0 and processed block hashes contain
        // block 1 and 2.x
        let request = GetSuccessorsRequest {
            anchor: genesis_hash,
            processed_block_hashes: vec![],
        };

        {
            let mut blockchain = handler.state.lock().await;
            blockchain.add_headers(&main_chain);
        }

        let response = handler.get_successors(request).await;

        // Since adapter is not yet passed highest checkpoint it should still be unavailbale.
        // Highest checkpoint for testnet is 546.
        assert_eq!(response.err().unwrap().code(), Code::Unavailable);
    }

    #[tokio::test]
    async fn test_get_successors_wait_header_sync_regtest() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = *blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) =
            channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
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
            let mut blockchain = handler.state.lock().await;
            blockchain.add_headers(&main_chain);
            blockchain
                .add_block(main_block_1.clone())
                .expect("invalid block");
            blockchain
                .add_block(main_block_2.clone())
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
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = *blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) =
            channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
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
            let mut blockchain = handler.state.lock().await;
            blockchain.add_headers(&main_chain);
            blockchain.add_headers(&side_chain);
            blockchain
                .add_block(main_block_1.clone())
                .expect("invalid block");
            blockchain
                .add_block(main_block_2.clone())
                .expect("invalid block");
            blockchain
                .add_block(side_block_1.clone())
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
            matches!(response.blocks.first(), Some(block) if block.block_hash() == main_block_1.block_hash())
        );
        assert!(
            matches!(response.blocks.get(1), Some(block) if block.block_hash() == side_block_1.block_hash())
        );
        assert!(
            matches!(response.blocks.get(2), Some(block) if block.block_hash() == main_block_2.block_hash())
        );
    }

    /// This tests ensures that `get_successor` returns no more than MAX_BLOCKS_LENGTH blocks.
    #[tokio::test]
    async fn test_get_successors_max_num_blocks() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = *blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) =
            channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );
        let main_chain = generate_headers(genesis_hash, genesis.time, 120, &[]);
        {
            let mut blockchain = handler.state.lock().await;
            blockchain.add_headers(&main_chain);
            for header in main_chain {
                let block = Block {
                    header,
                    txdata: vec![],
                };
                blockchain.add_block(block).expect("invalid block");
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
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = *blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) =
            channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
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
            let mut blockchain = handler.state.lock().await;
            let (_, maybe_err) = blockchain.add_headers(&main_chain);
            assert!(
                maybe_err.is_none(),
                "Error was found in main chain: {:#?}",
                maybe_err
            );

            let (_, maybe_err) = blockchain.add_headers(&side_chain);
            assert!(
                maybe_err.is_none(),
                "Error was found in side chain: {:#?}",
                maybe_err
            );
            blockchain.add_block(main_block_2).expect("invalid block");

            blockchain
                .add_block(side_block_1.clone())
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
                .map(|b| b.block_hash())
                .collect::<Vec<BlockHash>>()
        );
        assert!(
            matches!(response.blocks.first(), Some(block) if block.block_hash() == side_block_1.block_hash())
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
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = *blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) =
            channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );
        // Generate a blockchain with one large block.
        let large_blocks = generate_large_block_blockchain(genesis_hash, genesis.time, 1);
        let large_block = large_blocks.first().cloned().unwrap();
        let headers: Vec<BlockHeader> = large_blocks.iter().map(|b| b.header).collect();

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
            let mut blockchain = handler.state.lock().await;
            let (added_headers, _) = blockchain.add_headers(&headers);
            assert_eq!(added_headers.len(), 1);
            let (added_headers, _) = blockchain.add_headers(&additional_headers);
            assert_eq!(added_headers.len(), 1);

            blockchain
                .add_block(large_block.clone())
                .expect("invalid block");
            blockchain.add_block(small_block).expect("invalid block");
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
            matches!(response.blocks.first(), Some(block) if block.block_hash() == large_block.block_hash() && block.txdata.len() == large_block.txdata.len())
        );
        // The smaller block's header should be in the next field.
        assert!(
            matches!(response.next.first(), Some(header) if header.block_hash() == additional_headers[0].block_hash())
        );
    }

    /// This test ensures that `BlockchainManager::get_successors(...)` sends blocks up to the cap limit.
    #[tokio::test]
    async fn test_get_successors_many_blocks_until_size_cap_is_met() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = *blockchain_state.genesis();
        let genesis_hash = genesis.block_hash();
        let (blockchain_manager_tx, _blockchain_manager_rx) =
            channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            &MetricsRegistry::default(),
        );

        let main_chain = generate_headers(genesis_hash, genesis.time, 5, &[]);
        let large_blocks =
            generate_large_block_blockchain(main_chain[4].block_hash(), main_chain[4].time, 1);

        {
            let mut blockchain = handler.state.lock().await;
            let (added_headers, _) = blockchain.add_headers(&main_chain);
            assert_eq!(added_headers.len(), 5);
            let main_blocks = main_chain
                .iter()
                .map(|h| Block {
                    header: *h,
                    txdata: vec![],
                })
                .collect::<Vec<_>>();
            for block in main_blocks {
                blockchain.add_block(block).unwrap();
            }

            for block in &large_blocks {
                blockchain.add_block(block.clone()).unwrap();
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
            matches!(response.blocks.last(), Some(block) if block.block_hash() == main_chain.last().unwrap().block_hash())
        );

        // The next field should contain the large block header as it is too large for the request.
        assert_eq!(response.next.len(), 1);
        assert!(
            matches!(response.next.first(), Some(header) if large_blocks[0].block_hash() == header.block_hash())
        );
    }

    #[test]
    fn test_are_multiple_blocks_allowed() {
        // Mainnet
        assert!(
            are_multiple_blocks_allowed(Network::Bitcoin, 100_500),
            "Multiple blocks are allowed at 100_500"
        );
        assert!(
            are_multiple_blocks_allowed(Network::Bitcoin, MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT),
            "Multiple blocks are allowed at {}",
            MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT
        );
        assert!(
            !are_multiple_blocks_allowed(Network::Bitcoin, 900_000),
            "Multiple blocks are not allowed at 900_000"
        );

        // Testnet
        assert!(
            are_multiple_blocks_allowed(Network::Testnet, 1_000_000),
            "Multiple blocks are allowed at 1_000_000"
        );
        assert!(
            are_multiple_blocks_allowed(Network::Testnet, u32::MAX),
            "Multiple blocks are allowed at {}",
            u32::MAX
        );

        // Regtest
        assert!(
            are_multiple_blocks_allowed(Network::Regtest, 1),
            "Multiple blocks are allowed at 1"
        );
        assert!(
            are_multiple_blocks_allowed(Network::Regtest, u32::MAX),
            "Multiple blocks are allowed at {}",
            u32::MAX
        );
    }

    #[test]
    fn response_size() {
        assert_eq!(MAX_NEXT_BYTES + MAX_BLOCKS_BYTES, MAX_RESPONSE_SIZE);
    }
}
