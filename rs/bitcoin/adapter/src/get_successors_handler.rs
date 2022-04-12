use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use bitcoin::{Block, BlockHash, BlockHeader, Network};
use ic_logger::{error, ReplicaLogger};
use tokio::sync::{mpsc::Sender, Mutex};

use crate::{common::BlockHeight, BlockchainManagerRequest, BlockchainState, Config};

const ONE_MB: usize = 1_024 * 1_024;

/// Max size of the `GetSuccessorsResponse` message (2 MiB).
const MAX_GET_SUCCESSORS_RESPONSE_BLOCKS_SIZE_BYTES: usize = 2 * ONE_MB;

/// Max limit of how many headers should be returned in the `GetSuccessorsResponse`.
const MAX_NEXT_BLOCK_HEADERS_LENGTH: usize = 100;

/// Max height for sending multiple blocks when connecting the Bitcoin mainnet.
const MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT: BlockHeight = 700_000;

/// Max height for sending multiple blocks when connecting the Bitcoin testnet.
const TESTNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT: BlockHeight = 2_164_000;

#[derive(Debug)]
pub struct GetSuccessorsRequest {
    /// Hash of the most recent stable block in the Bitcoin canister.
    pub anchor: BlockHash,
    /// Most recent block hashes that have been processed by the canister.
    pub processed_block_hashes: Vec<BlockHash>,
}

#[derive(Debug)]
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
    command_sender: Sender<BlockchainManagerRequest>,
    network: Network,
    logger: ReplicaLogger,
}

impl GetSuccessorsHandler {
    /// Creates a GetSuccessorsHandler to be used to access the blockchain state
    /// inside of the adapter when a `GetSuccessorsRequest` is received.
    pub fn new(
        config: &Config,
        state: Arc<Mutex<BlockchainState>>,
        command_sender: Sender<BlockchainManagerRequest>,
        logger: ReplicaLogger,
    ) -> Self {
        Self {
            state,
            command_sender,
            network: config.network,
            logger,
        }
    }

    // TODO: ER-2157: GetSuccessors should only sync after the adapter is synced past the
    // highest checkpoint.
    // TODO: ER-2479: Pruning blocks from the cache should also consider the height of the anchor hash.
    /// Handles a request for get successors. The response will contain the blocks that the adapter
    /// currently contains in its cache as well as the headers for the next blocks.
    /// If the channels are full, PruneOldBlocks and EnqueueNewBlocksToDownload will not be executed.
    pub async fn get_successors(&self, request: GetSuccessorsRequest) -> GetSuccessorsResponse {
        let response = {
            let state = self.state.lock().await;
            let anchor_height = state
                .get_cached_header(&request.anchor)
                .map_or(0, |cached| cached.height);
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
                &self.logger,
            );
            GetSuccessorsResponse { blocks, next }
        };

        if !response.next.is_empty() {
            // TODO: better handling of full channel as the receivers are never closed.
            self.command_sender
                .try_send(BlockchainManagerRequest::EnqueueNewBlocksToDownload(
                    response.next.clone(),
                ))
                .ok();
        }

        if !request.processed_block_hashes.is_empty() {
            // TODO: better handling of full channel as the receivers are never closed.
            // As a part of the above TODO, prune old blocks should also receive the anchor hash.
            // This would allow prune to remove blocks that are below the anchor hash in cases where
            // the channel did fill completely and has caught up again.
            self.command_sender
                .try_send(BlockchainManagerRequest::PruneBlocks(
                    request.anchor,
                    request.processed_block_hashes,
                ))
                .ok();
        }

        response
    }
}

/// Performs a breadth-first search to retrieve blocks from the block cache.
/// a. A single block will be retrieved if the adapter has reached a particular height.
/// b. Otherwise, multiple blocks will be returned with a total limit of 2MiB.
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
    let mut queue: VecDeque<BlockHash> = state.get_children(anchor).into_iter().collect();

    // Compute the blocks by starting a breadth-first search.
    while let Some(node) = queue.pop_front() {
        if !seen.contains(&node) {
            // Retrieve the block from the cache.
            match state.get_block(&node) {
                Some(block) => {
                    let block_size = block.get_size();
                    if response_block_size == 0
                        || (response_block_size + block_size
                            <= MAX_GET_SUCCESSORS_RESPONSE_BLOCKS_SIZE_BYTES
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

        let children = state.get_children(&node);
        queue.extend(children);
    }

    successor_blocks
}

/// Get the next headers for blocks that may possibly be sent in upcoming GetSuccessor responses.
fn get_next_headers(
    state: &BlockchainState,
    anchor: &BlockHash,
    processed_block_hashes: &[BlockHash],
    blocks: &[Block],
    logger: &ReplicaLogger,
) -> Vec<BlockHeader> {
    let seen: HashSet<BlockHash> = processed_block_hashes
        .iter()
        .copied()
        .chain(blocks.iter().map(|b| b.block_hash()))
        .collect();
    let mut queue: VecDeque<BlockHash> = state.get_children(anchor).into_iter().collect();
    let mut next_headers = vec![];
    while let Some(node) = queue.pop_front() {
        if next_headers.len() >= MAX_NEXT_BLOCK_HEADERS_LENGTH {
            break;
        }

        match state.get_cached_header(&node) {
            Some(cached) => {
                if !seen.contains(&cached.header.block_hash()) {
                    next_headers.push(cached.header);
                }
            }
            None => {
                // Missing header, something has gone very wrong.
                error!(
                    logger,
                    "[ADAPTER-BUG] Missing header cache entry for block hash: {:?}. This should never happen.",
                    node
                );
                break;
            }
        }

        let children = state.get_children(&node);
        queue.extend(children);
    }
    next_headers
}

/// Helper used to determine if multiple blocks should be returned.
fn are_multiple_blocks_allowed(network: Network, anchor_height: BlockHeight) -> bool {
    match network {
        Network::Bitcoin => anchor_height <= MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT,
        Network::Testnet => anchor_height <= TESTNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT,
        Network::Signet | Network::Regtest => true,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::sync::Arc;

    use bitcoin::Network;
    use ic_logger::replica_logger::no_op_logger;
    use tokio::sync::{mpsc::channel, Mutex};

    use crate::{
        common::test_common::{
            generate_headers, generate_large_block_blockchain, headers_to_hashes,
        },
        config::test::ConfigBuilder,
    };

    /// This tests ensures that `BlockchainManager::get_successors(...)` will return relevant blocks
    /// with the next headers of many forks and enqueue missing block hashes.
    #[tokio::test]
    async fn test_get_successors() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            no_op_logger(),
        );
        // Set up the following chain:
        // |--> 1'---> 2'
        // 0 -> 1 ---> 2 ---> 3 -> 4
        // |--> 1'' -> 2'' -> 3''
        let mut previous_hashes = vec![];
        let main_chain = generate_headers(genesis_hash, genesis.header.time, 4, &[]);
        previous_hashes.extend(
            main_chain
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<_>>(),
        );
        let side_chain = generate_headers(genesis_hash, genesis.header.time, 2, &previous_hashes);
        previous_hashes.extend(
            side_chain
                .iter()
                .map(|h| h.block_hash())
                .collect::<Vec<_>>(),
        );
        let side_chain_2 = generate_headers(genesis_hash, genesis.header.time, 3, &previous_hashes);

        let main_block_2 = Block {
            header: main_chain[1],
            txdata: vec![],
        };
        let side_1 = side_chain.get(0).cloned().expect("Should have 1 header");
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

        let response = handler.get_successors(request).await;

        // Check that blocks contain block 1.
        assert_eq!(response.blocks.len(), 1);
        assert!(
            matches!(response.blocks.get(0), Some(block) if block.block_hash() == side_block_1.block_hash())
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

    /// This tests ensures that `BlockchainManager::handle_client_request(...)` returns multiple
    /// blocks from the main chain and a fork. Order should be preserved.
    #[tokio::test]
    async fn test_get_successors_multiple_blocks() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            no_op_logger(),
        );
        // Set up the following chain:
        // |-> 1'
        // 0 -> 1 -> 2
        let main_chain = generate_headers(genesis_hash, genesis.header.time, 2, &[]);
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
            genesis.header.time,
            1,
            &headers_to_hashes(&main_chain),
        );
        let side_1 = side_chain.get(0).cloned().expect("Should have 1 header");
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
        let response = handler.get_successors(request).await;
        assert_eq!(response.blocks.len(), 3);
        assert!(
            matches!(response.blocks.get(0), Some(block) if block.block_hash() == main_block_1.block_hash())
        );
        assert!(
            matches!(response.blocks.get(1), Some(block) if block.block_hash() == side_block_1.block_hash())
        );
        assert!(
            matches!(response.blocks.get(2), Some(block) if block.block_hash() == main_block_2.block_hash())
        );
    }

    /// This tests ensures that `BlockchainManager::get_successors(...)` returns multiple
    /// blocks from the main chain and a fork. Order should be preserved.
    #[tokio::test]
    async fn test_get_successors_multiple_blocks_out_of_order() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            no_op_logger(),
        );
        // Set up the following chain:
        // |-> 1'
        // 0 -> 1 -> 2
        let main_chain = generate_headers(genesis_hash, genesis.header.time, 2, &[]);
        let main_block_2 = Block {
            header: main_chain[1],
            txdata: vec![],
        };

        let side_chain = generate_headers(
            genesis_hash,
            genesis.header.time,
            1,
            &headers_to_hashes(&main_chain),
        );
        let side_1 = side_chain.get(0).cloned().expect("Should have 1 header");
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
        let response = handler.get_successors(request).await;
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
            matches!(response.blocks.get(0), Some(block) if block.block_hash() == side_block_1.block_hash())
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
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            no_op_logger(),
        );
        // Generate a blockchain with one large block.
        let large_blocks = generate_large_block_blockchain(genesis_hash, genesis.header.time, 1);
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
        let response = handler.get_successors(request).await;
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
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
            no_op_logger(),
        );

        let main_chain = generate_headers(genesis_hash, genesis.header.time, 5, &[]);
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
        let response = handler.get_successors(request).await;

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
            are_multiple_blocks_allowed(Network::Testnet, TESTNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT),
            "Multiple blocks are allowed at {}",
            TESTNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT
        );
        assert!(
            !are_multiple_blocks_allowed(Network::Testnet, 3_000_000),
            "Multiple blocks are not allowed at 3_000_000"
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
}
