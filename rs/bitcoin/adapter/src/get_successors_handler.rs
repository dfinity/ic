use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use bitcoin::{Block, BlockHash, BlockHeader, Network};
use ic_logger::{error, ReplicaLogger};
use tokio::sync::{mpsc::Sender, Mutex};

use crate::{
    blockchainmanager::{GetSuccessorsRequest, GetSuccessorsResponse},
    common::BlockHeight,
    BlockchainManagerRequest, BlockchainState, Config,
};

const ONE_MB: usize = 1_024 * 1_024;

/// Max size of the `GetSuccessorsResponse` message (2 MiB).
const MAX_GET_SUCCESSORS_RESPONSE_BLOCKS_SIZE_BYTES: usize = 2 * ONE_MB;

/// Max limit of how many headers should be returned in the `GetSuccessorsResponse`.
const MAX_NEXT_BLOCK_HEADERS_LENGTH: usize = 100;

/// Max height for sending multiple blocks when connecting the Bitcoin mainnet.
const MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT: BlockHeight = 700_000;

/// Max height for sending multiple blocks when connecting the Bitcoin testnet.
const TESTNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT: BlockHeight = 2_164_000;

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
                .try_send(BlockchainManagerRequest::PruneOldBlocks(
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
