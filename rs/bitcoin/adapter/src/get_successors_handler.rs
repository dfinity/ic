use std::sync::Arc;

use tokio::sync::{mpsc::Sender, Mutex};

use crate::{
    blockchainmanager::{GetSuccessorsRequest, GetSuccessorsResponse},
    BlockchainManager, BlockchainManagerRequest,
};

/// Contains the functionality to respond to GetSuccessorsRequests via the RPC
/// server.
pub struct GetSuccessorsHandler {
    blockchain_manager: Arc<Mutex<BlockchainManager>>,
    command_sender: Sender<BlockchainManagerRequest>,
}

impl GetSuccessorsHandler {
    /// Creates a GetSuccessorsHandler to be used to access the blockchain state
    /// inside of the adapter when a `GetSuccessorsRequest` is received.
    pub fn new(
        blockchain_manager: Arc<Mutex<BlockchainManager>>,
        command_sender: Sender<BlockchainManagerRequest>,
    ) -> Self {
        Self {
            blockchain_manager,
            command_sender,
        }
    }

    // TODO: ER-2157: GetSuccessors should only sync after the adapter is synced past the
    // highest checkpoint.
    // TODO: ER-2479: Pruning blocks from the cache should also consider the height of the anchor hash.
    /// Handles a request for get successors. The response will contain the blocks that the adapter
    /// currently contains in its cache as well as the headers for the next blocks.
    /// If the channels are full, PruneOldBlocks and EnqueueNewBlocksToDownload will not be executed.
    pub async fn get_successors(&self, request: GetSuccessorsRequest) -> GetSuccessorsResponse {
        let response = self
            .blockchain_manager
            .lock()
            .await
            .get_successors(&request);
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
