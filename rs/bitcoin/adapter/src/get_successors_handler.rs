use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use bitcoin::{Block, BlockHash, BlockHeader, Network};
use tokio::sync::{mpsc::Sender, Mutex};
use tonic::{Code, Status};

use crate::{
    blockchainstate::CachedHeader, common::BlockHeight, config::Config, BlockchainManagerRequest,
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

const BLOCK_HEADER_SIZE: usize = 80;

// The maximum number of bytes the `next` field in a response can take.
const MAX_NEXT_BYTES: usize = MAX_NEXT_BLOCK_HEADERS_LENGTH * BLOCK_HEADER_SIZE;

// The maximum number of bytes the `blocks` in a response can take.
// NOTE: This is a soft limit, and is only honored if there's > 1 blocks already in the response.
// Having this as a soft limit as necessary to prevent large blocks from stalling consensus.
const MAX_BLOCKS_BYTES: usize = MAX_RESPONSE_SIZE - MAX_NEXT_BYTES;

// Max height for sending multiple blocks when connecting the Bitcoin mainnet.
const MAINNET_MAX_MULTI_BLOCK_ANCHOR_HEIGHT: BlockHeight = 750_000;

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
}

impl GetSuccessorsHandler {
    /// Creates a GetSuccessorsHandler to be used to access the blockchain state
    /// inside of the adapter when a `GetSuccessorsRequest` is received.
    pub fn new(
        config: &Config,
        state: Arc<Mutex<BlockchainState>>,
        command_sender: Sender<BlockchainManagerRequest>,
    ) -> Self {
        Self {
            state,
            command_sender,
            network: config.network,
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

        if !response.next.is_empty() {
            // TODO: better handling of full channel as the receivers are never closed.
            self.command_sender
                .try_send(BlockchainManagerRequest::EnqueueNewBlocksToDownload(
                    response.next.clone(),
                ))
                .ok();
        }

        // TODO: better handling of full channel as the receivers are never closed.
        self.command_sender
            .try_send(BlockchainManagerRequest::PruneBlocks(
                request.anchor,
                request.processed_block_hashes,
            ))
            .ok();

        Ok(response)
    }
}

/// Bitcoin mainnet checkpoints
#[rustfmt::skip]
const BITCOIN: &[(BlockHeight, &str)] = &[
    (11_111, "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",),
    (33_333, "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",),
    (74_000, "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",),
    (105_000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",),
    (134_444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",),
    (168_000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",),
    (193_000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317",),
    (210_000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",),
    (216_116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e",),
    (225_430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932",),
    (250_000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",),
    (279_000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40",),
    (295_000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983",),
    (393_216, "00000000000000000390df7d2bdc06b9fcb260b39e3fb15b4bc9f62572553924"),
    (421_888, "000000000000000004b232ad9492d0729d7f9d6737399ffcdaac1c8160db5ef6"),
    (438_784, "0000000000000000040d6ef667d7a52caf93d8e0d1e40fd7155c787b42667179"),
    (451_840, "0000000000000000029103c8ade7786e7379623465c72d71d84624eb9c159bea"),
    (469_766, "000000000000000000130b2bd812c6a7ae9c02a74fc111806b1dd11e8975da45"),
    (481_824, "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"),
    (514_048, "00000000000000000022fe630be397a62c58972bb81f0a2d1ae8c968511a4659"),
    (553_472, "0000000000000000000e06b6698a4f65ab9915f24b23ca2f9d1abf30cc3e9173"),
    (571_392, "00000000000000000019c18b43077775fc299a6646ab0e9dbbd5770bf6ca392d"),
    (596_000, "0000000000000000000706f93dc673ca366c810f317e7cfe8d951c0107b65223"),
    (601_723, "000000000000000000009837f74796532b21d8ccf7def3dcfcb45aa92cd86b9e"),
    (617_056, "0000000000000000000ca51b293fb2be2fbaf1acc76dcbbbff7e4d7796380b9e"),
    (632_549, "00000000000000000001bae1b2b73ec3fde475c1ed7fdd382c2c49860ec19920"),
    (643_700, "00000000000000000002959e9b44507120453344794df09bd1276eb325ed7110"),
    (667_811, "00000000000000000007888a9d01313d69d6335df46ea33e875ee6832670c596"),
    (688_888, "0000000000000000000e1e3bd783ce0de7b0cdabf2034723595dbcd5a28cf831"),
    (704_256, "0000000000000000000465f5acfcd603337994261a4d67a647cb49866c98b538"),
];

/// Bitcoin testnet checkpoints
#[rustfmt::skip]
const TESTNET: &[(BlockHeight, &str)] = &[
    (546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")
];

/// Checks if the block height is higher than the last checkpoint's height.
/// By being beyond the last checkpoint, we ensure that we have stored
/// the correct chain up to the height of the last checkpoint.
pub fn is_beyond_last_checkpoint(network: &Network, height: BlockHeight) -> bool {
    last_checkpoint(network).map_or(true, |last| last <= height)
}

pub fn last_checkpoint(network: &Network) -> Option<BlockHeight> {
    match network {
        Network::Bitcoin => BITCOIN,
        Network::Testnet => TESTNET,
        Network::Signet => &[],
        Network::Regtest => &[],
    }
    .last()
    .map(|&(height, _)| height)
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
    let mut queue: VecDeque<CachedHeader> = state
        .get_cached_header(anchor)
        .map(|c| c.children.lock().clone())
        .unwrap_or_default()
        .into_iter()
        .collect();

    // Compute the blocks by starting a breadth-first search.
    while let Some(cached_header) = queue.pop_front() {
        let block_hash = cached_header.header.block_hash();
        if !seen.contains(&block_hash) {
            // Retrieve the block from the cache.
            match state.get_block(&block_hash) {
                Some(block) => {
                    let block_size = block.size();
                    if response_block_size == 0
                        || (response_block_size + block_size <= MAX_BLOCKS_BYTES
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

        queue.extend(cached_header.children.lock().clone());
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
    let mut queue: VecDeque<CachedHeader> = state
        .get_cached_header(anchor)
        .map(|c| c.children.lock().clone())
        .unwrap_or_default()
        .into_iter()
        .collect();
    let mut next_headers = vec![];
    while let Some(cached_header) = queue.pop_front() {
        if next_headers.len() >= MAX_NEXT_BLOCK_HEADERS_LENGTH {
            break;
        }

        let block_hash = cached_header.header.block_hash();
        if !seen.contains(&block_hash) {
            next_headers.push(cached_header.header);
        }
        queue.extend(cached_header.children.lock().clone());
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
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
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

        let response = handler.get_successors(request).await.unwrap();

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

    #[tokio::test]
    async fn test_get_successors_wait_header_sync_testnet() {
        let config = ConfigBuilder::new().with_network(Network::Testnet).build();
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
        );
        // Set up the following chain:
        // 0 -> 1 ---> 2 ---> 3 -> 4
        let mut previous_hashes = vec![];
        let main_chain = generate_headers(genesis_hash, genesis.header.time, 4, &[]);
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
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
        );

        // Set up the following chain:
        // 0 -> 1 -> 2 -> 3 -> 4 -> 5
        let main_chain = generate_headers(genesis_hash, genesis.header.time, 5, &[]);
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
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
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
        let response = handler.get_successors(request).await.unwrap();
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
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
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
        let blockchain_state = BlockchainState::new(&config, &MetricsRegistry::default());
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
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
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let (blockchain_manager_tx, _) = channel::<BlockchainManagerRequest>(10);
        let handler = GetSuccessorsHandler::new(
            &config,
            Arc::new(Mutex::new(blockchain_state)),
            blockchain_manager_tx,
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
