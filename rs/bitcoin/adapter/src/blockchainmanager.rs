use crate::{
    blockchainstate::{AddHeaderError, BlockchainState},
    common::{BlockHeight, MINIMUM_VERSION_NUMBER},
    config::Config,
    stream::{StreamEvent, StreamEventKind},
    Channel, Command, HandleClientRequest, HasHeight, ProcessEventError,
};
use bitcoin::{
    network::{
        message::{NetworkMessage, MAX_INV_SIZE},
        message_blockdata::{GetHeadersMessage, Inventory},
    },
    Block, BlockHash, BlockHeader, Network,
};
use slog::Logger;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use thiserror::Error;

/// This constant is the maximum number of seconds to wait until we get response to the getdata request sent by us.
const GETDATA_REQUEST_TIMEOUT_SECS: u64 = 30;

/// This constant represents the maximum size of `headers` messages.
/// https://developer.bitcoin.org/reference/p2p_networking.html#headers
const MAX_HEADERS_SIZE: usize = 2_000;

/// This constant stores the maximum number of headers allowed in an unsolicited `headers` message
/// (`headers message for which a `getheaders` request was not sent before.)
const MAX_UNSOLICITED_HEADERS: usize = 20;

///Max number of inventory in the "getdata" request that can be sent
/// to a peer at a time.
const INV_PER_GET_DATA_REQUEST: u32 = 8;

/// How many blocks the BlockManager should look ahead when responding to a `GetSuccessors` request.
const IMMEDIATE_SUCCESSORS_DEPTH: u32 = 10;

/// How many blocks the BlockManager should look ahead when pre-fetching blocks.
const FUTURE_SUCCESSORS_DEPTH: u32 = 20;

const ONE_MB: usize = 1_024 * 1_024;

/// Max size of the `GetSuccessorsResponse` message (2 MiB).
const MAX_GET_SUCCESSORS_RESPONSE_BLOCKS_SIZE_BYTES: usize = 2 * ONE_MB;

/// The limit at which we should stop making additional requests for new blocks as the block cache
/// becomes too large. Inflight `getdata` messages will remain active, but new `getdata` messages will
/// not be created.
const BLOCK_CACHE_THRESHOLD_BYTES: usize = 10 * ONE_MB;

/// Max limit of how many headers should be returned in the `GetSuccessorsResponse`.
const MAX_NEXT_BLOCK_HEADERS_LENGTH: usize = 100;

/// Max limit of how many block hashes should be stored in the block sync queue.
const MAX_BLOCK_SYNC_QUEUE_SIZE: usize = 200;

/// Max height for sending multiple blocks when connecting the Bitcoin mainnet.
const MAX_MULTI_MAINNET_ANCHOR_HEIGHT: BlockHeight = 700_000;

/// Max height for sending multiple blocks when connecting the Bitcoin testnet.
const MAX_MULTI_TESTNET_ANCHOR_HEIGHT: BlockHeight = 2_164_000;

/// Block locators. Consists of starting hashes and a stop hash.
type Locators = (Vec<BlockHash>, BlockHash);

/// The enum stores what to do if a timeout for a peer is received.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OnTimeout {
    /// Disconnect the peer on timeout.
    Disconnect,
    /// Do nothing on timeout.
    Ignore,
}

/// The possible errors the `BlockchainManager::received_headers_message(...)` may produce.
#[derive(Debug, Error)]
enum ReceivedHeadersMessageError {
    /// This variant represents when a message from a no longer known peer.
    #[error("Unknown peer")]
    UnknownPeer,
    #[error("Received too many headers (> 2000)")]
    ReceivedTooManyHeaders,
    #[error("Received too many unsolicited headers")]
    ReceivedTooManyUnsolicitedHeaders,
    #[error("Received an invalid header")]
    ReceivedInvalidHeader,
}

/// The possible errors the `BlockchainManager::received_inv_message(...)` may produce.
#[derive(Debug, Error)]
enum ReceivedInvMessageError {
    /// This variant represents when a message from a no longer known peer.
    #[error("Unknown peer")]
    UnknownPeer,
    /// The number of inventory in the message exceeds the maximum limit
    #[error("Received too many inventory items from a peer")]
    TooMuchInventory,
}

/// The possible errors the `BlockchainManager::received_block_message(...)` may produce.
#[derive(Debug, Error)]
pub enum ReceivedBlockMessageError {
    /// This variant represents when a message from a no longer known peer.
    #[error("Unknown peer")]
    UnknownPeer,
    /// This variant represents that a block was not able to be added to the `block_cache` in the
    /// BlockchainState.
    #[error("Failed to add block")]
    BlockNotAdded,
}

#[derive(Debug)]
pub struct GetSuccessorsRequest {
    /// Most recent stable block in the canister.
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

/// This struct stores the information regarding a peer w.r.t synchronizing blockchain.
/// This information is useful to keep track of the commands that have been sent to the peer,
/// and how much blockchain state has already been synced with the peer.
#[derive(Debug)]
pub struct PeerInfo {
    /// This field stores the socket address of the Bitcoin node (peer)
    socket: SocketAddr,
    /// This field stores the height of the last headers/data message received from the peer.
    height: BlockHeight,
    /// This field stores the block hash of the tip header received from the peer.
    tip: BlockHash,
    /// Locators sent in the last `getheaders` or `getdata` request
    last_asked: Option<Locators>,
    /// Time at which the request was sent.
    sent_at: Option<SystemTime>,
    /// What to do if this request times out.
    on_timeout: OnTimeout,
}

/// This struct stores the information related to a "getdata" request sent by the BlockChainManager
#[derive(Debug)]
pub struct GetDataRequestInfo {
    /// This field stores the socket address of the Bitcoin node to which the request was sent.
    socket: SocketAddr,
    /// This field contains the time at which the getdata request was sent.  
    sent_at: SystemTime,
    /// This field contains the action to take if the request is expired.
    _on_timeout: OnTimeout,
}

/// The BlockChainManager struct handles interactions that involve the headers.
#[derive(Debug)]
pub struct BlockchainManager {
    /// This field contains the BlockchainState, which stores and manages
    /// all the information related to the headers and blocks.
    blockchain: BlockchainState,

    /// This field stores the map of which bitcoin nodes sent which "inv" messages.
    peer_info: HashMap<SocketAddr, PeerInfo>,

    /// This HashMap stores the information related to each getdata request
    /// sent by the BlockChainManager. An entry is removed from this hashmap if
    /// (1) The corresponding "Block" response is received or
    /// (2) If the request is expired or
    /// (3) If the peer is disconnected.
    getdata_request_info: HashMap<BlockHash, GetDataRequestInfo>,

    /// This queue stores the set of block hashes belonging to blocks that have yet to be synced by the BlockChainManager
    /// and stored into the block cache.
    ///
    /// A block hash is added when the `GetSuccessors` request is processed. If the block hash cannot be
    /// found in the `getdata_request_info` field or in the `blockchain`'s block cache, the block hash
    /// is added to the queue.
    ///
    /// A block hash is removed when it is determined a peer can receive another `getdata` message.
    block_sync_queue: VecDeque<BlockHash>,

    /// This vector stores the list of messages that are to be sent to the Bitcoin network.
    outgoing_command_queue: Vec<Command>,
    /// This field contains a logger for the blockchain manager's use.
    logger: Logger,
    /// Contains the network type the adapter is connecting to.
    network: Network,
}

impl BlockchainManager {
    /// This function instantiates a BlockChainManager struct. A node is provided
    /// in order to get its client so the manager can send messages to the
    /// BTC network.
    pub fn new(config: &Config, logger: Logger) -> Self {
        let blockchain = BlockchainState::new(config);
        let peer_info = HashMap::new();
        let getdata_request_info = HashMap::new();
        let outgoing_command_queue = Vec::new();
        BlockchainManager {
            blockchain,
            peer_info,
            getdata_request_info,
            block_sync_queue: VecDeque::new(),
            outgoing_command_queue,
            logger,
            network: config.network,
        }
    }

    /// This method is used when the adapter is no longer receiving RPC calls from the replica.
    /// Clears the block cache, peer info, the blocks to be synced, outgoing command queue, and
    /// the `getdata` request info.
    pub fn make_idle(&mut self) {
        self.outgoing_command_queue.clear();
        self.block_sync_queue.clear();
        self.getdata_request_info.clear();
        self.peer_info.clear();
        self.blockchain.clear_blocks();
    }

    /// This method sends `getheaders` command to the adapter.
    /// The adapter then sends the `getheaders` request to the Bitcoin node.
    fn send_getheaders(&mut self, addr: &SocketAddr, locators: Locators, on_timeout: OnTimeout) {
        // TODO: ER-1394: Timeouts must for getheaders calls must be handled.
        //If the peer address is not stored in peer_info, then return;
        if let Some(peer_info) = self.peer_info.get_mut(addr) {
            slog::info!(
                self.logger,
                "Sending getheaders to {} : Locator hashes {:?}, Stop hash {}",
                addr,
                locators.0,
                locators.1
            );
            let command = Command {
                address: Some(*addr),
                message: NetworkMessage::GetHeaders(GetHeadersMessage {
                    locator_hashes: locators.0.clone(),
                    stop_hash: locators.1,
                    version: MINIMUM_VERSION_NUMBER,
                }),
            };
            //If sending the command is successful, then update the peer_info with the new details.
            self.outgoing_command_queue.push(command);
            // Caveat: Updating peer_info even if the command hasn't been set yet.
            peer_info.last_asked = Some(locators);
            peer_info.sent_at = Some(SystemTime::now());
            peer_info.on_timeout = on_timeout;
        }
    }

    /// This function processes "inv" messages received from Bitcoin nodes.
    /// Given a block_hash, this method sends the corresponding "getheaders" message to the Bitcoin node.
    fn received_inv_message(
        &mut self,
        addr: &SocketAddr,
        inventory: &[Inventory],
    ) -> Result<(), ReceivedInvMessageError> {
        // If the inv message has more inventory than MAX_INV_SIZE (50000), reject it.
        if inventory.len() > MAX_INV_SIZE {
            return Err(ReceivedInvMessageError::TooMuchInventory);
        }

        // If the inv message is received from a peer that is not connected, then reject it.
        slog::info!(
            self.logger,
            "Received inv message from {} : Inventory {:?}",
            addr,
            inventory
        );

        let peer = self
            .peer_info
            .get_mut(addr)
            .ok_or(ReceivedInvMessageError::UnknownPeer)?;

        //This field stores the block hash in the inventory that is not yet stored in the blockchain,
        // and has the highest height amongst all the hashes in the inventory.
        let mut last_block = None;

        for inv in inventory {
            if let Inventory::Block(hash) = inv {
                peer.tip = *hash;
                if !self.blockchain.is_block_hash_known(hash) {
                    last_block = Some(hash);
                }
            }
        }

        if let Some(stop_hash) = last_block {
            let locators = (self.blockchain.locator_hashes(), *stop_hash);

            // Send `getheaders` request to fetch the headers corresponding to inv message.
            self.send_getheaders(addr, locators, OnTimeout::Ignore);
        }
        Ok(())
    }

    fn received_headers_message(
        &mut self,
        addr: &SocketAddr,
        headers: &[BlockHeader],
    ) -> Result<(), ReceivedHeadersMessageError> {
        let peer = self
            .peer_info
            .get_mut(addr)
            .ok_or(ReceivedHeadersMessageError::UnknownPeer)?;
        slog::info!(
            self.logger,
            "Received headers from {}: {}",
            addr,
            headers.len()
        );
        // If no `getheaders` request was sent to the peer, the `headers` message is unsolicited.
        // Don't accept more than a few headers in that case.
        if headers.len() > MAX_UNSOLICITED_HEADERS && peer.last_asked.is_none() {
            return Err(ReceivedHeadersMessageError::ReceivedTooManyUnsolicitedHeaders);
        }

        // There are more than 2000 headers in the `headers` message.
        if headers.len() > MAX_HEADERS_SIZE {
            return Err(ReceivedHeadersMessageError::ReceivedTooManyHeaders);
        }

        // Grab the last header's block hash. If not found, no headers to add so exit early.
        let last_block_hash = match headers.last() {
            Some(header) => header.block_hash(),
            None => return Ok(()),
        };

        let prev_tip_height = self.blockchain.get_active_chain_tip().height;

        let (added_headers, maybe_err) = self.blockchain.add_headers(headers);
        let active_tip = self.blockchain.get_active_chain_tip();
        if prev_tip_height < active_tip.height {
            slog::info!(
                self.logger,
                "Added headers in the headers message. State Changed. Height = {}, Active chain's tip = {}",
                active_tip.height,
                active_tip.header.block_hash()
            );
        }

        // Update the peer's tip and height to the last
        let maybe_last_header = if added_headers.last().is_some() {
            added_headers.last()
        } else if self
            .blockchain
            .get_cached_header(&last_block_hash)
            .is_some()
        {
            self.blockchain.get_cached_header(&last_block_hash)
        } else {
            None
        };

        if let Some(last) = maybe_last_header {
            if last.height > peer.height {
                peer.tip = last.header.block_hash();
                peer.height = last.height;
                slog::debug!(
                    self.logger,
                    "Peer {}'s height = {}, tip = {}",
                    addr,
                    peer.height,
                    peer.tip
                );
            }
        }

        let maybe_locators = match maybe_err {
            Some(AddHeaderError::InvalidHeader(_, _)) => {
                return Err(ReceivedHeadersMessageError::ReceivedInvalidHeader)
            }
            Some(AddHeaderError::PrevHeaderNotCached(stop_hash)) => {
                Some((self.blockchain.locator_hashes(), stop_hash))
            }
            None => {
                if let Some(last) = maybe_last_header {
                    // If the headers length is less than the max headers size (2000), it is likely that the end
                    // of the chain has been reached.
                    if headers.len() < MAX_HEADERS_SIZE {
                        None
                    } else {
                        Some((vec![last.header.block_hash()], BlockHash::default()))
                    }
                } else {
                    None
                }
            }
        };

        if let Some(locators) = maybe_locators {
            self.send_getheaders(addr, locators, OnTimeout::Ignore);
        } else {
            // If the adapter is not going to ask for more headers, the peer's last_asked should
            // be reset.
            peer.last_asked = None;
        }

        Ok(())
    }

    /// This function processes "block" messages received from Bitcoin nodes
    fn received_block_message(
        &mut self,
        addr: &SocketAddr,
        block: &Block,
    ) -> Result<(), ReceivedBlockMessageError> {
        if !self.peer_info.contains_key(addr) {
            return Err(ReceivedBlockMessageError::UnknownPeer);
        }

        let block_hash = block.block_hash();

        let maybe_request_info = self.getdata_request_info.get(&block_hash);
        let time_taken = match maybe_request_info {
            Some(request_info) => request_info
                .sent_at
                .elapsed()
                .unwrap_or_else(|_| Duration::new(0, 0)),
            None => Duration::new(0, 0),
        };

        slog::info!(
            self.logger,
            "Received block message from {} : Took {:?}sec. Block {:?}",
            addr,
            time_taken,
            block_hash
        );

        //Remove the corresponding `getdata` request from peer_info and getdata_request_info.
        self.getdata_request_info.remove(&block_hash);

        match self.blockchain.add_block(block.clone()) {
            Ok(block_height) => {
                slog::info!(
                    self.logger,
                    "Block added to the cache successfully at height = {}",
                    block_height
                );
                Ok(())
            }
            Err(err) => {
                slog::warn!(
                    self.logger,
                    "Unable to add the received block in blockchain. Error: {:?}",
                    err
                );
                Err(ReceivedBlockMessageError::BlockNotAdded)
            }
        }
    }

    /// This function adds a new peer to `peer_info`
    /// and initiates sync with the peer by sending `getheaders` message.
    fn add_peer(&mut self, addr: &SocketAddr) {
        if self.peer_info.contains_key(addr) {
            return;
        }
        slog::info!(self.logger, "Adding peer_info with addr : {} ", addr);
        let initial_hash = self.blockchain.genesis().header.block_hash();
        self.peer_info.insert(
            *addr,
            PeerInfo {
                socket: *addr,
                height: self.blockchain.genesis().height,
                tip: initial_hash,
                last_asked: None,
                sent_at: None,
                on_timeout: OnTimeout::Ignore,
            },
        );
        let locators = (vec![initial_hash], BlockHash::default());
        self.send_getheaders(addr, locators, OnTimeout::Disconnect);
    }

    /// This function adds a new peer to `peer_info`
    /// and initiates sync with the peer by sending `getheaders` message.
    fn remove_peer(&mut self, addr: &SocketAddr) {
        slog::info!(self.logger, "Removing peer_info with addr : {} ", addr);
        self.peer_info.remove(addr);
        // Removing all the `getdata` requests that have been sent to the peer before.
        self.getdata_request_info.retain(|_, v| v.socket != *addr);
    }

    fn filter_expired_getdata_requests(&mut self) {
        let now = SystemTime::now();
        let timeout_period = Duration::new(GETDATA_REQUEST_TIMEOUT_SECS, 0);
        self.getdata_request_info
            .retain(|_, request| request.sent_at + timeout_period > now);
    }

    fn sync_blocks(&mut self) {
        if self.block_sync_queue.is_empty() {
            return;
        }

        slog::debug!(
            self.logger,
            "Cache Size: {}, Max Size: {}",
            self.blockchain.get_block_cache_size(),
            BLOCK_CACHE_THRESHOLD_BYTES
        );
        if self.blockchain.get_block_cache_size() >= BLOCK_CACHE_THRESHOLD_BYTES {
            return;
        }

        slog::debug!(
            self.logger,
            "Syncing blocks. Blocks to be synced : {:?}",
            self.block_sync_queue.len()
        );

        // Removing expired getdata requests from `self.getdata_request_info`
        self.filter_expired_getdata_requests();

        // Count the number of requests per peer.
        let mut requests_per_peer: HashMap<SocketAddr, u32> =
            self.peer_info.keys().map(|addr| (*addr, 0)).collect();
        for info in self.getdata_request_info.values() {
            let counter = requests_per_peer.entry(info.socket).or_insert(0);
            *counter = counter.saturating_add(1);
        }

        let mut peer_info: Vec<_> = self.peer_info.values_mut().collect();
        peer_info.sort_by(|a, b| {
            let requests_sent_to_a = requests_per_peer.get(&a.socket).unwrap_or(&0);
            let requests_sent_to_b = requests_per_peer.get(&b.socket).unwrap_or(&0);
            requests_sent_to_a.cmp(requests_sent_to_b)
        });

        // For each peer, select a random subset of the inventory and send a "getdata" request for it.
        for peer in peer_info {
            // Calculate number of inventory that can be sent in 'getdata' request to the peer.
            let requests_sent_to_peer = requests_per_peer.get(&peer.socket).unwrap_or(&0);
            let num_requests_to_be_sent =
                INV_PER_GET_DATA_REQUEST.saturating_sub(*requests_sent_to_peer);

            // Randomly sample some inventory to be requested from the peer.
            let mut selected_inventory = vec![];
            for _ in 0..num_requests_to_be_sent {
                match self.block_sync_queue.pop_front() {
                    Some(hash) => {
                        selected_inventory.push(hash);
                    }
                    None => break,
                }
            }

            if selected_inventory.is_empty() {
                break;
            }

            slog::info!(
                self.logger,
                "Sending getdata to {} : Inventory {:?}",
                peer.socket,
                selected_inventory
            );

            //Send 'getdata' request for the inventory to the peer.
            self.outgoing_command_queue.push(Command {
                address: Some(peer.socket),
                message: NetworkMessage::GetData(
                    selected_inventory
                        .iter()
                        .map(|h| Inventory::Block(*h))
                        .collect(),
                ),
            });

            for inv in selected_inventory {
                // Record the `getdata` request.
                self.getdata_request_info.insert(
                    inv,
                    GetDataRequestInfo {
                        socket: peer.socket,
                        sent_at: SystemTime::now(),
                        _on_timeout: OnTimeout::Ignore,
                    },
                );
            }
        }
    }

    /// This function is called by the adapter when a new event takes place.
    /// The event could be receiving "getheaders", "getdata", "inv" messages from bitcion peers.
    /// The event could be change in connection status with a bitcoin peer.
    pub fn process_event(&mut self, event: &StreamEvent) -> Result<(), ProcessEventError> {
        if let StreamEventKind::Message(message) = &event.kind {
            match message {
                NetworkMessage::Inv(inventory) => {
                    if self
                        .received_inv_message(&event.address, inventory)
                        .is_err()
                    {
                        return Err(ProcessEventError::InvalidMessage);
                    }
                }
                NetworkMessage::Headers(headers) => {
                    if self
                        .received_headers_message(&event.address, headers)
                        .is_err()
                    {
                        return Err(ProcessEventError::InvalidMessage);
                    }
                }
                NetworkMessage::Block(block) => {
                    if self.received_block_message(&event.address, block).is_err() {
                        return Err(ProcessEventError::InvalidMessage);
                    }
                }
                _ => {}
            };
        }
        Ok(())
    }

    /// This heartbeat method is called periodically by the adapter.
    /// This method is used to send messages to Bitcoin peers.
    pub fn tick(&mut self, channel: &mut impl Channel) {
        // Update the list of peers.
        let active_connections = channel.available_connections();
        // Removing inactive peers.
        let peer_addresses: Vec<SocketAddr> =
            self.peer_info.iter().map(|(addr, _)| *addr).collect();

        for addr in peer_addresses {
            if !active_connections.contains(&addr) {
                self.remove_peer(&addr);
            }
        }

        // Add new active peers.
        for addr in active_connections {
            if !self.peer_info.contains_key(&addr) {
                self.add_peer(&addr);
            }
        }

        self.sync_blocks();
        for command in self.outgoing_command_queue.drain(..) {
            channel.send(command).ok();
        }
    }

    /// This method returns the list of all successors (up to given depth) to the given list of block hashes in order.
    /// If depth = 1, the method returns immediate successors of `block_hashes`.
    /// If depth = 2, the method returns immediate successors of `block_hashes`, and immediate successors of the immediate successors.
    ///                               | -> 2'
    /// Example: if the chain is 0 -> 1 -> 2 -> 3 -> 4 -> 5 and the block hashes received are {1, 2, 3} with a depth of 1, then {2', 4} is returned.
    fn get_successor_block_hashes(&self, predecessors: &[BlockHash], depth: u32) -> Vec<BlockHash> {
        let levels = if depth > 1 { depth } else { 1 };
        let mut visited: HashSet<_> = predecessors.iter().copied().collect();
        let mut next_hashes: Vec<_> = predecessors.iter().copied().collect();
        let mut successors = vec![];

        for _ in 0..levels {
            let mut upcoming_hashes = vec![];
            for hash in next_hashes {
                for child in self.blockchain.get_children(&hash) {
                    if !visited.contains(&child) {
                        successors.push(child);
                    }
                    visited.insert(child);
                    upcoming_hashes.push(child);
                }
            }
            next_hashes = upcoming_hashes;
        }

        successors
    }

    /// Performs a breadth-first search to retrieve blocks from the block cache.
    /// a. A single block will be retrieved if the adapter has reached a particular height.
    /// b. Otherwise, multiple blocks will be returned with a total limit of 2MiB.
    fn get_successor_blocks(
        &self,
        anchor: &BlockHash,
        processed_block_hashes: &[BlockHash],
    ) -> (Vec<Block>, Vec<BlockHash>) {
        let anchor_height = self
            .blockchain
            .get_cached_header(anchor)
            .map_or(0, |cached| cached.height);
        let single_block_only = is_single_block_only_mode_enabled(self.network, anchor_height);
        let seen: HashSet<BlockHash> = processed_block_hashes.iter().copied().collect();

        let mut successor_blocks = vec![];
        // Block hashes that should be looked at in subsequent breadth-first searches.
        let mut searchable_block_hashes = vec![];
        let mut response_block_size: usize = 0;
        let mut queue: VecDeque<BlockHash> =
            self.blockchain.get_children(anchor).into_iter().collect();

        // Compute the blocks by starting a breadth-first search.
        while let Some(node) = queue.pop_front() {
            if !seen.contains(&node) {
                // Retrieve the block from the cache.
                match self.blockchain.get_block(&node) {
                    Some(block) => {
                        successor_blocks.push(block.clone());
                        response_block_size += block.get_size();
                        if response_block_size >= MAX_GET_SUCCESSORS_RESPONSE_BLOCKS_SIZE_BYTES
                            || single_block_only
                        {
                            searchable_block_hashes.push(node);
                            break;
                        }
                    }
                    None => {
                        // Cache miss has occurred. This block or any of its successors cannot
                        // be returned. Discarding this subtree from the BFS.
                        searchable_block_hashes.push(node);
                        continue;
                    }
                }
            }

            let children = self.blockchain.get_children(&node);
            queue.extend(children);
        }

        (successor_blocks, searchable_block_hashes)
    }

    /// Get the next headers for blocks that may possibly be sent in upcoming GetSuccessor responses.
    fn get_next_headers(&self, searchable_block_hashes: &[BlockHash]) -> Vec<BlockHeader> {
        let mut queue: VecDeque<BlockHash> = searchable_block_hashes.iter().copied().collect();
        let mut next_headers = vec![];
        while let Some(node) = queue.pop_front() {
            if next_headers.len() >= MAX_NEXT_BLOCK_HEADERS_LENGTH {
                break;
            }

            match self.blockchain.get_cached_header(&node) {
                Some(cached) => next_headers.push(cached.header),
                None => {
                    // Missing header, something has gone very wrong.
                    slog::error!(
                        self.logger,
                        "[ADAPTER-BUG] Missing header cache entry for block hash: {:?}. This should never happen.",
                        node
                    );
                    break;
                }
            }

            let children = self.blockchain.get_children(&node);
            queue.extend(children);
        }
        next_headers
    }

    /// Add block hashes to the sync queue that are not already being synced, planned to be synced,
    /// or in the block cache.
    fn enqueue_new_blocks_to_download(&mut self, searchable_block_hashes: &[BlockHash]) {
        let active_sent_hashes: HashSet<_> = self.getdata_request_info.keys().copied().collect();
        let already_queued_hashes: HashSet<_> = self.block_sync_queue.iter().copied().collect();
        let mut queue: VecDeque<BlockHash> = searchable_block_hashes.iter().copied().collect();
        while let Some(node) = queue.pop_front() {
            if !already_queued_hashes.contains(&node)
                && !active_sent_hashes.contains(&node)
                && self.blockchain.get_block(&node).is_none()
            {
                self.block_sync_queue.push_back(node);
            }

            // Stop adding block hashes when the block sync queue is full.
            if self.block_sync_queue.len() >= MAX_BLOCK_SYNC_QUEUE_SIZE {
                break;
            }

            let children = self.blockchain.get_children(&node);
            queue.extend(children);
        }
    }

    // TODO: ER-2157: GetSuccessors should only sync after the adapter is synced past the
    // highest checkpoint.
    /// Handles a request for get successors. The response will contain the blocks that the adapter
    /// currently contains in its cache as well as the headers for the next blocks. It also prunes
    /// the block cache for blocks that have already been processed.
    pub fn get_successors(&mut self, request: GetSuccessorsRequest) -> GetSuccessorsResponse {
        let GetSuccessorsRequest {
            anchor,
            processed_block_hashes,
        } = request;

        slog::debug!(
            self.logger,
            "Received a GetSuccessorsRequest for anchor hash: {:?}",
            anchor,
        );
        let (successor_blocks, searchable_block_hashes) =
            self.get_successor_blocks(&anchor, &processed_block_hashes);
        let next_headers = self.get_next_headers(&searchable_block_hashes);
        self.enqueue_new_blocks_to_download(&searchable_block_hashes);
        self.blockchain.prune_old_blocks(&processed_block_hashes);

        slog::info!(
            self.logger,
            "Number of blocks cached: {}, Number of uncached successor blocks : {}",
            successor_blocks.len(),
            self.block_sync_queue.len()
        );

        GetSuccessorsResponse {
            blocks: successor_blocks,
            next: next_headers,
        }
    }
}

impl HandleClientRequest for BlockchainManager {
    /// This method is called by Blockmananger::process_event when connection status with a Bitcoin node changed.
    /// If a node is disconnected, this method will remove the peer's info inside BlockChainManager.
    /// If a node is added to active peers list, this method will add the peer's info inside BlockChainManager.
    fn handle_client_request(&mut self, block_hashes: Vec<BlockHash>) -> Vec<Block> {
        slog::info!(
            self.logger,
            "Received a request for following block hashes from system component : {:?}",
            block_hashes
        );
        // Compute the entire set of block hashes that are immediate successors of the input `block_hashes`.
        let immediate_successor_block_hashes =
            self.get_successor_block_hashes(&block_hashes, IMMEDIATE_SUCCESSORS_DEPTH);
        // Compute the next 20 levels of successor block hashes of the input `block_hashes`.
        let mut future_successor_block_hashes: HashSet<BlockHash> = self
            .get_successor_block_hashes(&block_hashes, FUTURE_SUCCESSORS_DEPTH)
            .into_iter()
            .collect();
        slog::info!(
            self.logger,
            "Successor block hashes : {:?}, Future successor block hashes : {:?}",
            immediate_successor_block_hashes,
            future_successor_block_hashes
        );

        //Prune old blocks from block_cache.
        self.blockchain.prune_old_blocks(&block_hashes);

        // Fetch the blockchain state that contain blocks corresponding to the `immediate_successor_block_hashes`.
        let mut successor_blocks = vec![];
        for hash in &immediate_successor_block_hashes {
            if let Some(block) = self.blockchain.get_block(hash) {
                successor_blocks.push(block);
            } else {
                break;
            }
        }

        // Remove the found successor block hashes from `future_successor_block_hashes`.
        // The future successor block hashes will be used to send `getdata` requests so blocks may be cached
        // prior to being requested.
        for successor in &successor_blocks {
            future_successor_block_hashes.remove(&successor.block_hash());
        }

        // Add `future_successor_block_hashes` to `self.inventory_to_be_synced`
        // if `self.blockchain` does not currently have the block.
        let active_sent_hashes: HashSet<_> = self.getdata_request_info.keys().copied().collect();
        for block_hash in future_successor_block_hashes {
            if self.blockchain.get_block(&block_hash).is_none()
                && !active_sent_hashes.contains(&block_hash)
            {
                self.block_sync_queue.push_back(block_hash);
            }
        }

        slog::info!(
            self.logger,
            "Number of blocks cached: {}, Number of uncached successor blocks : {}",
            successor_blocks.len(),
            self.block_sync_queue.len()
        );

        // Send at least 1 block if available.
        // If more than 1 block, append blocks until we reach the max message size
        let mut blocks_to_send = vec![];
        let mut total_size: usize = 0;
        for block in successor_blocks {
            total_size = total_size.saturating_add(block.get_size());
            if blocks_to_send.is_empty()
                || total_size <= MAX_GET_SUCCESSORS_RESPONSE_BLOCKS_SIZE_BYTES
            {
                blocks_to_send.push(block.clone());
            }
        }

        blocks_to_send
    }
}

impl HasHeight for BlockchainManager {
    /// Retrieve the active chain's tip and return its height.
    fn get_height(&self) -> BlockHeight {
        self.blockchain.get_active_chain_tip().height
    }
}

/// Helper used to determine if only a single block should be returned.
fn is_single_block_only_mode_enabled(network: Network, anchor_height: BlockHeight) -> bool {
    match network {
        Network::Bitcoin => anchor_height > MAX_MULTI_MAINNET_ANCHOR_HEIGHT,
        Network::Testnet => anchor_height > MAX_MULTI_TESTNET_ANCHOR_HEIGHT,
        Network::Signet | Network::Regtest => false,
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::common::test_common::{
        generate_headers, generate_large_block_blockchain, make_logger, TestState, BLOCK_1_ENCODED,
        BLOCK_2_ENCODED,
    };
    use crate::config::test::ConfigBuilder;
    use crate::config::Config;
    use bitcoin::consensus::deserialize;
    use bitcoin::Network;
    use bitcoin::{
        network::message::NetworkMessage, network::message_blockdata::Inventory, BlockHash,
    };
    use hex::FromHex;
    use std::net::SocketAddr;
    use std::str::FromStr;

    /// Tests `BlockchainManager::send_getheaders(...)` to ensure the manager's outgoing command
    /// queue
    #[test]
    fn test_manager_can_send_getheaders_messages() {
        let config = ConfigBuilder::new().build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        blockchain_manager.add_peer(&addr);
        assert_eq!(blockchain_manager.outgoing_command_queue.len(), 1);
        let genesis_hash = blockchain_manager.blockchain.genesis().header.block_hash();

        let locators = (vec![genesis_hash], BlockHash::default());
        blockchain_manager.send_getheaders(&addr, locators, OnTimeout::Disconnect);

        let command = blockchain_manager
            .outgoing_command_queue
            .get(0)
            .expect("command not found");
        assert!(matches!(command.address, Some(address) if address == addr));
        assert!(
            matches!(&command.message, NetworkMessage::GetHeaders(GetHeadersMessage { version: _, locator_hashes: _, stop_hash }) if *stop_hash == BlockHash::default())
        );
        assert!(
            matches!(&command.message, NetworkMessage::GetHeaders(GetHeadersMessage { version, locator_hashes: _, stop_hash: _ }) if *version == MINIMUM_VERSION_NUMBER)
        );
        assert!(
            matches!(&command.message, NetworkMessage::GetHeaders(GetHeadersMessage { version: _, locator_hashes, stop_hash: _ }) if locator_hashes[0] == genesis_hash)
        );

        // Check peer info to ensure it has been updated.
        let peer_info = blockchain_manager
            .peer_info
            .get(&addr)
            .expect("peer missing");
        let locators = peer_info
            .last_asked
            .clone()
            .expect("last asked should contain locators");
        assert_eq!(locators.0.len(), 1);
        assert_eq!(
            *locators.0.first().expect("there should be 1 locator"),
            genesis_hash
        );
    }

    /// This unit test is used to verify if the BlockChainManager initiates sync from `adapter_genesis_hash`
    /// whenever a new peer is added.
    /// The test creates a new blockchain manager, an aribtrary chain and 3 peers.
    /// The test then adds each of the peers and verifies the response from the blockchain manager.
    #[test]
    fn test_init_sync() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());

        // Create an arbitrary chain and adding to the BlockchainState.
        let chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            16,
        );
        let runtime = tokio::runtime::Runtime::new().expect("runtime err");

        let sockets = vec![
            SocketAddr::from_str("127.0.0.1:8333").expect("bad address format"),
            SocketAddr::from_str("127.0.0.1:8334").expect("bad address format"),
            SocketAddr::from_str("127.0.0.1:8335").expect("bad address format"),
        ];
        runtime.block_on(async {
            for socket in sockets.iter() {
                blockchain_manager.add_peer(socket);
                if let Some(command) = blockchain_manager.outgoing_command_queue.first() {
                    assert_eq!(
                        command.address.unwrap(),
                        *socket,
                        "The getheaders command is not for the added peer"
                    );
                    assert!(
                        matches!(command.message, NetworkMessage::GetHeaders(_)),
                        "Didn't send getheaders command after adding the peer"
                    );
                    if let NetworkMessage::GetHeaders(get_headers_message) = &command.message {
                        assert_eq!(
                            get_headers_message.locator_hashes,
                            vec![blockchain_manager.blockchain.genesis().header.block_hash()],
                            "Didn't send the right genesis hash for initial syncing"
                        );
                        assert_eq!(
                            get_headers_message.stop_hash,
                            BlockHash::default(),
                            "Didn't send the right stop hash for initial syncing"
                        );
                    }

                    let event = StreamEvent {
                        address: *socket,
                        kind: StreamEventKind::Message(NetworkMessage::Headers(chain.clone())),
                    };

                    assert!(blockchain_manager.process_event(&event).is_ok());
                    let peer = blockchain_manager.peer_info.get(socket).unwrap();
                    assert_eq!(peer.height, 16, "Height of peer {} is not correct", socket);
                    assert_eq!(
                        blockchain_manager.blockchain.get_active_chain_tip().height,
                        16,
                        "Height of the blockchain is not matching after adding the headers"
                    );
                    blockchain_manager.outgoing_command_queue.remove(0);
                } else {
                    panic!("No command sent after adding a peer");
                }
            }
        });
    }

    #[test]
    /// This unit test verifies if the incoming inv messages are processed correctly.
    /// This test first creates a BlockChainManager, adds a peer, and let the initial sync happen.
    /// The test then sends an inv message for a fork chain, and verifies if the BlockChainManager responds correctly.
    fn test_received_inv() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());

        // Create an arbitrary chain and adding to the BlockchainState.
        let chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            16,
        );
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();

        let runtime = tokio::runtime::Runtime::new().expect("runtime err");

        let sockets = vec![
            SocketAddr::from_str("127.0.0.1:8333").expect("bad address format"),
            SocketAddr::from_str("127.0.0.1:8334").expect("bad address format"),
            SocketAddr::from_str("127.0.0.1:8335").expect("bad address format"),
        ];
        runtime.block_on(async {
            blockchain_manager.add_peer(&sockets[0]);
            blockchain_manager.outgoing_command_queue.remove(0);
            let event = StreamEvent {
                address: sockets[0],
                kind: StreamEventKind::Message(NetworkMessage::Headers(chain.clone())),
            };
            assert!(blockchain_manager.process_event(&event).is_ok());

            assert_eq!(
                blockchain_manager.blockchain.get_active_chain_tip().height,
                16,
                "Height of the blockchain is not matching after adding the headers"
            );

            //Send an inv message for a fork chain.
            let fork_chain = generate_headers(chain_hashes[10], chain[10].time, 16);
            let fork_hashes: Vec<BlockHash> = fork_chain
                .iter()
                .map(|header| header.block_hash())
                .collect();
            let message = NetworkMessage::Inv(
                fork_hashes
                    .iter()
                    .map(|hash| Inventory::Block(*hash))
                    .collect(),
            );
            let event = StreamEvent {
                address: sockets[0],
                kind: StreamEventKind::Message(message),
            };
            assert!(blockchain_manager.process_event(&event).is_ok());
            blockchain_manager.add_peer(&sockets[0]);
            if let Some(command) = blockchain_manager.outgoing_command_queue.first() {
                assert_eq!(
                    command.address.unwrap(),
                    sockets[0],
                    "The getheaders command is not for the correct peer"
                );
                assert!(
                    matches!(command.message, NetworkMessage::GetHeaders(_)),
                    "Didn't send getheaders command in response to inv message"
                );
                if let NetworkMessage::GetHeaders(get_headers_message) = &command.message {
                    assert!(
                        !get_headers_message.locator_hashes.is_empty(),
                        "Sent 0 locator hashes in getheaders message"
                    );
                    assert_eq!(
                        get_headers_message.locator_hashes.first().unwrap(),
                        chain_hashes.last().unwrap(),
                        "Didn't send the right locator hashes in response to inv message"
                    );
                    assert_eq!(
                        *get_headers_message.locator_hashes.last().unwrap(),
                        blockchain_manager.blockchain.genesis().header.block_hash(),
                        "Didn't send the right locator hashes in response to inv message"
                    );
                    assert_eq!(
                        get_headers_message.stop_hash,
                        *fork_hashes.last().unwrap(),
                        "Didn't send the right stop hash when responding to inv message"
                    );
                }
                blockchain_manager.outgoing_command_queue.remove(0);
            } else {
                panic!("The BlockChainManager didn't respond to inv message");
            }
        });
    }

    /// This test performs a surface level check to make ensure the `sync_blocks` and `received_block_message`
    /// adds to and removes from `BlockchainManager.getdata_request_info` correctly.
    #[test]
    fn test_simple_sync_blocks_and_received_block_message_lifecycle() {
        let peer_addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        // Mainnet block 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
        let encoded_block_1 = Vec::from_hex(BLOCK_1_ENCODED).expect("unable to make vec from hex");
        // Mainnet block 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
        let encoded_block_2 = Vec::from_hex(BLOCK_2_ENCODED).expect("unable to make vec from hex");
        let block_1: Block = deserialize(&encoded_block_1).expect("failed to decoded block 1");
        let block_2: Block = deserialize(&encoded_block_2).expect("failed to decoded block 2");

        let config = Config::default();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        let headers = vec![block_1.header, block_2.header];
        // Initialize the blockchain manager state
        let (added_headers, maybe_err) = blockchain_manager.blockchain.add_headers(&headers);
        assert_eq!(added_headers.len(), headers.len());
        assert!(maybe_err.is_none());
        blockchain_manager
            .block_sync_queue
            .push_back(block_1.block_hash());
        blockchain_manager
            .block_sync_queue
            .push_back(block_2.block_hash());

        blockchain_manager.add_peer(&peer_addr);
        // Ensure that the number of requests is at 0.
        {
            let available_requests_for_peer = blockchain_manager
                .getdata_request_info
                .values()
                .filter(|p| p.socket == peer_addr)
                .count();
            assert_eq!(available_requests_for_peer, 0);
        }

        // Sync block information.
        blockchain_manager.sync_blocks();
        // Ensure there are now 2 outbound requests for the blocks.
        {
            let available_requests_for_peer = blockchain_manager
                .getdata_request_info
                .values()
                .filter(|p| p.socket == peer_addr)
                .count();
            assert_eq!(available_requests_for_peer, 2);
        }

        // Ensure there is now 1 request.
        let result = blockchain_manager.received_block_message(&peer_addr, &block_1);
        assert!(result.is_ok());
        {
            let available_requests_for_peer = blockchain_manager
                .getdata_request_info
                .values()
                .filter(|p| p.socket == peer_addr)
                .count();
            assert_eq!(available_requests_for_peer, 1);
        }

        let result = blockchain_manager.received_block_message(&peer_addr, &block_2);
        assert!(result.is_ok());
        blockchain_manager.sync_blocks();
        // Ensure there is now zero requests.
        {
            let available_requests_for_peer = blockchain_manager
                .getdata_request_info
                .values()
                .filter(|p| p.socket == peer_addr)
                .count();
            assert_eq!(available_requests_for_peer, 0);
        }
    }

    #[test]
    fn test_get_successor_block_hashes() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());

        // Set up the following chain:
        // |-> 1' -> 2'
        // 0 -> 1 -> 2
        let main_chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            2,
        );

        let side_chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            2,
        );
        blockchain_manager.blockchain.add_headers(&main_chain);
        blockchain_manager.blockchain.add_headers(&side_chain);

        let block_hashes = vec![blockchain_manager.blockchain.genesis().header.block_hash()];

        //             |-> 1' -> 2'
        // If chain is 0 -> 1 -> 2 and block hashes are {0}  then {1, 1'} should be returned.
        let successor_hashes = blockchain_manager.get_successor_block_hashes(&block_hashes, 1);
        assert_eq!(successor_hashes.len(), 2);
        assert!(successor_hashes.contains(&main_chain[0].block_hash()));
        assert!(successor_hashes.contains(&side_chain[0].block_hash()));
        //             |-> 1' -> 2'
        // If chain is 0 -> 1 -> 2 and block hashes are {0, 1}  then {1', 2, 2'} should be returned.
        let block_hashes = vec![
            blockchain_manager.blockchain.genesis().header.block_hash(),
            main_chain[0].block_hash(),
        ];
        let successor_hashes = blockchain_manager.get_successor_block_hashes(&block_hashes, 2);

        assert_eq!(successor_hashes.len(), 3);
        assert!(successor_hashes.contains(&side_chain[0].block_hash()));
        assert!(successor_hashes.contains(&side_chain[1].block_hash()));
        assert!(successor_hashes.contains(&main_chain[1].block_hash()));
    }

    /// This tests ensures that `BlockchainManager::handle_client_request(...)` does the following:
    /// 1. Retrieves immediate successor hashes and returns block 1.
    /// 2. Adds block 2 to `blockchain_manager.block_sync_queue`.
    /// 3. Syncs the blocks.
    /// 4. Retrieves an empty set of blocks when provided a set of hashes containing block 1's hash.
    ///     a. Ensure that no blocks are returned as block 2 has yet to be retrieved.
    ///     b. Ensure Block 1 has been pruned from the block cache.
    ///     c. Ensure Block 2 is no longer in the `blockchain_manager.block_sync_queue` field as it has been requested.
    #[test]
    fn test_get_successors() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let headers = vec![test_state.block_1.header, test_state.block_2.header];
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        blockchain_manager.add_peer(&addr);
        let (added_headers, _) = blockchain_manager.blockchain.add_headers(&headers);
        assert_eq!(added_headers.len(), 2);

        blockchain_manager
            .blockchain
            .add_block(test_state.block_1.clone())
            .expect("invalid block");

        let request = GetSuccessorsRequest {
            anchor: blockchain_manager.blockchain.genesis().header.block_hash(),
            processed_block_hashes: vec![],
        };
        let response = blockchain_manager.get_successors(request);
        let block_1_hash = test_state.block_1.block_hash();
        let block_2_hash = test_state.block_2.block_hash();
        assert!(
            matches!(response.blocks.first(), Some(block) if block.block_hash() == block_1_hash)
        );
        assert_eq!(blockchain_manager.block_sync_queue.len(), 1);
        assert!(blockchain_manager.block_sync_queue.contains(&block_2_hash));

        blockchain_manager.sync_blocks();
        let request = GetSuccessorsRequest {
            anchor: blockchain_manager.blockchain.genesis().header.block_hash(),
            processed_block_hashes: vec![block_1_hash],
        };
        let response = blockchain_manager.get_successors(request);
        assert!(response.blocks.is_empty());
        assert!(blockchain_manager
            .blockchain
            .get_block(&block_1_hash)
            .is_none());
        assert!(blockchain_manager.block_sync_queue.is_empty());
    }

    /// This tests ensures that `BlockchainManager::handle_client_request(...)` returns multiple
    /// blocks from the main chain and a fork. Order should be preserved.
    #[test]
    fn test_get_successors_multiple_blocks() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        // Set up the following chain:
        // |-> 1'
        // 0 -> 1 -> 2
        let main_chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            2,
        );
        let main_block_1 = Block {
            header: main_chain[0],
            txdata: vec![],
        };
        let main_block_2 = Block {
            header: main_chain[1],
            txdata: vec![],
        };

        let side_chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            1,
        );
        let side_1 = side_chain.get(0).cloned().expect("Should have 1 header");
        let side_block_1 = Block {
            header: side_1,
            txdata: vec![],
        };
        blockchain_manager.blockchain.add_headers(&main_chain);
        blockchain_manager.blockchain.add_headers(&side_chain);
        blockchain_manager
            .blockchain
            .add_block(main_block_1.clone())
            .expect("invalid block");
        blockchain_manager
            .blockchain
            .add_block(main_block_2.clone())
            .expect("invalid block");
        blockchain_manager
            .blockchain
            .add_block(side_block_1.clone())
            .expect("invalid block");

        //             |-> 1'
        // If chain is 0 -> 1 -> 2 and block hashes are {0}  then {1, 1', 2} should be returned in that order.
        let request = GetSuccessorsRequest {
            anchor: blockchain_manager.blockchain.genesis().header.block_hash(),
            processed_block_hashes: vec![],
        };
        let response = blockchain_manager.get_successors(request);
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
    #[test]
    fn test_get_successors_multiple_blocks_out_of_order() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        // Set up the following chain:
        // |-> 1'
        // 0 -> 1 -> 2
        let main_chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            2,
        );
        let main_block_2 = Block {
            header: main_chain[1],
            txdata: vec![],
        };

        let side_chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            1,
        );
        let side_1 = side_chain.get(0).cloned().expect("Should have 1 header");
        let side_block_1 = Block {
            header: side_1,
            txdata: vec![],
        };
        blockchain_manager.blockchain.add_headers(&main_chain);
        blockchain_manager.blockchain.add_headers(&side_chain);
        blockchain_manager
            .blockchain
            .add_block(main_block_2)
            .expect("invalid block");
        blockchain_manager
            .blockchain
            .add_block(side_block_1.clone())
            .expect("invalid block");

        //             |-> 1'
        // If chain is 0 -> 1 -> 2 and block hashes are {0}  then {1, 1', 2} would be the successor blocks.
        // Block 1 is not in the cache yet. The Bitcoin virtual canister requires that the blocks
        // are received in order.
        let request = GetSuccessorsRequest {
            anchor: blockchain_manager.blockchain.genesis().header.block_hash(),
            processed_block_hashes: vec![],
        };
        let response = blockchain_manager.get_successors(request);
        assert_eq!(response.blocks.len(), 1);
        assert!(
            matches!(response.blocks.get(0), Some(block) if block.block_hash() == side_block_1.block_hash())
        );
        assert_eq!(response.next.len(), 2);
        assert_eq!(response.next[0].block_hash(), main_chain[0].block_hash());
        assert_eq!(response.next[1].block_hash(), main_chain[1].block_hash());
    }

    /// This test ensures that the 2MB limit is enforced by `BlockchainManager.get_successors(...)`.
    #[test]
    fn test_get_successors_large_block() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let blockchain_manager = BlockchainManager::new(&config, make_logger());
        let genesis = blockchain_manager.blockchain.genesis();

        let large_blocks =
            generate_large_block_blockchain(genesis.header.block_hash(), genesis.header.time, 1);
        let large_block = large_blocks.first().cloned().unwrap();
        let headers: Vec<BlockHeader> = large_blocks.iter().map(|b| b.header).collect();

        let additional_headers =
            generate_headers(large_block.block_hash(), large_block.header.time, 1);
        let small_block = Block {
            header: additional_headers[0],
            txdata: vec![],
        };

        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        blockchain_manager.add_peer(&addr);
        let (added_headers, _) = blockchain_manager.blockchain.add_headers(&headers);
        assert_eq!(added_headers.len(), 1);
        let (added_headers, _) = blockchain_manager
            .blockchain
            .add_headers(&additional_headers);
        assert_eq!(added_headers.len(), 1);

        blockchain_manager
            .blockchain
            .add_block(large_block.clone())
            .expect("invalid block");
        blockchain_manager
            .blockchain
            .add_block(small_block)
            .expect("invalid block");

        let request = GetSuccessorsRequest {
            anchor: blockchain_manager.blockchain.genesis().header.block_hash(),
            processed_block_hashes: vec![],
        };
        let response = blockchain_manager.get_successors(request);
        assert_eq!(response.blocks.len(), 1);
        assert!(
            matches!(response.blocks.first(), Some(block) if block.block_hash() == large_block.block_hash() && block.txdata.len() == large_block.txdata.len())
        );
        assert_eq!(blockchain_manager.block_sync_queue.len(), 0);
    }

    /// This function tests to ensure that the BlockchainManager does not send out `getdata`
    /// requests when the block cache has reached the size threshold.
    #[test]
    fn test_sync_blocks_size_limit() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");

        // Make 5 large blocks that are around 2MiB each.
        let genesis = blockchain_manager.blockchain.genesis();
        let large_blocks =
            generate_large_block_blockchain(genesis.header.block_hash(), genesis.header.time, 5);
        let headers = large_blocks.iter().map(|b| b.header).collect::<Vec<_>>();

        blockchain_manager.add_peer(&addr);
        let (added_headers, _) = blockchain_manager.blockchain.add_headers(&headers);
        assert_eq!(added_headers.len(), 5);

        // Add the 5 large blocks.
        for block in large_blocks {
            blockchain_manager.blockchain.add_block(block).unwrap();
        }

        blockchain_manager
            .block_sync_queue
            .push_back(test_state.block_2.block_hash());

        blockchain_manager.sync_blocks();
        // The `getdata_request_info` should be empty as the block cache is at the size threshold.
        assert!(blockchain_manager.getdata_request_info.is_empty());
    }

    /// Tests the `BlockchainManager::idle(...)` function to ensure it clears the state from the
    /// BlockchainManager.
    #[test]
    fn test_make_idle() {
        let peer_addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        // Mainnet block 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
        let encoded_block_1 = Vec::from_hex(BLOCK_1_ENCODED).expect("unable to make vec from hex");
        // Mainnet block 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
        let encoded_block_2 = Vec::from_hex(BLOCK_2_ENCODED).expect("unable to make vec from hex");
        let block_1: Block = deserialize(&encoded_block_1).expect("failed to decoded block 1");
        let block_2: Block = deserialize(&encoded_block_2).expect("failed to decoded block 2");
        let block_2_hash = block_2.block_hash();

        let config = Config::default();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        let headers = vec![block_1.header, block_2.header];
        // Initialize the blockchain manager state
        let (added_headers, maybe_err) = blockchain_manager.blockchain.add_headers(&headers);
        assert_eq!(added_headers.len(), headers.len());
        assert!(maybe_err.is_none());
        blockchain_manager
            .block_sync_queue
            .push_back(block_1.block_hash());
        blockchain_manager
            .blockchain
            .add_block(block_2)
            .expect("invalid block");
        blockchain_manager.add_peer(&peer_addr);

        assert_eq!(blockchain_manager.block_sync_queue.len(), 1);
        assert!(blockchain_manager
            .blockchain
            .get_block(&block_2_hash)
            .is_some());
        assert_eq!(blockchain_manager.peer_info.len(), 1);

        blockchain_manager.make_idle();
        assert_eq!(blockchain_manager.block_sync_queue.len(), 0);
        assert!(blockchain_manager
            .blockchain
            .get_block(&block_2_hash)
            .is_none());
        assert_eq!(blockchain_manager.peer_info.len(), 0);
    }
}
