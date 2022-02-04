use crate::{
    blockchainstate::{AddHeaderError, BlockchainState},
    common::{BlockHeight, MINIMUM_VERSION_NUMBER},
    config::Config,
    stream::{StreamEvent, StreamEventKind},
    Channel, Command, HandleClientRequest, ProcessEventError,
};
use bitcoin::{
    network::{
        message::{NetworkMessage, MAX_INV_SIZE},
        message_blockdata::{GetHeadersMessage, Inventory},
    },
    Block, BlockHash, BlockHeader,
};
use rand::prelude::*;
use slog::Logger;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use thiserror::Error;

// TODO: ER-2133: Unify usage of the `getdata` term when referring to the Bitcoin message.
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

/// Max size of the `GetSuccessorsResponse` message (2 MiB).
const MAX_GET_SUCCESSORS_RESPONSE_BLOCKS_SIZE_BYTES: usize = 2 * 1024 * 1024;

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
    /// Locators sent in the last `GetHeaders` or `GetData` request
    last_asked: Option<Locators>,
    /// Time at which the request was sent.
    sent_at: Option<SystemTime>,
    /// What to do if this request times out.
    on_timeout: OnTimeout,
}

/// This struct stores the information related to a "GetData" request sent by the BlockChainManager
#[derive(Debug)]
pub struct GetDataRequestInfo {
    /// This field stores the socket address of the Bitcoin node to which the request was sent.
    socket: SocketAddr,
    /// This field contains the time at which the GetData request was sent.  
    sent_at: SystemTime,
    /// This field contains the action to take if the request is expired.
    on_timeout: OnTimeout,
}

/// The BlockChainManager struct handles interactions that involve the headers.
#[derive(Debug)]
pub struct BlockchainManager {
    /// This field contains the BlockchainState, which stores and manages
    /// all the information related to the headers and blocks.
    blockchain: BlockchainState,

    /// This field stores the map of which bitcoin nodes sent which "inv" messages.
    peer_info: HashMap<SocketAddr, PeerInfo>,

    /// Random number generator used for sampling a random peer to send "GetData" request.
    rng: StdRng,

    /// This HashMap stores the information related to each get_data request
    /// sent by the BlockChainManager. An entry is removed from this hashmap if
    /// (1) The corresponding "Block" response is received or
    /// (2) If the request is expired or
    /// (3) If the peer is disconnected.
    get_data_request_info: HashMap<BlockHash, GetDataRequestInfo>,

    /// This HashSet stores the list of block hashes that has yet to be synced by the BlockChainManager.
    blocks_to_be_synced: HashSet<BlockHash>,

    /// This vector stores the list of messages that are to be sent to the Bitcoin network.
    outgoing_command_queue: Vec<Command>,
    /// This field contains a logger for the blockchain manager's use.
    logger: Logger,
}

impl BlockchainManager {
    /// This function instantiates a BlockChainManager struct. A node is provided
    /// in order to get its client so the manager can send messages to the
    /// BTC network.
    pub fn new(config: &Config, logger: Logger) -> Self {
        let blockchain = BlockchainState::new(config);
        let peer_info = HashMap::new();
        let get_data_request_info = HashMap::new();
        let rng = StdRng::from_entropy();
        let inventory_to_be_synced = HashSet::new();
        let outgoing_command_queue = Vec::new();
        BlockchainManager {
            blockchain,
            peer_info,
            rng,
            get_data_request_info,
            blocks_to_be_synced: inventory_to_be_synced,
            outgoing_command_queue,
            logger,
        }
    }

    /// This method sends `getheaders` command to the adapter.
    /// The adapter then sends the `getheaders` request to the Bitcoin node.
    fn send_getheaders(&mut self, addr: &SocketAddr, locators: Locators, on_timeout: OnTimeout) {
        // TODO: ER-1394: Timeouts must for getheaders calls must be handled.
        //If the peer address is not stored in peer_info, then return;
        if let Some(peer_info) = self.peer_info.get_mut(addr) {
            slog::debug!(
                self.logger,
                "Sending GetHeaders to {} : Locator hashes {:?}, Stop hash {}",
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
    /// Given a block_hash, this method sends the corresponding "GetHeaders" message to the Bitcoin node.
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

            // Send `GetHeaders` request to fetch the headers corresponding to inv message.
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
        } else if self.blockchain.get_header(&last_block_hash).is_some() {
            self.blockchain.get_header(&last_block_hash)
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
            Some(AddHeaderError::InvalidHeader(_)) => {
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

        let maybe_request_info = self.get_data_request_info.get(&block_hash);
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

        //Remove the corresponding `GetData` request from peer_info and get_data_request_info.
        self.get_data_request_info.remove(&block_hash);

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
    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        slog::info!(self.logger, "Removing peer_info with addr : {} ", addr);
        self.peer_info.remove(addr);
        // Removing all the `GetData` requests that have been sent to the peer before.
        self.get_data_request_info.retain(|_, v| v.socket != *addr);
    }

    fn filter_expired_get_data_requests(&mut self) {
        let now = SystemTime::now();
        let timeout_period = Duration::new(GETDATA_REQUEST_TIMEOUT_SECS, 0);
        self.get_data_request_info
            .retain(|_, request| request.sent_at + timeout_period > now);
    }

    pub fn sync_blocks(&mut self) {
        if self.blocks_to_be_synced.is_empty() {
            return;
        }

        slog::info!(
            self.logger,
            "Syning blocks. Blocks to be synced : {:?}",
            self.blocks_to_be_synced
        );

        // Removing expired GetData requests from `self.get_data_request_info`
        self.filter_expired_get_data_requests();

        slog::info!(self.logger, "Syncing blocks. Inventory to be synced after filtering out the past GetData requests : {:?}", self.blocks_to_be_synced);

        // Count the number of requests per peer.
        let mut requests_per_peer: HashMap<SocketAddr, u32> =
            self.peer_info.keys().map(|addr| (*addr, 0)).collect();
        for info in self.get_data_request_info.values() {
            let counter = requests_per_peer.entry(info.socket).or_insert(0);
            *counter = counter.saturating_add(1);
        }

        let mut peer_info: Vec<_> = self.peer_info.values_mut().collect();
        peer_info.sort_by(|a, b| {
            let requests_sent_to_a = requests_per_peer.get(&a.socket).unwrap_or(&0);
            let requests_sent_to_b = requests_per_peer.get(&b.socket).unwrap_or(&0);
            requests_sent_to_a.cmp(requests_sent_to_b)
        });

        // For each peer, select a random subset of the inventory and send a "GetData" request for it.
        for peer in peer_info {
            // Calculate number of inventory that can be sent in 'GetData' request to the peer.
            let requests_sent_to_peer = requests_per_peer.get(&peer.socket).unwrap_or(&0);
            let num_requests_to_be_sent =
                INV_PER_GET_DATA_REQUEST.saturating_sub(*requests_sent_to_peer);

            // Randomly sample some inventory to be requested from the peer.
            let selected_inventory = self
                .blocks_to_be_synced
                .iter()
                .cloned()
                .choose_multiple(&mut self.rng, num_requests_to_be_sent as usize);

            if selected_inventory.is_empty() {
                break;
            }

            slog::info!(
                self.logger,
                "Sending GetData to {} : Inventory {:?}",
                peer.socket,
                selected_inventory
            );

            //Send 'GetData' request for the inventory to the peer.
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
                self.get_data_request_info.insert(
                    inv,
                    GetDataRequestInfo {
                        socket: peer.socket,
                        sent_at: SystemTime::now(),
                        on_timeout: OnTimeout::Ignore,
                    },
                );

                // Remove the inventory that is going to be sent.
                self.blocks_to_be_synced.remove(&inv);
            }
        }
    }

    /// This function is called by the adapter when a new event takes place.
    /// The event could be receiving "GetHeaders", "GetData", "Inv" messages from bitcion peers.
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
        for command in self.outgoing_command_queue.iter() {
            channel.send(command.clone()).ok();
        }
        self.outgoing_command_queue = vec![];
    }

    // TODO: ER-1943: Implement "smart adapters" which prefer to return blocks in the longest chain.
    /// This method returns the list of all successors (up to given depth) to the given list of block hashes in order.
    /// If depth = 1, the method returns immediate successors of `block_hashes`.
    /// If depth = 2, the method returns immediate successors of `block_hashes`, and immediate successors of the immediate successors.
    ///                               | -> 2'
    /// Example: if the chain is 0 -> 1 -> 2 -> 3 -> 4 -> 5 and the block hashes received are {1, 2, 3} with a depth of 1, then {2', 4} is returned.
    fn get_successor_block_hashes(&self, predecessors: &[BlockHash], depth: u32) -> Vec<BlockHash> {
        let levels = if depth > 1 { depth } else { 1 };
        let mut visited: HashSet<&BlockHash> = predecessors.iter().collect();
        let mut next_hashes: Vec<_> = predecessors.iter().collect();
        let mut successors = vec![];

        for _ in 0..levels {
            let mut upcoming_hashes = vec![];
            for hash in next_hashes {
                if let Some(children) = self.blockchain.get_children(hash) {
                    for child in children {
                        if !visited.contains(child) {
                            successors.push(*child);
                        }
                        visited.insert(child);
                        upcoming_hashes.push(child);
                    }
                }
            }
            next_hashes = upcoming_hashes;
        }

        successors
    }
}

impl HandleClientRequest for BlockchainManager {
    // TODO: ER-2124: BlockchainManager should only provide blocks when fully synced.
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
        // The future successor block hashes will be used to send `GetData` requests so blocks may be cached
        // prior to being requested.
        for successor in &successor_blocks {
            future_successor_block_hashes.remove(&successor.block_hash());
        }

        // Add `future_successor_block_hashes` to `self.inventory_to_be_synced`
        // if `self.blockchain` does not currently have the block.
        let active_sent_hashes: HashSet<_> = self.get_data_request_info.keys().copied().collect();
        for block_hash in future_successor_block_hashes {
            if self.blockchain.get_block(&block_hash).is_none()
                && !active_sent_hashes.contains(&block_hash)
            {
                self.blocks_to_be_synced.insert(block_hash);
            }
        }

        slog::info!(
            self.logger,
            "Number of blocks cached: {}, Number of uncached successor blocks : {}",
            successor_blocks.len(),
            self.blocks_to_be_synced.len()
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

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::common::test_common::{
        generate_headers, large_block, make_logger, TestState, BLOCK_1_ENCODED, BLOCK_2_ENCODED,
    };
    use crate::config::test::ConfigBuilder;
    use crate::config::Config;
    use bitcoin::consensus::deserialize;
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
        let config = Config::default();
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
                        "The GetHeaders command is not for the added peer"
                    );
                    assert!(
                        matches!(command.message, NetworkMessage::GetHeaders(_)),
                        "Didn't send GetHeaders command after adding the peer"
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
                    assert_eq!(peer.height, 17, "Height of peer {} is not correct", socket);
                    assert_eq!(
                        blockchain_manager.blockchain.get_active_chain_tip().height,
                        17,
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
        let config = Config::default();
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
                17,
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
                    "The GetHeaders command is not for the correct peer"
                );
                assert!(
                    matches!(command.message, NetworkMessage::GetHeaders(_)),
                    "Didn't send GetHeaders command in response to inv message"
                );
                if let NetworkMessage::GetHeaders(get_headers_message) = &command.message {
                    assert!(
                        !get_headers_message.locator_hashes.is_empty(),
                        "Sent 0 locator hashes in GetHeaders message"
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
    /// adds to and removes from `BlockchainManager.get_data_request_info` correctly.
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
            .blocks_to_be_synced
            .insert(block_1.block_hash());
        blockchain_manager
            .blocks_to_be_synced
            .insert(block_2.block_hash());

        blockchain_manager.add_peer(&peer_addr);
        // Ensure that the number of requests is at 0.
        {
            let available_requests_for_peer = blockchain_manager
                .get_data_request_info
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
                .get_data_request_info
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
                .get_data_request_info
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
                .get_data_request_info
                .values()
                .filter(|p| p.socket == peer_addr)
                .count();
            assert_eq!(available_requests_for_peer, 0);
        }
    }

    #[test]
    fn test_get_successor_block_hashes() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());

        // Set up the following chain:
        // |-> 1' -> 2'
        // 0 -> 1 -> 2
        let main_chain = vec![test_state.block_1.header, test_state.block_2.header];
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
        assert!(successor_hashes.contains(&test_state.block_1.block_hash()));
        assert!(successor_hashes.contains(&side_chain[0].block_hash()));
        //             |-> 1' -> 2'
        // If chain is 0 -> 1 -> 2 and block hashes are {0, 1}  then {1', 2, 2'} should be returned.
        let block_hashes = vec![
            blockchain_manager.blockchain.genesis().header.block_hash(),
            test_state.block_1.block_hash(),
        ];
        let successor_hashes = blockchain_manager.get_successor_block_hashes(&block_hashes, 2);

        assert_eq!(successor_hashes.len(), 3);
        assert!(successor_hashes.contains(&side_chain[0].block_hash()));
        assert!(successor_hashes.contains(&side_chain[1].block_hash()));
        assert!(successor_hashes.contains(&test_state.block_2.block_hash()));
    }

    /// This tests ensures that `BlockchainManager::handle_client_request(...)` does the following:
    /// 1. Retrieves immediate successor hashes and returns block 1.
    /// 2. Adds block 2 to `blockchain_manager.blocks_to_be_synced`.
    /// 3. Sync the blocks.
    /// 4. Retrieves with a set of hashes containing block 1.
    ///     a. No block is returned
    ///     b. Block 1 has been pruned from the cache.
    ///     c. Block 2 is no longer in the `blockchain_manager.blocks_to_be_synced` field.
    #[test]
    fn test_handle_client_request() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        blockchain_manager.add_peer(&addr);
        blockchain_manager
            .blockchain
            .add_header(test_state.block_1.header)
            .expect("invalid header");
        blockchain_manager
            .blockchain
            .add_header(test_state.block_2.header)
            .expect("invalid header");
        blockchain_manager
            .blockchain
            .add_block(test_state.block_1.clone())
            .expect("invalid block");

        let hashes = vec![blockchain_manager.blockchain.genesis().header.block_hash()];
        let blocks = blockchain_manager.handle_client_request(hashes);
        let block_1_hash = test_state.block_1.block_hash();
        let block_2_hash = test_state.block_2.block_hash();
        assert!(matches!(blocks.first(), Some(block) if block.block_hash() == block_1_hash));
        assert_eq!(blockchain_manager.blocks_to_be_synced.len(), 1);
        assert!(blockchain_manager
            .blocks_to_be_synced
            .contains(&block_2_hash));

        let hashes = vec![
            blockchain_manager.blockchain.genesis().header.block_hash(),
            block_1_hash,
        ];

        blockchain_manager.sync_blocks();
        let blocks = blockchain_manager.handle_client_request(hashes);
        assert!(blocks.is_empty());
        assert!(blockchain_manager
            .blockchain
            .get_block(&block_1_hash)
            .is_none());
        assert!(blockchain_manager.blocks_to_be_synced.is_empty());
    }

    /// This tests ensures that `BlockchainManager::handle_client_request(...)` returns multiple
    /// blocks from the main chain and a fork. Order should be preserved.
    #[test]
    fn test_handle_client_request_multiple_blocks() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        // Set up the following chain:
        // |-> 1'
        // 0 -> 1 -> 2
        let main_chain = vec![test_state.block_1.header, test_state.block_2.header];
        let side_chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            0,
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
            .add_block(test_state.block_1.clone())
            .expect("invalid block");
        blockchain_manager
            .blockchain
            .add_block(test_state.block_2.clone())
            .expect("invalid block");
        blockchain_manager
            .blockchain
            .add_block(side_block_1.clone())
            .expect("invalid block");

        let block_hashes = vec![blockchain_manager.blockchain.genesis().header.block_hash()];

        //             |-> 1'
        // If chain is 0 -> 1 -> 2 and block hashes are {0}  then {1, 1', 2} should be returned in that order.
        let blocks = blockchain_manager.handle_client_request(block_hashes);
        assert_eq!(blocks.len(), 3);
        assert!(
            matches!(blocks.get(0), Some(block) if block.block_hash() == test_state.block_1.block_hash())
        );
        assert!(
            matches!(blocks.get(1), Some(block) if block.block_hash() == side_block_1.block_hash())
        );
        assert!(
            matches!(blocks.get(2), Some(block) if block.block_hash() == test_state.block_2.block_hash())
        );
    }

    /// This tests ensures that `BlockchainManager::handle_client_request(...)` returns multiple
    /// blocks from the main chain and a fork. Order should be preserved.
    #[test]
    fn test_handle_client_request_multiple_blocks_out_of_order() {
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        // Set up the following chain:
        // |-> 1'
        // 0 -> 1 -> 2
        let main_chain = vec![test_state.block_1.header, test_state.block_2.header];
        let side_chain = generate_headers(
            blockchain_manager.blockchain.genesis().header.block_hash(),
            blockchain_manager.blockchain.genesis().header.time,
            0,
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
            .add_block(test_state.block_2)
            .expect("invalid block");
        blockchain_manager
            .blockchain
            .add_block(side_block_1)
            .expect("invalid block");

        let block_hashes = vec![blockchain_manager.blockchain.genesis().header.block_hash()];

        //             |-> 1'
        // If chain is 0 -> 1 -> 2 and block hashes are {0}  then {1, 1', 2} would be the successor blocks.
        // Block 1 is not in the cache yet. The Bitcoin virtual canister requires that the blocks
        // are received in order.
        let blocks = blockchain_manager.handle_client_request(block_hashes);
        assert_eq!(blocks.len(), 0);
    }

    /// This test ensures that the 2MB limit is enforced by `BlockchainManager.handle_client_request(...)`.
    #[test]
    fn test_handle_client_request_large_block() {
        let large_block = large_block();
        let test_state = TestState::setup();
        let config = ConfigBuilder::new().build();
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");

        let mut block_2 = test_state.block_2;
        block_2.header.prev_blockhash = large_block.block_hash();

        let mut blockchain_manager = BlockchainManager::new(&config, make_logger());
        blockchain_manager.add_peer(&addr);
        blockchain_manager
            .blockchain
            .add_header(large_block.header)
            .expect("invalid header");
        blockchain_manager
            .blockchain
            .add_header(block_2.header)
            .expect("invalid header");
        blockchain_manager
            .blockchain
            .add_block(large_block.clone())
            .expect("invalid block");
        blockchain_manager
            .blockchain
            .add_block(block_2)
            .expect("invalid block");

        let hashes = vec![blockchain_manager.blockchain.genesis().header.block_hash()];
        let blocks = blockchain_manager.handle_client_request(hashes);
        let block_1_hash = large_block.block_hash();
        assert!(
            matches!(blocks.first(), Some(block) if block.block_hash() == block_1_hash && block.txdata.len() == large_block.txdata.len())
        );
        assert_eq!(blocks.len(), 1);
        assert_eq!(blockchain_manager.blocks_to_be_synced.len(), 0);
    }
}
