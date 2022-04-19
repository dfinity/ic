use crate::{
    blockchainstate::{AddHeaderError, BlockchainState},
    common::{BlockHeight, MINIMUM_VERSION_NUMBER},
    Channel, Command, ProcessBitcoinNetworkMessageError,
};
use bitcoin::{
    network::{
        message::{NetworkMessage, MAX_INV_SIZE},
        message_blockdata::{GetHeadersMessage, Inventory},
    },
    Block, BlockHash, BlockHeader,
};
use hashlink::LinkedHashSet;
use ic_logger::{debug, error, info, warn, ReplicaLogger};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Instant, SystemTime},
};
use thiserror::Error;
use tokio::sync::Mutex;

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

const ONE_MB: usize = 1_024 * 1_024;

/// The limit at which we should stop making additional requests for new blocks as the block cache
/// becomes too large. Inflight `getdata` messages will remain active, but new `getdata` messages will
/// not be created.
const BLOCK_CACHE_THRESHOLD_BYTES: usize = 10 * ONE_MB;

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
    /// This variant represents when a message from an unknown peer.
    #[error("Unknown peer")]
    UnknownPeer,
    #[error("Unknown block")]
    UnknownBlock,
    /// This variant represents that a block was not able to be added to the `block_cache` in the
    /// BlockchainState.
    #[error("Failed to add block")]
    BlockNotAdded,
}

/// This struct stores the information regarding a peer with respect to synchronizing the blockchain.
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
    sent_at: Instant,
    /// This field contains the action to take if the request is expired.
    _on_timeout: OnTimeout,
}

/// The BlockChainManager struct handles interactions that involve the headers.
pub struct BlockchainManager {
    /// This field contains the BlockchainState, which stores and manages
    /// all the information related to the headers and blocks.
    blockchain: Arc<Mutex<BlockchainState>>,

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
    block_sync_queue: LinkedHashSet<BlockHash>,

    /// This field contains a logger for the blockchain manager's use.
    logger: ReplicaLogger,
}

impl BlockchainManager {
    /// This function instantiates a BlockChainManager struct. A node is provided
    /// in order to get its client so the manager can send messages to the
    /// BTC network.
    pub fn new(blockchain: Arc<Mutex<BlockchainState>>, logger: ReplicaLogger) -> Self {
        let peer_info = HashMap::new();
        let getdata_request_info = HashMap::new();

        BlockchainManager {
            blockchain,
            peer_info,
            getdata_request_info,
            block_sync_queue: LinkedHashSet::new(),
            logger,
        }
    }

    /// This method is used when the adapter is no longer receiving RPC calls from the replica.
    /// Clears the block cache, peer info, the blocks to be synced, outgoing command queue, and
    /// the `getdata` request info.
    pub async fn make_idle(&mut self) {
        self.block_sync_queue.clear();
        self.getdata_request_info.clear();
        self.peer_info.clear();
        self.blockchain.lock().await.clear_blocks();
    }

    /// This method sends `getheaders` command to the adapter.
    /// The adapter then sends the `getheaders` request to the Bitcoin node.
    /// https://en.bitcoin.it/wiki/Protocol_documentation#getheaders
    fn send_getheaders(
        &mut self,
        channel: &mut impl Channel,
        addr: &SocketAddr,
        locators: Locators,
        on_timeout: OnTimeout,
    ) {
        // TODO: ER-1394: Timeouts must for getheaders calls must be handled.
        //If the peer address is not stored in peer_info, then return;
        if let Some(peer_info) = self.peer_info.get_mut(addr) {
            info!(
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
            channel.send(command).ok();
            // Caveat: Updating peer_info even if the command hasn't been set yet.
            peer_info.last_asked = Some(locators);
            peer_info.sent_at = Some(SystemTime::now());
            peer_info.on_timeout = on_timeout;
        }
    }

    /// This function processes "inv" messages received from Bitcoin nodes.
    /// Given a block_hash, this method sends the corresponding "getheaders" message to the Bitcoin node.
    async fn received_inv_message(
        &mut self,
        channel: &mut impl Channel,
        addr: &SocketAddr,
        inventory: &[Inventory],
    ) -> Result<(), ReceivedInvMessageError> {
        // If the inv message has more inventory than MAX_INV_SIZE (50000), reject it.
        if inventory.len() > MAX_INV_SIZE {
            return Err(ReceivedInvMessageError::TooMuchInventory);
        }

        // If the inv message is received from a peer that is not connected, then reject it.
        info!(
            self.logger,
            "Received inv message from {} : Inventory {:?}", addr, inventory
        );

        let peer = self
            .peer_info
            .get_mut(addr)
            .ok_or(ReceivedInvMessageError::UnknownPeer)?;

        //This field stores the block hash in the inventory that is not yet stored in the blockchain,
        // and has the highest height amongst all the hashes in the inventory.
        let mut last_block = None;

        let maybe_locators = {
            let blockchain_state = self.blockchain.lock().await;
            for inv in inventory {
                if let Inventory::Block(hash) = inv {
                    peer.tip = *hash;
                    if !blockchain_state.is_block_hash_known(hash) {
                        last_block = Some(hash);
                    }
                }
            }

            last_block.map(|stop_hash| (blockchain_state.locator_hashes(), *stop_hash))
        };

        if let Some(locators) = maybe_locators {
            // Send `getheaders` request to fetch the headers corresponding to inv message.
            self.send_getheaders(channel, addr, locators, OnTimeout::Ignore);
        }

        Ok(())
    }

    async fn received_headers_message(
        &mut self,
        channel: &mut impl Channel,
        addr: &SocketAddr,
        headers: &[BlockHeader],
    ) -> Result<(), ReceivedHeadersMessageError> {
        let peer = self
            .peer_info
            .get_mut(addr)
            .ok_or(ReceivedHeadersMessageError::UnknownPeer)?;
        info!(
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

        let maybe_locators = {
            let mut blockchain_state = self.blockchain.lock().await;
            let prev_tip_height = blockchain_state.get_active_chain_tip().height;

            let (added_headers, maybe_err) = blockchain_state.add_headers(headers);
            let active_tip = blockchain_state.get_active_chain_tip();
            if prev_tip_height < active_tip.height {
                info!(
                self.logger,
                "Added headers in the headers message. State Changed. Height = {}, Active chain's tip = {}",
                active_tip.height,
                active_tip.header.block_hash()
            );
            }

            // Update the peer's tip and height to the last
            let maybe_last_header = if added_headers.last().is_some() {
                added_headers.last()
            } else if blockchain_state
                .get_cached_header(&last_block_hash)
                .is_some()
            {
                blockchain_state.get_cached_header(&last_block_hash)
            } else {
                None
            };

            if let Some(last) = maybe_last_header {
                if last.height > peer.height {
                    peer.tip = last.header.block_hash();
                    peer.height = last.height;
                    debug!(
                        self.logger,
                        "Peer {}'s height = {}, tip = {}", addr, peer.height, peer.tip
                    );
                }
            }

            match maybe_err {
                Some(AddHeaderError::InvalidHeader(_, _)) => {
                    return Err(ReceivedHeadersMessageError::ReceivedInvalidHeader)
                }
                Some(AddHeaderError::PrevHeaderNotCached(stop_hash)) => {
                    Some((blockchain_state.locator_hashes(), stop_hash))
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
            }
        };

        if let Some(locators) = maybe_locators {
            self.send_getheaders(channel, addr, locators, OnTimeout::Ignore);
        } else {
            // If the adapter is not going to ask for more headers, the peer's last_asked should
            // be reset.
            peer.last_asked = None;
        }

        Ok(())
    }

    /// This function processes "block" messages received from Bitcoin nodes
    async fn received_block_message(
        &mut self,
        addr: &SocketAddr,
        block: &Block,
    ) -> Result<(), ReceivedBlockMessageError> {
        if !self.peer_info.contains_key(addr) {
            return Err(ReceivedBlockMessageError::UnknownPeer);
        }

        let block_hash = block.block_hash();
        let time_taken = self
            .getdata_request_info
            .get(&block_hash)
            .map(|i| i.sent_at.elapsed())
            .unwrap_or_default();

        info!(
            self.logger,
            "Received block message from {} : Took {:?}sec. Block {:?}",
            addr,
            time_taken,
            block_hash
        );

        //Remove the corresponding `getdata` request from peer_info and getdata_request_info.
        let maybe_request = self.getdata_request_info.remove(&block_hash);
        if maybe_request.is_none() {
            // Exit early. If the block is not in the `getdata_request_info`, the block is no longer wanted.
            return Err(ReceivedBlockMessageError::UnknownBlock);
        }

        match self.blockchain.lock().await.add_block(block.clone()) {
            Ok(block_height) => {
                info!(
                    self.logger,
                    "Block added to the cache successfully at height = {}", block_height
                );
                Ok(())
            }
            Err(err) => {
                warn!(
                    self.logger,
                    "Unable to add the received block in blockchain. Error: {:?}", err
                );
                Err(ReceivedBlockMessageError::BlockNotAdded)
            }
        }
    }

    /// This function adds a new peer to `peer_info`
    /// and initiates sync with the peer by sending `getheaders` message.
    async fn add_peer(&mut self, channel: &mut impl Channel, addr: &SocketAddr) {
        if self.peer_info.contains_key(addr) {
            return;
        }

        let (initial_hash, locator_hashes) = {
            let blockchain = self.blockchain.lock().await;
            (
                blockchain.genesis().header.block_hash(),
                blockchain.locator_hashes(),
            )
        };

        info!(self.logger, "Adding peer_info with addr : {} ", addr);
        self.peer_info.insert(
            *addr,
            PeerInfo {
                socket: *addr,
                height: 0,
                tip: initial_hash,
                last_asked: None,
                sent_at: None,
                on_timeout: OnTimeout::Ignore,
            },
        );
        let locators = (locator_hashes, BlockHash::default());
        self.send_getheaders(channel, addr, locators, OnTimeout::Disconnect);
    }

    /// This function adds a new peer to `peer_info`
    /// and initiates sync with the peer by sending `getheaders` message.
    fn remove_peer(&mut self, addr: &SocketAddr) {
        info!(self.logger, "Removing peer_info with addr : {} ", addr);
        self.peer_info.remove(addr);
        // Removing all the `getdata` requests that have been sent to the peer before.
        self.getdata_request_info.retain(|_, v| v.socket != *addr);
    }

    fn filter_expired_getdata_requests(&mut self) {
        self.getdata_request_info.retain(|_, request| {
            request.sent_at.elapsed().as_secs() <= GETDATA_REQUEST_TIMEOUT_SECS
        });
    }

    async fn sync_blocks(&mut self, channel: &mut impl Channel) {
        // Removing expired getdata requests so they may be enqueued again.
        self.filter_expired_getdata_requests();

        // If nothing to be synced, then there is nothing to do at this point.
        if self.block_sync_queue.is_empty() {
            return;
        }

        let block_cache_size = self.blockchain.lock().await.get_block_cache_size();

        debug!(
            self.logger,
            "Cache Size: {}, Max Size: {}", block_cache_size, BLOCK_CACHE_THRESHOLD_BYTES
        );
        if block_cache_size >= BLOCK_CACHE_THRESHOLD_BYTES {
            return;
        }

        debug!(
            self.logger,
            "Syncing blocks. Blocks to be synced : {:?}",
            self.block_sync_queue.len()
        );

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

            info!(
                self.logger,
                "Sending getdata to {} : Inventory {:?}", peer.socket, selected_inventory
            );

            //Send 'getdata' request for the inventory to the peer.
            channel
                .send(Command {
                    address: Some(peer.socket),
                    message: NetworkMessage::GetData(
                        selected_inventory
                            .iter()
                            .map(|h| Inventory::Block(*h))
                            .collect(),
                    ),
                })
                .ok();

            for inv in selected_inventory {
                // Record the `getdata` request.
                self.getdata_request_info.insert(
                    inv,
                    GetDataRequestInfo {
                        socket: peer.socket,
                        sent_at: Instant::now(),
                        _on_timeout: OnTimeout::Ignore,
                    },
                );
            }
        }
    }

    /// This function is called by the adapter when a new event takes place.
    /// The event could be receiving "getheaders", "getdata", "inv" messages from bitcion peers.
    /// The event could be change in connection status with a bitcoin peer.
    pub async fn process_bitcoin_network_message(
        &mut self,
        channel: &mut impl Channel,
        addr: SocketAddr,
        message: &NetworkMessage,
    ) -> Result<(), ProcessBitcoinNetworkMessageError> {
        match message {
            NetworkMessage::Inv(inventory) => {
                if self
                    .received_inv_message(channel, &addr, inventory)
                    .await
                    .is_err()
                {
                    return Err(ProcessBitcoinNetworkMessageError::InvalidMessage);
                }
            }
            NetworkMessage::Headers(headers) => {
                if self
                    .received_headers_message(channel, &addr, headers)
                    .await
                    .is_err()
                {
                    return Err(ProcessBitcoinNetworkMessageError::InvalidMessage);
                }
            }
            NetworkMessage::Block(block) => {
                if self.received_block_message(&addr, block).await.is_err() {
                    return Err(ProcessBitcoinNetworkMessageError::InvalidMessage);
                }
            }
            _ => {}
        };
        Ok(())
    }

    /// This heartbeat method is called periodically by the adapter.
    /// This method is used to send messages to Bitcoin peers.
    pub async fn tick(&mut self, channel: &mut impl Channel) {
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
                self.add_peer(channel, &addr).await;
            }
        }

        self.sync_blocks(channel).await;
    }

    /// Add block hashes to the sync queue that are not already being synced, planned to be synced,
    /// or in the block cache.
    pub async fn enqueue_new_blocks_to_download(&mut self, next_headers: Vec<BlockHeader>) {
        let state = self.blockchain.lock().await;
        for header in next_headers {
            let hash = header.block_hash();
            if state.get_block(&hash).is_none()
                && !self.block_sync_queue.contains(&hash)
                && !self.getdata_request_info.contains_key(&hash)
            {
                self.block_sync_queue.insert(hash);
            }
        }
    }

    /// Wrapper function to access the blockchain state to prune blocks that are no longer
    /// needed.
    pub async fn prune_blocks(
        &mut self,
        anchor: BlockHash,
        processed_block_hashes: Vec<BlockHash>,
    ) {
        {
            let mut blockchain = self.blockchain.lock().await;
            let anchor_height = blockchain
                .get_cached_header(&anchor)
                .map_or(0, |c| c.height);
            let filter_height = anchor_height
                .checked_add(1)
                .expect("prune by block height: overflow occurred");

            blockchain.prune_blocks(&processed_block_hashes);
            blockchain.prune_blocks_below_height(filter_height);

            self.getdata_request_info.retain(|b, _| {
                blockchain.get_cached_header(b).map_or(0, |c| c.height) >= filter_height
            });

            self.block_sync_queue.retain(|b| {
                blockchain.get_cached_header(b).map_or(0, |c| c.height) >= filter_height
            });
        };

        for block_hash in processed_block_hashes {
            self.getdata_request_info.remove(&block_hash);
            self.block_sync_queue.remove(&block_hash);
        }
    }

    /// Retrieves the height of the active tip.
    pub async fn get_height(&self) -> BlockHeight {
        self.blockchain.lock().await.get_active_chain_tip().height
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::common::test_common::{
        generate_headers, generate_large_block_blockchain, TestChannel, TestState, BLOCK_1_ENCODED,
        BLOCK_2_ENCODED,
    };
    use crate::config::test::ConfigBuilder;
    use bitcoin::consensus::deserialize;
    use bitcoin::Network;
    use bitcoin::{
        network::message::NetworkMessage, network::message_blockdata::Inventory, BlockHash,
    };
    use hex::FromHex;
    use ic_logger::replica_logger::no_op_logger;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::Duration;

    /// Tests `BlockchainManager::send_getheaders(...)` to ensure the manager's outgoing command
    /// queue
    #[tokio::test]
    async fn test_manager_can_send_getheaders_messages() {
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let mut channel = TestChannel::new(vec![addr]);
        let config = ConfigBuilder::new().build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        blockchain_manager.add_peer(&mut channel, &addr).await;

        assert_eq!(channel.command_count(), 1);

        let locators = (vec![genesis_hash], BlockHash::default());
        blockchain_manager.send_getheaders(&mut channel, &addr, locators, OnTimeout::Disconnect);

        let command = channel.pop_front().expect("command not found");
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

    /// This test ensures that, when a peer is connected to, the known locator hashes are sent
    /// to the peer. When first starting, the adapter should send only the genesis hash. After headers
    /// are received, the locator hashes sent should follow the algorithm defined in
    /// BlockchainState::locator_hashes.
    #[tokio::test]
    async fn test_init_sync() {
        let addr1 = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let addr2 = SocketAddr::from_str("127.0.0.1:8444").expect("bad address format");
        let sockets = vec![addr1, addr2];
        let mut channel = TestChannel::new(sockets.clone());
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        // Create an arbitrary chain and adding to the BlockchainState.
        let chain = generate_headers(genesis_hash, genesis.header.time, 16, &[]);
        let mut after_first_received_headers_message_hashes = chain
            .iter()
            .rev()
            .take(9)
            .map(|h| h.block_hash())
            .collect::<Vec<BlockHash>>();
        after_first_received_headers_message_hashes.push(chain[5].block_hash());
        after_first_received_headers_message_hashes.push(chain[1].block_hash());
        after_first_received_headers_message_hashes.push(genesis_hash);

        blockchain_manager.add_peer(&mut channel, &addr1).await;
        let command = channel
            .pop_front()
            .expect("there should be a getheaders message");
        assert_eq!(
            command.address.unwrap(),
            addr1,
            "The getheaders command is not for the addr1"
        );
        assert!(
            matches!(command.message, NetworkMessage::GetHeaders(_)),
            "Didn't send getheaders command after adding the peer"
        );
        let get_headers_message = match command.message {
            NetworkMessage::GetHeaders(get_headers_message) => get_headers_message,
            _ => GetHeadersMessage {
                version: 0,
                locator_hashes: vec![],
                stop_hash: BlockHash::default(),
            },
        };
        assert_eq!(
            get_headers_message.locator_hashes,
            vec![genesis_hash],
            "Didn't send the right genesis hash for initial syncing"
        );
        assert_eq!(
            get_headers_message.stop_hash,
            BlockHash::default(),
            "Didn't send the right stop hash for initial syncing"
        );

        // Add headers to the blockchain state.
        let message = NetworkMessage::Headers(chain.clone());
        assert!(blockchain_manager
            .process_bitcoin_network_message(&mut channel, addr1, &message)
            .await
            .is_ok());

        blockchain_manager.add_peer(&mut channel, &addr2).await;
        let command = channel
            .pop_front()
            .expect("there should be a getheaders message");
        assert_eq!(
            command.address.unwrap(),
            addr2,
            "The getheaders command is not for the addr2"
        );
        assert!(
            matches!(command.message, NetworkMessage::GetHeaders(_)),
            "Didn't send getheaders command after adding the peer"
        );
        let get_headers_message = match command.message {
            NetworkMessage::GetHeaders(get_headers_message) => get_headers_message,
            _ => GetHeadersMessage {
                version: 0,
                locator_hashes: vec![],
                stop_hash: BlockHash::default(),
            },
        };
        assert_eq!(
            get_headers_message.locator_hashes, after_first_received_headers_message_hashes,
            "Didn't send the right genesis hash for initial syncing"
        );
        assert_eq!(
            get_headers_message.stop_hash,
            BlockHash::default(),
            "Didn't send the right stop hash for initial syncing"
        );
    }

    #[tokio::test]
    /// This unit test verifies if the incoming inv messages are processed correctly.
    /// This test first creates a BlockChainManager, adds a peer, and let the initial sync happen.
    /// The test then sends an inv message for a fork chain, and verifies if the BlockChainManager responds correctly.
    async fn test_received_inv() {
        let sockets = vec![SocketAddr::from_str("127.0.0.1:8333").expect("bad address format")];
        let mut channel = TestChannel::new(sockets.clone());
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        // Create an arbitrary chain and adding to the BlockchainState.
        let chain = generate_headers(genesis_hash, genesis.header.time, 16, &[]);
        let chain_hashes: Vec<BlockHash> = chain.iter().map(|header| header.block_hash()).collect();

        blockchain_manager.add_peer(&mut channel, &sockets[0]).await;

        assert!(blockchain_manager
            .process_bitcoin_network_message(
                &mut channel,
                sockets[0],
                &NetworkMessage::Headers(chain.clone())
            )
            .await
            .is_ok());

        assert_eq!(
            blockchain_manager
                .blockchain
                .lock()
                .await
                .get_active_chain_tip()
                .height,
            16,
            "Height of the blockchain is not matching after adding the headers"
        );

        //Send an inv message for a fork chain.
        let fork_chain = generate_headers(chain_hashes[10], chain[10].time, 16, &chain_hashes);
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
        assert!(blockchain_manager
            .process_bitcoin_network_message(&mut channel, sockets[0], &message)
            .await
            .is_ok());
        if let Some(command) = channel.pop_back() {
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
                    genesis_hash,
                    "Didn't send the right locator hashes in response to inv message"
                );
                assert_eq!(
                    get_headers_message.stop_hash,
                    *fork_hashes.last().unwrap(),
                    "Didn't send the right stop hash when responding to inv message"
                );
            }
        } else {
            panic!("The BlockChainManager didn't respond to inv message");
        }
    }

    /// This test performs a surface level check to make ensure the `sync_blocks` and `received_block_message`
    /// adds to and removes from `BlockchainManager.getdata_request_info` correctly.
    #[tokio::test]
    async fn test_simple_sync_blocks_and_received_block_message_lifecycle() {
        let peer_addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let sockets = vec![peer_addr];
        let mut channel = TestChannel::new(sockets.clone());
        let config = ConfigBuilder::new().build();
        let blockchain_state = BlockchainState::new(&config);
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        let peer_addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        // Mainnet block 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
        let encoded_block_1 = Vec::from_hex(BLOCK_1_ENCODED).expect("unable to make vec from hex");
        // Mainnet block 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
        let encoded_block_2 = Vec::from_hex(BLOCK_2_ENCODED).expect("unable to make vec from hex");
        let block_1: Block = deserialize(&encoded_block_1).expect("failed to decoded block 1");
        let block_2: Block = deserialize(&encoded_block_2).expect("failed to decoded block 2");

        let headers = vec![block_1.header, block_2.header];
        // Initialize the blockchain manager state
        {
            let (added_headers, maybe_err) = blockchain_manager
                .blockchain
                .lock()
                .await
                .add_headers(&headers);
            assert_eq!(added_headers.len(), headers.len());
            assert!(maybe_err.is_none());
            blockchain_manager
                .block_sync_queue
                .insert(block_1.block_hash());
            blockchain_manager
                .block_sync_queue
                .insert(block_2.block_hash());
        }
        blockchain_manager.add_peer(&mut channel, &peer_addr).await;
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
        blockchain_manager.sync_blocks(&mut channel).await;
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
        let result = blockchain_manager
            .received_block_message(&peer_addr, &block_1)
            .await;
        assert!(result.is_ok());
        {
            let available_requests_for_peer = blockchain_manager
                .getdata_request_info
                .values()
                .filter(|p| p.socket == peer_addr)
                .count();
            assert_eq!(available_requests_for_peer, 1);
        }

        let result = blockchain_manager
            .received_block_message(&peer_addr, &block_2)
            .await;
        assert!(result.is_ok());
        blockchain_manager.sync_blocks(&mut channel).await;
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

    /// This function tests to ensure that the BlockchainManager does not send out `getdata`
    /// requests when the block cache has reached the size threshold.
    #[tokio::test]
    async fn test_sync_blocks_size_limit() {
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let sockets = vec![addr];
        let mut channel = TestChannel::new(sockets.clone());
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        let test_state = TestState::setup();

        // Make 5 large blocks that are around 2MiB each.
        let large_blocks = generate_large_block_blockchain(genesis_hash, genesis.header.time, 5);
        let headers = large_blocks.iter().map(|b| b.header).collect::<Vec<_>>();

        {
            blockchain_manager.add_peer(&mut channel, &addr).await;
            let mut blockchain = blockchain_manager.blockchain.lock().await;
            let (added_headers, _) = blockchain.add_headers(&headers);
            assert_eq!(added_headers.len(), 5);

            // Add the 5 large blocks.
            for block in large_blocks {
                blockchain.add_block(block).unwrap();
            }
        };

        blockchain_manager
            .block_sync_queue
            .insert(test_state.block_2.block_hash());
        blockchain_manager.sync_blocks(&mut channel).await;

        // The `getdata_request_info` should be empty as the block cache is at the size threshold.
        assert!(blockchain_manager.getdata_request_info.is_empty());
    }

    /// This function tests to ensure that the BlockchainManager clears out timed out `getdata` requests
    /// when calling `sync_blocks`.
    #[tokio::test]
    async fn test_ensure_sync_blocks_clears_timed_out_getdata_requests() {
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let sockets = vec![addr];
        let mut channel = TestChannel::new(sockets.clone());
        let config = ConfigBuilder::new().build();
        let blockchain_state = BlockchainState::new(&config);
        let test_state = TestState::setup();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        // Ensure that the request info will be timed out.
        let sent_at = Instant::now() - Duration::from_secs(GETDATA_REQUEST_TIMEOUT_SECS + 1);
        blockchain_manager.getdata_request_info.insert(
            test_state.block_1.block_hash(),
            GetDataRequestInfo {
                socket: addr,
                sent_at,
                _on_timeout: OnTimeout::Ignore,
            },
        );

        blockchain_manager.sync_blocks(&mut channel).await;

        assert!(blockchain_manager.getdata_request_info.is_empty());
    }

    /// Tests the `BlockchainManager::idle(...)` function to ensure it clears the state from the
    /// BlockchainManager.
    #[tokio::test]
    async fn test_make_idle() {
        let peer_addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        let sockets = vec![peer_addr];
        let mut channel = TestChannel::new(sockets.clone());
        let config = ConfigBuilder::new().build();
        let blockchain_state = BlockchainState::new(&config);
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        let peer_addr = SocketAddr::from_str("127.0.0.1:8333").expect("bad address format");
        // Mainnet block 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048
        let encoded_block_1 = Vec::from_hex(BLOCK_1_ENCODED).expect("unable to make vec from hex");
        // Mainnet block 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
        let encoded_block_2 = Vec::from_hex(BLOCK_2_ENCODED).expect("unable to make vec from hex");
        let block_1: Block = deserialize(&encoded_block_1).expect("failed to decoded block 1");
        let block_2: Block = deserialize(&encoded_block_2).expect("failed to decoded block 2");
        let block_2_hash = block_2.block_hash();

        let headers = vec![block_1.header, block_2.header];
        // Initialize the blockchain manager state
        {
            blockchain_manager.add_peer(&mut channel, &peer_addr).await;
            let mut blockchain = blockchain_manager.blockchain.lock().await;
            let (added_headers, maybe_err) = blockchain.add_headers(&headers);
            assert_eq!(added_headers.len(), headers.len());
            assert!(maybe_err.is_none());

            blockchain.add_block(block_2).expect("invalid block");
        };
        blockchain_manager
            .block_sync_queue
            .insert(block_1.block_hash());
        assert_eq!(blockchain_manager.block_sync_queue.len(), 1);

        assert!(blockchain_manager
            .blockchain
            .lock()
            .await
            .get_block(&block_2_hash)
            .is_some());

        assert_eq!(blockchain_manager.peer_info.len(), 1);

        blockchain_manager.make_idle().await;
        assert_eq!(blockchain_manager.block_sync_queue.len(), 0);
        assert!(blockchain_manager
            .blockchain
            .lock()
            .await
            .get_block(&block_2_hash)
            .is_none());
        assert_eq!(blockchain_manager.peer_info.len(), 0);
    }

    #[tokio::test]
    async fn test_enqueue_new_blocks_to_download() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        let next_headers = generate_headers(genesis_hash, genesis.header.time, 5, &[]);
        let next_hashes = next_headers
            .iter()
            .map(|h| h.block_hash())
            .collect::<Vec<_>>();

        blockchain_manager
            .enqueue_new_blocks_to_download(next_headers)
            .await;

        assert_eq!(blockchain_manager.block_sync_queue.len(), 5);

        let enqueued_blocks = blockchain_manager
            .block_sync_queue
            .iter()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            enqueued_blocks, next_hashes,
            "{:#?} != {:#?}",
            enqueued_blocks, next_hashes
        );
    }

    #[tokio::test]
    async fn test_enqueue_new_blocks_to_download_no_duplicates() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());

        let next_headers = generate_headers(genesis_hash, genesis.header.time, 5, &[]);
        let next_hashes = next_headers
            .iter()
            .take(3)
            .map(|h| h.block_hash())
            .collect::<Vec<_>>();
        // Extract last hash from the next_hashes and add it to the getdata_request_info
        // hashmap.
        blockchain_manager.getdata_request_info.insert(
            next_headers[4].block_hash(),
            GetDataRequestInfo {
                socket: SocketAddr::from_str("127.0.0.1:8333").expect("should be valid addr"),
                sent_at: Instant::now(),
                _on_timeout: OnTimeout::Ignore,
            },
        );

        // Create and add a block to the cache, remove the hash
        let block = Block {
            header: next_headers[3],
            txdata: vec![],
        };
        {
            let mut blockchain = blockchain_manager.blockchain.lock().await;
            let (headers_added, maybe_err) = blockchain.add_headers(&next_headers);
            assert_eq!(headers_added.len(), next_headers.len(), "{:#?}", maybe_err);
            blockchain.add_block(block).expect("unable to add block");
        }
        blockchain_manager
            .enqueue_new_blocks_to_download(next_headers)
            .await;

        assert_eq!(blockchain_manager.block_sync_queue.len(), 3);

        let enqueued_blocks = blockchain_manager
            .block_sync_queue
            .iter()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            enqueued_blocks, next_hashes,
            "{:#?} != {:#?}",
            enqueued_blocks, next_hashes
        );
    }

    #[tokio::test]
    async fn test_pruning_blocks_based_on_the_anchor_hash_and_processed_hashes() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let mut channel = TestChannel::new(vec![addr]);

        let next_headers = generate_headers(genesis_hash, genesis.header.time, 11, &[]);
        let next_hashes = next_headers
            .iter()
            .map(|h| h.block_hash())
            .collect::<Vec<_>>();
        // Create and add a block to the cache, remove the hash
        let block_3 = Block {
            header: next_headers[2],
            txdata: vec![],
        };

        {
            let mut blockchain = blockchain_manager.blockchain.lock().await;
            let (headers_added, maybe_err) = blockchain.add_headers(&next_headers);
            assert_eq!(headers_added.len(), next_headers.len(), "{:#?}", maybe_err);
            blockchain.add_block(block_3).expect("unable to add block");
        }

        blockchain_manager.add_peer(&mut channel, &addr).await;
        blockchain_manager
            .enqueue_new_blocks_to_download(next_headers)
            .await;

        // The block sync queue should contain 10 block hashes. Missing block 3 as it is in the cache already.
        assert_eq!(blockchain_manager.block_sync_queue.len(), 10);

        blockchain_manager.sync_blocks(&mut channel).await;
        assert_eq!(blockchain_manager.getdata_request_info.len(), 8);

        blockchain_manager
            .prune_blocks(next_hashes[2], next_hashes[3..8].to_vec())
            .await;
        // `getdata` requests should be completely clears based on the processed block hashes.
        assert_eq!(blockchain_manager.getdata_request_info.len(), 1);
        // Block sync should only contain block 11's hash.
        assert_eq!(blockchain_manager.block_sync_queue.len(), 2);
        assert_eq!(
            blockchain_manager
                .block_sync_queue
                .back()
                .expect("should contain 1 block hash"),
            next_hashes
                .last()
                .expect("next_hashes should contain 1 block hash")
        );
        // Block 3 should be removed from the cache as it is the anchor.
        assert!(blockchain_manager
            .blockchain
            .lock()
            .await
            .get_block(&next_hashes[2])
            .is_none());
    }

    #[tokio::test]
    async fn test_pruning_blocks_to_ensure_it_does_not_prune_anchor_adjacent_blocks() {
        let config = ConfigBuilder::new().with_network(Network::Regtest).build();
        let blockchain_state = BlockchainState::new(&config);
        let genesis = blockchain_state.genesis().clone();
        let genesis_hash = genesis.header.block_hash();
        let mut blockchain_manager =
            BlockchainManager::new(Arc::new(Mutex::new(blockchain_state)), no_op_logger());
        let addr = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let mut channel = TestChannel::new(vec![addr]);

        let next_headers = generate_headers(genesis_hash, genesis.header.time, 11, &[]);
        let next_hashes = next_headers
            .iter()
            .map(|h| h.block_hash())
            .collect::<Vec<_>>();
        // Create and add a block to the cache, remove the hash
        let block_5 = Block {
            header: next_headers[4],
            txdata: vec![],
        };

        {
            let mut blockchain = blockchain_manager.blockchain.lock().await;
            let (headers_added, maybe_err) = blockchain.add_headers(&next_headers);
            assert_eq!(headers_added.len(), next_headers.len(), "{:#?}", maybe_err);
            blockchain.add_block(block_5).expect("unable to add block");
        }

        blockchain_manager.add_peer(&mut channel, &addr).await;
        blockchain_manager
            .enqueue_new_blocks_to_download(next_headers)
            .await;

        // The block sync queue should contain 10 block hashes. Missing block 3 as it is in the cache already.
        assert_eq!(blockchain_manager.block_sync_queue.len(), 10);
        blockchain_manager.prune_blocks(genesis_hash, vec![]).await;
        assert_eq!(blockchain_manager.block_sync_queue.len(), 10);

        blockchain_manager.sync_blocks(&mut channel).await;
        assert_eq!(blockchain_manager.getdata_request_info.len(), 8);

        blockchain_manager.prune_blocks(genesis_hash, vec![]).await;
        // `getdata` requests should be completely clears based on the processed block hashes.
        assert_eq!(blockchain_manager.getdata_request_info.len(), 8);
        // Block sync should only contain block 11's hash.
        assert_eq!(blockchain_manager.block_sync_queue.len(), 2);
        assert_eq!(
            blockchain_manager
                .block_sync_queue
                .back()
                .expect("should contain 1 block hash"),
            next_hashes
                .last()
                .expect("next_hashes should contain 1 block hash")
        );
        // Block 5 shoul still be in the cache.
        assert!(blockchain_manager
            .blockchain
            .lock()
            .await
            .get_block(&next_hashes[4])
            .is_some());
    }
}
