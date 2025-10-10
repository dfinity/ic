#![cfg_attr(not(test), warn(missing_docs))]

//! The Bitcoin adapter interacts with the Bitcoin P2P network to obtain blocks
//! and publish transactions. Moreover, it interacts with the Bitcoin system
//! component to provide blocks and collect outgoing transactions.

use bitcoin::p2p::message::NetworkMessage;
use bitcoin::{BlockHash, block::Header as PureHeader};
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::{mpsc::channel, watch};
/// This module contains the AddressManager struct. The struct stores addresses
/// that will be used to create new connections. It also tracks addresses that
/// are in current use to encourage use from non-utilized addresses.
mod addressbook;
/// This module contains method for managing the local Bitcoin ledger,
/// sending "getheaders", "getdata" messages to Bitcoin peers,
/// processing the "inv", "headers", "block" messages received from Bitcoin peers, and
/// answering the queries of Bitcoin system component.
mod blockchainmanager;
/// This module contains the data structure for storing the current state of the Bitcoin ledger
mod blockchainstate;
/// This module contains constants and types that are shared by many modules.
mod common;
/// This module contains the basic configuration struct used to start up an
/// adapter instance.
pub mod config;
/// This module contains code that is used to manage a single connection to a
/// BTC node.
mod connection;
/// This module contains code that is used to manage multiple connections to
/// BTC nodes.
mod connectionmanager;
mod header_cache;
mod metrics;
/// The module is responsible for awaiting messages from bitcoin peers and dispaching them
/// to the correct component.
mod router;
/// This module contains code that is used to handle interactions to connected
/// BTC streams (SOCKS and TCP).
mod rpc_server;
mod stream;
mod transaction_store;

// This module contains code that is used to return requested blocks to the Bitcoin canister.
// For security reasons, it expects the returned blocks to be in a BFS order (for example, a
// malicious fork can be prioritized by a DFS, thus potentially ignoring honest forks).
mod get_successors_handler;

pub use blockchainmanager::MAX_HEADERS_SIZE;
pub use blockchainstate::BlockchainState;
pub use common::{
    AdapterNetwork, BlockchainBlock, BlockchainHeader, BlockchainNetwork, HeaderValidator,
};
pub use config::{Config, IncomingSource, address_limits};

use crate::{
    get_successors_handler::GetSuccessorsHandler, router::start_main_event_loop,
    rpc_server::start_grpc_server, stream::StreamEvent,
};

/// This struct is used to represent commands given to the adapter in order to interact
/// with BTC nodes.
#[derive(Clone, Eq, PartialEq, Debug)]
struct Command<Header, Block> {
    /// This is the address of the Bitcoin node to which the message is supposed to be sent.
    /// If the address is None, then the message will be sent to all the peers.
    address: Option<SocketAddr>,
    /// This the network message to be sent to the above peer.
    message: NetworkMessage<Header, Block>,
}

/// This enum is used to represent errors that could occur while dispatching an
/// event.
#[derive(Debug)]
enum ProcessNetworkMessageError {
    /// This variant is used to represent when an invalid message has been
    /// received from a peer node.
    InvalidMessage,
}

/// Error returned by `Channel::send`.
#[derive(Debug)]
enum ChannelError {}

/// This trait is to provide an interface so that managers can communicate to BTC nodes.
trait Channel<Header, Block> {
    /// This method is used to send a message to a specific connection
    /// or to all connections based on the [Command](Command)'s fields.
    fn send(&mut self, command: Command<Header, Block>) -> Result<(), ChannelError>;

    /// This method is used to retrieve a list of available connections
    /// that have completed the version handshake.
    fn available_connections(&self) -> Vec<SocketAddr>;

    /// Used to disconnect from nodes that are misbehaving.
    fn discard(&mut self, addr: &SocketAddr);
}

/// This trait provides an interface to anything that may need to react to a
/// [StreamEvent](crate::stream::StreamEvent).
trait ProcessEvent {
    /// This method is used to route an event in a component's internals and
    /// perform state updates.
    fn process_event(&mut self, event: &StreamEvent) -> Result<(), ProcessNetworkMessageError>;
}

/// This trait provides an interface for processing messages coming from
/// bitcoin peers.
/// [StreamEvent](crate::stream::StreamEvent).
trait ProcessNetworkMessage<Network: BlockchainNetwork> {
    /// This method is used to route an event in a component's internals and
    /// perform state updates.
    fn process_bitcoin_network_message(
        &mut self,
        addr: SocketAddr,
        message: &NetworkMessage<Network::Header, Network::Block>,
    ) -> Result<(), ProcessNetworkMessageError>;
}

/// Commands sent back to the router in order perform actions on the blockchain state.
#[derive(Debug)]
pub(crate) enum BlockchainManagerRequest {
    /// Inform the adapter to enqueue the next block headers into the syncing queue.
    EnqueueNewBlocksToDownload(Vec<PureHeader>),
    /// Inform the adapter to prune the following block hashes from the cache.
    PruneBlocks(BlockHash, Vec<BlockHash>),
}

/// The transaction manager is owned by a single thread which listens on a channel
/// for TransactionManagerRequest messages and executes the corresponding method.
#[derive(Debug)]
pub(crate) enum TransactionManagerRequest {
    /// Command for executing send_transaction
    SendTransaction(Vec<u8>),
}

/// The type tracks when then adapter should become idle. The type is
/// thread-safe.
#[derive(Clone)]
pub(crate) struct AdapterState {
    /// The field contains how long the adapter should wait before becoming idle.
    idle_seconds: u64,

    /// The watch channel that holds the last received time.
    /// The field contains the instant of the latest received request.
    /// None means that we haven't reveived a request yet and the adapter should be in idle mode!
    ///
    /// !!! BE CAREFUL HERE !!! since the adapter should ALWAYS be idle when starting up.
    /// This is important because most subnets will have bitcoin integration disabled and we don't want
    /// to unnecessary download bitcoin data.
    /// In a previous iteration we set this value to at least 'idle_seconds' in the past on startup.
    /// This way the adapter would always be in idle when starting since 'elapsed()' is greater than 'idle_seconds'.
    /// On MacOS this approach caused issues since on MacOS Instant::now() is time since boot and when subtracting
    /// 'idle_seconds' we encountered an underflow and panicked.
    ///
    /// It's simportant that this value is set to [`None`] on startup.
    last_received_rx: watch::Receiver<Option<Instant>>,
}

impl AdapterState {
    /// Creates a new instance of the [`AdapterState`].
    pub fn new(idle_seconds: u64) -> (Self, watch::Sender<Option<Instant>>) {
        // Initialize the watch channel with `None`, indicating no requests have been received yet.
        let (tx, last_received_rx) = watch::channel(None);
        (
            Self {
                idle_seconds,
                last_received_rx,
            },
            tx,
        )
    }

    /// A future that returns when/if the adapter becomes/is awake.
    pub async fn active(&mut self) {
        let _ = self
            .last_received_rx
            .wait_for(|v| {
                if let Some(last) = v {
                    return last.elapsed().as_secs() < self.idle_seconds;
                }
                false
            })
            .await;
    }

    /// Returns whether the adapter is idle.
    pub fn is_idle(&self) -> bool {
        match *self.last_received_rx.borrow() {
            Some(last) => last.elapsed().as_secs() >= self.idle_seconds,
            // Nothing received yet still in idle from startup.
            None => true,
        }
    }
}

async fn start_server_helper<Network>(
    log: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    config: config::Config<Network>,
) where
    Network: BlockchainNetwork + Sync + Send + 'static,
    Network::Header: Send,
    Network::Block: Send + Sync,
    BlockchainState<Network>: HeaderValidator<Network>,
    <BlockchainState<Network> as HeaderValidator<Network>>::HeaderError: Send + Sync,
{
    let (adapter_state, tx) = AdapterState::new(config.idle_seconds);
    let (blockchain_manager_tx, blockchain_manager_rx) = channel(100);
    let blockchain_state = BlockchainState::new(
        config.network,
        config.cache_dir.clone(),
        &metrics_registry,
        log.clone(),
    );
    let blockchain_state = Arc::new(blockchain_state);

    let (transaction_manager_tx, transaction_manager_rx) = channel(100);
    let handles = [
        start_grpc_server(
            config.network,
            config.incoming_source.clone(),
            log.clone(),
            tx,
            blockchain_state.clone(),
            blockchain_manager_tx,
            transaction_manager_tx,
            &metrics_registry,
        ),
        start_main_event_loop(
            &config,
            log.clone(),
            blockchain_state,
            transaction_manager_rx,
            adapter_state,
            blockchain_manager_rx,
            &metrics_registry,
        ),
    ];

    for handle in handles {
        let _ = handle.await; // Waits for each task to complete
    }
}

/// Starts the gRPC server and the router for handling incoming requests.
pub async fn start_server(
    log: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    config: config::Config<AdapterNetwork>,
) {
    match config.network {
        AdapterNetwork::Bitcoin(network) => {
            let btc_config = config.with_network(network);
            start_server_helper(log, metrics_registry, btc_config).await
        }
        AdapterNetwork::Dogecoin(network) => {
            let doge_config = config.with_network(network);
            start_server_helper(log, metrics_registry, doge_config).await
        }
    }
}
