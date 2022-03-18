#![warn(missing_docs)]

//! The Bitcoin adapter interacts with the Bitcoin P2P network to obtain blocks
//! and publish transactions. Moreover, it interacts with the Bitcoin system
//! component to provide blocks and collect outgoing transactions.

use bitcoin::network::message::NetworkMessage;
use parking_lot::RwLock;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
/// This module contains the main adapter code that controls the interactions of
/// the other modules.
mod adapter;
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
mod config;
/// This module contains code that is used to manage a single connection to a
/// BTC node.
mod connection;
/// This module contains code that is used to manage multiple connections to
/// BTC nodes.
mod connectionmanager;
/// This module contains code that is used to handle interactions to connected
/// BTC streams (SOCKS and TCP).
mod rpc_server;
mod stream;
mod transaction_manager;

mod cli;

pub use adapter::Adapter;
pub use blockchainmanager::BlockchainManager;
pub use cli::Cli;
use common::BlockHeight;
pub use config::{Config, IncomingSource};
pub use rpc_server::spawn_grpc_server;
use stream::StreamEvent;
pub use transaction_manager::TransactionManager;

/// This struct is used to represent commands given to the adapter in order to interact
/// with BTC nodes.
#[derive(Debug, Clone)]
pub struct Command {
    /// This is the address of the Bitcoin node to which the message is supposed to be sent.
    /// If the address is None, then the message will be sent to all the peers.
    address: Option<SocketAddr>,
    /// This the network message to be sent to the above peer.
    message: NetworkMessage,
}

/// This enum is used to represent errors that could occur while dispatching an
/// event.
#[derive(Debug)]
pub enum ProcessEventError {
    /// This variant is used to represent when an invalid message has been
    /// received from a Bitcoin node.
    InvalidMessage,
}

/// This enum is used to represent errors that  
pub enum ChannelError {
    /// This variant is used to indicate that the send failed to push
    /// the outgoing message to the BTC node.
    NotAvailable,
}

/// This trait is to provide an interface so that ti
pub trait Channel {
    /// This method is used to send a message to a specific connection
    /// or to all connections based on the [Command](Command)'s fields.
    fn send(&mut self, command: Command) -> Result<(), ChannelError>;

    /// This method is used to retrieve a list of available connections
    /// that have completed the version handshake.
    fn available_connections(&self) -> Vec<SocketAddr>;
}

/// This trait provides an interface to anything that may need to react to a
/// [StreamEvent](crate::stream::StreamEvent).
pub trait ProcessEvent {
    /// This method is used to route an event in a component's internals and
    /// perform state updates.
    fn process_event(&mut self, event: &StreamEvent) -> Result<(), ProcessEventError>;
}

/// This trait provides an interface to anything that may need to get the
/// active tip's height.
pub trait HasHeight {
    /// This function returns the active tip's height.
    fn get_height(&self) -> BlockHeight;
}

/// The type tracks when then adapter should become idle. The type is
/// thread-safe.
#[derive(Clone)]
pub struct AdapterState {
    /// The field contains instant of the latest received request.
    last_received_at: Arc<RwLock<Instant>>,
    /// The field contains how long the adapter should wait to before becoming idle.
    idle_seconds: u64,
}

impl AdapterState {
    /// Crates new instance of the AdapterState.
    pub fn new(idle_seconds: u64) -> Self {
        Self {
            // On purpose we pick such time so we are idle when created.
            last_received_at: Arc::new(RwLock::new(
                Instant::now() - Duration::from_secs(idle_seconds + 1),
            )),
            idle_seconds,
        }
    }

    /// Returns if the adapter is idle.
    pub fn is_idle(&self) -> bool {
        self.last_received_at.read().elapsed().as_secs() > self.idle_seconds
    }

    /// Updates the current state of the adapter given a request was received.
    pub fn received_now(&self) {
        // Instant::now() is monotonically nondecreasing clock.
        *self.last_received_at.write() = Instant::now();
    }
}
