use crate::{
    blockchainmanager::{BlockchainManager, GetSuccessorsRequest, GetSuccessorsResponse},
    connectionmanager::ConnectionManager,
    stream::handle_stream,
    transaction_manager::TransactionManager,
    Config, ProcessEvent, ProcessEventError,
};
use slog::Logger;
use std::{net::SocketAddr, time::Instant};

enum AdapterState {
    Idle,
    ActiveSince(Instant),
}

/// This struct is the overall wrapper around the functionality to communicate with the
/// Bitcoin network and the IC.
pub struct Adapter {
    /// The field stores headers and blocks of the blockchain.
    blockchain_manager: BlockchainManager,
    /// This field is used to contain the ConnectionManager. The manager contains the logic to push messages
    /// to various connections and manage a connection's state.
    connection_manager: ConnectionManager,
    /// This field is used to relay transactions from the replica state to the BTC network.
    transaction_manager: TransactionManager,
    /// This field contains the timestamp when the last RPC call was received from the adapter.
    update_state: AdapterState,
    /// This field contains the how long the adapter should wait to enter the [AdapterState::Idle](AdapterState::Idle) state.
    idle_seconds: u64,
}

impl Adapter {
    /// Constructs a new adapter.
    pub fn new(config: &Config, logger: Logger) -> Self {
        let connection_manager = ConnectionManager::new(config, logger.clone());
        let blockchain_manager = BlockchainManager::new(config, logger.clone());
        let transaction_manager = TransactionManager::new(logger.clone());

        Self {
            blockchain_manager,
            connection_manager,
            transaction_manager,
            update_state: AdapterState::Idle,
            idle_seconds: config.idle_seconds,
        }
    }

    fn disconnect(&mut self, address: SocketAddr) {
        self.connection_manager.discard(address);
    }

    /// Function to called periodically for updating the adapter's state.
    pub fn tick(&mut self) {
        if let AdapterState::ActiveSince(last_received_at) = self.update_state {
            if last_received_at.elapsed().as_secs() > self.idle_seconds {
                self.make_idle();
            }
        }

        if let AdapterState::Idle = self.update_state {
            return;
        }

        if let Some(event) = self.connection_manager.receive_stream_event() {
            if let Err(ProcessEventError::InvalidMessage) =
                self.connection_manager.process_event(&event)
            {
                self.disconnect(event.address);
            }

            if let Err(ProcessEventError::InvalidMessage) =
                self.blockchain_manager.process_event(&event)
            {
                self.disconnect(event.address);
            }

            if let Err(ProcessEventError::InvalidMessage) =
                self.transaction_manager.process_event(&event)
            {
                self.disconnect(event.address);
            }
        }

        // After an event is dispatched, the managers `tick` method is called to process possible
        // outgoing messages.
        self.connection_manager
            .tick(&self.blockchain_manager, handle_stream);
        self.blockchain_manager.tick(&mut self.connection_manager);
        self.transaction_manager.tick(&mut self.connection_manager);
    }

    /// Gets successors from the configured  bitcoin network.
    pub fn get_successors(&mut self, request: GetSuccessorsRequest) -> GetSuccessorsResponse {
        self.received_rpc_call();
        self.blockchain_manager.get_successors(request)
    }

    /// Sends transaction to the configured bitcoin network.
    pub fn send_transaction(&mut self, raw_tx: Vec<u8>) {
        self.received_rpc_call();
        self.transaction_manager.send_transaction(&raw_tx)
    }

    /// Set the state to `Active` with the current timestamp.
    fn received_rpc_call(&mut self) {
        self.update_state = AdapterState::ActiveSince(Instant::now());
    }

    /// When the adapter has not received a RPC call, this method is called.
    /// It does the following:
    /// * Close all connections and empty out the address book
    /// * Clean up the block cache
    /// * Clean up transaction state
    fn make_idle(&mut self) {
        self.update_state = AdapterState::Idle;
        self.connection_manager.make_idle();
        self.blockchain_manager.make_idle();
        self.transaction_manager.make_idle();
    }
}
