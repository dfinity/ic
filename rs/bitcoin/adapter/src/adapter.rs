use crate::{
    blockchainmanager::BlockchainManager,
    connectionmanager::{ConnectionManager, ConnectionManagerError},
    stream::handle_stream,
    transaction_manager::TransactionManager,
    Config, HandleClientRequest, ProcessEvent, ProcessEventError,
};
use bitcoin::{Block, BlockHash};
use slog::{error, Logger};
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("ConnectionManager: {0}")]
    ConnectionManager(ConnectionManagerError),
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
}

impl Adapter {
    /// Constructs a new adapter.
    pub fn new(config: &Config, logger: Logger) -> Result<Self, AdapterError> {
        let connection_manager = ConnectionManager::new(config, logger.clone())
            .map_err(AdapterError::ConnectionManager)?;
        let blockchain_manager = BlockchainManager::new(config, logger.clone());
        let transaction_manager = TransactionManager::new(logger.clone());

        Ok(Self {
            blockchain_manager,
            connection_manager,
            transaction_manager,
        })
    }

    fn disconnect(&mut self, address: SocketAddr) {
        self.connection_manager.discard(address);
    }

    /// Function to called periodically for updating the adapter's state.
    pub fn tick(&mut self) {
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
        self.connection_manager.tick(handle_stream);
        self.blockchain_manager.tick(&mut self.connection_manager);
        self.transaction_manager.tick(&mut self.connection_manager);
    }

    /// Gets successors from the configured  bitcoin network.
    pub fn get_successors(&mut self, block_hashes: Vec<BlockHash>) -> Vec<Block> {
        self.blockchain_manager.handle_client_request(block_hashes)
    }

    /// Sends transaction to the configured bitcoin network.
    pub fn send_transaction(&mut self, raw_tx: Vec<u8>) {
        self.transaction_manager.send_transaction(&raw_tx)
    }
}
