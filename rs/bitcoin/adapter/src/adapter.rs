use std::{net::SocketAddr, time::Duration};

use slog::Logger;
use thiserror::Error;

use crate::{
    blockchainmanager::BlockchainManager,
    connectionmanager::{ConnectionManager, ConnectionManagerError},
    rpc_server::spawn_grpc_server,
    stream::handle_stream,
    transaction_manager::TransactionManager,
    Config, ProcessEvent, ProcessEventError,
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("ConnectionManager: {0}")]
    ConnectionManager(ConnectionManagerError),
}

/// This struct is the overall wrapper around the functionality to communicate with the
/// Bitcoin network and the IC.
pub struct Adapter {
    /// The field stores headers and blocks of the blockchain.
    blockchain_manager: Arc<Mutex<BlockchainManager>>,
    /// This field is used to contain the ConnectionManager. The manager contains the logic to push messages
    /// to various connections and manage a connection's state.
    connection_manager: ConnectionManager,
    /// This field is used to relay transactions from the replica state to the BTC network.
    transaction_manager: Arc<Mutex<TransactionManager>>,
}

pub type AdapterResult<T> = Result<T, AdapterError>;

impl Adapter {
    /// This function initializes the network.
    pub fn new(config: &Config, logger: Logger) -> AdapterResult<Self> {
        let connection_manager = ConnectionManager::new(config, logger.clone())
            .map_err(AdapterError::ConnectionManager)?;
        let blockchain_manager =
            Arc::new(Mutex::new(BlockchainManager::new(config, logger.clone())));
        let transaction_manager = Arc::new(Mutex::new(TransactionManager::new(logger.clone())));

        spawn_grpc_server(
            Arc::clone(&blockchain_manager),
            Arc::clone(&transaction_manager),
        );

        Ok(Self {
            blockchain_manager,
            connection_manager,
            transaction_manager,
        })
    }

    /// This function is the main entry point when dealing with the network.
    /// It directs the pool in operation and pushes messages out to clients.
    pub fn run(&mut self) {
        loop {
            self.tick();
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn disconnect(&mut self, address: SocketAddr) {
        self.connection_manager.discard(address);
    }

    ///The main tick loop of the Adapter.
    fn tick(&mut self) {
        let blockchain_manager = Arc::clone(&self.blockchain_manager);
        let transaction_manager = Arc::clone(&self.transaction_manager);
        let mut blockchain_manager_guard = blockchain_manager.lock().unwrap();
        let mut transaction_manager_guard = transaction_manager.lock().unwrap();
        if let Some(event) = self.connection_manager.receive_stream_event() {
            if let Err(ProcessEventError::InvalidMessage) =
                self.connection_manager.process_event(&event)
            {
                self.disconnect(event.address);
            }

            if let Err(ProcessEventError::InvalidMessage) =
                blockchain_manager_guard.process_event(&event)
            {
                self.disconnect(event.address);
            }

            if let Err(ProcessEventError::InvalidMessage) =
                transaction_manager_guard.process_event(&event)
            {
                self.disconnect(event.address);
            }
        }

        // After an event is dispatched, the managers `tick` method is called to process possible
        // outgoing messages.
        self.connection_manager.tick(handle_stream);
        blockchain_manager_guard.tick(&mut self.connection_manager);
        transaction_manager_guard.tick(&mut self.connection_manager);
    }
}
