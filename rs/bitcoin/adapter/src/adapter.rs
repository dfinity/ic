use crate::{
    blockchainmanager::BlockchainManager, connectionmanager::ConnectionManager,
    stream::handle_stream, transaction_manager::TransactionManager, AdapterState, Config,
    HasHeight, ProcessEvent, ProcessEventError,
};
use ic_logger::ReplicaLogger;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

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
    /// This field contains the timestamp when the last RPC call was received from the adapter.
    adapter_state: AdapterState,
}

impl Adapter {
    /// Constructs a new adapter.
    pub fn new(
        config: &Config,
        logger: ReplicaLogger,
        blockchain_manager: Arc<Mutex<BlockchainManager>>,
        transaction_manager: Arc<Mutex<TransactionManager>>,
        adapter_state: AdapterState,
    ) -> Self {
        let connection_manager = ConnectionManager::new(config, logger);

        Self {
            blockchain_manager,
            connection_manager,
            transaction_manager,
            adapter_state,
        }
    }

    fn disconnect(&mut self, address: SocketAddr) {
        self.connection_manager.discard(address);
    }

    /// Function to called periodically for updating the adapter's state.
    pub async fn tick(&mut self) {
        if self.adapter_state.is_idle() {
            self.make_idle().await;
            return;
        }

        if let Some(event) = self.connection_manager.receive_stream_event() {
            if let Err(ProcessEventError::InvalidMessage) =
                self.connection_manager.process_event(&event)
            {
                self.disconnect(event.address);
            }

            let blockchain_manager_process_event_result =
                self.blockchain_manager.lock().await.process_event(&event);
            if let Err(ProcessEventError::InvalidMessage) = blockchain_manager_process_event_result
            {
                self.disconnect(event.address);
            }
            let transaction_manager_process_event_result =
                self.transaction_manager.lock().await.process_event(&event);
            if let Err(ProcessEventError::InvalidMessage) = transaction_manager_process_event_result
            {
                self.disconnect(event.address);
            }
        }

        // After an event is dispatched, the managers `tick` method is called to process possible
        // outgoing messages.
        self.connection_manager.tick(
            self.blockchain_manager.lock().await.get_height(),
            handle_stream,
        );
        self.blockchain_manager
            .lock()
            .await
            .tick(&mut self.connection_manager);
        self.transaction_manager
            .lock()
            .await
            .tick(&mut self.connection_manager);
    }

    /// When the adapter has not received a RPC call, this method is called.
    /// It does the following:
    /// * Close all connections and empty out the address book
    /// * Clean up the block cache
    /// * Clean up transaction state
    async fn make_idle(&mut self) {
        self.connection_manager.make_idle();
        self.blockchain_manager.lock().await.make_idle();
        self.transaction_manager.lock().await.make_idle();
    }
}
