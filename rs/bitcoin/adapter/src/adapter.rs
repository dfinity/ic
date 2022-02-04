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
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedSender},
    oneshot,
};

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

pub type AdapterResult<T> = Result<T, AdapterError>;
/// Possible messages that drive the adapter event handler loop.
#[derive(Debug)]
pub enum AdapterRequest {
    /// Periodic tick request
    Tick,
    /// GetSuccessors request coming from the gRPC server
    GetSuccessors(Vec<BlockHash>),
    /// SendTransaction request coming from the gRPC server
    SendTransaction(Vec<u8>),
}

/// Response type send back from the adapater event look back to the
/// caller.
#[derive(Debug)]
pub enum AdapterResponse {
    /// Response in case of a Tick request.
    Tick,
    /// Response in case of a GetSuccessors request.
    GetSuccessors(Vec<Block>),
    /// Response in case of a SendTransaction request.
    SendTransaction,
}

/// Messages passed to the event loop channel are tuples of AdapterRequest and oneshot
/// sender to be used as callback mechanism to the caller.
pub type AdapterRequestWithCallback = (AdapterRequest, oneshot::Sender<AdapterResponse>);

/// The function crates an Adapter instance and starts the its event loop that receives events over a channel. The returned sender is
/// the entry point for sending events to the adapter.
pub fn spawn_adapter(
    config: &Config,
    logger: Logger,
) -> AdapterResult<UnboundedSender<AdapterRequestWithCallback>> {
    let connection_manager =
        ConnectionManager::new(config, logger.clone()).map_err(AdapterError::ConnectionManager)?;
    let blockchain_manager = BlockchainManager::new(config, logger.clone());
    let transaction_manager = TransactionManager::new(logger.clone());

    let mut adapter = Adapter {
        blockchain_manager,
        connection_manager,
        transaction_manager,
    };

    let (tx, mut rx) = unbounded_channel::<AdapterRequestWithCallback>();
    tokio::task::spawn(async move {
        // the loop will exit iff all senders are dropped
        while let Some((req, sender)) = rx.recv().await {
            match req {
                AdapterRequest::Tick => {
                    adapter.tick();
                    sender.send(AdapterResponse::Tick)
                }
                AdapterRequest::GetSuccessors(block_hashes) => sender.send(
                    AdapterResponse::GetSuccessors(adapter.get_successors(block_hashes)),
                ),
                AdapterRequest::SendTransaction(transaction) => {
                    adapter.send_transaction(transaction);
                    sender.send(AdapterResponse::SendTransaction)
                }
            }
            .unwrap_or_else(|e| {
                error!(logger, "failed to process request: {:?}", e);
            });
        }
    });
    Ok(tx)
}

impl Adapter {
    fn disconnect(&mut self, address: SocketAddr) {
        self.connection_manager.discard(address);
    }

    ///The main tick loop of the Adapter.
    fn tick(&mut self) {
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

    fn get_successors(&mut self, block_hashes: Vec<BlockHash>) -> Vec<Block> {
        self.blockchain_manager.handle_client_request(block_hashes)
    }

    fn send_transaction(&mut self, raw_tx: Vec<u8>) {
        self.transaction_manager.send_transaction(&raw_tx)
    }
}
