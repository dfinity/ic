//! The module is responsible for awaiting messages from bitcoin peers and dispaching them
//! to the correct component.
use crate::{
    blockchainmanager::BlockchainManager, common::DEFAULT_CHANNEL_BUFFER_SIZE,
    connectionmanager::ConnectionManager, stream::handle_stream,
    transaction_manager::TransactionManager, AdapterState, BlockchainManagerRequest,
    BlockchainState, Config, ProcessBitcoinNetworkMessage, ProcessBitcoinNetworkMessageError,
    ProcessEvent, TransactionManagerRequest,
};
use bitcoin::network::message::NetworkMessage;
use ic_logger::ReplicaLogger;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    sync::{
        mpsc::UnboundedReceiver,
        mpsc::{channel, Receiver},
        Mutex,
    },
    task::JoinHandle,
    time::{interval, sleep},
};

/// The function starts a Tokio task that awaits messages from the ConnectionManager.
/// After receiving a message, it is dispached to _all_ relevant components for processing.
/// Having a design where we have a separate task that awaits on messages from the
/// ConnectionManager, we keep the ConnectionManager free of dependencies like the
/// TransactionManager or the BlockchainManager.
pub fn start_router(
    config: &Config,
    logger: ReplicaLogger,
    blockchain_state: Arc<Mutex<BlockchainState>>,
    mut transaction_manager_rx: UnboundedReceiver<TransactionManagerRequest>,
    adapter_state: AdapterState,
    mut blockchain_manager_rx: Receiver<BlockchainManagerRequest>,
) -> JoinHandle<()> {
    let (network_message_sender, mut network_message_receiver) =
        channel::<(SocketAddr, NetworkMessage)>(DEFAULT_CHANNEL_BUFFER_SIZE);

    let mut blockchain_manager = BlockchainManager::new(blockchain_state, logger.clone());
    let mut transaction_manager = TransactionManager::new(logger.clone());
    let mut connection_manager = ConnectionManager::new(config, logger, network_message_sender);

    tokio::task::spawn(async move {
        let mut tick_interval = interval(Duration::from_millis(100));
        loop {
            let sleep_idle_interval = Duration::from_millis(100);
            if adapter_state.is_idle() {
                connection_manager.make_idle();
                blockchain_manager.make_idle().await;
                transaction_manager.make_idle();
                // TODO: instead of sleeping here add some async synchonization.
                sleep(sleep_idle_interval).await;
                continue;
            }

            // We do a select over tokio::sync::mpsc::Receiver::recv, tokio::sync::mpsc::UnboundedReceiver::recv,
            // tokio::time::Interval::tick which are all cancellation safe.
            tokio::select! {
                event = connection_manager.receive_stream_event() => {
                    if let Err(ProcessBitcoinNetworkMessageError::InvalidMessage) =
                        connection_manager.process_event(&event)
                    {
                        connection_manager.discard(event.address);
                    }
                },
                network_message = network_message_receiver.recv() => {
                    let (address, message) = network_message.unwrap();
                    if let Err(ProcessBitcoinNetworkMessageError::InvalidMessage) =
                        connection_manager.process_bitcoin_network_message(address, &message) {
                        connection_manager.discard(address);
                    }

                    if let Err(ProcessBitcoinNetworkMessageError::InvalidMessage) = blockchain_manager.process_bitcoin_network_message(&mut connection_manager, address, &message).await {
                        connection_manager.discard(address);
                    }
                    if let Err(ProcessBitcoinNetworkMessageError::InvalidMessage) = transaction_manager.process_bitcoin_network_message(&mut connection_manager, address, &message) {
                        connection_manager.discard(address);
                    }
                },
                result = blockchain_manager_rx.recv() => {
                    let command = result.expect("Receiving should not fail because the sender part of the channel is never closed.");
                    match command {
                        BlockchainManagerRequest::EnqueueNewBlocksToDownload(next_headers) => {
                            blockchain_manager.enqueue_new_blocks_to_download(next_headers).await;
                        }
                        BlockchainManagerRequest::PruneOldBlocks(processed_block_hashes) => {
                            blockchain_manager.prune_old_blocks(&processed_block_hashes).await;
                        }
                    };
                }
                transaction_manager_request = transaction_manager_rx.recv() => {
                    match transaction_manager_request.unwrap() {
                        TransactionManagerRequest::SendTransaction(transaction) => transaction_manager.send_transaction(&transaction),
                    }
                },
                _ = tick_interval.tick() => {
                    // After an event is dispatched, the managers `tick` method is called to process possible
                    // outgoing messages.
                    connection_manager.tick(blockchain_manager.get_height().await, handle_stream);
                    blockchain_manager
                        .tick(&mut connection_manager).await;
                    transaction_manager.tick(&mut connection_manager);
                }
            };
        }
    })
}
