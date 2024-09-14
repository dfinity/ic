//! The module is responsible for awaiting messages from bitcoin peers and dispaching them
//! to the correct component.
use crate::{
    blockchainmanager::BlockchainManager, common::DEFAULT_CHANNEL_BUFFER_SIZE, config::Config,
    connectionmanager::ConnectionManager, metrics::RouterMetrics, stream::handle_stream,
    transaction_store::TransactionStore, AdapterState, BlockchainManagerRequest, BlockchainState,
    Channel, ProcessBitcoinNetworkMessage, ProcessBitcoinNetworkMessageError, ProcessEvent,
    TransactionManagerRequest,
};
use bitcoin::network::message::NetworkMessage;
use ic_logger::{error, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    sync::{
        mpsc::{channel, Receiver},
        Mutex,
    },
    time::{interval, sleep},
};

/// The function starts a Tokio task that awaits messages from the ConnectionManager.
/// After receiving a message, it is dispatched to _all_ relevant components for processing.
/// Having a design where we have a separate task that awaits on messages from the
/// ConnectionManager, we keep the ConnectionManager free of dependencies like the
/// TransactionStore or the BlockchainManager.
pub fn start_main_event_loop(
    config: &Config,
    logger: ReplicaLogger,
    blockchain_state: Arc<Mutex<BlockchainState>>,
    mut transaction_manager_rx: Receiver<TransactionManagerRequest>,
    adapter_state: AdapterState,
    mut blockchain_manager_rx: Receiver<BlockchainManagerRequest>,
    metrics_registry: &MetricsRegistry,
) {
    let (network_message_sender, mut network_message_receiver) =
        channel::<(SocketAddr, NetworkMessage)>(DEFAULT_CHANNEL_BUFFER_SIZE);

    let router_metrics = RouterMetrics::new(metrics_registry);

    let mut blockchain_manager =
        BlockchainManager::new(blockchain_state, logger.clone(), router_metrics.clone());
    let mut transaction_manager = TransactionStore::new(logger.clone(), metrics_registry);
    let mut connection_manager = ConnectionManager::new(
        config,
        logger.clone(),
        network_message_sender,
        router_metrics.clone(),
    );

    tokio::task::spawn(async move {
        let mut tick_interval = interval(Duration::from_millis(100));
        loop {
            let sleep_idle_interval = Duration::from_millis(100);
            if adapter_state.is_idle() {
                connection_manager.make_idle();
                blockchain_manager.make_idle().await;
                // TODO: instead of sleeping here add some async synchronization.
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
                        connection_manager.discard(&event.address);
                    }
                },
                network_message = network_message_receiver.recv() => {
                    let (address, message) = network_message.unwrap();
                    router_metrics
                        .bitcoin_messages_received
                        .with_label_values(&[message.cmd()])
                        .inc();
                    if let Err(ProcessBitcoinNetworkMessageError::InvalidMessage) =
                        connection_manager.process_bitcoin_network_message(address, &message) {
                        connection_manager.discard(&address);
                    }

                    if let Err(ProcessBitcoinNetworkMessageError::InvalidMessage) = blockchain_manager.process_bitcoin_network_message(&mut connection_manager, address, &message).await {
                        connection_manager.discard(&address);
                    }
                    if let Err(ProcessBitcoinNetworkMessageError::InvalidMessage) = transaction_manager.process_bitcoin_network_message(&mut connection_manager, address, &message) {
                        connection_manager.discard(&address);
                    }
                },
                result = blockchain_manager_rx.recv() => {
                    if let Some(command) = result {
                        match command {
                            BlockchainManagerRequest::EnqueueNewBlocksToDownload(next_headers) => {
                                blockchain_manager.enqueue_new_blocks_to_download(next_headers).await;
                            }
                            BlockchainManagerRequest::PruneBlocks(anchor, processed_block_hashes) => {
                                blockchain_manager.prune_blocks(anchor, processed_block_hashes).await;
                            }
                        };
                    } else {
                        error!(logger, "Receiving should not fail because the sender part of the channel is never closed.");
                    }
                }
                transaction_manager_request = transaction_manager_rx.recv() => {
                    match transaction_manager_request {
                        Some(TransactionManagerRequest::SendTransaction(transaction)) => transaction_manager.enqueue_transaction(&transaction),
                        None => error!(logger, "Receiving should not fail because the sender part of the channel is never closed."),
                    }
                },
                _ = tick_interval.tick() => {
                    // After an event is dispatched, the managers `tick` method is called to process possible
                    // outgoing messages.
                    connection_manager.tick(blockchain_manager.get_height().await, handle_stream);
                    blockchain_manager
                        .tick(&mut connection_manager).await;
                    transaction_manager.advertise_txids(&mut connection_manager);
                }
            };
        }
    });
}
