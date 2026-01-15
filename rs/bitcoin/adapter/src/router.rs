//! The module is responsible for awaiting messages from bitcoin peers and dispaching them
//! to the correct component.
use crate::{
    AdapterState, BlockchainManagerRequest, BlockchainState, Channel, ProcessEvent,
    ProcessNetworkMessage, ProcessNetworkMessageError, TransactionManagerRequest,
    blockchainmanager::BlockchainManager,
    common::{BlockchainNetwork, DEFAULT_CHANNEL_BUFFER_SIZE, HeaderValidator},
    config::Config,
    connectionmanager::ConnectionManager,
    metrics::RouterMetrics,
    stream::handle_stream,
    transaction_store::TransactionStore,
};
use bitcoin::p2p::message::NetworkMessage;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    sync::mpsc::{Receiver, channel},
    time::interval,
};

/// The function starts a Tokio task that awaits messages from the ConnectionManager.
/// After receiving a message, it is dispatched to _all_ relevant components for processing.
/// Having a design where we have a separate task that awaits on messages from the
/// ConnectionManager, we keep the ConnectionManager free of dependencies like the
/// TransactionStore or the BlockchainManager.
pub fn start_main_event_loop<Network>(
    config: &Config<Network>,
    logger: ReplicaLogger,
    blockchain_state: Arc<BlockchainState<Network>>,
    mut transaction_manager_rx: Receiver<TransactionManagerRequest>,
    mut adapter_state: AdapterState,
    mut blockchain_manager_rx: Receiver<BlockchainManagerRequest>,
    metrics_registry: &MetricsRegistry,
) -> tokio::task::JoinHandle<()>
where
    Network: BlockchainNetwork + Send + Sync + 'static,
    Network::Header: Send,
    Network::Block: Send + Sync,
    BlockchainState<Network>: HeaderValidator<Network>,
    <BlockchainState<Network> as HeaderValidator<Network>>::HeaderError: Send + Sync,
{
    let (network_message_sender, mut network_message_receiver) = channel::<(
        SocketAddr,
        NetworkMessage<Network::Header, Network::Block>,
    )>(DEFAULT_CHANNEL_BUFFER_SIZE);

    let router_metrics = RouterMetrics::new(metrics_registry);

    let mut blockchain_manager = BlockchainManager::new(
        blockchain_state,
        config.request_timeout(),
        logger.clone(),
        router_metrics.clone(),
    );
    let mut transaction_manager = TransactionStore::new(logger.clone(), metrics_registry);
    let mut connection_manager = ConnectionManager::new(
        config,
        logger,
        network_message_sender,
        router_metrics.clone(),
    );

    tokio::task::spawn(async move {
        let mut tick_interval = interval(Duration::from_millis(100));

        loop {
            if adapter_state.is_idle() {
                connection_manager.make_idle();
                blockchain_manager.make_idle();
                adapter_state.active().await;
            }

            // We do a select over tokio::sync::mpsc::Receiver::recv, tokio::sync::mpsc::UnboundedReceiver::recv,
            // tokio::time::Interval::tick which are all cancellation safe.
            tokio::select! {
                event = connection_manager.receive_stream_event() => {
                    if let Err(ProcessNetworkMessageError::InvalidMessage) =
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
                    if let Err(ProcessNetworkMessageError::InvalidMessage) =
                        connection_manager.process_bitcoin_network_message(address, &message) {
                        connection_manager.discard(&address);
                    }

                    if let Err(ProcessNetworkMessageError::InvalidMessage) = blockchain_manager.process_bitcoin_network_message(&mut connection_manager, address, &message).await {
                        connection_manager.discard(&address);
                    }
                    if let Err(ProcessNetworkMessageError::InvalidMessage) = transaction_manager.process_bitcoin_network_message(&mut connection_manager, address, &message) {
                        connection_manager.discard(&address);
                    }
                },
                result = blockchain_manager_rx.recv() => {
                    let command = result.expect("Receiving should not fail because the sender part of the channel is never closed.");
                    match command {
                        BlockchainManagerRequest::EnqueueNewBlocksToDownload(next_headers) => {
                            blockchain_manager.enqueue_new_blocks_to_download(next_headers);
                        }
                        BlockchainManagerRequest::PruneBlocks(anchor, processed_block_hashes) => {
                            blockchain_manager.prune_blocks(anchor, processed_block_hashes);
                        }
                    };
                }
                transaction_manager_request = transaction_manager_rx.recv() => {
                    match transaction_manager_request.unwrap() {
                        TransactionManagerRequest::SendTransaction(transaction) => transaction_manager.enqueue_transaction(&transaction),
                    }
                },
                _ = tick_interval.tick() => {
                    // After an event is dispatched, the managers `tick` method is called to process possible
                    // outgoing messages.
                    connection_manager.tick(blockchain_manager.get_height(), handle_stream).await;
                    blockchain_manager.tick(&mut connection_manager);
                    transaction_manager.advertise_txids(&mut connection_manager);
                }
            };
        }
    })
}
