//! The module is responsible for awaiting messages from bitcoin peers and dispaching them
//! to the correct component.
use crate::{
    blockchainmanager::BlockchainManager, connectionmanager::ConnectionManager,
    stream::handle_stream, transaction_manager::TransactionManager, AdapterState, Config,
    HasHeight, ProcessEvent, ProcessEventError, TransactionManagerRequest,
};
use ic_logger::ReplicaLogger;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    sync::{mpsc::UnboundedReceiver, Mutex},
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
    blockchain_manager: Arc<Mutex<BlockchainManager>>,
    mut transaction_manager_rx: UnboundedReceiver<TransactionManagerRequest>,
    adapter_state: AdapterState,
) -> JoinHandle<()> {
    let mut transaction_manager = TransactionManager::new(logger.clone());
    let mut connection_manager = ConnectionManager::new(config, logger);

    tokio::task::spawn(async move {
        let mut tick_interval = interval(Duration::from_millis(100));
        loop {
            let sleep_idle_interval = Duration::from_millis(100);
            if adapter_state.is_idle() {
                connection_manager.make_idle();
                blockchain_manager.lock().await.make_idle();
                transaction_manager.make_idle();
                // TODO: instead of sleeping here add some async synchonization.
                sleep(sleep_idle_interval).await;
                continue;
            }

            // We do a select over tokio::sync::mpsc::Receiver::recv, tokio::sync::mpsc::UnboundedReceiver::recv,
            // tokio::time::Interval::tick which are all cancellation safe.
            tokio::select! {
                event = connection_manager.receive_stream_event() => {
                    if let Err(ProcessEventError::InvalidMessage) =
                    connection_manager.process_event(&event)
                {
                    connection_manager.discard(event.address);
                }

                let blockchain_manager_process_event_result =
                    blockchain_manager.lock().await.process_event(&event);
                if let Err(ProcessEventError::InvalidMessage) =
                    blockchain_manager_process_event_result
                {
                    connection_manager.discard(event.address);
                }

                if let Err(ProcessEventError::InvalidMessage) =
                    transaction_manager.process_event(&event)
                {
                    connection_manager.discard(event.address);
                }

                },
                transaction_manager_request = transaction_manager_rx.recv() => {
                    match transaction_manager_request.unwrap() {
                        TransactionManagerRequest::SendTransaction(transaction) => transaction_manager.send_transaction(&transaction),
                    }
                },
                _ = tick_interval.tick() => {
                    // After an event is dispatched, the managers `tick` method is called to process possible
                    // outgoing messages.
                    connection_manager.tick(blockchain_manager.lock().await.get_height(), handle_stream);
                    blockchain_manager
                        .lock()
                        .await
                        .tick(&mut connection_manager);
                    transaction_manager.tick(&mut connection_manager);
                }
            };
        }
    })
}
