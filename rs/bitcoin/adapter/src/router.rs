//! The module is responsible for awaiting messages from bitcoin peers and dispaching them
//! to the correct component.
use crate::{
    blockchainmanager::BlockchainManager, connectionmanager::ConnectionManager,
    stream::handle_stream, transaction_manager::TransactionManager, AdapterState, Config,
    HasHeight, ProcessEvent, ProcessEventError,
};
use ic_logger::ReplicaLogger;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    sync::Mutex,
    time::{sleep, timeout},
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
    transaction_manager: Arc<Mutex<TransactionManager>>,
    adapter_state: AdapterState,
) {
    let mut connection_manager = ConnectionManager::new(config, logger);

    tokio::task::spawn(async move {
        loop {
            let interval = Duration::from_millis(100);
            if adapter_state.is_idle() {
                connection_manager.make_idle();
                blockchain_manager.lock().await.make_idle();
                transaction_manager.lock().await.make_idle();
                // TODO: instead of sleeping here add some async synchonization.
                sleep(interval).await;
                continue;
            }

            // in case we waited too long start the loop from the beggining because we the adapter
            // may be idle
            if let Ok(event) = timeout(interval, connection_manager.receive_stream_event()).await {
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

                let transaction_manager_process_event_result =
                    transaction_manager.lock().await.process_event(&event);
                if let Err(ProcessEventError::InvalidMessage) =
                    transaction_manager_process_event_result
                {
                    connection_manager.discard(event.address);
                }
            }
            // After an event is dispatched, the managers `tick` method is called to process possible
            // outgoing messages.
            connection_manager.tick(blockchain_manager.lock().await.get_height(), handle_stream);
            blockchain_manager
                .lock()
                .await
                .tick(&mut connection_manager);
            transaction_manager
                .lock()
                .await
                .tick(&mut connection_manager);
        }
    });
}
