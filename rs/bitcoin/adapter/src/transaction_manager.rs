use std::collections::VecDeque;
use std::net::SocketAddr;
use std::{collections::HashMap, time::Duration, time::SystemTime};

use bitcoin::consensus::deserialize;
use bitcoin::{
    blockdata::transaction::Transaction, hash_types::Txid, network::message::NetworkMessage,
    network::message_blockdata::Inventory,
};
use slog::Logger;

use crate::{stream::StreamEvent, stream::StreamEventKind, Channel, Command};
use crate::{ProcessEvent, ProcessEventError};

/// How often the cached transactions' IDs are broadcasted to peers.
const TX_ADVERTISE_INTERVAL: u64 = 2 * 60; // 2 minutes

/// How long should the transaction manager hold on to a transaction.
const TX_CACHE_TIMEOUT_PERIOD_SECS: u64 = 10 * 60; // 10 minutes

/// This struct represents the current information to track the
/// broadcasting of a transaction.
#[derive(Debug)]
struct TransactionInfo {
    /// The actual transaction to be sent to the BTC network.
    transaction: Transaction,
    /// This field represents the time that the transaction was last broadcasted out to peers.
    last_advertised_at: Option<SystemTime>,
    /// How long the transaction should be held on to.
    timeout_at: SystemTime,
}

impl TransactionInfo {
    /// This function is used to instantiate a [TransactionInfo](TransactionInfo) struct.
    fn new(transaction: &Transaction) -> Self {
        Self {
            transaction: transaction.clone(),
            last_advertised_at: None,
            timeout_at: SystemTime::now() + Duration::from_secs(TX_CACHE_TIMEOUT_PERIOD_SECS),
        }
    }

    /// This function is used to determine when the next broadcast should be.
    /// Defaults to the UNIX epoch if the transaction has not been broadcast before.
    fn next_advertisement_at(&self) -> SystemTime {
        match self.last_advertised_at {
            Some(last_broadcast_at) => {
                last_broadcast_at + Duration::from_secs(TX_ADVERTISE_INTERVAL)
            }
            None => SystemTime::UNIX_EPOCH,
        }
    }
}

/// This struct stores the list of transactions submitted by the system component.
#[derive(Debug)]
pub struct TransactionManager {
    /// This field contains a logger for the transaction manager to
    logger: Logger,
    /// This field contains the transactions being tracked by the manager.
    transactions: HashMap<Txid, TransactionInfo>,
    /// This field holds a queue for outgoing commands.
    outgoing_command_queue: VecDeque<Command>,
}

impl TransactionManager {
    /// This function creates a new transaction manager.
    pub fn new(logger: Logger) -> Self {
        TransactionManager {
            logger,
            transactions: HashMap::new(),
            outgoing_command_queue: VecDeque::new(),
        }
    }

    /// This function processes a `getdata` message from a BTC node.
    /// If there are messages for transactions, the transaction queues up outgoing messages
    /// to be processed later.
    fn process_getdata_message(&mut self, address: &SocketAddr, inventory: &[Inventory]) {
        for inv in inventory {
            if let Inventory::Transaction(txid) = inv {
                if let Some(info) = self.transactions.get(txid) {
                    self.outgoing_command_queue.push_back(Command {
                        address: Some(*address),
                        message: NetworkMessage::Tx(info.transaction.clone()),
                    });
                }
            }
        }
    }

    /// This heartbeat method is called periodically by the adapter.
    /// This method is used to send messages to Bitcoin peers.
    pub fn tick(&mut self, channel: &mut impl Channel) {
        self.advertise_txids(channel);
        self.process_outgoing_commands(channel);
        self.reap();
    }

    /// This method is used to send a single transaction.
    /// If the transaction is not known, the transaction is added the the transactions map.
    pub fn send_transaction(&mut self, raw_tx: &[u8]) {
        if let Ok(transaction) = deserialize::<Transaction>(raw_tx) {
            let txid = transaction.txid();
            slog::debug!(self.logger, "Received {} from the system component", txid);
            self.transactions
                .entry(txid)
                .or_insert_with(|| TransactionInfo::new(&transaction));
        }
    }

    /// This method is used when the adapter is no longer receiving RPC calls from the replica.
    /// Clears all transactions the adapter is currently caching.
    pub fn make_idle(&mut self) {
        self.transactions.clear();
        self.outgoing_command_queue.clear();
    }

    /// Clear out transactions that have been held on to for more than the transaction timeout period.
    fn reap(&mut self) {
        slog::debug!(self.logger, "Reaping old transactions");
        let now = SystemTime::now();
        self.transactions.retain(|_, info| info.timeout_at > now);
    }

    /// This method is used to broadcast known transaction IDs to connected peers.
    /// If the timeout period has passed for a transaction ID, it is broadcasted again.
    /// If the transaction has not been broadcasted, the transaction ID is broadcasted.
    fn advertise_txids(&mut self, channel: &mut impl Channel) {
        let now = SystemTime::now();
        let mut inventory = vec![];
        for (txid, info) in self.transactions.iter_mut() {
            if info.next_advertisement_at() <= now {
                inventory.push(Inventory::Transaction(*txid));
                info.last_advertised_at = Some(now);
            }
        }

        if inventory.is_empty() {
            return;
        }

        slog::debug!(self.logger, "Broadcasting Txids ({:?}) to peers", inventory);

        channel
            .send(Command {
                address: None,
                message: NetworkMessage::Inv(inventory),
            })
            .ok();
    }

    /// This method is used to send outgoing messages built up in the queue.
    fn process_outgoing_commands(&mut self, channel: &mut impl Channel) {
        while let Some(command) = self.outgoing_command_queue.pop_front() {
            channel.send(command).ok();
        }
    }
}

impl ProcessEvent for TransactionManager {
    /// This method is used to process an event from the connected BTC nodes.
    fn process_event(&mut self, event: &StreamEvent) -> Result<(), ProcessEventError> {
        if let StreamEventKind::Message(NetworkMessage::GetData(inventory)) = &event.kind {
            self.process_getdata_message(&event.address, inventory);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::{
        blockdata::constants::genesis_block, consensus::serialize, Network, Transaction,
    };

    use crate::{common::test_common::make_logger, Channel, ChannelError, Command};

    use super::*;

    /// This struct is used to capture Commands generated by the [TransactionManager](TransactionManager).
    struct TestChannel {
        /// This field holds Commands that are generated by the [TransactionManager](TransactionManager).
        received_commands: VecDeque<Command>,
    }

    impl TestChannel {
        fn new() -> Self {
            Self {
                received_commands: VecDeque::new(),
            }
        }
    }

    impl Channel for TestChannel {
        fn send(&mut self, command: Command) -> Result<(), ChannelError> {
            self.received_commands.push_back(command);
            Ok(())
        }

        fn available_connections(&self) -> Vec<std::net::SocketAddr> {
            vec![]
        }
    }

    /// This function creates a new transaction manager with a test logger.
    fn make_transaction_manager() -> TransactionManager {
        TransactionManager::new(make_logger())
    }

    /// This function pulls a transaction out of the `regtest` genesis block.
    fn get_transaction() -> Transaction {
        let block = genesis_block(Network::Regtest);
        block
            .txdata
            .first()
            .cloned()
            .expect("There should be a transaction here.")
    }

    /// This function tests the `TransactionManager::reap(...)` method.
    /// Test Steps:
    /// 1. Receive a transaction
    /// 2. Attempt to reap the transaction that was just received.
    /// 3. Update the TransactionManager's `last_received_transactions_at` field to a timestamp
    ///    in the future.
    /// 4. Attempt to reap transactions again.
    #[test]
    fn test_reap() {
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        manager.send_transaction(&raw_tx);
        assert_eq!(manager.transactions.len(), 1);
        manager.reap();
        assert_eq!(manager.transactions.len(), 1);

        let info = manager
            .transactions
            .get_mut(&transaction.txid())
            .expect("transaction should be map");
        info.timeout_at = SystemTime::now() - Duration::from_secs(TX_CACHE_TIMEOUT_PERIOD_SECS);
        manager.reap();
        assert_eq!(manager.transactions.len(), 0);
    }

    /// This function tests the `TransactionManager::broadcast_txids(...)` method.
    /// Test Steps:
    /// 1. Receive a transaction
    /// 2. Perform an initial broadcast.
    /// 3. Attempt to re-broadcast.
    /// 4. Update the transaction's `last_broadcast_at` field so it may be re-broadcast.
    /// 5. Attempt to re-broadcast.
    #[test]
    fn test_broadcast_txids() {
        let mut channel = TestChannel::new();
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        let txid = transaction.txid();
        manager.send_transaction(&raw_tx);
        assert_eq!(manager.transactions.len(), 1);
        let info = manager
            .transactions
            .get(&transaction.txid())
            .expect("transaction should be map");
        assert!(info.last_advertised_at.is_none());
        // Initial broadcast
        manager.advertise_txids(&mut channel);
        let info = manager
            .transactions
            .get_mut(&txid)
            .expect("transaction should be map");
        assert!(info.last_advertised_at.is_some());
        assert_eq!(channel.received_commands.len(), 1);
        let command = channel
            .received_commands
            .pop_front()
            .expect("There should be one.");
        assert!(command.address.is_none());
        assert!(match &command.message {
            NetworkMessage::Inv(inv) => {
                if let Inventory::Transaction(ctxid) = inv.first().unwrap() {
                    *ctxid == txid
                } else {
                    false
                }
            }
            _ => false,
        });

        // Set up for a re-broadcast
        info.last_advertised_at =
            Some(SystemTime::now() - Duration::from_secs(TX_ADVERTISE_INTERVAL));
        manager.advertise_txids(&mut channel);

        let info = manager
            .transactions
            .get(&txid)
            .expect("transaction should be map");
        assert!(info.last_advertised_at.is_some());
        assert!(channel.received_commands.len() == 1);

        // Attempt re-broadcast, but it should be ignored as the timeout period has not passed.
        manager.advertise_txids(&mut channel);
        assert!(channel.received_commands.len() == 1);
    }

    /// This function tests the `TransactionManager::process_event(...)` method.
    /// Test Steps:
    /// 1. Receive a transaction.
    /// 2. Process a [StreamEvent](StreamEvent) containing a `getdata` network message.
    /// 3. Process the outgoing commands.
    /// 4. Check the TestChannel for received outgoing commands.
    #[test]
    fn test_process_event() {
        let mut channel = TestChannel::new();
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        let txid = transaction.txid();
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        manager.send_transaction(&raw_tx);
        assert_eq!(manager.transactions.len(), 1);
        manager
            .process_event(&StreamEvent {
                address,
                kind: StreamEventKind::Message(NetworkMessage::GetData(vec![
                    Inventory::Transaction(txid),
                ])),
            })
            .ok();
        manager.process_outgoing_commands(&mut channel);
        assert_eq!(channel.received_commands.len(), 1);
        let command = channel.received_commands.pop_front().unwrap();
        assert!(match &command.message {
            NetworkMessage::Tx(t) => t.txid() == txid,
            _ => false,
        });
    }

    /// This function tests the `TransactionManager::tick(...)` method.
    /// Test Steps:
    /// 1. Receive a transaction.
    /// 2. Process a [StreamEvent](StreamEvent) containing a `getdata` network message.
    /// 3. Call the manager's `tick` method.
    /// 4. Check the TestChannel for received outgoing commands for an `inv` message and a `tx` message.
    #[test]
    fn test_tick() {
        let mut channel = TestChannel::new();
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        let txid = transaction.txid();
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        manager.send_transaction(&raw_tx);
        manager
            .process_event(&StreamEvent {
                address,
                kind: StreamEventKind::Message(NetworkMessage::GetData(vec![
                    Inventory::Transaction(txid),
                ])),
            })
            .ok();
        manager.tick(&mut channel);
        assert_eq!(channel.received_commands.len(), 2);
        assert_eq!(manager.transactions.len(), 1);

        let command = channel.received_commands.pop_front().unwrap();
        assert!(match &command.message {
            NetworkMessage::Inv(inv) => {
                if let Inventory::Transaction(ctxid) = inv.first().unwrap() {
                    *ctxid == txid
                } else {
                    false
                }
            }
            _ => false,
        });

        let command = channel.received_commands.pop_front().unwrap();
        assert!(match command.message {
            NetworkMessage::Tx(t) => t.txid() == txid,
            _ => false,
        });

        let info = manager
            .transactions
            .get_mut(&transaction.txid())
            .expect("transaction should be in the map");
        info.timeout_at = SystemTime::now() - Duration::from_secs(TX_CACHE_TIMEOUT_PERIOD_SECS);
        manager.tick(&mut channel);
        assert_eq!(manager.transactions.len(), 0);
    }

    /// Test to ensure that when `TransactionManager.idle(...)` is called that the `transactions`
    /// and `outgoing_command_queue` fields are cleared.
    #[test]
    fn test_make_idle() {
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        let txid = transaction.txid();
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let inventory = vec![Inventory::Transaction(txid)];

        manager.send_transaction(&raw_tx);
        manager.process_getdata_message(&address, &inventory);

        assert_eq!(manager.transactions.len(), 1);
        assert!(manager.transactions.contains_key(&txid));
        assert_eq!(manager.outgoing_command_queue.len(), 1);

        manager.make_idle();
        assert_eq!(manager.transactions.len(), 0);
        assert!(!manager.transactions.contains_key(&txid));
        assert_eq!(manager.outgoing_command_queue.len(), 0);
    }
}
