use std::net::SocketAddr;
use std::{collections::HashMap, time::Duration, time::SystemTime};

use bitcoin::consensus::deserialize;
use bitcoin::{
    blockdata::transaction::Transaction, hash_types::Txid, network::message::NetworkMessage,
    network::message_blockdata::Inventory,
};
use ic_logger::{debug, ReplicaLogger};

use crate::ProcessBitcoinNetworkMessageError;
use crate::{Channel, Command};

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
pub struct TransactionManager {
    /// This field contains a logger for the transaction manager to
    logger: ReplicaLogger,
    /// This field contains the transactions being tracked by the manager.
    transactions: HashMap<Txid, TransactionInfo>,
}

impl TransactionManager {
    /// This function creates a new transaction manager.
    pub fn new(logger: ReplicaLogger) -> Self {
        TransactionManager {
            logger,
            transactions: HashMap::new(),
        }
    }

    /// This function processes a `getdata` message from a BTC node.
    /// If there are messages for transactions, the transaction queues up outgoing messages
    /// to be processed later.
    fn process_getdata_message(
        &mut self,
        channel: &mut impl Channel,
        address: &SocketAddr,
        inventory: &[Inventory],
    ) {
        for inv in inventory {
            if let Inventory::Transaction(txid) = inv {
                if let Some(info) = self.transactions.get(txid) {
                    channel
                        .send(Command {
                            address: Some(*address),
                            message: NetworkMessage::Tx(info.transaction.clone()),
                        })
                        .ok();
                }
            }
        }
    }

    /// This heartbeat method is called periodically by the adapter.
    /// This method is used to send messages to Bitcoin peers.
    pub fn tick(&mut self, channel: &mut impl Channel) {
        self.advertise_txids(channel);
        self.reap();
    }

    /// This method is used to send a single transaction.
    /// If the transaction is not known, the transaction is added the the transactions map.
    pub fn send_transaction(&mut self, raw_tx: &[u8]) {
        if let Ok(transaction) = deserialize::<Transaction>(raw_tx) {
            let txid = transaction.txid();
            debug!(self.logger, "Received {} from the system component", txid);
            self.transactions
                .entry(txid)
                .or_insert_with(|| TransactionInfo::new(&transaction));
        }
    }

    /// This method is used when the adapter is no longer receiving RPC calls from the replica.
    /// Clears all transactions the adapter is currently caching.
    pub fn make_idle(&mut self) {
        self.transactions.clear();
    }

    /// Clear out transactions that have been held on to for more than the transaction timeout period.
    fn reap(&mut self) {
        debug!(self.logger, "Reaping old transactions");
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

        debug!(self.logger, "Broadcasting Txids ({:?}) to peers", inventory);

        for address in channel.available_connections() {
            channel
                .send(Command {
                    address: Some(address),
                    message: NetworkMessage::Inv(inventory.clone()),
                })
                .ok();
        }
    }

    /// This method is used to process an event from the connected BTC nodes.
    pub fn process_bitcoin_network_message(
        &mut self,
        channel: &mut impl Channel,
        addr: SocketAddr,
        message: &NetworkMessage,
    ) -> Result<(), ProcessBitcoinNetworkMessageError> {
        if let NetworkMessage::GetData(inventory) = message {
            self.process_getdata_message(channel, &addr, inventory);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::test_common::TestChannel;
    use bitcoin::{
        blockdata::constants::genesis_block, consensus::serialize, Network, Transaction,
    };
    use ic_logger::replica_logger::no_op_logger;
    use std::str::FromStr;

    /// This function creates a new transaction manager with a test logger.
    fn make_transaction_manager() -> TransactionManager {
        TransactionManager::new(no_op_logger())
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
        let mut channel = TestChannel::new(vec![
            SocketAddr::from_str("127.0.0.1:8333").expect("invalid address")
        ]);
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
        assert_eq!(channel.command_count(), 1);
        let command = channel.pop_front().expect("There should be one.");
        assert!(command.address.is_some());
        assert!(matches!(command.message, NetworkMessage::Inv(_)));
        let inventory = if let NetworkMessage::Inv(inv) = command.message {
            inv
        } else {
            vec![]
        };
        assert!(
            matches!(inventory.first().expect("should be one entry"), Inventory::Transaction(ctxid) if *ctxid == txid)
        );

        // Set up for a re-broadcast
        info.last_advertised_at =
            Some(SystemTime::now() - Duration::from_secs(TX_ADVERTISE_INTERVAL));
        manager.advertise_txids(&mut channel);

        let info = manager
            .transactions
            .get(&txid)
            .expect("transaction should be map");
        assert!(info.last_advertised_at.is_some());
        assert_eq!(channel.command_count(), 1);

        // Attempt re-broadcast, but it should be ignored as the timeout period has not passed.
        manager.advertise_txids(&mut channel);
        assert_eq!(channel.command_count(), 1);
    }

    /// This function tests the `TransactionManager::process_bitcoin_network_message(...)` method.
    /// Test Steps:
    /// 1. Receive a transaction.
    /// 2. Process a [StreamEvent](StreamEvent) containing a `getdata` network message.
    /// 3. Process the outgoing commands.
    /// 4. Check the TestChannel for received outgoing commands.
    #[test]
    fn test_process_bitcoin_network_message() {
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let mut channel = TestChannel::new(vec![address]);
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        let txid = transaction.txid();
        manager.send_transaction(&raw_tx);
        assert_eq!(manager.transactions.len(), 1);
        manager
            .process_bitcoin_network_message(
                &mut channel,
                address,
                &NetworkMessage::GetData(vec![Inventory::Transaction(txid)]),
            )
            .ok();
        assert_eq!(channel.command_count(), 1);
        let command = channel.pop_front().unwrap();
        assert!(matches!(command.message, NetworkMessage::Tx(t) if t.txid() == txid));
    }

    /// This function tests the `TransactionManager::tick(...)` method.
    /// Test Steps:
    /// 1. Receive a transaction.
    /// 2. Process a [StreamEvent](StreamEvent) containing a `getdata` network message.
    /// 3. Call the manager's `tick` method.
    /// 4. Check the TestChannel for received outgoing commands for an `inv` message and a `tx` message.
    #[test]
    fn test_tick() {
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let mut channel = TestChannel::new(vec![address]);
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        let txid = transaction.txid();
        manager.send_transaction(&raw_tx);
        manager.tick(&mut channel);
        manager
            .process_bitcoin_network_message(
                &mut channel,
                address,
                &NetworkMessage::GetData(vec![Inventory::Transaction(txid)]),
            )
            .ok();
        assert_eq!(channel.command_count(), 2);
        assert_eq!(manager.transactions.len(), 1);

        let command = channel.pop_front().unwrap();
        assert!(matches!(command.message, NetworkMessage::Inv(_)));
        let inventory = if let NetworkMessage::Inv(inv) = command.message {
            inv
        } else {
            vec![]
        };
        assert!(
            matches!(inventory.first().expect("should be one entry"), Inventory::Transaction(ctxid) if *ctxid == txid)
        );

        let command = channel.pop_front().unwrap();
        assert!(matches!(command.message, NetworkMessage::Tx(t) if t.txid() == txid));

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
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let mut channel = TestChannel::new(vec![address]);
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        let txid = transaction.txid();
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let inventory = vec![Inventory::Transaction(txid)];

        manager.send_transaction(&raw_tx);
        manager.process_getdata_message(&mut channel, &address, &inventory);

        assert_eq!(manager.transactions.len(), 1);
        assert!(manager.transactions.contains_key(&txid));
        assert_eq!(channel.command_count(), 1);

        manager.make_idle();
        assert_eq!(manager.transactions.len(), 0);
        assert!(!manager.transactions.contains_key(&txid));
    }
}
