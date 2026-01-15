use std::collections::HashSet;
use std::net::SocketAddr;
use std::{time::Duration, time::SystemTime};

use bitcoin::consensus::deserialize;
use bitcoin::{
    blockdata::transaction::Transaction, hash_types::Txid, p2p::message::NetworkMessage,
    p2p::message_blockdata::Inventory,
};
use hashlink::LinkedHashMap;
use ic_logger::{ReplicaLogger, debug, info, trace};
use ic_metrics::MetricsRegistry;

use crate::ProcessNetworkMessageError;
use crate::metrics::TransactionMetrics;
use crate::{Channel, Command};

/// How long should the transaction manager hold on to a transaction.
const TX_CACHE_TIMEOUT_PERIOD_SECS: u64 = 10 * 60; // 10 minutes

/// Maximum number of transaction to advertise.
// https://developer.bitcoin.org/reference/p2p_networking.html#inv
const MAXIMUM_TRANSACTION_PER_INV: usize = 50_000;

/// Maximum number of transactions the adapter holds.
/// A transaction gets removed from the cache in two cases:
///     - Transaction times out
///     - Cache size limit is hit and this transaction is the oldest.
/// Note: This number should not be too large since it holds user generated
/// transaction data, which can be a few Mb per transaction.
const TX_CACHE_SIZE: usize = 250;

/// This struct represents the current information to track the
/// broadcasting of a transaction.
#[derive(Debug)]
struct TransactionInfo {
    /// The actual transaction to be sent to the BTC network.
    transaction: Transaction,
    /// Set of peer to which we advertised this transaction.
    /// Having a peer in this set doesn't guarantee that the peer actually saw the transaction.
    /// If the connection is healthy during sending most likely the peer will see the transaction.
    /// The adapter maintains a pool of connected peers, so it is unlikely that
    /// the transaction won't be seen by at least a few peers.
    advertised: HashSet<SocketAddr>,
    /// How long the transaction should be held on to.
    /// This is needed in order to be able to reply to GetData requests.
    ttl: SystemTime,
}

impl TransactionInfo {
    /// This function is used to instantiate a [TransactionInfo](TransactionInfo) struct.
    fn new(transaction: &Transaction) -> Self {
        Self {
            transaction: transaction.clone(),
            advertised: HashSet::new(),
            ttl: SystemTime::now() + Duration::from_secs(TX_CACHE_TIMEOUT_PERIOD_SECS),
        }
    }
}

/// This struct stores the list of transactions submitted by the system component.
pub struct TransactionStore {
    /// This field contains a logger for the transaction manager to
    logger: ReplicaLogger,
    /// This field contains the transactions being tracked by the manager.
    transactions: LinkedHashMap<Txid, TransactionInfo>,
    metrics: TransactionMetrics,
}

impl TransactionStore {
    /// This function creates a new transaction manager.
    pub fn new(logger: ReplicaLogger, metrics_registry: &MetricsRegistry) -> Self {
        TransactionStore {
            logger,
            transactions: LinkedHashMap::new(),
            metrics: TransactionMetrics::new(metrics_registry),
        }
    }

    /// This method is used to enqueue a single transaction.
    /// If the transaction is not known, the transaction is added the the transactions map.
    /// In case the transaction queue is full, we drop the oldest transaction a.k.a. FIFO.
    pub fn enqueue_transaction(&mut self, raw_tx: &[u8]) {
        if let Ok(transaction) = deserialize::<Transaction>(raw_tx) {
            self.metrics
                .txn_ops
                .with_label_values(&["insert", "enqueued"])
                .inc();
            let txid = transaction.compute_txid();
            trace!(self.logger, "Received {} from the system component", txid);
            // If hashmap has `TX_CACHE_SIZE` values we remove the oldest transaction in the cache.
            if self.transactions.len() == TX_CACHE_SIZE {
                self.metrics
                    .txn_ops
                    .with_label_values(&["remove", "pushed_out"])
                    .inc();
                self.transactions.pop_front();
            }
            self.transactions
                .entry(txid)
                .or_insert_with(|| TransactionInfo::new(&transaction));
        }
    }

    /// Clear out transactions that have been held on to for more than the transaction's ttl period.
    fn remove_old_txns(&mut self) {
        let now = SystemTime::now();
        self.transactions.retain(|tx, info| {
            if info.ttl < now {
                self.metrics
                    .txn_ops
                    .with_label_values(&["remove", "ttled"])
                    .inc();
                info!(
                    self.logger,
                    "Advertising bitcoin transaction {} timed out.", tx
                );
                false
            } else {
                true
            }
        });
    }

    /// This method is used to broadcast known transaction IDs to connected peers.
    /// If the timeout period has passed for a transaction ID, it is broadcasted again.
    /// If the transaction has not been broadcasted, the transaction ID is broadcasted.
    pub fn advertise_txids<Header, Block>(&mut self, channel: &mut impl Channel<Header, Block>) {
        self.remove_old_txns();
        for address in channel.available_connections() {
            let mut inventory = vec![];
            for (txid, info) in self.transactions.iter_mut() {
                if !info.advertised.contains(&address) {
                    inventory.push(Inventory::Transaction(*txid));
                    info.advertised.insert(address);
                }
                // If the inventory contains the maximum allowed number of transactions, we will send it
                // and start building a new one.
                if inventory.len() == MAXIMUM_TRANSACTION_PER_INV {
                    debug!(
                        self.logger,
                        "Broadcasting Txids ({:?}) to peer {:?}", inventory, address
                    );
                    for address in channel.available_connections() {
                        channel
                            .send(Command {
                                address: Some(address),
                                message: NetworkMessage::Inv(std::mem::take(&mut inventory)),
                            })
                            .ok();
                    }
                }
            }
            if !inventory.is_empty() {
                debug!(
                    self.logger,
                    "Broadcasting Txids ({:?}) to peer {:?}", inventory, address
                );
                channel
                    .send(Command {
                        address: Some(address),
                        message: NetworkMessage::Inv(inventory),
                    })
                    .ok();
            }
        }
    }

    /// This method is used to process an event from the connected BTC nodes.
    /// This function processes a `getdata` message from a BTC node.
    /// If there are messages for transactions, the transaction is sent to the
    /// requesting node. Transactions sent are then removed from the cache.
    pub fn process_bitcoin_network_message<Header, Block>(
        &self,
        channel: &mut impl Channel<Header, Block>,
        addr: SocketAddr,
        message: &NetworkMessage<Header, Block>,
    ) -> Result<(), ProcessNetworkMessageError> {
        if let NetworkMessage::GetData(inventory) = message {
            if inventory.len() > MAXIMUM_TRANSACTION_PER_INV {
                return Err(ProcessNetworkMessageError::InvalidMessage);
            }

            for inv in inventory {
                if let Inventory::Transaction(txid) = inv
                    && let Some(TransactionInfo { transaction, .. }) = self.transactions.get(txid)
                {
                    channel
                        .send(Command {
                            address: Some(addr),
                            message: NetworkMessage::Tx(transaction.clone()),
                        })
                        .ok();
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::{
        Block, Network, Transaction,
        absolute::{LOCK_TIME_THRESHOLD, LockTime},
        block::Header,
        blockdata::constants::genesis_block,
        consensus::serialize,
    };
    use ic_logger::replica_logger::no_op_logger;
    use std::str::FromStr;

    type TestChannel = crate::common::test_common::TestChannel<Header, Block>;

    /// This function creates a new transaction manager with a test logger.
    fn make_transaction_manager() -> TransactionStore {
        TransactionStore::new(no_op_logger(), &MetricsRegistry::default())
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

    /// This function tests the `TransactionStore::reap(...)` method.
    /// Test Steps:
    /// 1. Receive a transaction
    /// 2. Attempt to reap the transaction that was just received.
    /// 3. Update the TransactionStore's `last_received_transactions_at` field to a timestamp
    ///    in the future.
    /// 4. Attempt to reap transactions again.
    #[test]
    fn test_reap() {
        let mut channel = TestChannel::new(vec![
            SocketAddr::from_str("127.0.0.1:8333").expect("invalid address"),
        ]);
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        manager.enqueue_transaction(&raw_tx);
        assert_eq!(manager.transactions.len(), 1);
        manager.advertise_txids(&mut channel);
        assert_eq!(manager.transactions.len(), 1);

        let info = manager
            .transactions
            .get_mut(&transaction.compute_txid())
            .expect("transaction should be map");
        info.ttl = SystemTime::now() - Duration::from_secs(TX_CACHE_TIMEOUT_PERIOD_SECS);
        manager.advertise_txids(&mut channel);
        assert_eq!(manager.transactions.len(), 0);
    }

    /// This function tests the `TransactionStore::broadcast_txids(...)` method.
    /// Test Steps:
    /// 1. Receive a transaction
    /// 2. Perform an initial broadcast.
    #[test]
    fn test_broadcast_txids() {
        let mut channel = TestChannel::new(vec![
            SocketAddr::from_str("127.0.0.1:8333").expect("invalid address"),
        ]);
        let mut manager = make_transaction_manager();
        let transaction = get_transaction();
        let raw_tx = serialize(&transaction);
        let txid = transaction.compute_txid();
        manager.enqueue_transaction(&raw_tx);
        assert_eq!(manager.transactions.len(), 1);
        let info = manager
            .transactions
            .get(&transaction.compute_txid())
            .expect("transaction should be map");
        assert!(info.advertised.is_empty());
        // Initial broadcast
        manager.advertise_txids(&mut channel);
        let info = manager
            .transactions
            .get_mut(&txid)
            .expect("transaction should be map");
        assert!(info.advertised.len() == 1);
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
    }

    /// This function tests that the oldest transaction gets removed in case of a full transaction cache.
    /// Test Steps:
    /// 1. Add transaction that should be removed to manager.
    /// 2. Add n transaction such that the first one gets evicted.
    /// 3. Make sure the first transaction is actually removed from the cache.
    #[test]
    fn test_adapter_transaction_cache_full() {
        let mut manager = make_transaction_manager();

        // Send one transaction. This transaction should be removed first if we are at capacity.
        let mut first_tx = get_transaction();
        first_tx.lock_time = LockTime::from_height(LOCK_TIME_THRESHOLD - 1).unwrap();
        let raw_tx = serialize(&first_tx);
        manager.enqueue_transaction(&raw_tx);

        for i in 0..TX_CACHE_SIZE {
            // First regtest genesis transaction.
            let mut transaction = get_transaction();
            // Alter transaction such that we get a different `txid`
            transaction.lock_time = LockTime::from_height(i.try_into().unwrap()).unwrap();
            let raw_tx = serialize(&transaction);
            manager.enqueue_transaction(&raw_tx);
        }
        assert_eq!(manager.transactions.len(), TX_CACHE_SIZE);
        assert!(manager.transactions.get(&first_tx.compute_txid()).is_none());
    }

    /// This function tests that we don't readvertise transactions that were already advertised.
    /// Test Steps:
    /// 1. Add transaction to manager.
    /// 2. Advertise that transaction and create requests from peer.
    /// 3. Check that this transaction does not get advertised again during manager tick.
    /// 3. Check transaction advertisement is correctly tracked.
    #[test]
    fn test_adapter_dont_readvertise() {
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let mut channel = TestChannel::new(vec![address]);
        let mut manager = make_transaction_manager();

        let mut transaction = get_transaction();
        transaction.lock_time = LockTime::ZERO;
        let raw_tx = serialize(&transaction);
        manager.enqueue_transaction(&raw_tx);
        manager.advertise_txids(&mut channel);
        channel.pop_front().unwrap();

        // Request transaction
        manager
            .process_bitcoin_network_message(
                &mut channel,
                address,
                &NetworkMessage::GetData(vec![Inventory::Transaction(transaction.compute_txid())]),
            )
            .unwrap();
        // Send transaction
        channel.pop_front().unwrap();

        manager.advertise_txids(&mut channel);
        // Transaction should not be readvertised.
        assert_eq!(channel.command_count(), 0);
        // Transaction should be marked as advertised
        assert_eq!(
            manager
                .transactions
                .get(&transaction.compute_txid())
                .unwrap()
                .advertised
                .len(),
            1
        );
        assert_eq!(
            manager
                .transactions
                .get(&transaction.compute_txid())
                .unwrap()
                .advertised
                .get(&address),
            Some(&address)
        );
    }

    /// This function tests that we advertise to multiple peers and don't readvertise after
    /// first adverisment.
    /// Test Steps:
    /// 1. Add transaction to manager.
    /// 2. Advertise that transaction and request it from peer 1.
    /// 3. Check that this transaction does not get readvertised.
    #[test]
    fn test_adapter_dont_readvertise_multiple_peers() {
        let address1 = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let address2 = SocketAddr::from_str("127.0.0.1:8334").expect("invalid address");
        let mut channel = TestChannel::new(vec![address1, address2]);
        let mut manager = make_transaction_manager();

        let mut transaction = get_transaction();
        transaction.lock_time = LockTime::ZERO;
        let raw_tx = serialize(&transaction);
        manager.enqueue_transaction(&raw_tx);
        manager.advertise_txids(&mut channel);
        // Transaction advertisement to both peers.
        assert_eq!(channel.command_count(), 2);
        channel.pop_front().unwrap();
        channel.pop_front().unwrap();

        // Request transaction from peer 1
        manager
            .process_bitcoin_network_message(
                &mut channel,
                address1,
                &NetworkMessage::GetData(vec![Inventory::Transaction(transaction.compute_txid())]),
            )
            .unwrap();
        // Send transaction to peer 1
        channel.pop_front().unwrap();
        assert_eq!(channel.command_count(), 0);

        manager.advertise_txids(&mut channel);
        // Transaction should not be readvertised.
        assert_eq!(channel.command_count(), 0);
    }

    /// This function tests that we advertise and already advertised tx to new peers.
    /// Test Steps:
    /// 1. Add transaction to manager.
    /// 2. Advertise that transaction and request it.
    /// 3. Check that this transaction does not get readvertised to peer 1.
    /// 4. Add new peer to available connections.
    /// 5. Check that new peer get advertisement.
    #[test]
    fn test_adapter_advertise_new_peer() {
        let address1 = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let mut channel = TestChannel::new(vec![address1]);
        let mut manager = make_transaction_manager();

        // 1.
        let mut transaction = get_transaction();
        transaction.lock_time = LockTime::ZERO;
        let raw_tx = serialize(&transaction);
        manager.enqueue_transaction(&raw_tx);
        manager.advertise_txids(&mut channel);
        assert_eq!(channel.command_count(), 1);
        channel.pop_front().unwrap();

        // 2.
        manager
            .process_bitcoin_network_message(
                &mut channel,
                address1,
                &NetworkMessage::GetData(vec![Inventory::Transaction(transaction.compute_txid())]),
            )
            .unwrap();
        channel.pop_front().unwrap();
        assert_eq!(channel.command_count(), 0);

        // 3.
        manager.advertise_txids(&mut channel);
        assert_eq!(channel.command_count(), 0);

        // 4.
        let address2 = SocketAddr::from_str("127.0.0.2:8333").expect("invalid address");
        channel.add_address(address2);
        manager.advertise_txids(&mut channel);

        // 5.
        assert_eq!(
            channel.pop_front().unwrap(),
            Command {
                address: Some(address2),
                message: NetworkMessage::Inv(vec![Inventory::Transaction(
                    transaction.compute_txid()
                )])
            }
        );
    }

    /// This function tests the `TransactionStore::process_bitcoin_network_message(...)` method.
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
        let txid = transaction.compute_txid();
        manager.enqueue_transaction(&raw_tx);
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
        assert!(matches!(command.message, NetworkMessage::Tx(t) if t.compute_txid() == txid));
    }

    /// This function tests the `TransactionStore::process_bitcoin_network_message(...)` method.
    /// Test Steps:
    /// 1. Receive a more than `MAXIMUM_TRANSACTION_PER_INV` transaction.
    /// 2. Process a [StreamEvent](StreamEvent) containing a `getdata` network message and reject.
    #[test]
    fn test_invalid_process_bitcoin_network_message() {
        let num_transaction = MAXIMUM_TRANSACTION_PER_INV + 1;
        let address = SocketAddr::from_str("127.0.0.1:8333").expect("invalid address");
        let mut channel = TestChannel::new(vec![address]);
        let manager = make_transaction_manager();

        let mut inventory = vec![];
        for i in 0..num_transaction {
            // First regtest genesis transaction.
            let mut transaction = get_transaction();
            // Alter transaction such that we get a different `txid`
            transaction.lock_time = LockTime::from_height(i.try_into().unwrap()).unwrap();
            let txid = transaction.compute_txid();
            inventory.push(Inventory::Transaction(txid));
        }
        manager
            .process_bitcoin_network_message(
                &mut channel,
                address,
                &NetworkMessage::GetData(inventory),
            )
            .unwrap_err();
    }

    /// This function tests the `TransactionStore::tick(...)` method.
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
        let txid = transaction.compute_txid();
        manager.enqueue_transaction(&raw_tx);
        manager.advertise_txids(&mut channel);
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
        assert!(matches!(command.message, NetworkMessage::Tx(t) if t.compute_txid() == txid));

        manager.enqueue_transaction(&raw_tx);
        let info = manager
            .transactions
            .get_mut(&transaction.compute_txid())
            .expect("transaction should be in the map");
        info.ttl = SystemTime::now() - Duration::from_secs(TX_CACHE_TIMEOUT_PERIOD_SECS);
        manager.advertise_txids(&mut channel);
        assert_eq!(manager.transactions.len(), 0);
    }
}
