use std::{
    collections::{BTreeMap, btree_map::Entry},
    ops::Add,
};

use ic_interfaces::ingress_pool::IngressPoolObject;
use ic_logger::{ReplicaLogger, warn};
use ic_types::{CountBytes, NodeId};

pub(super) struct Counter {
    pub(super) bytes: usize,
    pub(super) messages: usize,
}

impl Add for Counter {
    type Output = Counter;

    fn add(self, rhs: Self) -> Self::Output {
        Counter {
            bytes: self.bytes + rhs.bytes,
            messages: self.messages + rhs.messages,
        }
    }
}

#[derive(Clone)]
/// Keeps track of the number of messages and total size of the messages per peer.
pub(super) struct PeerCounters {
    bytes_counters: PeerCounter,
    message_counters: PeerCounter,
}

impl PeerCounters {
    /// Create a new [`PeerCounters`] without any limits on the number/size of messages.
    pub(super) fn new(log: ReplicaLogger) -> Self {
        Self {
            bytes_counters: PeerCounter::new(log.clone()),
            message_counters: PeerCounter::new(log),
        }
    }

    pub(super) fn observe(&mut self, ingress_message: &IngressPoolObject) {
        self.message_counters.add(ingress_message.originator_id, 1);
        self.bytes_counters
            .add(ingress_message.originator_id, ingress_message.count_bytes());
    }

    pub(super) fn forget(&mut self, ingress_message: &IngressPoolObject) {
        self.message_counters
            .subtract(ingress_message.originator_id, 1);
        self.bytes_counters
            .subtract(ingress_message.originator_id, ingress_message.count_bytes());
    }

    pub(super) fn count_total_bytes(&self) -> usize {
        self.bytes_counters.total()
    }

    pub(super) fn get_counters(&self, originator_id: &NodeId) -> Counter {
        Counter {
            bytes: self
                .bytes_counters
                .counter_per_peer
                .get(originator_id)
                .copied()
                .unwrap_or_default(),
            messages: self
                .message_counters
                .counter_per_peer
                .get(originator_id)
                .copied()
                .unwrap_or_default(),
        }
    }
}

// TODO: find a better name for this structure
#[derive(Clone)]
struct PeerCounter {
    counter_per_peer: BTreeMap<NodeId, usize>,
    log: ReplicaLogger,
}

impl PeerCounter {
    fn new(log: ReplicaLogger) -> Self {
        Self {
            counter_per_peer: BTreeMap::default(),
            log,
        }
    }

    fn add(&mut self, originator_id: NodeId, count: usize) {
        *self.counter_per_peer.entry(originator_id).or_default() += count;
    }

    fn subtract(&mut self, originator_id: NodeId, count: usize) {
        match self.counter_per_peer.entry(originator_id) {
            Entry::Occupied(mut entry) => {
                let counter = entry.get_mut();
                *counter = counter.saturating_sub(count);

                if *counter == 0 {
                    entry.remove_entry();
                }
            }
            Entry::Vacant(_) => {
                warn!(
                    self.log,
                    "Attempting to subtract the counter for unknown node: {}", originator_id
                );

                if cfg!(debug_assertions) {
                    panic!("Attempting to subtract the counter for unknown node: {originator_id}");
                }
            }
        }
    }

    fn total(&self) -> usize {
        self.counter_per_peer.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use ic_logger::no_op_logger;
    use ic_test_utilities_types::{
        ids::{NODE_1, NODE_2},
        messages::SignedIngressBuilder,
    };

    use super::*;

    #[test]
    fn observe_test() {
        let mut peer_counters = PeerCounters::new(no_op_logger());
        let ingress_message_1 = fake_ingress_pool_object(NODE_1, 1);
        let ingress_message_2 = fake_ingress_pool_object(NODE_2, 2);
        let ingress_message_3 = fake_ingress_pool_object(NODE_2, 3);
        let message_size = ingress_message_1.count_bytes();

        peer_counters.observe(&ingress_message_1);
        peer_counters.observe(&ingress_message_2);
        peer_counters.observe(&ingress_message_3);

        assert_eq!(
            peer_counters.bytes_counters.counter_per_peer,
            BTreeMap::from([(NODE_1, message_size), (NODE_2, 2 * message_size)])
        );
        assert_eq!(
            peer_counters.message_counters.counter_per_peer,
            BTreeMap::from([(NODE_1, 1), (NODE_2, 2)])
        );
    }

    #[test]
    fn forget_test() {
        let mut peer_counters = PeerCounters::new(no_op_logger());
        let ingress_message_1 = fake_ingress_pool_object(NODE_1, 1);
        let ingress_message_2 = fake_ingress_pool_object(NODE_2, 2);
        let ingress_message_3 = fake_ingress_pool_object(NODE_2, 3);
        let message_size = ingress_message_1.count_bytes();

        peer_counters.observe(&ingress_message_1);
        peer_counters.observe(&ingress_message_2);
        peer_counters.observe(&ingress_message_3);

        peer_counters.forget(&ingress_message_1);
        peer_counters.forget(&ingress_message_3);

        assert_eq!(
            peer_counters.bytes_counters.counter_per_peer,
            BTreeMap::from([(NODE_2, message_size)])
        );
        assert_eq!(
            peer_counters.message_counters.counter_per_peer,
            BTreeMap::from([(NODE_2, 1)])
        );
    }

    fn fake_ingress_pool_object(originator_id: NodeId, nonce: u64) -> IngressPoolObject {
        IngressPoolObject::new(
            originator_id,
            SignedIngressBuilder::new().nonce(nonce).build(),
        )
    }
}
