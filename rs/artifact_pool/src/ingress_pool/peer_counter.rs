use std::collections::BTreeMap;

use ic_interfaces::ingress_pool::IngressPoolObject;
use ic_types::{CountBytes, NodeId};

#[derive(Clone)]
/// Keeps track of the number of messages and total size of the messages per peer.
pub(super) struct PeerCounters {
    bytes_counters: PeerCounter,
    count_counters: PeerCounter,
}

impl PeerCounters {
    /// Created a new [`PeerCounters`] without any limits on the number/size of messages.
    pub(super) fn new() -> Self {
        Self {
            bytes_counters: PeerCounter::new(),
            count_counters: PeerCounter::new(),
        }
    }

    /// Created a new [`PeerCounters`] with the provided limits on the number/size of messages.
    pub(super) fn new_with_limits(max_bytes: usize, max_count: usize) -> Self {
        Self {
            bytes_counters: PeerCounter::new_with_limit(max_bytes),
            count_counters: PeerCounter::new_with_limit(max_count),
        }
    }

    pub(super) fn observe(&mut self, ingress_message: &IngressPoolObject) {
        self.count_counters.add(ingress_message.peer_id, 1);
        self.bytes_counters
            .add(ingress_message.peer_id, ingress_message.count_bytes());
    }

    pub(super) fn forget(&mut self, ingress_message: &IngressPoolObject) {
        self.count_counters.subtract(ingress_message.peer_id, 1);
        self.bytes_counters
            .subtract(ingress_message.peer_id, ingress_message.count_bytes());
    }

    /// Checks whether either the number of messages or their total size exceed the
    /// respective limits.
    pub(super) fn exceeds_limit(&self, peer_id: &NodeId) -> bool {
        self.bytes_counters.exceeds_limit(peer_id) || self.count_counters.exceeds_limit(peer_id)
    }
}

#[derive(Clone)]
struct PeerCounter {
    counter_per_peer: BTreeMap<NodeId, usize>,
    limit: Option<usize>,
}

impl PeerCounter {
    fn new() -> Self {
        Self {
            counter_per_peer: BTreeMap::default(),
            limit: None,
        }
    }

    fn new_with_limit(limit: usize) -> Self {
        Self {
            counter_per_peer: BTreeMap::default(),
            limit: Some(limit),
        }
    }

    fn add(&mut self, peer_id: NodeId, count: usize) {
        *self.counter_per_peer.entry(peer_id).or_default() += count;
    }

    fn subtract(&mut self, peer_id: NodeId, count: usize) {
        *self.counter_per_peer.entry(peer_id).or_default() -= count;

        if self.counter_per_peer.get(&peer_id) == Some(&0) {
            self.counter_per_peer.remove(&peer_id);
        }
    }

    fn exceeds_limit(&self, peer_id: &NodeId) -> bool {
        self.limit.is_some_and(|limit| {
            self.counter_per_peer
                .get(peer_id)
                .copied()
                .unwrap_or_default()
                > limit
        })
    }
}

#[cfg(test)]
mod tests {
    use ic_test_utilities_types::{
        ids::{NODE_1, NODE_2},
        messages::SignedIngressBuilder,
    };

    use super::*;

    #[test]
    fn observe_test() {
        let mut peer_counters = PeerCounters::new();
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
            peer_counters.count_counters.counter_per_peer,
            BTreeMap::from([(NODE_1, 1), (NODE_2, 2)])
        );
    }

    #[test]
    fn forget_test() {
        let mut peer_counters = PeerCounters::new();
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
            peer_counters.count_counters.counter_per_peer,
            BTreeMap::from([(NODE_2, 1)])
        );
    }

    #[test]
    fn exceeds_limits_when_too_many_messages_test() {
        let ingress_message_1 = fake_ingress_pool_object(NODE_1, 1);
        let ingress_message_2 = fake_ingress_pool_object(NODE_1, 2);
        let message_size = ingress_message_1.count_bytes();
        let mut peer_counters = PeerCounters::new_with_limits(2 * message_size, 1);

        peer_counters.observe(&ingress_message_1);
        peer_counters.observe(&ingress_message_2);

        assert!(peer_counters.exceeds_limit(&NODE_1));
    }

    #[test]
    fn exceeds_limits_when_too_many_bytes_test() {
        let ingress_message_1 = fake_ingress_pool_object(NODE_1, 1);
        let ingress_message_2 = fake_ingress_pool_object(NODE_1, 2);
        let message_size = ingress_message_1.count_bytes();
        let mut peer_counters = PeerCounters::new_with_limits(2 * message_size - 1, 2);

        peer_counters.observe(&ingress_message_1);
        peer_counters.observe(&ingress_message_2);

        assert!(peer_counters.exceeds_limit(&NODE_1));
    }

    #[test]
    fn does_not_exceed_limits_test() {
        let ingress_message_1 = fake_ingress_pool_object(NODE_1, 1);
        let ingress_message_2 = fake_ingress_pool_object(NODE_1, 2);
        let ingress_message_3 = fake_ingress_pool_object(NODE_2, 3);
        let message_size = ingress_message_1.count_bytes();
        let mut peer_counters = PeerCounters::new_with_limits(2 * message_size, 2);

        peer_counters.observe(&ingress_message_1);
        peer_counters.observe(&ingress_message_2);
        peer_counters.observe(&ingress_message_3);

        assert!(!peer_counters.exceeds_limit(&NODE_1));
        assert!(!peer_counters.exceeds_limit(&NODE_2));
    }

    fn fake_ingress_pool_object(peer_id: NodeId, nonce: u64) -> IngressPoolObject {
        IngressPoolObject::new(peer_id, SignedIngressBuilder::new().nonce(nonce).build())
    }
}
