use ic_types::NodeId;
use std::collections::BTreeMap;

#[derive(Clone)]
struct PeerBucket {
    quota_used: usize,
}

impl PeerBucket {
    fn new() -> PeerBucket {
        PeerBucket { quota_used: 0 }
    }

    #[allow(dead_code)]
    fn get_quota_used(&self) -> usize {
        self.quota_used
    }

    fn increase_quota_used(&mut self, size_of_artifact: usize) {
        self.quota_used += size_of_artifact;
    }

    fn decrease_quota_used(&mut self, size_of_artifact: usize) {
        self.quota_used -= size_of_artifact
    }
}

/// PeerIndex has a Map for peers and the hash of artifacts held for a
/// particular peer. PeerIndex needs to be used for only unvalidated artifacts.
/// It provides the quota remaining for each peer and updates the quota used by
/// the peer as an artifact is inserted or removed.
#[derive(Clone)]
pub(crate) struct PeerIndex {
    peer_map: BTreeMap<NodeId, PeerBucket>,
    max_quota_per_peer: usize,
}

impl PeerIndex {
    pub(crate) fn new(max_quota_per_peer: usize) -> PeerIndex {
        PeerIndex {
            peer_map: BTreeMap::new(),
            max_quota_per_peer,
        }
    }

    pub(crate) fn insert(&mut self, peer_id: NodeId, size_of_artifact: usize) {
        self.peer_map
            .entry(peer_id)
            .or_insert_with(PeerBucket::new)
            .increase_quota_used(size_of_artifact)
    }

    pub(crate) fn remove(&mut self, peer_id: NodeId, size_of_artifact: usize) {
        if let Some(bucket) = self.peer_map.get_mut(&peer_id) {
            bucket.decrease_quota_used(size_of_artifact);
        }
    }

    pub(crate) fn get_remaining_quota(&self, peer_id: &NodeId) -> usize {
        match self.peer_map.get(peer_id) {
            Some(bucket) => {
                let quota_used = bucket.get_quota_used();
                if self.max_quota_per_peer > quota_used {
                    self.max_quota_per_peer - quota_used
                } else {
                    0
                }
            }
            None => self.max_quota_per_peer,
        }
    }
}
