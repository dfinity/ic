use ic_types::crypto::CryptoHash;
use ic_types::p2p::GossipAdvert;
use std::collections::HashMap;

type Counter = usize;

#[derive(Debug)]
#[allow(dead_code)]
enum AdvertViewError {
    InternalError,
    NotFound,
}

#[allow(dead_code)]
enum AdvertViewResult {
    Alright,
    CapacityAlert(usize),
}

#[derive(Default)]
struct AdvertViewSendEntry {
    idx: usize,
    counter: Counter,
    data: Option<GossipAdvert>,
    #[allow(dead_code)]
    sent: bool,
}

#[derive(Default)]
#[allow(dead_code)]
struct AdvertViewRecvEntry {
    idx: usize,
    counter: Counter,
    data: Option<GossipAdvert>,
}

trait AdvertViewUpdate {
    fn get_index(&self) -> usize;
    fn get_counter(&self) -> Counter;
    fn get_data(&self) -> Option<GossipAdvert>;
}

#[allow(dead_code)]
impl AdvertViewSendEntry {
    fn new(idx: usize) -> Self {
        Self {
            idx,
            counter: 0,
            data: None,
            sent: false,
        }
    }
}

impl AdvertViewUpdate for AdvertViewSendEntry {
    fn get_index(&self) -> usize {
        self.idx
    }

    fn get_counter(&self) -> Counter {
        self.counter
    }

    fn get_data(&self) -> Option<GossipAdvert> {
        self.data.clone()
    }
}

#[allow(dead_code)]
impl AdvertViewRecvEntry {
    fn new(idx: usize) -> Self {
        Self {
            idx,
            counter: 0,
            data: None,
        }
    }

    fn process_update(&mut self, update: &dyn AdvertViewUpdate) -> bool {
        if update.get_index() != self.idx {
            return false;
        }
        self.counter = update.get_counter();
        self.data = update.get_data();
        true
    }
}

#[derive(Default)]
#[allow(dead_code)]
struct AdvertViewSend {
    adverts: Vec<AdvertViewSendEntry>,
    index: HashMap<CryptoHash, usize>,
    // `free` is used as a stack, so that most recently emptied cells are used first
    // This can be used to make the send side view unaware of the actual C, if the
    // client is guaranteed to have some upper bound C on the number of adverts it
    // may have active simultaneously. The receive side view still must be aware of C.
    free: Vec<usize>,
    alert_limit: usize,
}

#[allow(dead_code)]
impl AdvertViewSend {
    fn new(alert_limit: usize) -> Self {
        Self {
            adverts: Vec::new(),
            index: HashMap::new(),
            free: Vec::new(),
            alert_limit,
        }
    }

    fn add(&mut self, a: GossipAdvert) -> Result<AdvertViewResult, AdvertViewError> {
        if self.free.is_empty() {
            // Current capacity is exceeded, add new entry
            let new_idx = self.adverts.len();
            self.adverts
                .insert(new_idx, AdvertViewSendEntry::new(new_idx));
            self.free.push(new_idx);
        }
        let idx = self.free.pop().unwrap(); // unwrap should be safe due to the check above
        let entry = self
            .adverts
            .get_mut(idx)
            .ok_or(AdvertViewError::InternalError)?;
        let integrity_hash = a.integrity_hash.clone();
        entry.counter += 1;
        entry.data = Some(a);
        entry.sent = false;
        self.index.insert(integrity_hash, idx);
        // Check if alert_limit has been reached
        if self.adverts.len() >= self.alert_limit {
            // alert
            Ok(AdvertViewResult::CapacityAlert(self.adverts.len()))
        } else {
            Ok(AdvertViewResult::Alright)
        }
    }

    fn delete(&mut self, integrity_hash: &CryptoHash) -> Result<AdvertViewResult, AdvertViewError> {
        let idx = self
            .index
            .remove(integrity_hash)
            .ok_or(AdvertViewError::NotFound)?;
        let entry = self
            .adverts
            .get_mut(idx)
            .ok_or(AdvertViewError::InternalError)?;
        entry.counter += 1;
        entry.data = None;
        entry.sent = false;
        self.free.push(idx);
        Ok(AdvertViewResult::Alright)
    }
}

#[derive(Default)]
#[allow(dead_code)]
struct AdvertViewRecv {
    adverts: HashMap<usize, AdvertViewRecvEntry>,
    alert_limit: usize,
}

#[allow(dead_code)]
impl AdvertViewRecv {
    fn new(alert_limit: usize) -> Self {
        Self {
            adverts: HashMap::new(),
            alert_limit,
        }
    }

    fn process_update(
        &mut self,
        update: &dyn AdvertViewUpdate,
    ) -> Result<AdvertViewResult, AdvertViewError> {
        let entry = self.adverts.get_mut(&update.get_index());
        match entry {
            Some(e) => {
                e.process_update(update);
            }
            None => {
                let mut entry = AdvertViewRecvEntry::new(update.get_index());
                entry.process_update(update);
                self.adverts.insert(update.get_index(), entry);
            }
        }
        if update.get_index() >= self.alert_limit {
            // alert
            Ok(AdvertViewResult::CapacityAlert(update.get_index()))
        } else {
            Ok(AdvertViewResult::Alright)
        }
    }

    fn len(&self) -> usize {
        self.adverts
            .values()
            .filter(|entry| entry.data.is_some())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_types::artifact::{Advert, ArtifactKind};
    use ic_types::artifact::{ArtifactAttribute, ArtifactId, ArtifactTag};
    use ic_types::crypto::CryptoHash;

    #[derive(Clone)]
    struct TestArtifact;

    struct TestMessage {
        id: u128,
    }

    impl ArtifactKind for TestArtifact {
        const TAG: ArtifactTag = ArtifactTag::FileTreeSyncArtifact;
        type Id = ArtifactId;
        type Message = TestMessage;
        type Attribute = ArtifactAttribute;
        type Filter = u64;

        /// The function converts a `ConsensusMessage` into an advert for a
        /// `ConsensusArtifact`.
        fn message_to_advert(msg: &TestMessage) -> Advert<TestArtifact> {
            Advert {
                id: ArtifactId::FileTreeSync(msg.id.to_string()),
                attribute: ArtifactAttribute::FileTreeSync("".to_string()),
                size: 0,
                integrity_hash: CryptoHash(Vec::from(msg.id.to_be_bytes())),
            }
        }
    }

    #[test]
    fn test_advert_view() {
        // For testing purposes only
        fn send_all(sender: &mut AdvertViewSend, receiver: &mut AdvertViewRecv) {
            sender
                .adverts
                .iter_mut()
                .filter(|entry| !entry.sent)
                .for_each(|entry| {
                    if receiver.process_update(entry).is_ok() {
                        entry.sent = true;
                    }
                });
        }

        // A utility to create new adverts with unique IDs
        let mut next_artifact_id: u128 = 1;
        let mut new_advert = || {
            let msg = TestMessage {
                id: next_artifact_id,
            };
            let advert: Advert<TestArtifact> = ArtifactKind::message_to_advert(&msg);
            let wire_advert: GossipAdvert = GossipAdvert::from(advert);
            next_artifact_id += 1;
            wire_advert
        };

        // Create send and recv views
        let mut send_view = AdvertViewSend::new(20);
        let mut recv_view = AdvertViewRecv::new(20);

        // Fill in some entries on the send side
        for _i in 0..10 {
            send_view
                .add(new_advert().clone())
                .expect("Failed to add advert");
        }

        // Send all
        send_all(&mut send_view, &mut recv_view);

        // Assert
        assert_eq!(recv_view.len(), 10);

        // Delete some entries
        send_view
            .delete(&CryptoHash(Vec::from(3_u128.to_be_bytes())))
            .expect("Failed to delete advert");
        send_view
            .delete(&CryptoHash(Vec::from(7_u128.to_be_bytes())))
            .expect("Failed to delete advert");
        send_view
            .delete(&CryptoHash(Vec::from(5_u128.to_be_bytes())))
            .expect("Failed to delete advert");

        // Send all
        send_all(&mut send_view, &mut recv_view);

        // Assert
        assert_eq!(recv_view.len(), 7);

        // Fill until a capacity alert is returned
        for _i in 0..13 {
            send_view
                .add(new_advert().clone())
                .expect("Failed to add advert");
        }
        let res = send_view.add(new_advert());
        assert!(matches!(res, Ok(AdvertViewResult::CapacityAlert(_))));

        // Delete and re-fill so entries are reused
        for i in 10..15 {
            send_view
                .delete(&CryptoHash(Vec::from((i as u128).to_be_bytes())))
                .expect("Failed to delete advert");
        }
        for _i in 0..5 {
            send_view
                .add(new_advert().clone())
                .expect("Failed to add advert");
        }

        // Send all
        send_all(&mut send_view, &mut recv_view);

        // Assert
        assert_eq!(recv_view.len(), 21);
    }
}
