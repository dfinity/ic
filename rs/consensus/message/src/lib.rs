use ic_types::{artifact::ConsensusMessageId, consensus::*};

pub trait ConsensusMessageHashable: Clone {
    fn get_id(&self) -> ConsensusMessageId;
    fn get_cm_hash(&self) -> ConsensusMessageHash;
    fn assert(msg: &ConsensusMessage) -> Option<&Self>;
    fn into_message(self) -> ConsensusMessage;

    /// Check integrity of a message. Default is true.
    /// This should be implemented for those that have `Hashed<H, V>`.
    /// Note that if lazy loading is also used, it will force evaluation.
    fn check_integrity(&self) -> bool {
        true
    }
}

impl ConsensusMessageHashable for Finalization {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::Finalization(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::Finalization(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::Finalization(self)
    }
}

impl ConsensusMessageHashable for FinalizationShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::FinalizationShare(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::FinalizationShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::FinalizationShare(self)
    }
}

impl ConsensusMessageHashable for Notarization {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::Notarization(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::Notarization(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::Notarization(self)
    }
}

impl ConsensusMessageHashable for NotarizationShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::NotarizationShare(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::NotarizationShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::NotarizationShare(self)
    }
}

impl ConsensusMessageHashable for RandomBeacon {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::RandomBeacon(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::RandomBeacon(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::RandomBeacon(self)
    }
}

impl ConsensusMessageHashable for RandomBeaconShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::RandomBeaconShare(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::RandomBeaconShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::RandomBeaconShare(self)
    }
}

impl ConsensusMessageHashable for BlockProposal {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::BlockProposal(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::BlockProposal(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::BlockProposal(self)
    }

    fn check_integrity(&self) -> bool {
        let block_hash = self.content.get_hash();
        let block = self.as_ref();
        let payload_hash = block.payload.get_hash();
        let block_payload = block.payload.as_ref();
        block.payload.is_summary() == block_payload.is_summary()
            && &ic_crypto::crypto_hash(block_payload) == payload_hash
            && &ic_crypto::crypto_hash(block) == block_hash
    }
}

impl ConsensusMessageHashable for RandomTape {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::RandomTape(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::RandomTape(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::RandomTape(self)
    }
}

impl ConsensusMessageHashable for RandomTapeShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.content.height,
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::RandomTapeShare(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::RandomTapeShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::RandomTapeShare(self)
    }
}

impl ConsensusMessageHashable for CatchUpPackage {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::CatchUpPackage(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::CatchUpPackage(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::CatchUpPackage(self)
    }

    fn check_integrity(&self) -> bool {
        let content = &self.content;
        let block_hash = content.block.get_hash();
        let block = content.block.as_ref();
        let random_beacon_hash = content.random_beacon.get_hash();
        let random_beacon = content.random_beacon.as_ref();
        let payload_hash = block.payload.get_hash();
        let block_payload = block.payload.as_ref();
        block.payload.is_summary() == block_payload.is_summary()
            && &ic_crypto::crypto_hash(random_beacon) == random_beacon_hash
            && &ic_crypto::crypto_hash(block) == block_hash
            && &ic_crypto::crypto_hash(block_payload) == payload_hash
    }
}

impl ConsensusMessageHashable for CatchUpPackageShare {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        ConsensusMessageHash::CatchUpPackageShare(ic_crypto::crypto_hash(self))
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        if let ConsensusMessage::CatchUpPackageShare(value) = msg {
            Some(value)
        } else {
            None
        }
    }

    fn into_message(self) -> ConsensusMessage {
        ConsensusMessage::CatchUpPackageShare(self)
    }

    fn check_integrity(&self) -> bool {
        let content = &self.content;
        let random_beacon_hash = content.random_beacon.get_hash();
        &ic_crypto::crypto_hash(content.random_beacon.as_ref()) == random_beacon_hash
    }
}

impl ConsensusMessageHashable for ConsensusMessage {
    fn get_id(&self) -> ConsensusMessageId {
        ConsensusMessageId {
            hash: self.get_cm_hash(),
            height: self.height(),
        }
    }

    fn get_cm_hash(&self) -> ConsensusMessageHash {
        match self {
            ConsensusMessage::RandomBeacon(value) => value.get_cm_hash(),
            ConsensusMessage::Finalization(value) => value.get_cm_hash(),
            ConsensusMessage::Notarization(value) => value.get_cm_hash(),
            ConsensusMessage::BlockProposal(value) => value.get_cm_hash(),
            ConsensusMessage::RandomBeaconShare(value) => value.get_cm_hash(),
            ConsensusMessage::NotarizationShare(value) => value.get_cm_hash(),
            ConsensusMessage::FinalizationShare(value) => value.get_cm_hash(),
            ConsensusMessage::RandomTape(value) => value.get_cm_hash(),
            ConsensusMessage::RandomTapeShare(value) => value.get_cm_hash(),
            ConsensusMessage::CatchUpPackage(value) => value.get_cm_hash(),
            ConsensusMessage::CatchUpPackageShare(value) => value.get_cm_hash(),
        }
    }

    fn assert(msg: &ConsensusMessage) -> Option<&Self> {
        Some(msg)
    }

    fn into_message(self) -> ConsensusMessage {
        self
    }
}
