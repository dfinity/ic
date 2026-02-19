use candid::{CandidType, Principal};
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub const MAX_MESSAGES_PER_INBOX: usize = 1000;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    pub sender: Principal,
    #[serde(with = "serde_bytes")]
    pub encrypted_message: Vec<u8>,
    pub timestamp: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Default)]
pub struct Inbox {
    pub messages: Vec<Message>,
}

impl Storable for Inbox {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_cbor::to_vec(self).expect("failed to serialize"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_cbor::from_slice(&bytes).expect("failed to deserialize")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for Message {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_cbor::to_vec(self).expect("failed to serialize"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_cbor::from_slice(&bytes).expect("failed to deserialize")
    }

    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct SendMessageRequest {
    pub receiver: Principal,
    #[serde(with = "serde_bytes")]
    pub encrypted_message: Vec<u8>,
}
