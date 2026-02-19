use std::borrow::Cow;

use candid::{CandidType, Principal};
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};

pub type CanisterId = Principal;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]

pub struct Signature {
    pub message: String,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

impl Storable for Signature {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(serde_cbor::to_vec(self).expect("failed to serialize"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        serde_cbor::from_slice(&bytes).expect("failed to deserialize")
    }

    const BOUND: Bound = Bound::Unbounded;
}
