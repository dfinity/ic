use candid::Principal;
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, Storable,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use std::{borrow::Cow, cell::RefCell, collections::HashSet};

pub type Timestamp = u64;

type Memory = VirtualMemory<DefaultMemoryImpl>;
pub type StableMap<K, V> = StableBTreeMap<K, V, Memory>;

const MEMORY_ID_SALT: MemoryId = MemoryId::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorableSalt {
    // A cryptographic salt. Represents a random value to be added to input data before hashing.
    pub salt: Vec<u8>,
    // The timestamp (in nanoseconds) when the cryptographic salt was regenerated.
    // Allows to track updates, ensuring it is refreshed periodically to maintain security.
    pub salt_id: Timestamp,
}

impl Storable for StorableSalt {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("StorableSalt serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("StorableSalt deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

// Declare storage variables
// NOTE: initialization is lazy
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // A cryptographic salt stored in stable memory to ensure persistence across upgrades.
    pub static SALT: RefCell<StableMap<(), StorableSalt>> = RefCell::new(
        StableMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_SALT)))
    );

    // Authorized principals allowed to retrieve the salt from the canister.
    pub static API_BOUNDARY_NODE_PRINCIPALS: RefCell<HashSet<Principal>> = RefCell::new(HashSet::new());
}
