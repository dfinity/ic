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

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_stable_structures_0_6::BTreeMap as BTreeMap0_6;
    use ic_stable_structures_0_6::memory_manager::{
        MemoryId as MemoryId0_6, MemoryManager as MemoryManager0_6,
    };

    /// Stores a `T` through ic-stable-structures 0.6, using `T`'s own `Storable` encoding.
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct V0_6<T>(T);

    impl<T: Storable> ic_stable_structures_0_6::Storable for V0_6<T> {
        fn to_bytes(&self) -> Cow<'_, [u8]> {
            self.0.to_bytes()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            Self(T::from_bytes(bytes))
        }

        const BOUND: ic_stable_structures_0_6::storable::Bound = match T::BOUND {
            Bound::Unbounded => ic_stable_structures_0_6::storable::Bound::Unbounded,
            Bound::Bounded {
                max_size,
                is_fixed_size,
            } => ic_stable_structures_0_6::storable::Bound::Bounded {
                max_size,
                is_fixed_size,
            },
        };
    }

    // The canister's stable memory has the same layout with ic-stable-structures 0.6 and 0.7:
    // each version reads what the other one wrote.
    #[test]
    fn stable_memory_is_compatible_with_ic_stable_structures_0_6() {
        let memory = DefaultMemoryImpl::default();

        // Write with 0.6, at the memory ID the canister uses.
        {
            let mm = MemoryManager0_6::init(memory.clone());
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(0))).insert(
                V0_6(()),
                V0_6(StorableSalt {
                    salt: vec![1, 2, 3],
                    salt_id: 7,
                }),
            );
        }

        // Read and overwrite with 0.7, as the canister does.
        {
            let mm = MemoryManager::init(memory.clone());
            let mut salt: StableMap<(), StorableSalt> = StableMap::init(mm.get(MEMORY_ID_SALT));
            let stored = salt.get(&()).unwrap();
            assert_eq!((stored.salt, stored.salt_id), (vec![1, 2, 3], 7));

            salt.insert(
                (),
                StorableSalt {
                    salt: vec![4, 5, 6],
                    salt_id: 8,
                },
            );
        }

        // Read with 0.6 what 0.7 wrote.
        let mm = MemoryManager0_6::init(memory);
        let salt: BTreeMap0_6<V0_6<()>, V0_6<StorableSalt>, _> =
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(0)));
        let stored = salt.get(&V0_6(())).unwrap().0;
        assert_eq!((stored.salt, stored.salt_id), (vec![4, 5, 6], 8));
    }
}
