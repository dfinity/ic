use candid::Principal;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    DefaultMemoryImpl, StableBTreeMap, Storable,
};
use rate_limits_api::SchemaVersion;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, cell::RefCell, collections::HashSet, thread::LocalKey};

use crate::types::{IncidentId, RuleId, Timestamp, Version};

// Type aliases for stable memory
type Memory = VirtualMemory<DefaultMemoryImpl>;
pub type LocalRef<T> = &'static LocalKey<RefCell<T>>;
pub type StableMap<K, V> = StableBTreeMap<K, V, Memory>;

// Memory IDs for stable memory management
const MEMORY_ID_CONFIGS: MemoryId = MemoryId::new(0);
const MEMORY_ID_RULES: MemoryId = MemoryId::new(1);
const MEMORY_ID_INCIDENTS: MemoryId = MemoryId::new(2);

// Storables
#[derive(Clone, Debug, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct StorableVersion(pub Version);

#[derive(Clone, Debug, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct StorableRuleId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct StorableIncidentId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorableRuleMetadata {
    pub incident_id: IncidentId,
    pub rule_raw: Vec<u8>,
    pub description: String,
    pub disclosed_at: Option<Timestamp>,
    pub added_in_version: Version,
    pub removed_in_version: Option<Version>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorableConfig {
    pub schema_version: SchemaVersion,
    pub active_since: Timestamp,
    pub rule_ids: Vec<RuleId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorableIncidentMetadata {
    pub is_disclosed: bool,
    pub rule_ids: Vec<RuleId>,
}

impl Storable for StorableVersion {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(bincode::serialize(&self.0).expect("StorableVersion serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(bincode::deserialize(&bytes).expect("StorableVersion deserialization failed"))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: std::mem::size_of::<Version>() as u32,
        is_fixed_size: true,
    };
}

impl Storable for StorableRuleId {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(bincode::serialize(&self.0).expect("StorableRuleId serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(bincode::deserialize(&bytes).expect("StorableRuleId deserialization failed"))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 256,
        is_fixed_size: false,
    };
}

impl Storable for StorableIncidentId {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(bincode::serialize(&self.0).expect("StorableIncidentId serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(bincode::deserialize(&bytes).expect("StorableIncidentId deserialization failed"))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 256,
        is_fixed_size: false,
    };
}

impl Storable for StorableConfig {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(bincode::serialize(self).expect("StorableConfig serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        bincode::deserialize(&bytes).expect("StorableConfig deserialization failed")
    }

    // TODO: adjust these bounds
    const BOUND: Bound = Bound::Bounded {
        max_size: 1024,
        is_fixed_size: false,
    };
}

impl Storable for StorableIncidentMetadata {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(bincode::serialize(self).expect("StorableIncidentMetadata serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        bincode::deserialize(&bytes).expect("StorableIncidentMetadata deserialization failed")
    }

    // TODO: adjust these bounds
    const BOUND: Bound = Bound::Bounded {
        max_size: 2048,
        is_fixed_size: false,
    };
}

impl Storable for StorableRuleMetadata {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(bincode::serialize(self).expect("StorableRuleMetadata serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        bincode::deserialize(&bytes).expect("StorableRuleMetadata deserialization failed")
    }

    // TODO: adjust these bounds
    const BOUND: Bound = Bound::Bounded {
        max_size: 4096,
        is_fixed_size: false,
    };
}

// Declare storage variables
// NOTE: initialization is lazy
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    pub static CONFIGS: RefCell<StableMap<StorableVersion, StorableConfig>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_CONFIGS)),
        )
    );

    pub static RULES: RefCell<StableMap<StorableRuleId, StorableRuleMetadata>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_RULES)),
        )
    );

    pub static INCIDENTS: RefCell<StableMap<StorableIncidentId, StorableIncidentMetadata>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_INCIDENTS)),
        )
    );

    pub static API_BOUNDARY_NODE_PRINCIPALS: RefCell<HashSet<Principal>> = RefCell::new(HashSet::new());
}

impl From<Version> for StorableVersion {
    fn from(version: Version) -> Self {
        StorableVersion(version)
    }
}

impl From<RuleId> for StorableRuleId {
    fn from(rule_id: RuleId) -> Self {
        StorableRuleId(rule_id)
    }
}
