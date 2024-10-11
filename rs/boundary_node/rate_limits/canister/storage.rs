use std::{borrow::Cow, cell::RefCell};

use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
    DefaultMemoryImpl, StableBTreeMap, Storable,
};
use serde::{Deserialize, Serialize};

use crate::types::{RuleId, Timestamp, Version};

// Type aliases for stable memory
type Memory = VirtualMemory<DefaultMemoryImpl>;

type StableMap<K, V> = StableBTreeMap<K, V, Memory>;
type StableValue<T> = StableMap<(), T>;

// Memory IDs for stable memory management
const MEMORY_ID_VERSION: u8 = 0;
const _MEMORY_ID_CONFIGS: u8 = 1;
const _MEMORY_ID_RULES: u8 = 2;
const _MEMORY_ID_INCIDENTS: u8 = 3;

// Storables
#[derive(Clone, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct StorableVersion(pub Version);

#[derive(Clone, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct StorableRuleId(pub String);

#[derive(Clone, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct StorableIncidentId(String);

#[derive(Serialize, Deserialize)]
pub struct StorableRuleMetadata {
    pub rule_raw: Vec<u8>,
    pub description: String,
    pub disclosed_at: Option<Timestamp>,
    pub added_in_version: Version,
    pub removed_in_version: Option<Version>,
}

#[derive(Serialize, Deserialize)]
struct StorableConfig {
    active_since: Timestamp,
    rule_ids: Vec<RuleId>,
}

#[derive(Serialize, Deserialize)]
pub struct StorableRuleIds {
    rule_ids: Vec<RuleId>,
}

impl Storable for StorableVersion {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(u64::from_bytes(bytes))
    }

    const BOUND: Bound = <Version as Storable>::BOUND;
}

impl Storable for StorableRuleId {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }

    // TODO: make it bounded
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for StorableIncidentId {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(String::from_bytes(bytes))
    }

    // TODO: make it bounded
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for StorableConfig {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode StorableConfig");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        ciborium::de::from_reader(&bytes[..]).expect("failed to decode StorableConfig")
    }

    // TODO: make it bounded
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for StorableRuleIds {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode StorableRuleIds");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        ciborium::de::from_reader(&bytes[..]).expect("failed to decode StorableRuleIds")
    }

    // TODO: make it bounded
    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for StorableRuleMetadata {
    fn to_bytes(&self) -> Cow<[u8]> {
        let mut buf = vec![];
        ciborium::ser::into_writer(self, &mut buf).expect("failed to encode StorableRuleMetadata");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        ciborium::de::from_reader(&bytes[..]).expect("failed to decode StorableRuleMetadata")
    }

    // TODO: make it bounded
    const BOUND: Bound = Bound::Unbounded;
}

pub fn set_stable_version(version: Version) {
    VERSION.with(|v| {
        let mut v = v.borrow_mut();
        v.insert((), StorableVersion(version));
    });
}

pub fn get_stable_version() -> Version {
    let version = VERSION.with(|v| {
        let v = v.borrow();
        v.get(&()).expect("failed to get version")
    });
    version.0
}

// Declare storage, initialized lazily
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

thread_local! {
    pub static VERSION: RefCell<StableValue<StorableVersion>> = RefCell::new(
        StableValue::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_VERSION))),
        )
    );

    pub static CONFIGS: RefCell<StableMap<StorableVersion, StorableConfig>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(_MEMORY_ID_CONFIGS))),
        )
    );

    pub static RULES: RefCell<StableMap<StorableRuleId, StorableRuleMetadata>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(_MEMORY_ID_RULES))),
        )
    );

    pub static INCIDENTS: RefCell<StableMap<StorableIncidentId, StorableRuleIds>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(_MEMORY_ID_INCIDENTS))),
        )
    );
}
