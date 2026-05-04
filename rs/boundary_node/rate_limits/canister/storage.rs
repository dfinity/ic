use candid::Principal;
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, Storable,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    storable::Bound,
};
use rate_limits_api::SchemaVersion;
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use std::{borrow::Cow, cell::RefCell, collections::HashSet, thread::LocalKey};
use uuid::Uuid;

use crate::types::{IncidentId, RuleId, Timestamp, Version};

// Type aliases for stable memory
type Memory = VirtualMemory<DefaultMemoryImpl>;
pub type LocalRef<T> = &'static LocalKey<RefCell<T>>;
pub type StableMap<K, V> = StableBTreeMap<K, V, Memory>;

// Memory IDs for stable memory management
const MEMORY_ID_CONFIGS: MemoryId = MemoryId::new(0);
const MEMORY_ID_RULES: MemoryId = MemoryId::new(1);
const MEMORY_ID_INCIDENTS: MemoryId = MemoryId::new(2);
const MEMORY_ID_AUTHORIZED_PRINCIPAL: MemoryId = MemoryId::new(3);

// Storables
pub type StorablePrincipal = Principal;
pub type StorableVersion = Version;

#[derive(Clone, Debug, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct StorableRuleId(pub Uuid);

#[derive(Clone, Debug, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub struct StorableIncidentId(pub Uuid);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StorableRule {
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
pub struct StorableIncident {
    pub is_disclosed: bool,
    pub rule_ids: HashSet<RuleId>,
}

impl Storable for StorableRuleId {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("StorableRuleId serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(from_slice(&bytes).expect("StorableRuleId deserialization failed"))
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for StorableIncidentId {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("StorableIncidentId serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self(from_slice(&bytes).expect("StorableIncidentId deserialization failed"))
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for StorableConfig {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("StorableConfig serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("StorableConfig deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for StorableIncident {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("StorableIncident serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("StorableIncident deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
}

impl Storable for StorableRule {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("StorableRule serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("StorableRule deserialization failed")
    }

    const BOUND: Bound = Bound::Unbounded;
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

    pub static RULES: RefCell<StableMap<StorableRuleId, StorableRule>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_RULES)),
        )
    );

    pub static AUTHORIZED_PRINCIPAL: RefCell<StableMap<(), StorablePrincipal>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_AUTHORIZED_PRINCIPAL)),
        )
    );

    pub static INCIDENTS: RefCell<StableMap<StorableIncidentId, StorableIncident>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_INCIDENTS)),
        )
    );

    pub static API_BOUNDARY_NODE_PRINCIPALS: RefCell<HashSet<Principal>> = RefCell::new(HashSet::new());
}

impl From<RuleId> for StorableRuleId {
    fn from(rule_id: RuleId) -> Self {
        StorableRuleId(rule_id.0)
    }
}

impl From<IncidentId> for StorableIncidentId {
    fn from(incident_id: IncidentId) -> Self {
        StorableIncidentId(incident_id.0)
    }
}
