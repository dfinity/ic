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

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
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

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
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

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
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

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
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

    fn into_bytes(self) -> Vec<u8> {
        self.to_bytes().into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_stable_structures_0_6::BTreeMap as BTreeMap0_6;
    use ic_stable_structures_0_6::memory_manager::{
        MemoryId as MemoryId0_6, MemoryManager as MemoryManager0_6,
    };
    use std::ops::Range;

    /// Stores a `T` through ic-stable-structures 0.6, using `T`'s own `Storable` encoding. Only
    /// types that implement their own encoding are wrapped: `u64`, `()` and `Principal` use 0.6's
    /// implementation.
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

    /// Rules for the given IDs, in key order. Some of them span several pages.
    fn rules(ids: Range<u128>) -> Vec<(StorableRuleId, StorableRule)> {
        ids.map(|id| {
            let rule = StorableRule {
                incident_id: IncidentId(Uuid::from_u128(id % 3)),
                rule_raw: vec![b'x'; 100 * (id as usize % 30)],
                description: format!("rule {id}"),
                disclosed_at: (id % 2 == 0).then_some(id as u64),
                added_in_version: 1,
                removed_in_version: None,
            };
            (StorableRuleId(Uuid::from_u128(id)), rule)
        })
        .collect()
    }

    // The canister's stable memory has the same layout with ic-stable-structures 0.6 and 0.7:
    // each version reads what the other one wrote.
    #[test]
    fn stable_memory_is_compatible_with_ic_stable_structures_0_6() {
        let rule_id = RuleId(Uuid::from_u128(1));
        let incident_id = StorableIncidentId(Uuid::from_u128(1));
        let principal = Principal::from_slice(&[1, 2, 3]);
        let next_principal = Principal::from_slice(&[4, 5, 6]);
        let memory = DefaultMemoryImpl::default();

        // Write with 0.6, at the memory IDs the canister uses.
        {
            let mm = MemoryManager0_6::init(memory.clone());
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(0))).insert(
                2_u64,
                V0_6(StorableConfig {
                    schema_version: 1,
                    active_since: 5,
                    rule_ids: vec![rule_id],
                }),
            );
            let mut rules_0_6 = BTreeMap0_6::init(mm.get(MemoryId0_6::new(1)));
            for (id, rule) in rules(0..40) {
                rules_0_6.insert(V0_6(id), V0_6(rule));
            }
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(2))).insert(
                V0_6(incident_id.clone()),
                V0_6(StorableIncident {
                    is_disclosed: true,
                    rule_ids: HashSet::from([rule_id]),
                }),
            );
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(3))).insert((), principal);
        }

        // Read and extend with 0.7, as the canister does.
        {
            let mm = MemoryManager::init(memory.clone());
            let mut configs: StableMap<StorableVersion, StorableConfig> =
                StableMap::init(mm.get(MEMORY_ID_CONFIGS));
            let mut rules_0_7: StableMap<StorableRuleId, StorableRule> =
                StableMap::init(mm.get(MEMORY_ID_RULES));
            let incidents: StableMap<StorableIncidentId, StorableIncident> =
                StableMap::init(mm.get(MEMORY_ID_INCIDENTS));
            let mut authorized_principal: StableMap<(), StorablePrincipal> =
                StableMap::init(mm.get(MEMORY_ID_AUTHORIZED_PRINCIPAL));

            let config = configs.get(&2).unwrap();
            assert_eq!(
                (config.schema_version, config.active_since, config.rule_ids),
                (1, 5, vec![rule_id])
            );
            assert_eq!(
                rules_0_7
                    .iter()
                    .map(|entry| entry.into_pair())
                    .collect::<Vec<_>>(),
                rules(0..40)
            );
            let incident = incidents.get(&incident_id).unwrap();
            assert_eq!(
                (incident.is_disclosed, incident.rule_ids),
                (true, HashSet::from([rule_id]))
            );
            assert_eq!(authorized_principal.get(&()), Some(principal));

            authorized_principal.insert((), next_principal);
            for (id, rule) in rules(40..80) {
                rules_0_7.insert(id, rule);
            }
            configs.insert(
                3,
                StorableConfig {
                    schema_version: 1,
                    active_since: 6,
                    rule_ids: vec![rule_id],
                },
            );
        }

        // Read with 0.6 what 0.7 wrote.
        let mm = MemoryManager0_6::init(memory);
        let configs: BTreeMap0_6<u64, V0_6<StorableConfig>, _> =
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(0)));
        assert_eq!(
            configs
                .iter()
                .map(|(version, config)| (version, config.0.active_since, config.0.rule_ids))
                .collect::<Vec<_>>(),
            vec![(2, 5, vec![rule_id]), (3, 6, vec![rule_id])]
        );
        let rules_0_6: BTreeMap0_6<V0_6<StorableRuleId>, V0_6<StorableRule>, _> =
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(1)));
        assert_eq!(
            rules_0_6
                .iter()
                .map(|(id, rule)| (id.0, rule.0))
                .collect::<Vec<_>>(),
            rules(0..80)
        );
        let authorized_principal: BTreeMap0_6<(), Principal, _> =
            BTreeMap0_6::init(mm.get(MemoryId0_6::new(3)));
        assert_eq!(authorized_principal.get(&()), Some(next_principal));
    }
}
