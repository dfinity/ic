use crate::extensions::ExtensionSpec;
use candid::Principal;
use ic_base_types::{CanisterId, PrincipalId};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{BTreeMap, DefaultMemoryImpl, Storable};
use prost::Message;
use std::borrow::Cow;
use std::cell::RefCell;

/// Constants to define memory segments.  Must not change.
const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);
const REGISTERED_EXTENSIONS_MEMORY_ID: MemoryId = MemoryId::new(1);

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    // The memory where the governance reads and writes its state during an upgrade.
    pub static UPGRADES_MEMORY: RefCell<VirtualMemory<DefaultMemoryImpl>> = MEMORY_MANAGER.with(|memory_manager|
        RefCell::new(memory_manager.borrow().get(UPGRADES_MEMORY_ID)));

    pub static REGISTERED_EXTENSIONS: RefCell<BTreeMap<Principal, ExtensionSpec, VM>> = MEMORY_MANAGER.with_borrow(|memory_manager| {
        RefCell::new(BTreeMap::init(memory_manager.get(REGISTERED_EXTENSIONS_MEMORY_ID)))
    });
}

pub fn with_upgrades_memory<R>(f: impl FnOnce(&VM) -> R) -> R {
    UPGRADES_MEMORY.with_borrow(f)
}

pub fn cache_registered_extension(canister_id: CanisterId, spec: ExtensionSpec) {
    REGISTERED_EXTENSIONS.with_borrow_mut(|map| map.insert(canister_id.get().0, spec));
}

pub fn clear_registered_extension_cache(canister_id: CanisterId) {
    REGISTERED_EXTENSIONS.with_borrow_mut(|map| map.remove(&canister_id.get().0));
}

pub fn get_registered_extension_from_cache(canister_id: CanisterId) -> Option<ExtensionSpec> {
    REGISTERED_EXTENSIONS.with_borrow(|map| map.get(&canister_id.get().0))
}

pub fn list_registered_extensions_from_cache() -> Vec<(CanisterId, ExtensionSpec)> {
    REGISTERED_EXTENSIONS.with_borrow(|map| {
        map.iter()
            .map(|(principal, spec)| {
                (
                    CanisterId::unchecked_from_principal(PrincipalId::from(principal)),
                    spec,
                )
            })
            .collect()
    })
}

impl Storable for ExtensionSpec {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(crate::pb::v1::ExtensionSpec::from(self.clone()).encode_to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let proto = crate::pb::v1::ExtensionSpec::decode(bytes.as_ref()).unwrap();
        Self::try_from(proto).unwrap()
    }

    const BOUND: Bound = Bound::Unbounded;
}
