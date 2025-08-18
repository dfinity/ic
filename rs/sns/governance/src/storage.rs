use crate::extensions::ExtensionSpec;
use ic_base_types::CanisterId;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{BTreeMap, DefaultMemoryImpl, Storable};
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

    pub static REGISTERED_EXTENSIONS: RefCell<BTreeMap<CanisterId, ExtensionSpec, VM>> = MEMORY_MANAGER.with_borrow(|memory_manager| {
        RefCell::new(BTreeMap::init(memory_manager.get(REGISTERED_EXTENSIONS_MEMORY_ID)))
    });
}

pub fn with_upgrades_memory<R>(f: impl FnOnce(&VM) -> R) -> R {
    UPGRADES_MEMORY.with_borrow(f)
}

pub fn with_registered_extensions_map<R>(
    f: impl FnOnce(&BTreeMap<CanisterId, ExtensionSpec, VM>) -> R,
) -> R {
    REGISTERED_EXTENSIONS.with_borrow(f)
}

pub fn with_registered_extensions_map_mut<R>(
    f: impl FnOnce(&mut BTreeMap<CanisterId, ExtensionSpec, VM>) -> R,
) -> R {
    REGISTERED_EXTENSIONS.with_borrow_mut(f)
}

// TODO - how should we handle this?  The extension spec has to come from somewhere.
// Eventually it will not come from our local machine.  It needs to be serializable.  And so do
// the validation functions.
// But currently, we are creating specs for operations and extensions that use types and
// function pointers.  How is that going to be something that we can transfer into SNS Governance?
// If we cache them with a reference to a hash, we can work well until such time as that hash
// goes away.  Using the data tree of references seems like a less than ideal solution.
impl Storable for ExtensionSpec {
    fn to_bytes(&self) -> Cow<[u8]> {
        todo!()
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        todo!()
    }

    const BOUND: Bound = Bound::Unbounded;
}
