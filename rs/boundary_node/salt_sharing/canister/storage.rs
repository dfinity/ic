use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use std::cell::RefCell;

pub type Timestamp = u64;
pub const SALT_SIZE: usize = 64;

type Memory = VirtualMemory<DefaultMemoryImpl>;
pub type StableMap<K, V> = StableBTreeMap<K, V, Memory>;

const MEMORY_ID_SALT: MemoryId = MemoryId::new(0);
const MEMORY_ID_LAST_SALT_NS: MemoryId = MemoryId::new(1);

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    // A cryptographic salt stored in stable memory to ensure persistence across upgrades.
    // Represents a random value added to input data before hashing.
    pub static SALT: RefCell<StableMap<(), Vec<u8>>> = RefCell::new(
        StableMap::init(MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_SALT)))
    );

    // The last timestamp (in nanoseconds) when the cryptographic salt was regenerated.
    // Allows to track last updates, ensuring it is refreshed periodically to maintain security.
    // Stored in stable memory for persistency across upgrades.
    pub static LAST_SALT_NS: RefCell<StableMap<(), Timestamp>> = RefCell::new(StableMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MEMORY_ID_LAST_SALT_NS)),
    ));
}
