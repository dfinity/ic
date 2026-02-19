use crate::{Blob, Hash};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, Memory, StableBTreeMap};
use std::cell::RefCell;

const BLOB_STORE_MEMORY_ID: MemoryId = MemoryId::new(0);
type VMem = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static BLOB_STORE: RefCell<BlobStore<VMem>> =
        MEMORY_MANAGER.with(|m| RefCell::new(BlobStore::init(m.borrow().get(BLOB_STORE_MEMORY_ID))));
}

pub fn read_blob_store<F, R>(f: F) -> R
where
    F: FnOnce(&BlobStore<VMem>) -> R,
{
    BLOB_STORE.with(|s| f(&s.borrow()))
}

pub fn mutate_blob_store<F, R>(f: F) -> R
where
    F: FnOnce(&mut BlobStore<VMem>) -> R,
{
    BLOB_STORE.with(|s| f(&mut s.borrow_mut()))
}

pub struct BlobStore<M: Memory> {
    store: StableBTreeMap<Hash, Vec<u8>, M>,
}

impl<M: Memory> BlobStore<M> {
    pub fn init(memory: M) -> Self {
        Self {
            store: StableBTreeMap::init(memory),
        }
    }

    pub fn get(&self, hash: &Hash) -> Option<Blob> {
        self.store
            .get(hash)
            .map(|b| Blob::new_unchecked(b, hash.clone()))
    }

    pub fn insert<B: Into<Blob>>(&mut self, blob: B) -> Option<Hash> {
        let Blob { data, hash } = blob.into();
        if self.store.contains_key(&hash) {
            return None;
        }
        assert_eq!(self.store.insert(hash.clone(), data), None);
        Some(hash)
    }
}
