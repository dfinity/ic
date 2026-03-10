use crate::{Blob, Hash, Metadata};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, Memory, StableBTreeMap, Storable};
use std::borrow::Cow;
use std::cell::RefCell;

const BLOB_STORE_MEMORY_ID: MemoryId = MemoryId::new(0);
const METADATA_MEMORY_ID: MemoryId = MemoryId::new(1);
type VMem = VirtualMemory<DefaultMemoryImpl>;

impl Storable for Metadata {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("failed to encode BlobMetadata");
        Cow::Owned(buf)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        ciborium::from_reader(&*bytes).expect("failed to decode BlobMetadata")
    }

    const BOUND: Bound = Bound::Unbounded;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static BLOB_STORE: RefCell<BlobStore<VMem>> =
        MEMORY_MANAGER.with(|m| {
            let mgr = m.borrow();
            RefCell::new(BlobStore::init(
                mgr.get(BLOB_STORE_MEMORY_ID),
                mgr.get(METADATA_MEMORY_ID),
            ))
        });
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
    metadata: StableBTreeMap<Hash, Metadata, M>,
}

impl<M: Memory> BlobStore<M> {
    pub fn init(store_memory: M, metadata_memory: M) -> Self {
        Self {
            store: StableBTreeMap::init(store_memory),
            metadata: StableBTreeMap::init(metadata_memory),
        }
    }

    pub fn get(&self, hash: Hash) -> Option<Blob> {
        self.store.get(&hash).map(|b| Blob::new_unchecked(b, hash))
    }

    pub fn get_metadata(&self, hash: Hash) -> Option<Metadata> {
        self.metadata.get(&hash)
    }

    pub fn insert<B: Into<Blob>>(&mut self, blob: B, metadata: Metadata) -> Option<Hash> {
        let Blob { data, hash } = blob.into();
        if self.store.contains_key(&hash) {
            return None;
        }
        assert_eq!(self.store.insert(hash, data), None);
        assert_eq!(self.metadata.insert(hash, metadata), None);
        Some(hash)
    }
}
