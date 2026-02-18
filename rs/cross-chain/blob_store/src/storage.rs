use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::Bound;
use ic_stable_structures::{DefaultMemoryImpl, Memory, StableBTreeMap, Storable};
use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

const BLOB_STORE_MEMORY_ID: MemoryId = MemoryId::new(0);
type VMem = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static BLOB_STORE: RefCell<BlobStore<VMem>> =
        MEMORY_MANAGER.with(|m| RefCell::new(BlobStore::init(m.borrow().get(BLOB_STORE_MEMORY_ID))));
}

pub fn mutate_blob_store<F, R>(f: F) -> R
where
    F: FnOnce(&mut BlobStore<VMem>) -> R,
{
    BLOB_STORE.with(|s| f(&mut s.borrow_mut()))
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Hash([u8; 32]);

impl Hash {
    pub fn sha256(data: &[u8]) -> Self {
        use sha2::Digest;
        Hash(sha2::Sha256::digest(data).into())
    }
}

impl FromStr for Hash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        <[u8; 32]>::from_hex(s).map(Hash)
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Storable for Hash {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Hash(arr)
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 32,
        is_fixed_size: true,
    };
}

pub struct Blob {
    data: Vec<u8>,
    hash: Hash,
}

impl Blob {
    pub fn new(data: Vec<u8>) -> Self {
        let hash = Hash::sha256(&data);
        Self { data, hash }
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }
}

impl From<Vec<u8>> for Blob {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
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

    pub fn insert<B: Into<Blob>>(&mut self, blob: B) -> Option<Hash> {
        let Blob { data, hash } = blob.into();
        if self.store.contains_key(&hash) {
            return None;
        }
        assert_eq!(self.store.insert(hash.clone(), data), None);
        Some(hash)
    }
}
