use std::{cell::RefCell, collections::HashMap, convert::AsRef, hash::Hash};

use candid::CandidType;
use serde::Deserialize;

#[derive(CandidType, Deserialize, Default)]
pub struct KVStore<K, V>
where
    K: Eq + Hash + AsRef<[u8]> + 'static,
{
    map: HashMap<K, V>,
}

impl<K, V> KVStore<K, V>
where
    K: Eq + Hash + AsRef<[u8]> + Clone,
    V: AsRef<[u8]>,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn put(&mut self, key: K, value: V) {
        self.map.insert(key, value);
    }
}

thread_local! {
    static STORE: RefCell<KVStore<String, String>> = RefCell::new(KVStore::new());
}

pub fn get(key: &String) -> Option<String> {
    STORE.with(|s| s.borrow().get(key).cloned())
}
pub fn put(key: String, value: String) {
    STORE.with(|s| s.borrow_mut().put(key, value));
}
pub fn pre_upgrade() -> KVStore<String, String> {
    STORE.with(|s| s.take())
}
pub fn post_upgrade(store: KVStore<String, String>) {
    STORE.with(|s| s.replace(store));
}
