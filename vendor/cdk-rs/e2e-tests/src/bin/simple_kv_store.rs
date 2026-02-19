use ic_cdk::{post_upgrade, pre_upgrade, query, update};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::collections::BTreeMap;

type Store = BTreeMap<String, ByteBuf>;

thread_local! {
    static STORE: RefCell<Store> = RefCell::default();
}

#[update]
fn insert(key: String, value: ByteBuf) {
    STORE.with(|store| store.borrow_mut().insert(key, value));
}

#[query]
fn lookup(key: String) -> Option<ByteBuf> {
    STORE.with(|store| store.borrow().get(&key).cloned())
}

#[pre_upgrade]
fn pre_upgrade() {
    STORE.with(|store| ic_cdk::storage::stable_save((store,)).unwrap());
}

#[post_upgrade]
fn post_upgrade() {
    let (persisted_store,): (Store,) = ic_cdk::storage::stable_restore().unwrap();
    STORE.with(|store| *store.borrow_mut() = persisted_store);
}

fn main() {}
