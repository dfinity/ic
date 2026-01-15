use std::cell::RefCell;

use ic_cdk::api::{certified_data_set, data_certificate};
use ic_certified_map::{AsHashTree, Hash as ICHash, RbTree, labeled, labeled_hash};
use serde::Serialize;
use serde_cbor::Serializer;
use sha2::{Digest, Sha256};

thread_local! {
    static TREE: RefCell<RbTree<String, ICHash>> = const { RefCell::new(RbTree::new()) };
}

pub fn get() -> Vec<u8> {
    data_certificate().unwrap()
}

pub fn get_tree(key: &str) -> Vec<u8> {
    TREE.with(|tree| {
        let tree = tree.borrow();
        let witness = tree.witness(key.as_ref());
        let tree = labeled(b"http_assets", witness);

        let mut data = vec![];
        let mut serializer = Serializer::new(&mut data);
        serializer.self_describe().unwrap();
        tree.serialize(&mut serializer).unwrap();
        data
    })
}

pub fn put(key: &str, value: &str) {
    let root_hash = TREE.with(|tree| {
        let mut tree = tree.borrow_mut();
        tree.insert(key.to_string(), Sha256::digest(value).into());
        labeled_hash(b"http_assets", &tree.root_hash())
    });

    certified_data_set(root_hash);
}

pub fn pre_upgrade() -> Vec<(String, ICHash)> {
    TREE.with(|c| c.borrow().iter().map(|(k, v)| (k.clone(), *v)).collect())
}

pub fn post_upgrade(tree: Vec<(String, ICHash)>) {
    TREE.with(|c| c.replace(tree.into_iter().collect()));
}
