use candid::Encode;
use certificate_orchestrator_interface::{
    BoundedString, ExportPackage, IcCertificate, Id, LABEL_DOMAINS, LEFT_GUARD, RIGHT_GUARD,
};
use ic_cdk::api::{certified_data_set, data_certificate};
use ic_certified_map::{AsHashTree, Hash as ICHash, RbTree, labeled, labeled_hash};
use serde::Serialize;
use serde_cbor::Serializer;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, convert::AsRef};

thread_local! {
    static CERT_TREE: RefCell<RbTree<Id, ICHash>> = const { RefCell::new(RbTree::new()) };
}

pub fn init_cert_tree() {
    CERT_TREE.with(|tree| {
        let mut tree = tree.borrow_mut();
        let value: Vec<u8> = Vec::new();
        tree.insert(LEFT_GUARD.into(), Sha256::digest(&value).into());
        tree.insert(RIGHT_GUARD.into(), Sha256::digest(&value).into());
        certified_data_set(labeled_hash(LABEL_DOMAINS, &tree.root_hash()));
    });
}

pub fn set_root_hash() {
    let root_hash = CERT_TREE.with(|tree| labeled_hash(LABEL_DOMAINS, &tree.borrow().root_hash()));
    certified_data_set(root_hash);
}

pub fn remove_cert(key: BoundedString<64>) {
    CERT_TREE.with(|tree| tree.borrow_mut().delete((String::from(key)).as_ref()));
}

pub fn add_cert(key: BoundedString<64>, pkg: &ExportPackage) {
    let value: Vec<u8> = Encode!(pkg).unwrap();
    CERT_TREE.with(|tree| {
        tree.borrow_mut()
            .insert(key.into(), Sha256::digest(&value).into())
    });
}

pub fn get_cert_for_range(first: &Id, last: &Id) -> IcCertificate {
    CERT_TREE.with(|tree| {
        let tree = tree.borrow();
        let witness = tree.value_range(first.as_ref(), last.as_ref());
        let tree = labeled(LABEL_DOMAINS, witness);
        let mut data = vec![];
        let mut serializer = Serializer::new(&mut data);
        serializer.self_describe().unwrap();
        tree.serialize(&mut serializer).unwrap();
        IcCertificate {
            cert: data_certificate().unwrap(),
            tree: data,
        }
    })
}
