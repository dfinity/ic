use std::{cell::RefCell, ops::Deref};

use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableVec};

// This canister uses conflicting stores in stable memory to avoid measuring
// the overhead of the `MemoryManager`.  Only one structure can actually be
// used in any given installation of the canister.
thread_local! {
    pub static STABLE_BTREE_U64: RefCell<StableBTreeMap<u64, u64, DefaultMemoryImpl>> =
      RefCell::new(StableBTreeMap::init(DefaultMemoryImpl::default()));

    pub static STABLE_VEC_U64: RefCell<StableVec<u64, DefaultMemoryImpl>> =
      RefCell::new(StableVec::init(DefaultMemoryImpl::default()).expect("Unable to create Vec memory"));
}

// For each structure we have 4 operations: repeated read, sparse read, repeated
// write, sparse write. Reads operate in query mode, writes/insert in
// update mode.  Sparse operations can be made to roughly touch a new OS page on
// each iteration of the loop.

// BTree Operations

#[ic_cdk::query]
fn query_btree_u64_single_read(count: u32) {
    STABLE_BTREE_U64.with(|map| {
        let map = map.borrow();
        for _ in 0..count {
            map.get(&0).unwrap();
        }
    })
}

#[ic_cdk::query]
fn query_btree_u64_sparse_read(count: u32) {
    STABLE_BTREE_U64.with(|map| {
        let map = map.borrow();
        let length = map.len();
        let step = length / count as u64;
        for i in (0..length).step_by(step as usize) {
            map.get(&i).unwrap();
        }
    })
}

#[ic_cdk::update]
fn update_btree_u64_single_write(count: u32) {
    STABLE_BTREE_U64.with(|map| {
        let mut map = map.borrow_mut();
        for i in 0..count {
            map.insert(0, i as u64).unwrap();
        }
    })
}

#[ic_cdk::update]
fn update_btree_u64_sparse_write(count: u32) {
    STABLE_BTREE_U64.with(|map| {
        let mut map = map.borrow_mut();
        let length = map.len();
        let step = length / count as u64;
        for i in (0..length).step_by(step as usize) {
            map.insert(i, i).unwrap();
        }
    })
}

fn btree_u64_insert(count: u32) {
    STABLE_BTREE_U64.with(|map| {
        let mut map = map.borrow_mut();
        for i in 0..count {
            map.insert(i as u64, 1);
        }
    })
}

#[ic_cdk::update]
fn update_btree_u64_insert(count: u32) {
    btree_u64_insert(count)
}

// Vector Operations

#[ic_cdk::query]
fn query_vec_u64_single_read(count: u32) {
    STABLE_VEC_U64.with(|vec| {
        let vec = vec.borrow();
        for _ in 0..count {
            vec.get(0).unwrap();
        }
    })
}

#[ic_cdk::query]
fn query_vec_u64_sparse_read(count: u32) {
    STABLE_VEC_U64.with(|vec| {
        let vec = vec.borrow();
        let length = vec.len();
        let step = length / count as u64;
        for i in (0..length).step_by(step as usize) {
            vec.get(i).unwrap();
        }
    })
}

#[ic_cdk::update]
fn update_vec_u64_single_write(count: u32) {
    STABLE_VEC_U64.with(|vec| {
        let vec = vec.borrow();
        for i in 0..count {
            vec.set(0, &(i as u64));
        }
    })
}

#[ic_cdk::update]
fn update_vec_u64_sparse_write(count: u32) {
    STABLE_VEC_U64.with(|vec| {
        let vec = vec.borrow();
        let length = vec.len();
        let step = length / count as u64;
        for i in (0..length).step_by(step as usize) {
            vec.set(i, &i);
        }
    })
}

fn vec_u64_insert(count: u32) {
    STABLE_VEC_U64.with(|vec| {
        let vec = vec.borrow();
        for _ in 0..count {
            vec.push(&1).unwrap();
        }
    })
}

#[ic_cdk::update]
fn update_vec_u64_insert(count: u32) {
    vec_u64_insert(count)
}

#[ic_cdk::update]
fn update_empty() {}

#[ic_cdk::query]
fn query_empty() {}

#[ic_cdk::init]
fn init(structure: String, count: u32) {
    match structure.deref() {
        "btree_u64" => btree_u64_insert(count),
        "vec_u64" => vec_u64_insert(count),
        "none" => {}
        _ => panic!("Invalid structure {structure}"),
    }
}

fn main() {}
