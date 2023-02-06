use std::cell::RefCell;

use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};

thread_local! {
    pub static STABLE_MAP: RefCell<StableBTreeMap<u64, u64, DefaultMemoryImpl>> = RefCell::new(
        StableBTreeMap::init(DefaultMemoryImpl::default())
    );
}

fn increment_values(range: impl Iterator<Item = u64>) {
    STABLE_MAP.with(|map| {
        let mut map = map.borrow_mut();
        for i in range {
            match map.get(&i) {
                None => map.insert(i, i),
                Some(current) => map.insert(i, current + 1),
            };
        }
    })
}

fn increment_one_value(count: u32) {
    STABLE_MAP.with(|map| {
        let mut map = map.borrow_mut();
        for _ in 0..(count as usize) {
            match map.get(&0) {
                None => map.insert(0, 0),
                Some(current) => map.insert(0, current + 1),
            };
        }
    })
}

fn write_values(range: impl Iterator<Item = u64>) {
    STABLE_MAP.with(|map| {
        let mut map = map.borrow_mut();
        for i in range {
            map.insert(i, 123_456);
        }
    })
}

// Updates

#[ic_cdk_macros::update]
fn update_empty() {}

#[ic_cdk_macros::update]
fn update_write_values(entries_to_update: u64) {
    write_values(0..entries_to_update)
}

#[ic_cdk_macros::update]
fn update_increment_one_value(count: u32) {
    increment_one_value(count)
}

#[ic_cdk_macros::update]
fn update_increment_values_seq(entries_to_update: u64) {
    increment_values(0..entries_to_update)
}

#[ic_cdk_macros::update]
fn update_increment_values_sparse(entries_to_update: u64, skip: u64) {
    increment_values((0..(entries_to_update * skip)).skip(skip as usize))
}

// Queries

#[ic_cdk_macros::query]
fn query_empty() {}

#[ic_cdk_macros::query]
fn query_write_values(entries_to_update: u64) {
    write_values(0..entries_to_update)
}

#[ic_cdk_macros::query]
fn query_increment_one_value(count: u32) {
    increment_one_value(count)
}

#[ic_cdk_macros::query]
fn query_increment_values_seq(entries_to_update: u64) {
    increment_values(0..entries_to_update)
}

#[ic_cdk_macros::query]
fn query_increment_values_sparse(entries_to_update: u64, skip: u64) {
    increment_values((0..(entries_to_update * skip)).skip(skip as usize))
}

// Initialization

#[ic_cdk_macros::init]
fn init(initial_entry_count: u64) {
    increment_values(0..initial_entry_count)
}

fn main() {}
