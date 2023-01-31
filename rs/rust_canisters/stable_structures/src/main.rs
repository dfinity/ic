use std::{cell::RefCell, ops::Range};

use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};

thread_local! {
    pub static STABLE_MAP: RefCell<StableBTreeMap<u64, u64, DefaultMemoryImpl>> = RefCell::new(
        StableBTreeMap::init( DefaultMemoryImpl::default())
    );
}

fn increment_values(range: Range<u64>) {
    STABLE_MAP.with(|map| {
        let mut map = map.borrow_mut();
        for i in range {
            match map.get(&i) {
                None => map.insert(i, i),
                Some(current) => map.insert(i, current + 1),
            }
            .expect("Error inserting into stable map");
        }
    })
}

#[ic_cdk_macros::update]
fn update_increment_values(entries_to_update: u64) {
    increment_values(0..entries_to_update)
}

#[ic_cdk_macros::init]
fn init(initial_entry_count: u64) {
    increment_values(0..initial_entry_count)
}

fn main() {}
