use std::{cell::RefCell, time::Duration};

use anonymization_interface::{
    self as ifc, InitArg, QueryResponse, RegisterResponse, SubmitResponse,
};
use candid::Principal;
use ic_cdk::{id, spawn};
use ic_cdk_timers::set_timer_interval;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use lazy_static::lazy_static;
use registry::{Client, List};

mod registry;

type Memory = VirtualMemory<DefaultMemoryImpl>;

type StableMap<K, V> = StableBTreeMap<K, V, Memory>;
type StableSet<T> = StableMap<T, ()>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

const REGISTRY_CANISTER_ID: &str = "bnz7o-iuaaa-aaaaa-qaaaa-cai";

const MEMORY_ID_ALLOWED_PRINCIPALS: u8 = 0;

lazy_static! {
    static ref API_BOUNDARY_NODES_LISTER: Box<dyn List> = {
        let cid =
            Principal::from_text(REGISTRY_CANISTER_ID).expect("failed to construct principal");

        let v = Client::new(cid);
        Box::new(v)
    };
}

thread_local! {
    static ALLOWED_PRINCIPALS: RefCell<StableSet<Principal>> = RefCell::new(
        StableSet::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ALLOWED_PRINCIPALS))),
        )
    );
}

// Timers

fn timers() {
    // ACLs
    set_timer_interval(Duration::from_secs(10), || {
        // Switch to async
        spawn(async {
            // List registry entries
            let ids = match API_BOUNDARY_NODES_LISTER.list().await {
                Ok(ids) => ids,

                // Abort on failure
                Err(_) => return,
            };

            // Update allowed principals
            ALLOWED_PRINCIPALS.with(|ps| {
                let mut ps = ps.borrow_mut();

                // Clear allowed principals
                ps.clear_new();

                ids.iter().for_each(|p| {
                    ps.insert(p.to_owned(), ());
                });
            });
        });
    });
}

// Service

#[allow(dead_code)]
fn main() {}

#[ic_cdk::init]
fn init(_arg: InitArg) {
    // Self-authorize
    ALLOWED_PRINCIPALS.with(|m| {
        m.borrow_mut().insert(
            id(), // canister id
            (),   // unit
        )
    });

    // Start timers
    timers();
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    // Start timers
    timers();
}

#[ic_cdk::update]
fn register(_pubkey: Vec<u8>) -> RegisterResponse {
    unimplemented!()
}

#[ic_cdk::query]
fn query() -> QueryResponse {
    unimplemented!()
}

#[ic_cdk::update]
fn submit(_vs: Vec<ifc::Pair>) -> SubmitResponse {
    unimplemented!()
}
