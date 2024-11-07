use std::{cell::RefCell, thread::LocalKey, time::Duration};

use acl::{Authorize, Authorizer, WithAuthorize};
use anonymization_interface::{
    self as ifc, InitArg, QueryResponse, RegisterResponse, SubmitResponse,
};
use candid::Principal;
use ic_cdk::{id, spawn};
use ic_cdk_timers::set_timer_interval;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use lazy_static::lazy_static;
use queue::{
    Pair, Querier, Query, QueryError, Register, RegisterError, Registrator, Submit, SubmitError,
    Submitter, WithDedupe, WithLeaderAssignment, WithLeaderCheck, WithUnassignLeader,
};
use registry::{Client, List};

mod acl;
mod queue;
mod registry;

type Memory = VirtualMemory<DefaultMemoryImpl>;
type LocalRef<T> = &'static LocalKey<RefCell<T>>;

type StableMap<K, V> = StableBTreeMap<K, V, Memory>;
type StableSet<T> = StableMap<T, ()>;
type StableValue<T> = StableMap<(), T>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

const MEMORY_ID_ALLOWED_PRINCIPALS: u8 = 0;
const MEMORY_ID_PUBLIC_KEYS: u8 = 1;
const MEMORY_ID_QUEUE: u8 = 2;
const MEMORY_ID_ENCRYPTTED_VALUES: u8 = 3;
const MEMORY_ID_LEADER_ASSIGNMENT: u8 = 4;

lazy_static! {
    static ref API_BOUNDARY_NODES_LISTER: Box<dyn List> = {
        let cid = Principal::from(REGISTRY_CANISTER_ID);

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

    static AUTHORIZER: RefCell<Box<dyn Authorize>> = RefCell::new({
        let v = Authorizer::new(&ALLOWED_PRINCIPALS);
        Box::new(v)
    });
}

thread_local! {
    static PUBLIC_KEYS: RefCell<StableMap<Principal, Vec<u8>>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_PUBLIC_KEYS))),
        )
    );

    static QUEUE: RefCell<StableSet<Principal>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_QUEUE))),
        )
    );

    static ENCRYPTED_VALUES: RefCell<StableMap<Principal, Vec<u8>>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ENCRYPTTED_VALUES))),
        )
    );

    static LEADER_ASSIGNMENT: RefCell<StableValue<Principal>> = RefCell::new(
        StableValue::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_LEADER_ASSIGNMENT))),
        )
    );
}

thread_local! {
    static REGISTRATOR: RefCell<Box<dyn Register>> = RefCell::new({
        let v = Registrator::new(&PUBLIC_KEYS, &QUEUE, &ENCRYPTED_VALUES);
        let v = WithUnassignLeader(v, &LEADER_ASSIGNMENT);
        let v = WithDedupe(v, &PUBLIC_KEYS);
        let v = WithAuthorize(v, &AUTHORIZER);
        Box::new(v)
    });

    static QUERIER: RefCell<Box<dyn Query>> = RefCell::new({
        let v = Querier::new(&ENCRYPTED_VALUES);
        let v = WithLeaderAssignment(v, &LEADER_ASSIGNMENT, &QUEUE, &PUBLIC_KEYS, &ENCRYPTED_VALUES);
        let v = WithAuthorize(v, &AUTHORIZER);
        Box::new(v)
    });

    static SUBMITTER: RefCell<Box<dyn Submit>> = RefCell::new({
        let v = Submitter::new(&QUEUE, &ENCRYPTED_VALUES);
        let v = WithLeaderCheck(v, &LEADER_ASSIGNMENT);
        let v = WithAuthorize(v, &AUTHORIZER);
        Box::new(v)
    });
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

            // Remove stale public-keys
            PUBLIC_KEYS.with(|ks| {
                let mut ks = ks.borrow_mut();

                let stale: Vec<Principal> = ks
                    .iter()
                    .filter_map(|(p, _)| (!ids.contains(&p)).then_some(p))
                    .collect();

                for p in stale {
                    ks.remove(&p);
                }
            });

            // Remove stale encrypted values
            ENCRYPTED_VALUES.with(|vs| {
                let mut vs = vs.borrow_mut();

                let stale: Vec<Principal> = vs
                    .iter()
                    .filter_map(|(p, _)| (!ids.contains(&p)).then_some(p))
                    .collect();

                for p in stale {
                    vs.remove(&p);
                }
            });

            // Remove stale queue entries
            QUEUE.with(|q| {
                let mut q = q.borrow_mut();

                let stale: Vec<Principal> = q
                    .iter()
                    .filter_map(|(p, _)| (!ids.contains(&p)).then_some(p))
                    .collect();

                for p in stale {
                    q.remove(&p);
                }
            });
        });
    });

    // Leader
    set_timer_interval(Duration::from_secs(30), || {
        // Collect candidates that have registered a public-key
        let ps: Vec<Principal> =
            PUBLIC_KEYS.with(|ks| ks.borrow().iter().map(|(p, _)| p).collect());

        // Clear previous assignment
        if ps.is_empty() {
            LEADER_ASSIGNMENT.with(|v| v.borrow_mut().remove(&()));
            return;
        }

        // Choose the next leader
        let p = match LEADER_ASSIGNMENT
            .with(|v| {
                v.borrow().get(&()).map(|v| {
                    ps.iter()
                        .position(|&p| p == v)
                        // Select next in line
                        .map(|i| ps.get((i + 1) % ps.len()))
                })
            })
            .flatten()
            .flatten()
        {
            Some(p) => p,

            // Assign first available
            None => &ps[0],
        };

        LEADER_ASSIGNMENT.with(|v| v.borrow_mut().insert((), p.to_owned()));
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
fn register(pubkey: Vec<u8>) -> RegisterResponse {
    match REGISTRATOR.with(|v| v.borrow().register(&pubkey)) {
        Ok(_) => RegisterResponse::Ok,
        Err(err) => RegisterResponse::Err(match err {
            RegisterError::Unauthorized => ifc::RegisterError::Unauthorized,
            RegisterError::UnexpectedError(err) => {
                ifc::RegisterError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[ic_cdk::query]
fn query() -> QueryResponse {
    match QUERIER.with(|v| v.borrow().query()) {
        Ok(v) => QueryResponse::Ok(v),
        Err(err) => QueryResponse::Err(match err {
            QueryError::Unauthorized => ifc::QueryError::Unauthorized,
            QueryError::Unavailable => ifc::QueryError::Unavailable,
            QueryError::LeaderMode(mode, ps) => ifc::QueryError::Leader(
                (&mode).into(),                      // mode
                ps.iter().map(Into::into).collect(), // pairs
            ),
            QueryError::UnexpectedError(err) => ifc::QueryError::UnexpectedError(err.to_string()),
        }),
    }
}

#[ic_cdk::update]
fn submit(vs: Vec<ifc::Pair>) -> SubmitResponse {
    // Convert input
    let vs: Vec<Pair> = vs.iter().map(Into::into).collect();

    match SUBMITTER.with(|v| v.borrow().submit(&vs)) {
        Ok(_) => SubmitResponse::Ok,
        Err(err) => SubmitResponse::Err(match err {
            SubmitError::Unauthorized => ifc::SubmitError::Unauthorized,
            SubmitError::UnexpectedError(err) => ifc::SubmitError::UnexpectedError(err.to_string()),
        }),
    }
}
