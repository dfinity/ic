use std::{cell::RefCell, thread::LocalKey, time::Duration};

use acl::{Authorize, Authorizer, WithAuthorize};
use anonymization_interface::{
    self as ifc, HeaderField, HttpRequest, HttpResponse, InitArg, QueryResponse, RegisterResponse,
    SubmitResponse,
};
use candid::Principal;
use ic_cdk::{
    api::{call::accept_message, stable::WASM_PAGE_SIZE_IN_BYTES, time},
    caller, id, spawn, trap,
};
use ic_cdk_timers::set_timer_interval;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use lazy_static::lazy_static;
use prometheus::{CounterVec, Encoder, Gauge, Opts, Registry, TextEncoder};
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

// Metrics

const SERVICE_NAME: &str = "backend";

thread_local! {
    static COUNTER_AUTHORIZE_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_authorize_total"), // name
            "number of times authorize was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_REGISTER_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_register_total"), // name
            "number of times register was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_SUBMIT_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_submit_total"), // name
            "number of times submit was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_LIST_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_list_total"), // name
            "number of times list was called", // help
        ), &["status"]).unwrap()
    });

    static GAUGE_ALLOWED_PRINCIPALS_TOTAL: RefCell<Gauge> = RefCell::new({
        Gauge::new(
            format!("{SERVICE_NAME}_allowed_principals_total"), // name
            "total number of allowed principals", // help
        ).unwrap()
    });

    static GAUGE_QUEUE_TOTAL: RefCell<Gauge> = RefCell::new({
        Gauge::new(
            format!("{SERVICE_NAME}_queue_total"), // name
            "total number of queue entries", // help
        ).unwrap()
    });

    static GAUGE_CANISTER_CYCLES_BALANCE: RefCell<Gauge> = RefCell::new({
        Gauge::new(
            format!("{SERVICE_NAME}_canister_cycles_balance"), // name
            "cycles balance available to the canister", // help
        ).unwrap()
    });

    static GAUGE_CANISTER_STABLE_BYTES_TOTAL: RefCell<Gauge> = RefCell::new({
        Gauge::new(
            format!("{SERVICE_NAME}_canister_stable_bytes_total"), // name
            "stable memory byte size", // help
        ).unwrap()
    });

    static GAUGE_CANISTER_LAST_UPDATE_SECS: RefCell<Gauge> = RefCell::new({
        Gauge::new(
            format!("{SERVICE_NAME}_last_update_secs"), // name
            "timestamp in seconds of the last canister update", // help
        ).unwrap()
    });

    static METRICS_REGISTRY: RefCell<Registry> = RefCell::new({
        let r = Registry::new();

        COUNTER_REGISTER_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_AUTHORIZE_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_SUBMIT_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_LIST_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        GAUGE_QUEUE_TOTAL.with(|g| {
            let g = Box::new(g.borrow().to_owned());
            r.register(g).unwrap();
        });

        GAUGE_ALLOWED_PRINCIPALS_TOTAL.with(|g| {
            let g = Box::new(g.borrow().to_owned());
            r.register(g).unwrap();
        });

        GAUGE_CANISTER_CYCLES_BALANCE.with(|g| {
            let g = Box::new(g.borrow().to_owned());
            r.register(g).unwrap();
        });

        GAUGE_CANISTER_STABLE_BYTES_TOTAL.with(|g| {
            let g = Box::new(g.borrow().to_owned());
            r.register(g).unwrap();
        });

        GAUGE_CANISTER_LAST_UPDATE_SECS.with(|g| {
            let g = Box::new(g.borrow().to_owned());
            r.register(g).unwrap();
        });

        r
    });
}

pub struct WithLogs<T>(pub T);
pub struct WithMetrics<T>(pub T, LocalRef<CounterVec>);

lazy_static! {
    static ref API_BOUNDARY_NODES_LISTER: Box<dyn List> = {
        let cid = Principal::from(REGISTRY_CANISTER_ID);

        let v = Client::new(cid);
        let v = WithLogs(v);
        let v = WithMetrics(v, &COUNTER_LIST_TOTAL);
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
        let v = WithMetrics(v, &COUNTER_AUTHORIZE_TOTAL);
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
        let v = WithMetrics(v, &COUNTER_REGISTER_TOTAL);
        let v = WithLogs(v);
        Box::new(v)
    });

    static QUERIER: RefCell<Box<dyn Query>> = RefCell::new({
        let v = Querier::new(&ENCRYPTED_VALUES);
        let v = WithLeaderAssignment(v, &LEADER_ASSIGNMENT, &QUEUE, &PUBLIC_KEYS, &ENCRYPTED_VALUES);
        let v = WithAuthorize(v, &AUTHORIZER);
        let v = WithLogs(v);
        Box::new(v)
    });

    static SUBMITTER: RefCell<Box<dyn Submit>> = RefCell::new({
        let v = Submitter::new(&QUEUE, &ENCRYPTED_VALUES);
        let v = WithLeaderCheck(v, &LEADER_ASSIGNMENT);
        let v = WithAuthorize(v, &AUTHORIZER);
        let v = WithMetrics(v, &COUNTER_SUBMIT_TOTAL);
        let v = WithLogs(v);
        Box::new(v)
    });
}

// Timers

const SECOND: Duration = Duration::from_secs(1);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn timers() {
    // ACLs
    set_timer_interval(10 * SECOND, || {
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

                // Self authorize
                ps.insert(id(), ());

                // Authorize API Boundary Nodes
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

    // TTLs
    set_timer_interval(7 * DAY, || {
        // Remove all encrypted values
        let ids = ENCRYPTED_VALUES.with(|vs| {
            let mut vs = vs.borrow_mut();

            let ids: Vec<_> = vs.iter().map(|(k, _)| k).collect();
            vs.clear_new();

            ids
        });

        // Re-queue
        QUEUE.with(|q| {
            let mut q = q.borrow_mut();

            for id in ids {
                q.insert(
                    id, // principal
                    (), // unit
                );
            }
        });
    });

    // Leader
    set_timer_interval(30 * SECOND, || {
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
    // Start timers
    timers();

    // Set update time
    GAUGE_CANISTER_LAST_UPDATE_SECS.with(|g| g.borrow_mut().set((time() as f64 / 1e9).trunc()));
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    // Start timers
    timers();

    // Set update time
    GAUGE_CANISTER_LAST_UPDATE_SECS.with(|g| g.borrow_mut().set((time() as f64 / 1e9).trunc()));
}

#[ic_cdk::inspect_message]
fn inspect_message() {
    (&AUTHORIZER)
        .authorize(&caller())
        .err()
        .inspect(|err| trap(&err.to_string()));

    accept_message();
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
            QueryError::LeaderDuty(mode, ps) => ifc::QueryError::LeaderDuty(
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

// Metrics

#[ic_cdk::query]
fn http_request(request: HttpRequest) -> HttpResponse {
    if request.url != "/metrics" {
        return HttpResponse {
            status_code: 404,
            headers: vec![],
            body: "404 Not Found".as_bytes().to_owned(),
        };
    }

    if request.method.to_lowercase() != "get" {
        return HttpResponse {
            status_code: 405,
            headers: vec![HeaderField("Allow".into(), "GET".into())],
            body: "405 Method Not Allowed".as_bytes().to_owned(),
        };
    }

    // Set Gauges
    QUEUE.with(|q| {
        GAUGE_QUEUE_TOTAL.with(|g| g.borrow_mut().set(q.borrow().len() as f64));
    });

    ALLOWED_PRINCIPALS.with(|ps| {
        GAUGE_ALLOWED_PRINCIPALS_TOTAL.with(|g| g.borrow_mut().set(ps.borrow().len() as f64));
    });

    GAUGE_CANISTER_CYCLES_BALANCE
        .with(|g| g.borrow_mut().set(ic_cdk::api::canister_balance() as f64));

    GAUGE_CANISTER_STABLE_BYTES_TOTAL.with(|g| {
        g.borrow_mut()
            .set((ic_cdk::api::stable::stable_size() * WASM_PAGE_SIZE_IN_BYTES) as f64)
    });

    // Export metrics
    let bs = METRICS_REGISTRY.with(|r| {
        let mfs = r.borrow().gather();

        let mut buffer = vec![];
        let enc = TextEncoder::new();

        if let Err(err) = enc.encode(&mfs, &mut buffer) {
            trap(&format!("failed to encode metrics: {err}"));
        };

        buffer
    });

    HttpResponse {
        status_code: 200,
        headers: vec![],
        body: bs,
    }
}
