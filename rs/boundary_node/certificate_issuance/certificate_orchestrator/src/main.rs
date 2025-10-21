use std::{cell::RefCell, cmp::Reverse, collections::BTreeMap, thread::LocalKey, time::Duration};

use candid::{Principal, candid_method};
use certificate_orchestrator_interface::{
    BoundedString, CreateRegistrationError, CreateRegistrationResponse, DispenseTaskError,
    DispenseTaskResponse, EncryptedPair, ExportCertificatesCertifiedResponse,
    ExportCertificatesError, ExportCertificatesResponse, ExportPackage, GetCertificateError,
    GetCertificateResponse, GetRegistrationError, GetRegistrationResponse, HeaderField,
    HttpRequest, HttpResponse, Id, InitArg, ListAllowedPrincipalsError,
    ListAllowedPrincipalsResponse, ListRegistrationsError, ListRegistrationsResponse,
    ListTasksError, ListTasksResponse, ModifyAllowedPrincipalError, ModifyAllowedPrincipalResponse,
    Name, PeekTaskError, PeekTaskResponse, QueueTaskError, QueueTaskResponse, Registration,
    RemoveRegistrationError, RemoveRegistrationResponse, RemoveTaskError, RemoveTaskResponse,
    State, UpdateRegistrationError, UpdateRegistrationResponse, UpdateType, UploadCertificateError,
    UploadCertificateResponse,
};
use ic_cdk::{
    api::{canister_self, msg_caller, time},
    post_upgrade, pre_upgrade, trap,
};
use ic_cdk::{init, query, update};
use ic_cdk_timers::set_timer_interval;
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
};
use priority_queue::PriorityQueue;
use prometheus::{CounterVec, Encoder, Gauge, GaugeVec, Opts, Registry, TextEncoder};
use work::{Peek, PeekError, TaskRemover};

use crate::{
    acl::{Authorize, AuthorizeError, Authorizer, WithAuthorize},
    certificate::{
        CertGetter, Export, ExportError, Exporter, GetCert, GetCertError, Upload, UploadError,
        UploadWithIcCertification, Uploader,
    },
    ic_certification::{add_cert, init_cert_tree, set_root_hash},
    id::{Generate, Generator},
    rate_limiter::WithRateLimit,
    registration::{
        Create, CreateError, Creator, Expire, Expirer, Get, GetError, Getter, Remove, RemoveError,
        Remover, Update, UpdateError, UpdateWithIcCertification, Updater,
    },
    work::{Dispense, DispenseError, Dispenser, Peeker, Queue, QueueError, Queuer, Retrier, Retry},
};

mod acl;
mod certificate;
mod ic_certification;
mod id;
mod persistence;
mod rate_limiter;
mod registration;
mod work;

// Stable Memory

type Memory = VirtualMemory<DefaultMemoryImpl>;
type LocalRef<T> = &'static LocalKey<RefCell<T>>;

type StableMap<K, V> = StableBTreeMap<K, V, Memory>;
type StableSet<T> = StableMap<T, ()>;
type StableValue<T> = StableMap<(), T>;

// Storables

type StorablePrincipal = BoundedString<63>;
type StorableId = BoundedString<64>;

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

const REGISTRATION_RATE_LIMIT_RATE: u32 = 5; // 5 subdomain registrations per hour
const REGISTRATION_RATE_LIMIT_PERIOD: Duration = Duration::from_secs(HOUR); // 1 hour

// Memory
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

const MEMORY_ID_ROOT_PRINCIPALS: u8 = 0;
const MEMORY_ID_ALLOWED_PRINCIPALS: u8 = 1;
const MEMORY_ID_ID_COUNTER: u8 = 2;
const MEMORY_ID_ID_SEED: u8 = 3;
const MEMORY_ID_REGISTRATIONS: u8 = 4;
const MEMORY_ID_NAMES: u8 = 5;
const MEMORY_ID_ENCRYPTED_CERTIFICATES: u8 = 6;
const MEMORY_ID_TASKS: u8 = 7;
const MEMORY_ID_EXPIRATIONS: u8 = 8;
const MEMORY_ID_RETRIES: u8 = 9;
const MEMORY_ID_REGISTRATION_EXPIRATION_TTL: u8 = 10;
const MEMORY_ID_IN_PROGRESS_TTL: u8 = 11;
const MEMORY_ID_MANAGEMENT_TASK_INTERVAL: u8 = 12;

const SUFFIX_LIST_STR: &str = include_str!("../public_suffix_list.dat");

// Metrics

const SERVICE_NAME: &str = "certificate_orchestrator";

thread_local! {
    static COUNTER_CREATE_REGISTRATION_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_create_registration_total"), // name
            "number of times create_registration was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_UPDATE_REGISTRATION_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_update_registration_total"), // name
            "number of times update_registration was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_REMOVE_REGISTRATION_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_remove_registration_total"), // name
            "number of times remove_registration was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_UPLOAD_CERTIFICATE_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_upload_certificate_total"), // name
            "number of times upload_certificate was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_QUEUE_TASK_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_queue_task_total"), // name
            "number of times queue_task was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_PEEK_TASK_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_peek_task_total"), // name
            "number of times peek_task was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_DISPENSE_TASK_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_dispense_task_total"), // name
            "number of times dispense_task was called", // help
        ), &["status"]).unwrap()
    });

    static COUNTER_REMOVE_TASK_TOTAL: RefCell<CounterVec> = RefCell::new({
        CounterVec::new(Opts::new(
            format!("{SERVICE_NAME}_remove_task_total"), // name
            "number of times remove_task was called", // help
        ), &["status"]).unwrap()
    });

    static GAUGE_REGISTRATIONS_TOTAL: RefCell<GaugeVec> = RefCell::new({
        GaugeVec::new(Opts::new(
            format!("{SERVICE_NAME}_registrations_total"), // name
            "total number of registrations", // help
        ), &["state"]).unwrap()
    });

    static GAUGE_TASKS_TOTAL: RefCell<Gauge> = RefCell::new({
        Gauge::new(
            format!("{SERVICE_NAME}_tasks_total"), // name
            "total number of tasks", // help
        ).unwrap()
    });

    static GAUGE_ALLOWED_PRINCIPALS_TOTAL: RefCell<Gauge> = RefCell::new({
        Gauge::new(
            format!("{SERVICE_NAME}_allowed_principals_total"), // name
            "total number of allowed principals", // help
        ).unwrap()
    });

    static GAUGE_CANISTER_CYCLES_BALANCE: RefCell<Gauge> = RefCell::new({
        Gauge::new(
            format!("{SERVICE_NAME}_canister_cycles_balance"), // name
            "cycles balance available to the canister", // help
        ).unwrap()
    });

    static METRICS_REGISTRY: RefCell<Registry> = RefCell::new({
        let r = Registry::new();

        COUNTER_CREATE_REGISTRATION_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_UPDATE_REGISTRATION_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_REMOVE_REGISTRATION_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_UPLOAD_CERTIFICATE_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_QUEUE_TASK_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_PEEK_TASK_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_DISPENSE_TASK_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        COUNTER_REMOVE_TASK_TOTAL.with(|c| {
            let c = Box::new(c.borrow().to_owned());
            r.register(c).unwrap();
        });

        GAUGE_REGISTRATIONS_TOTAL.with(|g| {
            let g = Box::new(g.borrow().to_owned());
            r.register(g).unwrap();
        });

        GAUGE_TASKS_TOTAL.with(|g| {
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

        r
    });
}

pub struct WithMetrics<T>(pub T, LocalRef<CounterVec>);

// ACLs
thread_local! {
    static ROOT_PRINCIPALS: RefCell<StableSet<StorablePrincipal>> = RefCell::new(
        StableSet::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ROOT_PRINCIPALS))),
        )
    );

    static ROOT_AUTHORIZER: RefCell<Box<dyn Authorize>> = RefCell::new({
        let a = Authorizer::new(&ROOT_PRINCIPALS);
        Box::new(a)
    });
}

thread_local! {
    static ALLOWED_PRINCIPALS: RefCell<StableSet<StorablePrincipal>> = RefCell::new(
        StableSet::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ALLOWED_PRINCIPALS))),
        )
    );

    static MAIN_AUTHORIZER: RefCell<Box<dyn Authorize>> = RefCell::new({
        let a = Authorizer::new(&ALLOWED_PRINCIPALS);
        Box::new(a)
    });
}

// ID Generation
thread_local! {
    static ID_COUNTER: RefCell<StableValue<u128>> = RefCell::new(
        StableValue::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ID_COUNTER))),
        )
    );

    static ID_SEED: RefCell<StableValue<u128>> = RefCell::new(
        StableValue::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ID_SEED))),
        )
    );

    static ID_GENERATOR: RefCell<Box<dyn Generate>> = RefCell::new({
        let g = Generator::new(&ID_COUNTER, &ID_SEED);
        Box::new(g)
    });
}

// Registrations
thread_local! {
    static REGISTRATIONS: RefCell<StableMap<StorableId, Registration>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_REGISTRATIONS))),
        )
    );

    static NAMES: RefCell<StableMap<Name, StorableId>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_NAMES))),
        )
    );

    static ENCRYPTED_CERTIFICATES: RefCell<StableMap<StorableId, EncryptedPair>> = RefCell::new(
        StableMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ENCRYPTED_CERTIFICATES))),
        )
    );

    static TASKS: RefCell<PriorityQueue<Id, Reverse<u64>>> = RefCell::new(PriorityQueue::new());

    static EXPIRATIONS: RefCell<PriorityQueue<Id, Reverse<u64>>> = RefCell::new(PriorityQueue::new());

    static RETRIES: RefCell<PriorityQueue<Id, Reverse<u64>>> = RefCell::new(PriorityQueue::new());

    // Rate limiting for CREATOR
    static AVAILABLE_TOKENS: RefCell<BTreeMap<String, u32>> = const { RefCell::new(BTreeMap::new()) };

    static CREATOR: RefCell<Box<dyn Create>> = RefCell::new({
        let c = Creator::new(&ID_GENERATOR, &REGISTRATIONS, &NAMES, &EXPIRATIONS);
        let c = WithRateLimit::new(c, REGISTRATION_RATE_LIMIT_RATE, &AVAILABLE_TOKENS, SUFFIX_LIST_STR.parse().unwrap());
        let c = WithAuthorize(c, &MAIN_AUTHORIZER);
        let c = WithMetrics(c, &COUNTER_CREATE_REGISTRATION_TOTAL);
        Box::new(c)
    });

    static GETTER: RefCell<Box<dyn Get>> = RefCell::new({
        let g = Getter::new(&REGISTRATIONS);
        let g = WithAuthorize(g, &MAIN_AUTHORIZER);
        Box::new(g)
    });

    static UPDATER: RefCell<Box<dyn Update>> = RefCell::new({
        let u = Updater::new(&REGISTRATIONS, &EXPIRATIONS, &RETRIES);
        let u = UpdateWithIcCertification::new(u, &ENCRYPTED_CERTIFICATES, &REGISTRATIONS);
        let u = WithAuthorize(u, &MAIN_AUTHORIZER);
        let u = WithMetrics(u, &COUNTER_UPDATE_REGISTRATION_TOTAL);
        Box::new(u)
    });

    static REMOVER: RefCell<Box<dyn Remove>> = RefCell::new({
        let r = Remover::new(&REGISTRATIONS, &NAMES, &TASKS, &EXPIRATIONS, &RETRIES, &ENCRYPTED_CERTIFICATES);
        let r = WithAuthorize(r, &MAIN_AUTHORIZER);
        let r = WithMetrics(r, &COUNTER_REMOVE_REGISTRATION_TOTAL);
        Box::new(r)
    });

    static REGISTRATION_LISTER: RefCell<Box<dyn registration::List>> = RefCell::new({
        let v = registration::Lister::new(&REGISTRATIONS);
        let v = WithAuthorize(v, &ROOT_AUTHORIZER);
        Box::new(v)
    });
}

// Certificates
thread_local! {
    static UPLOADER: RefCell<Box<dyn Upload>> = RefCell::new({
        let u = Uploader::new(&ENCRYPTED_CERTIFICATES, &REGISTRATIONS);
        let u = UploadWithIcCertification::new(u, &REGISTRATIONS);
        let u = WithAuthorize(u, &MAIN_AUTHORIZER);
        let u = WithMetrics(u, &COUNTER_UPLOAD_CERTIFICATE_TOTAL);
        Box::new(u)
    });

    static EXPORTER: RefCell<Box<dyn Export>> = RefCell::new({
        let e = Exporter::new(&ENCRYPTED_CERTIFICATES, &REGISTRATIONS);
        let e = WithAuthorize(e, &MAIN_AUTHORIZER);
        Box::new(e)
    });

    static CERT_GETTER: RefCell<Box<dyn GetCert>> = RefCell::new({
        let c = CertGetter::new(&ENCRYPTED_CERTIFICATES);
        let c = WithAuthorize(c, &MAIN_AUTHORIZER);
        Box::new(c)
    });
}

// Tasks

thread_local! {
    static QUEUER: RefCell<Box<dyn Queue>> = RefCell::new({
        let q = Queuer::new(&TASKS, &REGISTRATIONS);
        let q = WithAuthorize(q, &MAIN_AUTHORIZER);
        let q = WithMetrics(q, &COUNTER_QUEUE_TASK_TOTAL);
        Box::new(q)
    });

    static PEEKER: RefCell<Box<dyn Peek>> = RefCell::new({
        let d = Peeker::new(&TASKS);
        let d = WithAuthorize(d, &MAIN_AUTHORIZER);
        let d = WithMetrics(d, &COUNTER_PEEK_TASK_TOTAL);
        Box::new(d)
    });

    static TASK_LISTER: RefCell<Box<dyn work::List>> = RefCell::new({
        let v = work::Lister::new(&TASKS, &REGISTRATIONS);
        let v = WithAuthorize(v, &ROOT_AUTHORIZER);
        Box::new(v)
    });

    static DISPENSER: RefCell<Box<dyn Dispense>> = RefCell::new({
        let d = Dispenser::new(&TASKS, &RETRIES);
        let d = WithAuthorize(d, &MAIN_AUTHORIZER);
        let d = WithMetrics(d, &COUNTER_DISPENSE_TASK_TOTAL);
        Box::new(d)
    });

    static TASK_REMOVER: RefCell<Box<dyn work::Remove>> = RefCell::new({
        let v = TaskRemover::new(&TASKS);
        let v = WithAuthorize(v, &ROOT_AUTHORIZER);
        let v = WithMetrics(v, &COUNTER_REMOVE_TASK_TOTAL);
        Box::new(v)
    });
}

// Expirations and retries

thread_local! {
    static REGISTRATION_EXPIRATION_TTL: RefCell<StableValue<u64>> = RefCell::new(
        StableValue::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_REGISTRATION_EXPIRATION_TTL))),
        )
    );

    static IN_PROGRESS_TTL: RefCell<StableValue<u64>> = RefCell::new(
        StableValue::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_IN_PROGRESS_TTL))),
        )
    );

    static EXPIRER: RefCell<Box<dyn Expire>> = RefCell::new({
        let e = Expirer::new(&REMOVER, &EXPIRATIONS);
        Box::new(e)
    });

    static RETRIER: RefCell<Box<dyn Retry>> = RefCell::new({
        let r = Retrier::new(&TASKS, &RETRIES);
        Box::new(r)
    });
}

// Management task interval

thread_local! {
    static MANAGEMENT_TASK_INTERVAL: RefCell<StableValue<u64>> = RefCell::new(
        StableValue::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_MANAGEMENT_TASK_INTERVAL))),
        )
    );
}

// main() is empty and present because our Bazel build setup requires
// canisters to be in a main.rs file. Otherwise we would default to a lib.rs
// as is usually done for canister projects.
fn main() {}

// Timers

fn init_timers_fn() {
    let interval =
        Duration::from_secs(MANAGEMENT_TASK_INTERVAL.with(|s| s.borrow().get(&()).unwrap()));

    set_timer_interval(interval, || {
        if let Err(err) = EXPIRER.with(|e| e.borrow().expire(time())) {
            trap(format!("failed to run expire: {err}"));
        }
    });

    set_timer_interval(interval, || {
        if let Err(err) = RETRIER.with(|r| r.borrow().retry(time())) {
            trap(format!("failed to run retry: {err}"));
        }
    });

    // update the available tokens for rate limiting
    set_timer_interval(
        REGISTRATION_RATE_LIMIT_PERIOD / REGISTRATION_RATE_LIMIT_RATE,
        || {
            AVAILABLE_TOKENS.with(|at| {
                let mut at = at.borrow_mut();

                // clean the items with no tokens used
                at.retain(|_, tokens| *tokens < REGISTRATION_RATE_LIMIT_RATE);

                // add a token to all items left
                for (_, tokens) in at.iter_mut() {
                    *tokens += 1;
                }
            });
        },
    );
}

// Init / Upgrade

#[init]
#[candid_method(init)]
fn init_fn(
    InitArg {
        root_principals,
        id_seed,
        registration_expiration_ttl,
        in_progress_ttl,
        management_task_interval,
    }: InitArg,
) {
    ROOT_PRINCIPALS.with(|m| {
        let mut m = m.borrow_mut();
        root_principals.iter().for_each(|p| {
            m.insert(p.to_text().into(), ());
        });
    });

    ID_SEED.with(|s| {
        s.borrow_mut().insert(
            (),      //
            id_seed, //
        )
    });

    // REGISTRATION_EXPIRATION_TTL
    REGISTRATION_EXPIRATION_TTL.with(|s| {
        s.borrow_mut().insert(
            (),                                             //
            registration_expiration_ttl.unwrap_or(3 * DAY), //
        )
    });

    // IN_PROGRESS_TTL
    IN_PROGRESS_TTL.with(|s| {
        s.borrow_mut().insert(
            (),                                     //
            in_progress_ttl.unwrap_or(10 * MINUTE), //
        )
    });

    // MANAGEMENT_TASK_INTERVAL
    MANAGEMENT_TASK_INTERVAL.with(|s| {
        s.borrow_mut().insert(
            (),                                         //
            management_task_interval.unwrap_or(MINUTE), //
        )
    });

    // authorize the canister ID so that timer functions are authorized
    ALLOWED_PRINCIPALS.with(|m| {
        m.borrow_mut().insert(
            canister_self().to_text().into(), // principal
            (),                               //
        )
    });

    init_timers_fn();
    init_cert_tree();
}

#[pre_upgrade]
fn pre_upgrade_fn() {
    MEMORY_MANAGER.with(|m| {
        let m = m.borrow();

        TASKS.with(|tasks| {
            if let Err(err) = persistence::store(m.get(MemoryId::new(MEMORY_ID_TASKS)), tasks) {
                trap(format!("failed to persist tasks: {err}"));
            }
        });

        EXPIRATIONS.with(|exps| {
            if let Err(err) = persistence::store(m.get(MemoryId::new(MEMORY_ID_EXPIRATIONS)), exps)
            {
                trap(format!("failed to persist expirations: {err}"));
            }
        });

        RETRIES.with(|retries| {
            if let Err(err) = persistence::store(m.get(MemoryId::new(MEMORY_ID_RETRIES)), retries) {
                trap(format!("failed to persist retries: {err}"));
            }
        });
    });
}

#[post_upgrade]
fn post_upgrade_fn() {
    MEMORY_MANAGER.with(|m| {
        let m = m.borrow();

        TASKS.with(|tasks| {
            match persistence::load(m.get(MemoryId::new(MEMORY_ID_TASKS))) {
                Ok(v) => *tasks.borrow_mut() = v,
                Err(err) => trap(format!("failed to load tasks: {err}")),
            };
        });

        EXPIRATIONS.with(|exps| {
            match persistence::load(m.get(MemoryId::new(MEMORY_ID_EXPIRATIONS))) {
                Ok(v) => *exps.borrow_mut() = v,
                Err(err) => trap(format!("failed to load expirations: {err}")),
            };
        });

        RETRIES.with(|retries| {
            match persistence::load(m.get(MemoryId::new(MEMORY_ID_RETRIES))) {
                Ok(v) => *retries.borrow_mut() = v,
                Err(err) => trap(format!("failed to load retries: {err}")),
            };
        });
    });

    // authorize the canister ID so that timer functions are authorized
    ALLOWED_PRINCIPALS.with(|m| {
        m.borrow_mut().insert(
            canister_self().to_text().into(), // principal
            (),                               //
        )
    });

    // REGISTRATION_EXPIRATION_TTL
    REGISTRATION_EXPIRATION_TTL.with(|s| {
        let v = s.borrow().get(&()).unwrap_or(3 * DAY);
        s.borrow_mut().insert((), v)
    });

    // IN_PROGRESS_TTL
    IN_PROGRESS_TTL.with(|s| {
        let v = s.borrow().get(&()).unwrap_or(10 * MINUTE);
        s.borrow_mut().insert((), v)
    });

    // MANAGEMENT_TASK_INTERVAL
    MANAGEMENT_TASK_INTERVAL.with(|s| {
        let v = s.borrow().get(&()).unwrap_or(MINUTE);
        s.borrow_mut().insert((), v)
    });

    init_timers_fn();

    // rebuild the IC certification tree
    init_cert_tree();
    ENCRYPTED_CERTIFICATES.with(|pairs| {
        REGISTRATIONS.with(|regs| {
            let regs = regs.borrow();
            for (id, pair) in pairs.borrow().iter() {
                let package_to_certify = {
                    let reg = regs.get(&id.clone()).unwrap();
                    ExportPackage {
                        id: id.clone().into(),
                        name: reg.name,
                        canister: reg.canister,
                        pair,
                    }
                };
                add_cert(id, &package_to_certify);
            }
            set_root_hash();
        })
    });
}

// Registration

#[update(name = "createRegistration")]
#[candid_method(update, rename = "createRegistration")]
fn create_registration(name: String, canister: Principal) -> CreateRegistrationResponse {
    match CREATOR.with(|c| c.borrow().create(&name, &canister)) {
        Ok(id) => CreateRegistrationResponse::Ok(id),
        Err(err) => CreateRegistrationResponse::Err(match err {
            CreateError::Duplicate(id) => CreateRegistrationError::Duplicate(id),
            CreateError::NameError(err) => CreateRegistrationError::NameError(err.to_string()),
            CreateError::RateLimited(domain) => CreateRegistrationError::RateLimited(domain),
            CreateError::Unauthorized => CreateRegistrationError::Unauthorized,
            CreateError::UnexpectedError(err) => {
                CreateRegistrationError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[query(name = "getRegistration")]
#[candid_method(query, rename = "getRegistration")]
fn get_registration(id: Id) -> GetRegistrationResponse {
    match GETTER.with(|g| g.borrow().get(&id)) {
        Ok(reg) => GetRegistrationResponse::Ok(reg),
        Err(err) => GetRegistrationResponse::Err(match err {
            GetError::NotFound => GetRegistrationError::NotFound,
            GetError::Unauthorized => GetRegistrationError::Unauthorized,
            GetError::UnexpectedError(err) => {
                GetRegistrationError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[update(name = "updateRegistration")]
#[candid_method(update, rename = "updateRegistration")]
fn update_registration(id: Id, typ: UpdateType) -> UpdateRegistrationResponse {
    match UPDATER.with(|u| u.borrow().update(&id, typ)) {
        Ok(()) => UpdateRegistrationResponse::Ok(()),
        Err(err) => UpdateRegistrationResponse::Err(match err {
            UpdateError::NotFound => UpdateRegistrationError::NotFound,
            UpdateError::Unauthorized => UpdateRegistrationError::Unauthorized,
            UpdateError::UnexpectedError(_) => {
                UpdateRegistrationError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[update(name = "removeRegistration")]
#[candid_method(update, rename = "removeRegistration")]
fn remove_registration(id: Id) -> RemoveRegistrationResponse {
    match REMOVER.with(|r| r.borrow().remove(&id)) {
        Ok(()) => {
            set_root_hash();
            RemoveRegistrationResponse::Ok(())
        }
        Err(err) => RemoveRegistrationResponse::Err(match err {
            RemoveError::NotFound => RemoveRegistrationError::NotFound,
            RemoveError::Unauthorized => RemoveRegistrationError::Unauthorized,
            RemoveError::UnexpectedError(_) => {
                RemoveRegistrationError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[query(name = "listRegistrations")]
#[candid_method(query, rename = "listRegistrations")]
fn list_registrations() -> ListRegistrationsResponse {
    match REGISTRATION_LISTER.with(|v| v.borrow().list()) {
        Ok(rs) => ListRegistrationsResponse::Ok(rs),
        Err(err) => ListRegistrationsResponse::Err(match err {
            registration::ListError::Unauthorized => ListRegistrationsError::Unauthorized,
            registration::ListError::UnexpectedError(err) => {
                ListRegistrationsError::UnexpectedError(err.to_string())
            }
        }),
    }
}

// Certificates

#[query(name = "getCertificate")]
#[candid_method(query, rename = "getCertificate")]
fn get_certificate(id: Id) -> GetCertificateResponse {
    match CERT_GETTER.with(|c| c.borrow().get_cert(&id)) {
        Ok(enc_pair) => GetCertificateResponse::Ok(enc_pair),
        Err(err) => GetCertificateResponse::Err(match err {
            GetCertError::NotFound => GetCertificateError::NotFound,
            GetCertError::Unauthorized => GetCertificateError::Unauthorized,
            GetCertError::UnexpectedError(err) => {
                GetCertificateError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[update(name = "uploadCertificate")]
#[candid_method(update, rename = "uploadCertificate")]
fn upload_certificate(id: Id, pair: EncryptedPair) -> UploadCertificateResponse {
    match UPLOADER.with(|u| u.borrow().upload(&id, pair)) {
        Ok(()) => UploadCertificateResponse::Ok(()),
        Err(err) => UploadCertificateResponse::Err(match err {
            UploadError::NotFound => UploadCertificateError::NotFound,
            UploadError::Unauthorized => UploadCertificateError::Unauthorized,
            UploadError::UnexpectedError(_) => {
                UploadCertificateError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[query(name = "exportCertificatesPaginated")]
#[candid_method(query, rename = "exportCertificatesPaginated")]
fn export_certificates_paginated(key: Option<String>, limit: u64) -> ExportCertificatesResponse {
    match EXPORTER.with(|e| e.borrow().export(key, limit)) {
        Ok(pkgs) => ExportCertificatesResponse::Ok(pkgs),
        Err(err) => ExportCertificatesResponse::Err(match err {
            ExportError::Unauthorized => ExportCertificatesError::Unauthorized,
            ExportError::UnexpectedError(_) => {
                ExportCertificatesError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[query(name = "exportCertificatesCertified")]
#[candid_method(query, rename = "exportCertificatesCertified")]
fn export_certificates_certified(
    key: Option<String>,
    limit: u64,
) -> ExportCertificatesCertifiedResponse {
    match EXPORTER.with(|e| e.borrow().export_certified(key, limit)) {
        Ok(pkgs) => ExportCertificatesCertifiedResponse::Ok(pkgs),
        Err(err) => ExportCertificatesCertifiedResponse::Err(match err {
            ExportError::Unauthorized => ExportCertificatesError::Unauthorized,
            ExportError::UnexpectedError(_) => {
                ExportCertificatesError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[query(name = "exportCertificates")]
#[candid_method(query, rename = "exportCertificates")]
fn export_certificates() -> ExportCertificatesResponse {
    match EXPORTER.with(|e| e.borrow().export(None, u64::MAX)) {
        Ok(pkgs) => ExportCertificatesResponse::Ok(pkgs),
        Err(err) => ExportCertificatesResponse::Err(match err {
            ExportError::Unauthorized => ExportCertificatesError::Unauthorized,
            ExportError::UnexpectedError(_) => {
                ExportCertificatesError::UnexpectedError(err.to_string())
            }
        }),
    }
}

// Tasks

#[update(name = "queueTask")]
#[candid_method(update, rename = "queueTask")]
fn queue_task(id: Id, timestamp: u64) -> QueueTaskResponse {
    match QUEUER.with(|q| q.borrow().queue(id, timestamp)) {
        Ok(()) => QueueTaskResponse::Ok(()),
        Err(err) => QueueTaskResponse::Err(match err {
            QueueError::NotFound => QueueTaskError::NotFound,
            QueueError::Unauthorized => QueueTaskError::Unauthorized,
            QueueError::UnexpectedError(err) => QueueTaskError::UnexpectedError(err.to_string()),
        }),
    }
}

#[query(name = "peekTask")]
#[candid_method(query, rename = "peekTask")]
fn peek_task() -> PeekTaskResponse {
    match PEEKER.with(|p| p.borrow().peek()) {
        Ok(id) => PeekTaskResponse::Ok(id),
        Err(err) => PeekTaskResponse::Err(match err {
            PeekError::NoTasksAvailable => PeekTaskError::NoTasksAvailable,
            PeekError::Unauthorized => PeekTaskError::Unauthorized,
            PeekError::UnexpectedError(err) => PeekTaskError::UnexpectedError(err.to_string()),
        }),
    }
}

#[update(name = "dispenseTask")]
#[candid_method(update, rename = "dispenseTask")]
fn dispense_task() -> DispenseTaskResponse {
    match DISPENSER.with(|d| d.borrow().dispense()) {
        Ok(id) => DispenseTaskResponse::Ok(id),
        Err(err) => DispenseTaskResponse::Err(match err {
            DispenseError::NoTasksAvailable => DispenseTaskError::NoTasksAvailable,
            DispenseError::Unauthorized => DispenseTaskError::Unauthorized,
            DispenseError::UnexpectedError(err) => {
                DispenseTaskError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[update(name = "removeTask")]
#[candid_method(update, rename = "removeTask")]
fn remove_task(id: Id) -> RemoveTaskResponse {
    match TASK_REMOVER.with(|v| v.borrow().remove(&id)) {
        Ok(()) => RemoveTaskResponse::Ok,
        Err(err) => RemoveTaskResponse::Err(match err {
            work::RemoveError::NotFound => RemoveTaskError::NotFound,
            work::RemoveError::Unauthorized => RemoveTaskError::Unauthorized,
            work::RemoveError::UnexpectedError(err) => {
                RemoveTaskError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[query(name = "listTasks")]
#[candid_method(query, rename = "listTasks")]
fn list_tasks() -> ListTasksResponse {
    match TASK_LISTER.with(|v| v.borrow().list()) {
        Ok(ts) => ListTasksResponse::Ok(ts),
        Err(err) => ListTasksResponse::Err(match err {
            work::ListError::Unauthorized => ListTasksError::Unauthorized,
            work::ListError::UnexpectedError(err) => {
                ListTasksError::UnexpectedError(err.to_string())
            }
        }),
    }
}

// Metrics

#[query(name = "http_request")]
#[candid_method(query, rename = "http_request")]
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
    REGISTRATIONS.with(|regs| {
        GAUGE_REGISTRATIONS_TOTAL.with(|g| {
            regs.borrow().iter().for_each(|(_, reg)| {
                g.borrow_mut()
                    .with_label_values(&[match reg.state {
                        State::Failed(_) => "failed",
                        State::PendingOrder => "pendingOrder",
                        State::PendingChallengeResponse => "pendingChallengeResponse",
                        State::PendingAcmeApproval => "pendingAcmeApproval",
                        State::Available => "available",
                    }])
                    .inc()
            });
        });
    });

    TASKS.with(|tasks| {
        GAUGE_TASKS_TOTAL.with(|g| g.borrow_mut().set(tasks.borrow().len() as f64));
    });

    ALLOWED_PRINCIPALS.with(|tasks| {
        GAUGE_ALLOWED_PRINCIPALS_TOTAL.with(|g| g.borrow_mut().set(tasks.borrow().len() as f64));
    });

    GAUGE_CANISTER_CYCLES_BALANCE.with(|g| {
        g.borrow_mut()
            .set(ic_cdk::api::canister_cycle_balance() as f64)
    });

    // Export metrics
    let bs = METRICS_REGISTRY.with(|r| {
        let mfs = r.borrow().gather();

        let mut buffer = vec![];
        let enc = TextEncoder::new();

        if let Err(err) = enc.encode(&mfs, &mut buffer) {
            trap(format!("failed to encode metrics: {err}"));
        };

        buffer
    });

    HttpResponse {
        status_code: 200,
        headers: vec![],
        body: bs,
    }
}

// ACLs

#[query(name = "listAllowedPrincipals")]
#[candid_method(query, rename = "listAllowedPrincipals")]
fn list_allowed_principals() -> ListAllowedPrincipalsResponse {
    if let Err(err) = ROOT_AUTHORIZER.with(|a| a.borrow().authorize(&msg_caller())) {
        return ListAllowedPrincipalsResponse::Err(match err {
            AuthorizeError::Unauthorized => ListAllowedPrincipalsError::Unauthorized,
            AuthorizeError::UnexpectedError(err) => {
                ListAllowedPrincipalsError::UnexpectedError(err.to_string())
            }
        });
    }

    // filter out own canister ID from response
    ListAllowedPrincipalsResponse::Ok(ALLOWED_PRINCIPALS.with(|m| {
        m.borrow()
            .iter()
            .map(|(k, _)| Principal::from_text(k.as_str()).expect("failed to parse principal"))
            .filter(|k| k != &canister_self())
            .collect()
    }))
}

#[update(name = "addAllowedPrincipal")]
#[candid_method(update, rename = "addAllowedPrincipal")]
fn add_allowed_principal(principal: Principal) -> ModifyAllowedPrincipalResponse {
    if let Err(err) = ROOT_AUTHORIZER.with(|a| a.borrow().authorize(&msg_caller())) {
        return ModifyAllowedPrincipalResponse::Err(match err {
            AuthorizeError::Unauthorized => ModifyAllowedPrincipalError::Unauthorized,
            AuthorizeError::UnexpectedError(err) => {
                ModifyAllowedPrincipalError::UnexpectedError(err.to_string())
            }
        });
    }

    ALLOWED_PRINCIPALS.with(|m| m.borrow_mut().insert(principal.to_text().into(), ()));

    ModifyAllowedPrincipalResponse::Ok(())
}

#[update(name = "rmAllowedPrincipal")]
#[candid_method(update, rename = "rmAllowedPrincipal")]
fn rm_allowed_principal(principal: Principal) -> ModifyAllowedPrincipalResponse {
    if let Err(err) = ROOT_AUTHORIZER.with(|a| a.borrow().authorize(&msg_caller())) {
        return ModifyAllowedPrincipalResponse::Err(match err {
            AuthorizeError::Unauthorized => ModifyAllowedPrincipalError::Unauthorized,
            AuthorizeError::UnexpectedError(err) => {
                ModifyAllowedPrincipalError::UnexpectedError(err.to_string())
            }
        });
    }

    if ALLOWED_PRINCIPALS
        .with(|m| m.borrow_mut().remove(&principal.to_text().into()))
        .is_none()
    {
        return ModifyAllowedPrincipalResponse::Err(ModifyAllowedPrincipalError::UnexpectedError(
            "principal not found".to_string(),
        ));
    };

    ModifyAllowedPrincipalResponse::Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_candid_interface() {
        use candid_parser::utils::{CandidSource, service_equal};

        candid::export_service!();
        let new_interface = __export_service();

        service_equal(
            CandidSource::Text(&new_interface),
            CandidSource::Text(include_str!("../interface.did")),
        )
        .unwrap();
    }
}
