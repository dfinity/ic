use std::{cell::RefCell, cmp::Reverse, mem::size_of, thread::LocalKey};

use candid::{CandidType, Deserialize};
use certificate_orchestrator_interface::{
    CreateRegistrationError, CreateRegistrationResponse, DispenseTaskError, DispenseTaskResponse,
    EncryptedPair, ExportCertificatesError, ExportCertificatesResponse, GetRegistrationError,
    GetRegistrationResponse, Id, Name, QueueTaskError, QueueTaskResponse, Registration, State,
    UpdateRegistrationError, UpdateRegistrationResponse, UploadCertificateError,
    UploadCertificateResponse, NAME_MAX_LEN,
};
use ic_cdk::{caller, export::Principal, trap};
use ic_cdk_macros::{init, query, update};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use priority_queue::PriorityQueue;

use crate::{
    acl::{Authorize, AuthorizeError, Authorizer, WithAuthorize},
    certificate::{Export, ExportError, Exporter, Upload, UploadError, Uploader},
    id::{Generate, Generator},
    registration::{
        Create, CreateError, Creator, Get, GetError, Getter, Update, UpdateError, Updater,
    },
    work::{Dispense, DispenseError, Dispenser, Queue, QueueError, Queuer},
};

mod acl;
mod certificate;
mod id;
mod registration;
mod work;

type Memory = VirtualMemory<DefaultMemoryImpl>;
type LocalRef<T> = &'static LocalKey<RefCell<T>>;
type StableSet<T> = StableBTreeMap<Memory, T, ()>;
type StableValue<T> = StableBTreeMap<Memory, (), T>;

const BYTE: u32 = 1;
const KB: u32 = 1024 * BYTE;

const CONST_KEY_LEN: u32 = 0;
const SET_VALUE_LEN: u32 = 0;

const PRINCIPAL_ID_LEN: u32 = 63 * BYTE;
const ID_COUNTER_LEN: u32 = size_of::<u128>() as u32;
const REGISTRATION_ID_LEN: u32 = 64 * BYTE;
const REGISTRATION_LEN: u32 = 128;
const ENCRYPED_PRIVATE_KEY_LEN: u32 = KB; // 1 * KB
const ENCRYPED_CERTIFICATE_LEN: u32 = 8 * KB;
const ENCRYPTED_PAIR_LEN: u32 = ENCRYPED_PRIVATE_KEY_LEN + ENCRYPED_CERTIFICATE_LEN;

// Memory
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

const MEMORY_ID_ROOT_PRINCIPALS: u8 = 0;
const MEMORY_ID_ALLOWED_PRINCIPALS: u8 = 1;
const MEMORY_ID_ID_COUNTER: u8 = 2;
const MEMORY_ID_REGISTRATIONS: u8 = 3;
const MEMORY_ID_NAMES: u8 = 4;
const MEMORY_ID_ENCRPYTED_CERTIFICATES: u8 = 5;

// ACLs
thread_local! {
    static ROOT_PRINCIPALS: RefCell<StableSet<String>> = RefCell::new(
        StableSet::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ROOT_PRINCIPALS))),
            PRINCIPAL_ID_LEN, // MAX_KEY_SIZE,
            SET_VALUE_LEN,    // MAX_VALUE_SIZE
        )
    );

    static ROOT_AUTHORIZER: RefCell<Box<dyn Authorize>> = RefCell::new({
        let a = Authorizer::new(&ROOT_PRINCIPALS);
        Box::new(a)
    });
}

thread_local! {
    static ALLOWED_PRINCIPALS: RefCell<StableSet<String>> = RefCell::new(
        StableSet::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ALLOWED_PRINCIPALS))),
            PRINCIPAL_ID_LEN, // MAX_KEY_SIZE,
            SET_VALUE_LEN,    // MAX_VALUE_SIZE
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
            CONST_KEY_LEN,  // MAX_KEY_SIZE,
            ID_COUNTER_LEN, // MAX_VALUE_SIZE
        )
    );

    static ID_GENERATOR: RefCell<Box<dyn Generate>> = RefCell::new({
        let g = Generator::new(&ID_COUNTER);
        Box::new(g)
    });
}

// Registrations
thread_local! {
    static REGISTRATIONS: RefCell<StableBTreeMap<Memory, Id, Registration>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_REGISTRATIONS))),
            REGISTRATION_ID_LEN, // MAX_KEY_SIZE,
            REGISTRATION_LEN,    // MAX_VALUE_SIZE
        )
    );

    static NAMES: RefCell<StableBTreeMap<Memory, Name, Id>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_NAMES))),
            NAME_MAX_LEN,        // MAX_KEY_SIZE,
            REGISTRATION_ID_LEN, // MAX_VALUE_SIZE
        )
    );

    static CREATOR: RefCell<Box<dyn Create>> = RefCell::new({
        let c = Creator::new(&ID_GENERATOR, &REGISTRATIONS, &NAMES);
        let c = WithAuthorize(c, &MAIN_AUTHORIZER);
        Box::new(c)
    });

    static GETTER: RefCell<Box<dyn Get>> = RefCell::new({
        let g = Getter::new(&REGISTRATIONS);
        let g = WithAuthorize(g, &MAIN_AUTHORIZER);
        Box::new(g)
    });

    static UPDATER: RefCell<Box<dyn Update>> = RefCell::new({
        let u = Updater::new(&REGISTRATIONS);
        let u = WithAuthorize(u, &MAIN_AUTHORIZER);
        Box::new(u)
    });
}

// Certificates
thread_local! {
    static ENCRYPTED_CERTIFICATES: RefCell<StableBTreeMap<Memory, Id, EncryptedPair>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(MEMORY_ID_ENCRPYTED_CERTIFICATES))),
            REGISTRATION_ID_LEN, // MAX_KEY_SIZE,
            ENCRYPTED_PAIR_LEN,  // MAX_VALUE_SIZE
        )
    );

    static UPLOADER: RefCell<Box<dyn Upload>> = RefCell::new({
        let u = Uploader::new(&ENCRYPTED_CERTIFICATES, &REGISTRATIONS);
        let u = WithAuthorize(u, &MAIN_AUTHORIZER);
        Box::new(u)
    });

    static EXPORTER: RefCell<Box<dyn Export>> = RefCell::new({
        let e = Exporter::new(&ENCRYPTED_CERTIFICATES, &REGISTRATIONS);
        let e = WithAuthorize(e, &MAIN_AUTHORIZER);
        Box::new(e)
    });
}

// Tasks
thread_local! {
    static TASKS: RefCell<PriorityQueue<String, Reverse<u64>>> = RefCell::new(PriorityQueue::new());

    static QUEUER: RefCell<Box<dyn Queue>> = RefCell::new({
        let q = Queuer::new(&TASKS, &REGISTRATIONS);
        let q = WithAuthorize(q, &MAIN_AUTHORIZER);
        Box::new(q)
    });

    static DISPENSER: RefCell<Box<dyn Dispense>> = RefCell::new({
        let d = Dispenser::new(&TASKS);
        let d = WithAuthorize(d, &MAIN_AUTHORIZER);
        Box::new(d)
    });
}

#[derive(Clone, Debug, CandidType, Deserialize)]
struct InitArg {
    #[serde(rename = "rootPrincipals")]
    root_principals: Vec<Principal>,
}

#[init]
fn init_fn(InitArg { root_principals }: InitArg) {
    ROOT_PRINCIPALS.with(|m| {
        let mut m = m.borrow_mut();
        root_principals.iter().for_each(|p| {
            if let Err(err) = m.insert(p.to_text(), ()) {
                trap(&format!("failed to insert root principal: {err}"));
            }
        });
    });
}

// Registration

#[update(name = "createRegistration")]
fn create_registration(name: String, canister: Principal) -> CreateRegistrationResponse {
    match CREATOR.with(|c| c.borrow().create(&name, &canister)) {
        Ok(id) => CreateRegistrationResponse::Ok(id),
        Err(err) => CreateRegistrationResponse::Err(match err {
            CreateError::Duplicate(id) => CreateRegistrationError::Duplicate(id),
            CreateError::NameError(err) => CreateRegistrationError::NameError(err.to_string()),
            CreateError::Unauthorized => CreateRegistrationError::Unauthorized,
            CreateError::UnexpectedError(err) => {
                CreateRegistrationError::UnexpectedError(err.to_string())
            }
        }),
    }
}

#[query(name = "getRegistration")]
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
fn update_registration(id: Id, state: State) -> UpdateRegistrationResponse {
    match UPDATER.with(|u| u.borrow().update(id, state)) {
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

// Certificates

#[update(name = "uploadCertificate")]
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

#[query(name = "exportCertificates")]
fn export_certificates() -> ExportCertificatesResponse {
    match EXPORTER.with(|e| e.borrow().export()) {
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

#[update(name = "dispenseTask")]
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

// ACLs

#[query(name = "listAllowedPrincipals")]
fn list_allowed_principals() -> Vec<Principal> {
    if let Err(err) = ROOT_AUTHORIZER.with(|a| a.borrow().authorize(&caller())) {
        match err {
            AuthorizeError::Unauthorized => trap(&err.to_string()),
            AuthorizeError::UnexpectedError(err) => trap(&err.to_string()),
        }
    }

    ALLOWED_PRINCIPALS.with(|m| {
        m.borrow()
            .iter()
            .map(|(k, _)| Principal::from_text(k).unwrap())
            .collect()
    })
}

#[update(name = "addAllowedPrincipal")]
fn add_allowed_principal(principal: Principal) {
    if let Err(err) = ROOT_AUTHORIZER.with(|a| a.borrow().authorize(&caller())) {
        match err {
            AuthorizeError::Unauthorized => trap(&err.to_string()),
            AuthorizeError::UnexpectedError(err) => trap(&err.to_string()),
        }
    }

    ALLOWED_PRINCIPALS
        .with(|m| m.borrow_mut().insert(principal.to_text(), ()))
        .expect("failed to add allowed principal");
}

#[update(name = "rmAllowedPrincipal")]
fn rm_allowed_principal(principal: Principal) {
    if let Err(err) = ROOT_AUTHORIZER.with(|a| a.borrow().authorize(&caller())) {
        match err {
            AuthorizeError::Unauthorized => trap(&err.to_string()),
            AuthorizeError::UnexpectedError(err) => trap(&err.to_string()),
        }
    }

    ALLOWED_PRINCIPALS
        .with(|m| m.borrow_mut().remove(&principal.to_text()))
        .expect("failed to remove allowed principal");
}
