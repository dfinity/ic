use std::{cmp::Reverse, time::Duration};

use candid::Principal;
use certificate_orchestrator_interface::{
    EncryptedPair, ExportPackage, Id, Name, NameError, Registration, State, UpdateType,
};
use ic_cdk::api::msg_caller;
use mockall::automock;
use priority_queue::PriorityQueue;
use prometheus::labels;

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use tests::time;
        use tests::set_root_hash;
    } else {
        use ic_cdk::api::time;
        use crate::ic_certification::set_root_hash;
    }
}

use crate::{
    LocalRef, REGISTRATION_EXPIRATION_TTL, StableMap, StorableId, WithMetrics,
    acl::{Authorize, AuthorizeError, WithAuthorize},
    ic_certification::{add_cert, remove_cert},
    id::Generate,
};

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error(transparent)]
    NameError(#[from] NameError),
    #[error("Registration '{0}' already exists")]
    Duplicate(Id),
    #[error("Rate limit exceeded for domain '{0}'")]
    RateLimited(String),
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Create {
    fn create(&self, name: &str, canister: &Principal) -> Result<Id, CreateError>;
}

pub struct Creator {
    id_generator: LocalRef<Box<dyn Generate>>,
    registrations: LocalRef<StableMap<StorableId, Registration>>,
    names: LocalRef<StableMap<Name, StorableId>>,
    expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Creator {
    pub fn new(
        id_generator: LocalRef<Box<dyn Generate>>,
        registrations: LocalRef<StableMap<StorableId, Registration>>,
        names: LocalRef<StableMap<Name, StorableId>>,
        expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    ) -> Self {
        Self {
            id_generator,
            registrations,
            names,
            expirations,
        }
    }
}

impl Create for Creator {
    fn create(&self, name: &str, canister: &Principal) -> Result<Id, CreateError> {
        let name: Name = name.try_into()?;

        // Check for duplicate
        if let Some(id) = self.names.with(|names| names.borrow().get(&name)) {
            return Err(CreateError::Duplicate(id.into()));
        }

        // Generate ID
        let id = self.id_generator.with(|g| g.borrow().generate());

        // Create registration
        self.registrations.with(|regs| {
            regs.borrow_mut().insert(
                id.to_owned().into(),
                Registration {
                    name: name.to_owned(),
                    canister: canister.to_owned(),
                    state: State::PendingOrder,
                },
            )
        });

        // Update name mapping
        self.names.with(|names| {
            names
                .borrow_mut()
                .insert(name.to_owned(), id.to_owned().into())
        });

        // Schedule expiration
        let expiration_delay =
            Duration::from_secs(REGISTRATION_EXPIRATION_TTL.with(|s| s.borrow().get(&()).unwrap()));

        self.expirations.with(|expirations| {
            let mut expirations = expirations.borrow_mut();
            expirations.push(
                id.to_owned(),
                Reverse(time() + expiration_delay.as_nanos() as u64),
            );
        });

        Ok(id)
    }
}

impl<T: Create, A: Authorize> Create for WithAuthorize<T, A> {
    fn create(&self, domain: &str, canister: &Principal) -> Result<Id, CreateError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => CreateError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => CreateError::UnexpectedError(err),
            });
        };

        self.0.create(domain, canister)
    }
}

impl<T: Create> Create for WithMetrics<T> {
    fn create(&self, domain: &str, canister: &Principal) -> Result<Id, CreateError> {
        let out = self.0.create(domain, canister);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            CreateError::NameError(_) => "name-error",
                            CreateError::Duplicate(_) => "duplicate",
                            CreateError::RateLimited(_) => "rate-limited",
                            CreateError::Unauthorized => "unauthorized",
                            CreateError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Get {
    fn get(&self, id: &Id) -> Result<Registration, GetError>;
}

pub struct Getter {
    registrations: LocalRef<StableMap<StorableId, Registration>>,
}

impl Getter {
    pub fn new(registrations: LocalRef<StableMap<StorableId, Registration>>) -> Self {
        Self { registrations }
    }
}

impl Get for Getter {
    fn get(&self, id: &Id) -> Result<Registration, GetError> {
        self.registrations
            .with(|regs| regs.borrow().get(&id.into()).ok_or(GetError::NotFound))
    }
}

impl<T: Get, A: Authorize> Get for WithAuthorize<T, A> {
    fn get(&self, id: &Id) -> Result<Registration, GetError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => GetError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => GetError::UnexpectedError(err),
            });
        };

        self.0.get(id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Update {
    fn update(&self, id: &Id, typ: UpdateType) -> Result<(), UpdateError>;
}

pub struct Updater {
    registrations: LocalRef<StableMap<StorableId, Registration>>,
    expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Updater {
    pub fn new(
        registrations: LocalRef<StableMap<StorableId, Registration>>,
        expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    ) -> Self {
        Self {
            registrations,
            expirations,
            retries,
        }
    }
}

impl Update for Updater {
    fn update(&self, id: &Id, typ: UpdateType) -> Result<(), UpdateError> {
        match typ {
            // Update canister ID
            UpdateType::Canister(canister) => self.registrations.with(|regs| {
                let Registration { name, state, .. } =
                    regs.borrow().get(&id.into()).ok_or(UpdateError::NotFound)?;

                regs.borrow_mut().insert(
                    id.into(),
                    Registration {
                        name,
                        canister,
                        state,
                    },
                );

                Ok(())
            }),

            // Update state
            UpdateType::State(state) => {
                self.registrations.with(|regs| {
                    let Registration { name, canister, .. } =
                        regs.borrow().get(&id.into()).ok_or(UpdateError::NotFound)?;

                    regs.borrow_mut().insert(
                        id.into(),
                        Registration {
                            name,
                            canister,
                            state: state.to_owned(),
                        },
                    );

                    Ok::<(), UpdateError>(())
                })?;

                // Successful registrations should not be expired or retried
                if state == State::Available {
                    self.expirations.with(|exps| exps.borrow_mut().remove(id));
                    self.retries.with(|rets| rets.borrow_mut().remove(id));
                }

                // If a registration is being processed, but its expiration has not been scheduled,
                // schedule it. This is needed, for example, for certificate renewals
                if state != State::Available
                    && !self
                        .expirations
                        .with(|exps| exps.borrow().get(id).is_some())
                {
                    let expiration_delay = Duration::from_secs(
                        REGISTRATION_EXPIRATION_TTL.with(|s| s.borrow().get(&()).unwrap()),
                    );

                    self.expirations.with(|exps| {
                        let mut exps = exps.borrow_mut();
                        exps.push(
                            id.to_owned(),
                            Reverse(time() + expiration_delay.as_nanos() as u64),
                        );
                    });
                }

                Ok(())
            }
        }
    }
}

pub struct UpdateWithIcCertification<T> {
    updater: T,
    pairs: LocalRef<StableMap<StorableId, EncryptedPair>>,
    registrations: LocalRef<StableMap<StorableId, Registration>>,
}

impl<T: Update> UpdateWithIcCertification<T> {
    pub fn new(
        updater: T,
        pairs: LocalRef<StableMap<StorableId, EncryptedPair>>,
        registrations: LocalRef<StableMap<StorableId, Registration>>,
    ) -> Self {
        Self {
            updater,
            pairs,
            registrations,
        }
    }
}

impl<T: Update> Update for UpdateWithIcCertification<T> {
    fn update(&self, id: &Id, typ: UpdateType) -> Result<(), UpdateError> {
        if let UpdateType::Canister(canister) = typ {
            // If the encrypted pair has been uploaded, update the entry in certification tree
            if let Some(pair) = self.pairs.with(|pairs| pairs.borrow().get(&id.into())) {
                let Registration { name, .. } = self
                    .registrations
                    .with(|regs| regs.borrow().get(&id.into()))
                    .ok_or(UpdateError::NotFound)?;

                let package_to_certify = ExportPackage {
                    id: id.into(),
                    name,
                    canister,
                    pair,
                };
                add_cert(id.into(), &package_to_certify);
                set_root_hash();
            }
        }
        self.updater.update(id, typ)
    }
}

impl<T: Update, A: Authorize> Update for WithAuthorize<T, A> {
    fn update(&self, id: &Id, typ: UpdateType) -> Result<(), UpdateError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => UpdateError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => UpdateError::UnexpectedError(err),
            });
        };

        self.0.update(id, typ)
    }
}

impl<T: Update> Update for WithMetrics<T> {
    fn update(&self, id: &Id, typ: UpdateType) -> Result<(), UpdateError> {
        let out = self.0.update(id, typ);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            UpdateError::NotFound => "not-found",
                            UpdateError::Unauthorized => "unauthorized",
                            UpdateError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait List {
    fn list(&self) -> Result<Vec<(String, Registration)>, ListError>;
}

pub struct Lister {
    registrations: LocalRef<StableMap<StorableId, Registration>>,
}

impl Lister {
    pub fn new(registrations: LocalRef<StableMap<StorableId, Registration>>) -> Self {
        Self { registrations }
    }
}

impl List for Lister {
    fn list(&self) -> Result<Vec<(String, Registration)>, ListError> {
        Ok(self.registrations.with(|rs| {
            rs.borrow()
                .iter()
                .map(|(id, r)| (id.to_string(), r))
                .collect()
        }))
    }
}

impl<T: List, A: Authorize> List for WithAuthorize<T, A> {
    fn list(&self) -> Result<Vec<(String, Registration)>, ListError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => ListError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => ListError::UnexpectedError(err),
            });
        };

        self.0.list()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoveError {
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[automock]
pub trait Remove {
    fn remove(&self, id: &Id) -> Result<(), RemoveError>;
}

pub struct Remover {
    registrations: LocalRef<StableMap<StorableId, Registration>>,
    names: LocalRef<StableMap<Name, StorableId>>,
    tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    encrypted_certificates: LocalRef<StableMap<StorableId, EncryptedPair>>,
}

impl Remover {
    pub fn new(
        registrations: LocalRef<StableMap<StorableId, Registration>>,
        names: LocalRef<StableMap<Name, StorableId>>,
        tasks: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
        encrypted_certificates: LocalRef<StableMap<StorableId, EncryptedPair>>,
    ) -> Self {
        Self {
            registrations,
            names,
            tasks,
            expirations,
            retries,
            encrypted_certificates,
        }
    }
}

impl Remove for Remover {
    fn remove(&self, id: &Id) -> Result<(), RemoveError> {
        let Registration { name, .. } = self
            .registrations
            .with(|regs| regs.borrow().get(&id.into()).ok_or(RemoveError::NotFound))?;

        // remove registration
        self.registrations
            .with(|regs| regs.borrow_mut().remove(&id.into()));

        // remove name mapping
        self.names.with(|names| names.borrow_mut().remove(&name));

        // remove task/retry/expiry if present
        let _ = [self.tasks, self.retries, self.expirations]
            .map(|pq| pq.with(|pq| pq.borrow_mut().remove(id)));

        // remove certificate
        self.encrypted_certificates
            .with(|certs| certs.borrow_mut().remove(&id.into()));

        // remove the IC certificate for the domain
        remove_cert(id.into());

        Ok(())
    }
}

impl<T: Remove, A: Authorize> Remove for WithAuthorize<T, A> {
    fn remove(&self, id: &Id) -> Result<(), RemoveError> {
        if let Err(err) = self.1.authorize(&msg_caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => RemoveError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => RemoveError::UnexpectedError(err),
            });
        };

        self.0.remove(id)
    }
}

impl<T: Remove> Remove for WithMetrics<T> {
    fn remove(&self, id: &Id) -> Result<(), RemoveError> {
        let out = self.0.remove(id);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            RemoveError::NotFound => "not-found",
                            RemoveError::Unauthorized => "unauthorized",
                            RemoveError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExpireError {
    #[error(transparent)]
    RemoveError(#[from] RemoveError),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Expire {
    fn expire(&self, t: u64) -> Result<(), ExpireError>;
}

pub struct Expirer {
    remover: LocalRef<Box<dyn Remove>>,
    expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Expirer {
    pub fn new(
        remover: LocalRef<Box<dyn Remove>>,
        expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    ) -> Self {
        Self {
            remover,
            expirations,
        }
    }
}

impl Expirer {
    fn get_id(&self, t: u64) -> Option<String> {
        self.expirations.with(|exps| {
            let mut exps = exps.borrow_mut();
            // Check for next expiration
            let p = exps.peek().map(|(_, p)| p.0)?;

            if p > t {
                return None;
            }

            exps.pop().map(|(id, _)| id)
        })
    }
}

impl Expire for Expirer {
    fn expire(&self, t: u64) -> Result<(), ExpireError> {
        while let Some(id) = self.get_id(t) {
            // Remove registration
            self.remover.with(|r| r.borrow().remove(&id))?;
        }
        set_root_hash();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use anyhow::Error;
    use certificate_orchestrator_interface::EncryptedPair;
    use mockall::predicate;

    use super::*;
    use crate::{
        ENCRYPTED_CERTIFICATES, EXPIRATIONS, ID_GENERATOR, NAMES, REGISTRATIONS, RETRIES, TASKS,
    };

    pub fn time() -> u64 {
        0
    }

    pub fn set_root_hash() {}

    #[test]
    fn get_empty() {
        let getter = Getter::new(&REGISTRATIONS);

        match getter.get(&Id::from("id")) {
            Err(GetError::NotFound) => {}
            other => panic!("expected NotFound but got {other:?}"),
        };
    }

    #[test]
    fn get_ok() -> Result<(), Error> {
        let reg = Registration {
            name: Name::try_from("name.com")?,
            canister: Principal::from_text("aaaaa-aa")?,
            state: State::Available,
        };

        REGISTRATIONS.with(|regs| {
            regs.borrow_mut()
                .insert("id".to_string().into(), reg.clone())
        });

        let getter = Getter::new(&REGISTRATIONS);

        let out = match getter.get(&Id::from("id")) {
            Ok(reg) => reg,
            other => panic!("expected registration but got {other:?}"),
        };

        assert_eq!(out, reg);

        Ok(())
    }

    #[test]
    fn create_ok() -> Result<(), Error> {
        crate::ID_SEED.with(|s| s.borrow_mut().insert((), 0));

        REGISTRATION_EXPIRATION_TTL.with(|s| {
            let mut s = s.borrow_mut();
            s.insert((), 60 * 60 * 24 * 3);
        });

        let creator = Creator::new(&ID_GENERATOR, &REGISTRATIONS, &NAMES, &EXPIRATIONS);

        let id = creator.create(
            "name.com",                         // name
            &Principal::from_text("aaaaa-aa")?, // canister
        )?;

        // Check registration
        let reg = REGISTRATIONS
            .with(|regs| regs.borrow().get(&id.to_owned().into()))
            .expect("expected registration to exist but none found");

        assert_eq!(
            reg,
            Registration {
                name: Name::try_from("name.com")?,
                canister: Principal::from_text("aaaaa-aa")?,
                state: State::PendingOrder,
            }
        );

        // Check name
        let iid: String = NAMES
            .with(|names| {
                names
                    .borrow()
                    .get(&Name::try_from("name.com").expect("failed to create name"))
            })
            .expect("expected name mapping to exist but none found")
            .into();

        assert_eq!(id, iid, "expected ids to match");

        Ok(())
    }

    #[test]
    fn update_canister_ok() -> Result<(), Error> {
        let reg = Registration {
            name: Name::try_from("name.com")?,
            canister: Principal::from_text("aaaaa-aa")?,
            state: State::PendingOrder,
        };

        REGISTRATIONS.with(|regs| regs.borrow_mut().insert("id".to_string().into(), reg));

        Updater::new(&REGISTRATIONS, &EXPIRATIONS, &RETRIES).update(
            &Id::from("id"),
            UpdateType::Canister(Principal::from_text("2ibo7-dia")?),
        )?;

        // Check registration
        let reg = REGISTRATIONS
            .with(|regs| regs.borrow().get(&"id".to_string().into()))
            .expect("expected registration to exist but none found");

        assert_eq!(
            reg,
            Registration {
                name: Name::try_from("name.com")?,
                canister: Principal::from_text("2ibo7-dia")?,
                state: State::PendingOrder,
            }
        );

        Ok(())
    }

    #[test]
    fn update_state_ok() -> Result<(), Error> {
        let reg = Registration {
            name: Name::try_from("name.com")?,
            canister: Principal::from_text("aaaaa-aa")?,
            state: State::PendingOrder,
        };

        REGISTRATION_EXPIRATION_TTL.with(|s| {
            let mut s = s.borrow_mut();
            s.insert((), 60 * 60 * 24 * 3);
        });

        REGISTRATIONS.with(|regs| regs.borrow_mut().insert("id".to_string().into(), reg));

        Updater::new(&REGISTRATIONS, &EXPIRATIONS, &RETRIES).update(
            &Id::from("id"),
            UpdateType::State(State::PendingChallengeResponse),
        )?;

        // Check registration
        let reg = REGISTRATIONS
            .with(|regs| regs.borrow().get(&"id".to_string().into()))
            .expect("expected registration to exist but none found");

        assert_eq!(
            reg,
            Registration {
                name: Name::try_from("name.com")?,
                canister: Principal::from_text("aaaaa-aa")?,
                state: State::PendingChallengeResponse,
            }
        );

        Ok(())
    }

    #[test]
    fn remove_not_found() -> Result<(), Error> {
        let r = Remover::new(
            &REGISTRATIONS,
            &NAMES,
            &TASKS,
            &EXPIRATIONS,
            &RETRIES,
            &ENCRYPTED_CERTIFICATES,
        );

        match r.remove(&Id::from("id")) {
            Err(RemoveError::NotFound) => {}
            other => panic!("expected RemoveError::NotFound but got {other:?}"),
        };

        Ok(())
    }

    #[test]
    fn remove_ok() -> Result<(), Error> {
        REGISTRATIONS.with(|regs| {
            regs.borrow_mut().insert(
                "id".to_string().into(),
                Registration {
                    name: Name::try_from("name.com").unwrap(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    state: State::PendingOrder,
                },
            )
        });

        NAMES.with(|names| {
            names
                .borrow_mut()
                .insert(Name::try_from("name.com").unwrap(), "id".to_string().into())
        });

        TASKS.with(|tasks| {
            tasks.borrow_mut().push(
                "id".into(), // item
                Reverse(0),  // priority
            )
        });

        EXPIRATIONS.with(|tasks| {
            tasks.borrow_mut().push(
                "id".into(), // item
                Reverse(0),  // priority
            )
        });

        RETRIES.with(|tasks| {
            tasks.borrow_mut().push(
                "id".into(), // item
                Reverse(0),  // priority
            )
        });

        ENCRYPTED_CERTIFICATES.with(|certs| {
            certs
                .borrow_mut()
                .insert("id".to_string().into(), EncryptedPair(vec![], vec![]))
        });

        let r = Remover::new(
            &REGISTRATIONS,
            &NAMES,
            &TASKS,
            &EXPIRATIONS,
            &RETRIES,
            &ENCRYPTED_CERTIFICATES,
        );

        match r.remove(&Id::from("id")) {
            Ok(()) => {}
            other => panic!("expected Ok but got {other:?}"),
        };

        match REGISTRATIONS.with(|regs| regs.borrow().get(&"id".to_string().into())) {
            None => {}
            Some(_) => panic!("expected registration to be removed, but it wasn't"),
        };

        match NAMES.with(|names| names.borrow().get(&Name::try_from("name.com").unwrap())) {
            None => {}
            Some(_) => panic!("expected name mapping to be removed, but it wasn't"),
        };

        TASKS.with(|tasks| match tasks.borrow().get(&"id".to_string()) {
            None => {}
            Some(_) => panic!("expected task to be removed, but it wasn't"),
        });

        EXPIRATIONS.with(|exps| match exps.borrow().get(&"id".to_string()) {
            None => {}
            Some(_) => panic!("expected expiration to be removed, but it wasn't"),
        });

        RETRIES.with(|retries| match retries.borrow().get(&"id".to_string()) {
            None => {}
            Some(_) => panic!("expected retry to be removed, but it wasn't"),
        });

        ENCRYPTED_CERTIFICATES.with(|certs| match certs.borrow().get(&"id".to_string().into()) {
            None => {}
            Some(_) => panic!("expected certs to be removed, but they were not"),
        });

        Ok(())
    }

    #[test]
    fn remove_partial() -> Result<(), Error> {
        REGISTRATIONS.with(|regs| {
            regs.borrow_mut().insert(
                "id".to_string().into(),
                Registration {
                    name: Name::try_from("name.com").unwrap(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    state: State::PendingOrder,
                },
            )
        });

        let r = Remover::new(
            &REGISTRATIONS,
            &NAMES,
            &TASKS,
            &EXPIRATIONS,
            &RETRIES,
            &ENCRYPTED_CERTIFICATES,
        );

        match r.remove(&Id::from("id")) {
            Ok(()) => {}
            other => panic!("expected Ok but got {other:?}"),
        };

        match REGISTRATIONS.with(|regs| regs.borrow().get(&"id".to_string().into())) {
            None => {}
            Some(_) => panic!("expected registration to be removed, but it wasn't"),
        };

        Ok(())
    }

    #[test]
    fn expire_ok() -> Result<(), Error> {
        let _ = [("id-1", 0), ("id-2", 1)].map(|(id, p)| {
            EXPIRATIONS.with(|exps| {
                exps.borrow_mut().push(
                    id.into(),  // item
                    Reverse(p), // priority
                )
            })
        });

        thread_local!(static REMOVER: RefCell<Box<dyn Remove>> = RefCell::new(Box::new({
            let mut r = MockRemove::new();
            r.expect_remove().times(1).with(predicate::eq(String::from("id-1"))).returning(|_| Ok(()));
            r
        })));

        match Expirer::new(&REMOVER, &EXPIRATIONS).expire(0) {
            Ok(()) => {}
            other => panic!("expected Ok but got {other:?}"),
        };

        Ok(())
    }
}
