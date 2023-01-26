use std::cmp::Reverse;

use anyhow::anyhow;
use candid::Principal;
use certificate_orchestrator_interface::{Id, Name, NameError, Registration, State};
use ic_cdk::caller;
use ic_stable_structures::StableBTreeMap;
use priority_queue::PriorityQueue;

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use tests::time;
    } else {
        use ic_cdk::api::time;
    }
}

use crate::{
    acl::{Authorize, AuthorizeError, WithAuthorize},
    id::Generate,
    LocalRef, Memory, REGISTRATION_EXPIRATION_TTL,
};

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error(transparent)]
    NameError(#[from] NameError),
    #[error("Registration '{0}' already exists")]
    Duplicate(Id),
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
    registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
    names: LocalRef<StableBTreeMap<Memory, Name, Id>>,
    expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Creator {
    pub fn new(
        id_generator: LocalRef<Box<dyn Generate>>,
        registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
        names: LocalRef<StableBTreeMap<Memory, Name, Id>>,
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
            return Err(CreateError::Duplicate(id));
        }

        // Generate ID
        let id = self.id_generator.with(|g| g.borrow().generate());

        // Create registration
        self.registrations.with(|regs| {
            regs.borrow_mut()
                .insert(
                    id.clone(),
                    Registration {
                        name: name.to_owned(),
                        canister: canister.to_owned(),
                        state: State::PendingOrder,
                    },
                )
                .map_err(|err| anyhow!(format!("failed to insert: {err}")))
        })?;

        // Update name mapping
        self.names.with(|names| {
            names
                .borrow_mut()
                .insert(name.to_owned(), id.to_owned())
                .map_err(|err| anyhow!(format!("failed to insert: {err}")))
        })?;

        // Schedule expiration
        self.expirations.with(|expirations| {
            let mut expirations = expirations.borrow_mut();
            expirations.push(
                id.to_owned(),
                Reverse(time() + REGISTRATION_EXPIRATION_TTL.as_nanos() as u64),
            );
        });

        Ok(id)
    }
}

impl<T: Create, A: Authorize> Create for WithAuthorize<T, A> {
    fn create(&self, domain: &str, canister: &Principal) -> Result<Id, CreateError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => CreateError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => CreateError::UnexpectedError(err),
            });
        };

        self.0.create(domain, canister)
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
    registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
}

impl Getter {
    pub fn new(registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>) -> Self {
        Self { registrations }
    }
}

impl Get for Getter {
    fn get(&self, id: &Id) -> Result<Registration, GetError> {
        self.registrations
            .with(|regs| regs.borrow().get(id).ok_or(GetError::NotFound))
    }
}

impl<T: Get, A: Authorize> Get for WithAuthorize<T, A> {
    fn get(&self, id: &Id) -> Result<Registration, GetError> {
        if let Err(err) = self.1.authorize(&caller()) {
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
    fn update(&self, id: Id, state: State) -> Result<(), UpdateError>;
}

pub struct Updater {
    registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
    expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    retries: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Updater {
    pub fn new(
        registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
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
    fn update(&self, id: Id, state: State) -> Result<(), UpdateError> {
        self.registrations.with(|regs| {
            let Registration {
                name: domain,
                canister,
                ..
            } = regs.borrow().get(&id).ok_or(UpdateError::NotFound)?;

            regs.borrow_mut()
                .insert(
                    id.to_owned(),
                    Registration {
                        name: domain,
                        canister,
                        state: state.to_owned(),
                    },
                )
                .map_err(|err| UpdateError::from(anyhow!(format!("failed to insert: {err}"))))
        })?;

        // Successful registrations should not be expired or retried
        if state == State::Available {
            self.expirations.with(|exps| exps.borrow_mut().remove(&id));
            self.retries.with(|rets| rets.borrow_mut().remove(&id));
        }

        Ok(())
    }
}

impl<T: Update, A: Authorize> Update for WithAuthorize<T, A> {
    fn update(&self, id: Id, state: State) -> Result<(), UpdateError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => UpdateError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => UpdateError::UnexpectedError(err),
            });
        };

        self.0.update(id, state)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExpireError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Expire {
    fn expire(&self, t: u64) -> Result<(), ExpireError>;
}

pub struct Expirer {
    registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
    names: LocalRef<StableBTreeMap<Memory, Name, Id>>,
    tasks: LocalRef<PriorityQueue<String, Reverse<u64>>>,
    expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
}

impl Expirer {
    pub fn new(
        registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
        names: LocalRef<StableBTreeMap<Memory, Name, Id>>,
        tasks: LocalRef<PriorityQueue<String, Reverse<u64>>>,
        expirations: LocalRef<PriorityQueue<Id, Reverse<u64>>>,
    ) -> Self {
        Self {
            registrations,
            names,
            tasks,
            expirations,
        }
    }
}

impl Expire for Expirer {
    fn expire(&self, t: u64) -> Result<(), ExpireError> {
        self.expirations.with(|exps| {
            let mut exps = exps.borrow_mut();

            #[allow(clippy::while_let_loop)]
            loop {
                // Check for next expiration
                let p = match exps.peek() {
                    Some((_, p)) => p.0,
                    None => break,
                };

                if p > t {
                    break;
                }

                let id = match exps.pop() {
                    Some((id, _)) => id,
                    None => break,
                };

                // Remove registration and name mapping
                let name = self
                    .registrations
                    .with(|regs| match regs.borrow().get(&id) {
                        Some(reg) => Ok(reg.name),
                        None => Err(anyhow!("expired registration not found")),
                    })?;

                self.registrations
                    .with(|regs| regs.borrow_mut().remove(&id));

                self.names.with(|names| names.borrow_mut().remove(&name));

                // Remove task
                self.tasks.with(|tasks| tasks.borrow_mut().remove(&id));
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;

    use super::*;
    use crate::{EXPIRATIONS, ID_GENERATOR, NAMES, REGISTRATIONS, RETRIES};

    pub fn time() -> u64 {
        0
    }

    #[test]
    fn get_empty() {
        let getter = Getter::new(&REGISTRATIONS);

        match getter.get(&String::from("id")) {
            Err(GetError::NotFound) => {}
            other => panic!("expected NotFound but got {other:?}"),
        };
    }

    #[test]
    fn get_ok() -> Result<(), Error> {
        let reg = Registration {
            name: Name::try_from("name")?,
            canister: Principal::from_text("aaaaa-aa")?,
            state: State::Available,
        };

        REGISTRATIONS.with(|regs| {
            regs.borrow_mut().insert("id".into(), reg.clone()).unwrap();
        });

        let getter = Getter::new(&REGISTRATIONS);

        let out = match getter.get(&String::from("id")) {
            Ok(reg) => reg,
            other => panic!("expected registration but got {other:?}"),
        };

        assert_eq!(out, reg);

        Ok(())
    }

    #[test]
    fn create_ok() -> Result<(), Error> {
        crate::ID_SEED.with(|s| {
            s.borrow_mut()
                .insert((), 0)
                .expect("failed to insert id seed")
        });

        let creator = Creator::new(&ID_GENERATOR, &REGISTRATIONS, &NAMES, &EXPIRATIONS);

        let id = creator.create(
            "name",                             // name
            &Principal::from_text("aaaaa-aa")?, // canister
        )?;

        // Check regsitration
        let reg = REGISTRATIONS
            .with(|regs| regs.borrow().get(&id))
            .expect("expected registration to exist but none found");

        assert_eq!(
            reg,
            Registration {
                name: Name::try_from("name")?,
                canister: Principal::from_text("aaaaa-aa")?,
                state: State::PendingOrder,
            }
        );

        // Check name
        let iid = NAMES
            .with(|names| {
                names
                    .borrow()
                    .get(&Name::try_from("name").expect("failed to create name"))
            })
            .expect("expected name mapping to exist but none found");

        assert_eq!(id, iid, "expected ids to match");

        Ok(())
    }

    #[test]
    fn update_ok() -> Result<(), Error> {
        let reg = Registration {
            name: Name::try_from("name")?,
            canister: Principal::from_text("aaaaa-aa")?,
            state: State::PendingOrder,
        };

        REGISTRATIONS
            .with(|regs| regs.borrow_mut().insert("id".into(), reg))
            .expect("failed to insert");

        Updater::new(&REGISTRATIONS, &EXPIRATIONS, &RETRIES)
            .update("id".into(), State::PendingChallengeResponse)?;

        // Check registration
        let reg = REGISTRATIONS
            .with(|regs| regs.borrow().get(&String::from("id")))
            .expect("expected registration to exist but none found");

        assert_eq!(
            reg,
            Registration {
                name: Name::try_from("name")?,
                canister: Principal::from_text("aaaaa-aa")?,
                state: State::PendingChallengeResponse,
            }
        );

        Ok(())
    }
}
