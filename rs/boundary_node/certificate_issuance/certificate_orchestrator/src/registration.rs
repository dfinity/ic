use anyhow::anyhow;
use candid::Principal;
use certificate_orchestrator_interface::{Id, Name, NameError, Registration, State};
use ic_cdk::caller;
use ic_stable_structures::StableBTreeMap;

use crate::{
    acl::{Authorize, AuthorizeError, WithAuthorize},
    id::Generate,
    LocalRef, Memory,
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
}

impl Creator {
    pub fn new(
        id_generator: LocalRef<Box<dyn Generate>>,
        registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>,
        names: LocalRef<StableBTreeMap<Memory, Name, Id>>,
    ) -> Self {
        Self {
            id_generator,
            registrations,
            names,
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
                .insert(name.to_owned(), id.clone())
                .map_err(|err| anyhow!(format!("failed to insert: {err}")))
        })?;

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
}

impl Updater {
    pub fn new(registrations: LocalRef<StableBTreeMap<Memory, Id, Registration>>) -> Self {
        Self { registrations }
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
                    id,
                    Registration {
                        name: domain,
                        canister,
                        state,
                    },
                )
                .map_err(|err| UpdateError::from(anyhow!(format!("failed to insert: {err}"))))?;

            Ok(())
        })
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
