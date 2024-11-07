use candid::Principal;

use crate::{LocalRef, StableSet};

#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Authorize {
    fn authorize(&self, p: &Principal) -> Result<(), AuthorizeError>;
}

pub struct Authorizer {
    authorized_principals: LocalRef<StableSet<Principal>>,
}

impl Authorizer {
    pub fn new(authorized_principals: LocalRef<StableSet<Principal>>) -> Self {
        Self {
            authorized_principals,
        }
    }
}

impl Authorize for Authorizer {
    fn authorize(&self, p: &Principal) -> Result<(), AuthorizeError> {
        if !self
            .authorized_principals
            .with(|ps| ps.borrow().contains_key(p))
        {
            return Err(AuthorizeError::Unauthorized);
        }

        Ok(())
    }
}

impl<T: Authorize> Authorize for LocalRef<T> {
    fn authorize(&self, p: &Principal) -> Result<(), AuthorizeError> {
        self.with(|a| a.borrow().authorize(p))
    }
}

impl Authorize for Box<dyn Authorize> {
    fn authorize(&self, p: &Principal) -> Result<(), AuthorizeError> {
        (**self).authorize(p)
    }
}

pub struct WithAuthorize<T, A>(pub T, pub A);
