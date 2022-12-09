use ic_cdk::export::Principal;

use crate::{LocalRef, StableSet};

#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Authorize {
    fn authorize(&self, principal: &Principal) -> Result<(), AuthorizeError>;
}

pub struct Authorizer {
    authorized_principals: LocalRef<StableSet<String>>,
}

impl Authorizer {
    pub fn new(authorized_principals: LocalRef<StableSet<String>>) -> Self {
        Self {
            authorized_principals,
        }
    }
}

impl Authorize for Authorizer {
    fn authorize(&self, principal: &Principal) -> Result<(), AuthorizeError> {
        if !self
            .authorized_principals
            .with(|ps| ps.borrow().contains_key(&principal.to_text()))
        {
            return Err(AuthorizeError::Unauthorized);
        }

        Ok(())
    }
}

impl<T: Authorize> Authorize for LocalRef<T> {
    fn authorize(&self, principal: &Principal) -> Result<(), AuthorizeError> {
        self.with(|a| a.borrow().authorize(principal))
    }
}

impl Authorize for Box<dyn Authorize> {
    fn authorize(&self, principal: &Principal) -> Result<(), AuthorizeError> {
        (**self).authorize(principal)
    }
}

pub struct WithAuthorize<T, A>(pub T, pub A);
