use candid::Principal;
use prometheus::labels;

use crate::{LocalRef, StableSet, WithMetrics};

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

impl<T: Authorize> Authorize for WithMetrics<T> {
    fn authorize(&self, p: &Principal) -> Result<(), AuthorizeError> {
        let out = self.0.authorize(p);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            AuthorizeError::Unauthorized => "unauthorized",
                            AuthorizeError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}
