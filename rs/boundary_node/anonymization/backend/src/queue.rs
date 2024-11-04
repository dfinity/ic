use anonymization_interface::{self as ifc};
use candid::Principal;
use ic_cdk::caller;

use crate::{
    acl::{Authorize, AuthorizeError, WithAuthorize},
    LocalRef, StableMap, StableSet,
};

#[derive(Clone)]
pub struct Pair(pub Principal, pub Vec<u8>);

impl std::fmt::Debug for Pair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Pair")
            .field(&self.0.to_text())
            .field(&"..")
            .finish()
    }
}

impl From<&ifc::Pair> for Pair {
    fn from(value: &ifc::Pair) -> Self {
        Self(value.0, value.1.to_owned())
    }
}

impl From<&Pair> for ifc::Pair {
    fn from(value: &Pair) -> Self {
        Self(value.0, value.1.to_owned())
    }
}

// Register

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Register {
    fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError>;
}

pub struct Registrator {
    _pubkeys: LocalRef<StableMap<Principal, Vec<u8>>>,
    _queue: LocalRef<StableSet<Principal>>,
    _encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
}

impl Registrator {
    pub fn new(
        pubkeys: LocalRef<StableMap<Principal, Vec<u8>>>,
        queue: LocalRef<StableSet<Principal>>,
        encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
    ) -> Self {
        Self {
            _pubkeys: pubkeys,
            _queue: queue,
            _encrypted_values: encrypted_values,
        }
    }
}

impl Register for Registrator {
    fn register(&self, _pubkey: &[u8]) -> Result<(), RegisterError> {
        unimplemented!()
    }
}

impl<T: Register, A: Authorize> Register for WithAuthorize<T, A> {
    fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => RegisterError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => RegisterError::UnexpectedError(err),
            });
        };

        self.0.register(pubkey)
    }
}

// Query

#[derive(Debug)]
pub enum LeaderMode {
    Bootstrap,
    Refresh,
}

impl From<&LeaderMode> for ifc::LeaderMode {
    fn from(value: &LeaderMode) -> Self {
        match &value {
            LeaderMode::Bootstrap => Self::Bootstrap,
            LeaderMode::Refresh => Self::Refresh,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Query {
    fn query(&self) -> Result<Vec<u8>, QueryError>;
}

pub struct Querier {
    _encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
}

impl Querier {
    pub fn new(encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>) -> Self {
        Self {
            _encrypted_values: encrypted_values,
        }
    }
}

impl Query for Querier {
    fn query(&self) -> Result<Vec<u8>, QueryError> {
        unimplemented!()
    }
}

impl<T: Query, A: Authorize> Query for WithAuthorize<T, A> {
    fn query(&self) -> Result<Vec<u8>, QueryError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => QueryError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => QueryError::UnexpectedError(err),
            });
        };

        self.0.query()
    }
}

// Submit

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("Unauthorized")]
    Unauthorized,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Submit {
    fn submit(&self, ps: &[Pair]) -> Result<(), SubmitError>;
}

pub struct Submitter {
    _queue: LocalRef<StableSet<Principal>>,
    _encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
}

impl Submitter {
    pub fn new(
        queue: LocalRef<StableSet<Principal>>,
        encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
    ) -> Self {
        Self {
            _queue: queue,
            _encrypted_values: encrypted_values,
        }
    }
}

impl Submit for Submitter {
    fn submit(&self, _ps: &[Pair]) -> Result<(), SubmitError> {
        unimplemented!()
    }
}

impl<T: Submit, A: Authorize> Submit for WithAuthorize<T, A> {
    fn submit(&self, ps: &[Pair]) -> Result<(), SubmitError> {
        if let Err(err) = self.1.authorize(&caller()) {
            return Err(match err {
                AuthorizeError::Unauthorized => SubmitError::Unauthorized,
                AuthorizeError::UnexpectedError(err) => SubmitError::UnexpectedError(err),
            });
        };

        self.0.submit(ps)
    }
}
