use anonymization_interface::{self as ifc};
use candid::Principal;
use ic_cdk::caller;
use prometheus::labels;

use crate::{
    acl::{Authorize, AuthorizeError, WithAuthorize},
    LocalRef, StableMap, StableSet, StableValue, WithLogs, WithMetrics,
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
    pubkeys: LocalRef<StableMap<Principal, Vec<u8>>>,
    queue: LocalRef<StableSet<Principal>>,
    encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
}

impl Registrator {
    pub fn new(
        pubkeys: LocalRef<StableMap<Principal, Vec<u8>>>,
        queue: LocalRef<StableSet<Principal>>,
        encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
    ) -> Self {
        Self {
            pubkeys,
            queue,
            encrypted_values,
        }
    }
}

impl Register for Registrator {
    fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        // Register public-key
        self.pubkeys.with(|ks| {
            ks.borrow_mut().insert(
                caller(),          // principal
                pubkey.to_owned(), // pubkey
            )
        });

        // Remove previous encrypted value, if any exist
        self.encrypted_values
            .with(|vs| vs.borrow_mut().remove(&caller()));

        // Add to queue
        self.queue.with(|q| {
            q.borrow_mut().insert(
                caller(), // principal
                (),       // unit
            )
        });

        Ok(())
    }
}

pub struct WithDedupe<T>(pub T, pub LocalRef<StableMap<Principal, Vec<u8>>>);

impl<T: Register> Register for WithDedupe<T> {
    fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        // Ignore duplicate registrations
        if let Some(v) = self.1.with(|ks| ks.borrow().get(&caller())) {
            if v.eq(pubkey) {
                return Ok(());
            }
        }

        self.0.register(pubkey)
    }
}

pub struct WithUnassignLeader<T>(
    pub T,
    pub LocalRef<StableValue<Principal>>, // LeaderAssignment
);

impl<T: Register> Register for WithUnassignLeader<T> {
    fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        // Unassign if leader
        self.1.with(|p| {
            let mut p = p.borrow_mut();

            if match p.get(&()) {
                Some(p) => caller() == p,
                None => false,
            } {
                p.remove(&());
            }
        });

        self.0.register(pubkey)
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

impl<T: Register> Register for WithLogs<T> {
    fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        let out = self.0.register(pubkey);

        let status = match &out {
            Ok(_) => "ok",
            Err(err) => match err {
                RegisterError::Unauthorized => "unauthorized",
                RegisterError::UnexpectedError(_) => "fail",
            },
        };

        ic_cdk::println!(
            "action = '{}', status = {}, error = {:?}",
            "register",
            status,
            out.as_ref().err()
        );

        out
    }
}

impl<T: Register> Register for WithMetrics<T> {
    fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        let out = self.0.register(pubkey);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            RegisterError::Unauthorized => "unauthorized",
                            RegisterError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
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

    #[error("Unavailable")]
    Unavailable,

    #[error("LeaderDuty")]
    LeaderDuty(LeaderMode, Vec<Pair>),

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

pub trait Query {
    fn query(&self) -> Result<Vec<u8>, QueryError>;
}

pub struct Querier {
    encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
}

impl Querier {
    pub fn new(encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>) -> Self {
        Self { encrypted_values }
    }
}

impl Query for Querier {
    fn query(&self) -> Result<Vec<u8>, QueryError> {
        self.encrypted_values
            .with(|vs| vs.borrow().get(&caller()))
            .ok_or(QueryError::Unavailable)
    }
}

pub struct WithLeaderAssignment<T>(
    pub T,
    pub LocalRef<StableValue<Principal>>, // LeaderAssignment
    pub LocalRef<StableSet<Principal>>,   // Queue
    pub LocalRef<StableMap<Principal, Vec<u8>>>, // PublicKeys
    pub LocalRef<StableMap<Principal, Vec<u8>>>, // EncryptedValues
);

impl<T: Query> Query for WithLeaderAssignment<T> {
    fn query(&self) -> Result<Vec<u8>, QueryError> {
        // Check leader assignment
        let is_leader = match self.1.with(|p| p.borrow().get(&())) {
            Some(p) => caller() == p,
            None => false,
        };

        if !is_leader {
            return self.0.query();
        }

        // Check queue
        let ps: Vec<Principal> = self.2.with(|q| q.borrow().iter().map(|(k, _)| k).collect());

        // Ignore when queue is empty
        if ps.is_empty() {
            return self.0.query();
        }

        // Convert to principal public-key pairs
        let ps: Vec<Pair> = ps
            .into_iter()
            .filter_map(|p| self.3.with(|ks| ks.borrow().get(&p).map(|k| Pair(p, k))))
            .collect();

        // Ignore if there are missing public-keys
        if ps.is_empty() {
            return self.0.query();
        }

        // Decide on mode
        let mode = match self.4.with(|vs| vs.borrow().is_empty()) {
            true => LeaderMode::Bootstrap,
            _ => LeaderMode::Refresh,
        };

        Err(QueryError::LeaderDuty(
            mode, // mode
            ps,   // principal pubkey pairs
        ))
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

impl<T: Query> Query for WithLogs<T> {
    fn query(&self) -> Result<Vec<u8>, QueryError> {
        let out = self.0.query();

        let status = match &out {
            Ok(_) => "ok",
            Err(err) => match err {
                QueryError::Unauthorized => "unauthorized",
                QueryError::Unavailable => "unavailable",
                QueryError::LeaderDuty(mode, _) => match mode {
                    LeaderMode::Bootstrap => "leader-bootstrap",
                    LeaderMode::Refresh => "leader-refresh",
                },
                QueryError::UnexpectedError(_) => "fail",
            },
        };

        ic_cdk::println!(
            "action = '{}', status = {}, error = {:?}",
            "query",
            status,
            out.as_ref().err()
        );

        out
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
    queue: LocalRef<StableSet<Principal>>,
    encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
}

impl Submitter {
    pub fn new(
        queue: LocalRef<StableSet<Principal>>,
        encrypted_values: LocalRef<StableMap<Principal, Vec<u8>>>,
    ) -> Self {
        Self {
            queue,
            encrypted_values,
        }
    }
}

impl Submit for Submitter {
    fn submit(&self, ps: &[Pair]) -> Result<(), SubmitError> {
        // Discard pairs that arent in the queue
        let ps: Vec<&Pair> = ps
            .iter()
            .filter(|Pair(p, _)| self.queue.with(|q| q.borrow().contains_key(p)))
            .collect();

        ps.iter().for_each(|Pair(p, ct)| {
            // Set encrypted values
            self.encrypted_values.with(|vs| {
                vs.borrow_mut().insert(
                    p.to_owned(),  // principal
                    ct.to_owned(), // ciphertext
                )
            });

            // Remove from queue once complete
            self.queue.with(|q| {
                q.borrow_mut().remove(
                    p, // principal
                )
            });
        });

        Ok(())
    }
}

pub struct WithLeaderCheck<T>(
    pub T,
    pub LocalRef<StableValue<Principal>>, // LeaderAssignment
);

impl<T: Submit> Submit for WithLeaderCheck<T> {
    fn submit(&self, ps: &[Pair]) -> Result<(), SubmitError> {
        // Check leader assignment
        let is_leader = match self.1.with(|p| p.borrow().get(&())) {
            Some(p) => caller() == p,
            None => false,
        };

        if !is_leader {
            return Err(SubmitError::Unauthorized);
        }

        self.0.submit(ps)
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

impl<T: Submit> Submit for WithLogs<T> {
    fn submit(&self, ps: &[Pair]) -> Result<(), SubmitError> {
        let out = self.0.submit(ps);

        let status = match &out {
            Ok(_) => "ok",
            Err(err) => match err {
                SubmitError::Unauthorized => "unauthorized",
                SubmitError::UnexpectedError(_) => "fail",
            },
        };

        ic_cdk::println!(
            "action = '{}', status = {}, error = {:?}",
            "submit",
            status,
            out.as_ref().err()
        );

        out
    }
}

impl<T: Submit> Submit for WithMetrics<T> {
    fn submit(&self, ps: &[Pair]) -> Result<(), SubmitError> {
        let out = self.0.submit(ps);

        self.1.with(|c| {
            c.borrow()
                .with(&labels! {
                    "status" => match &out {
                        Ok(_) => "ok",
                        Err(err) => match err {
                            SubmitError::Unauthorized => "unauthorized",
                            SubmitError::UnexpectedError(_) => "fail",
                        },
                    },
                })
                .inc()
        });

        out
    }
}
