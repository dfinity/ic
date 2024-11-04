use std::time::SystemTime;

use anonymization_interface::{self as ifc};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use ic_canister_client::Agent;

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("unauthorized")]
    Unauthorized,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Register: Sync + Send {
    async fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError>;
}

/// LeaderMode indicates whether a new salt is required
#[derive(Debug)]
pub enum LeaderMode {
    /// Generate a fresh salt
    Bootstrap,

    /// Refresh the encrypted values
    Refresh,
}

impl From<ifc::LeaderMode> for LeaderMode {
    fn from(value: ifc::LeaderMode) -> Self {
        match value {
            ifc::LeaderMode::Bootstrap => LeaderMode::Bootstrap,
            ifc::LeaderMode::Refresh => LeaderMode::Refresh,
        }
    }
}

/// Pair associates a principal with a binary-blob (pubkey, ciphertext, etc)
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

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("unavailable")]
    Unavailable,

    #[error("leader assignment received")]
    Leader(LeaderMode, Vec<Pair>),

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Query: Sync + Send {
    async fn query(&self) -> Result<Vec<u8>, QueryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    #[error("unauthorized")]
    Unauthorized,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Submit: Sync + Send {
    async fn submit(&self, vs: &[Pair]) -> Result<(), SubmitError>;
}

#[derive(Clone)]
pub struct Canister {
    agent: Agent,
    cid: Principal,
}

impl Canister {
    pub fn new(agent: Agent, cid: Principal) -> Self {
        Self { agent, cid }
    }
}

fn nonce() -> Vec<u8> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes()
        .to_vec()
}

#[async_trait]
impl Register for Canister {
    async fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        use ifc::{RegisterError as Error, RegisterResponse as Response};

        let args = Encode!(&pubkey).context("failed to encode arg")?;

        let cid = self
            .cid
            .as_slice()
            .try_into()
            .context("failed to convert cid")?;

        let resp = self
            .agent
            .execute_update(
                &cid,       // effective_canister_id
                &cid,       // canister_id
                "register", // method
                args,       // arguments
                nonce(),    // nonce
            )
            .await
            .map_err(|err| anyhow!("failed to execute: {err:?}"))?;

        let resp = resp
            .ok_or(anyhow!("received empty response"))
            .and_then(|resp| {
                Decode!(&resp, Response) // decode
                    .context("failed to decode canister response")
            })?;

        match resp {
            Response::Ok => Ok(()),
            Response::Err(err) => Err(match err {
                Error::Unauthorized => RegisterError::Unauthorized,
                Error::UnexpectedError(err) => RegisterError::UnexpectedError(anyhow!(err)),
            }),
        }
    }
}

#[async_trait]
impl Query for Canister {
    async fn query(&self) -> Result<Vec<u8>, QueryError> {
        use ifc::{QueryError as Error, QueryResponse as Response};

        let args = Encode!(&()).context("failed to encode arg")?;

        let cid = self
            .cid
            .as_slice()
            .try_into()
            .context("failed to convert cid")?;

        let resp = self
            .agent
            .execute_query(
                &cid,    // canister_id
                "query", // method
                args,    // arguments
            )
            .await
            .map_err(|err| anyhow!("failed to execute: {err:?}"))?;

        let resp = resp
            .ok_or(anyhow!("received empty response"))
            .and_then(|resp| {
                Decode!(&resp, Response) // decode
                    .context("failed to decode canister response")
            })?;

        match resp {
            Response::Ok(v) => Ok(v),
            Response::Err(err) => Err(match err {
                Error::Unauthorized => QueryError::Unauthorized,
                Error::Unavailable => QueryError::Unavailable,
                Error::Leader(mode, ks) => {
                    QueryError::Leader(
                        mode.into(),                         // mode
                        ks.iter().map(Into::into).collect(), // public-keys
                    )
                }
                Error::UnexpectedError(err) => QueryError::UnexpectedError(anyhow!(err)),
            }),
        }
    }
}

#[async_trait]
impl Submit for Canister {
    async fn submit(&self, vs: &[Pair]) -> Result<(), SubmitError> {
        use ifc::{SubmitError as Error, SubmitResponse as Response};

        let cid = self
            .cid
            .as_slice()
            .try_into()
            .context("failed to convert cid")?;

        // Convert input
        let vs: Vec<ifc::Pair> = vs.iter().map(Into::into).collect();

        let args = Encode!(&vs).context("failed to encode arg")?;

        let resp = self
            .agent
            .execute_update(
                &cid,     // effective_canister_id
                &cid,     // canister_id
                "submit", // method
                args,     // arguments
                nonce(),  // nonce
            )
            .await
            .map_err(|err| anyhow!("failed to execute: {err:?}"))?;

        let resp = resp
            .ok_or(anyhow!("received empty response"))
            .and_then(|resp| {
                Decode!(&resp, Response) // decode
                    .context("failed to decode canister response")
            })?;

        match resp {
            Response::Ok => Ok(()),
            Response::Err(err) => Err(match err {
                Error::Unauthorized => SubmitError::Unauthorized,
                Error::UnexpectedError(err) => SubmitError::UnexpectedError(anyhow!(err)),
            }),
        }
    }
}
