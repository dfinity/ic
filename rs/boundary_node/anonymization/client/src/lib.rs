use std::{sync::Arc, time::SystemTime};

use anonymization_interface::{self as ifc};
use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use ic_canister_client::Agent;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    rand_core::CryptoRngCore,
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

const SALT_SIZE: usize = 64;
const RSA_KEY_SIZE: usize = 2048;

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
    LeaderDuty(LeaderMode, Vec<Pair>),

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
    // Agent for interacting with the IC
    // Note the use of `ic_canister_client::Agent` instead of `ic_cdk::Agent`
    // Ths reason for this is that `ic_canister_client` allows accepting a custom signer
    agent: Agent,

    // cid for the secret-sharing canister
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
                Error::LeaderDuty(mode, ks) => {
                    QueryError::LeaderDuty(
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

// Canister methods

pub struct CanisterMethods {
    /// register method tied to canister
    register: Arc<dyn Register>,

    /// query method tied to canister
    query: Arc<dyn Query>,

    /// submit method tied to canister
    submit: Arc<dyn Submit>,
}

impl From<Canister> for CanisterMethods {
    fn from(value: Canister) -> Self {
        Self {
            register: Arc::new(value.clone()),
            query: Arc::new(value.clone()),
            submit: Arc::new(value.clone()),
        }
    }
}

// Client

#[async_trait]
pub trait Track: Sync + Send {
    async fn track(&mut self, cb: impl Fn(Vec<u8>) + Send + Sync) -> Result<(), Error>;
}

pub struct Tracker {
    /// rng for generating a salt when needed
    rng: Box<dyn CryptoRngCore + Send + Sync>,

    /// canister client for salt sharing
    canister: CanisterMethods,

    /// Ephemeral private key for identifying client
    pkey: RsaPrivateKey,

    /// Current value of the salt
    cur: Option<Vec<u8>>,
}

impl Tracker {
    pub fn new(
        mut rng: Box<dyn CryptoRngCore + Send + Sync>,
        canister: CanisterMethods,
    ) -> Result<Self, Error> {
        // Generate private key
        let pkey = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
            .context("failed to generate rsa private key")?;

        Ok(Self {
            rng,
            canister,
            pkey,
            cur: None,
        })
    }

    fn vec_pubkey(&self) -> Vec<u8> {
        self.pkey
            .to_public_key()
            .to_pkcs1_der()
            .expect("failed to encode public-key")
            .to_vec()
    }
}

#[async_trait]
impl Track for Tracker {
    async fn track(&mut self, cb: impl Fn(Vec<u8>) + Send + Sync) -> Result<(), Error> {
        // Register public-key
        loop {
            if self
                .canister
                .register
                .register(&self.vec_pubkey())
                .await
                .is_ok()
            {
                break;
            }
        }

        loop {
            match self.canister.query.query().await {
                // Ok means we got a new salt value
                Ok(ct) => {
                    // Decrypt salt
                    let salt = match self.pkey.decrypt(
                        Pkcs1v15Encrypt, // padding
                        &ct,             // ciphertext
                    ) {
                        Ok(v) => v,

                        // Retry on failure
                        Err(_) => continue,
                    };

                    // Set value
                    self.cur = Some(salt.to_owned());

                    // Trigger callback
                    cb(salt);
                }

                // Leader means we're being asked to generate a salt
                // and encrypt it for others
                Err(QueryError::Leader(mode, pairs)) => {
                    let salt = match mode {
                        // Generate salt
                        LeaderMode::Bootstrap => {
                            let mut salt = vec![0u8; SALT_SIZE];
                            self.rng.fill_bytes(&mut salt);
                            salt
                        }

                        LeaderMode::Refresh => {
                            match &self.cur {
                                // Re-use existing salt
                                Some(salt) => salt.to_owned(),

                                // Do nothing
                                None => continue,
                            }
                        }
                    };

                    // Encrypt salt for each principal
                    let mut out = vec![];

                    for Pair(p, pk) in pairs {
                        // Parse public-key
                        let pubkey = match RsaPublicKey::from_pkcs1_der(&pk) {
                            Ok(v) => v,

                            // Skip invalid keys
                            Err(_) => continue,
                        };

                        // Encrypt salt for principal
                        let ct = match pubkey.encrypt(
                            &mut self.rng,   // rng
                            Pkcs1v15Encrypt, // padding
                            &salt,           // msg
                        ) {
                            Ok(v) => v,

                            // Skip on failure
                            Err(_) => continue,
                        };

                        // Append to result
                        out.push(Pair(
                            p,  // principal
                            ct, // ciphertext
                        ));
                    }

                    // Submit encrypted salt values
                    let _ = self.canister.submit.submit(&out).await;
                }

                Err(_) => continue,
            }
        }
    }
}
