use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use anonymization_interface::{self as ifc};
use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use ic_canister_client::Agent;
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry, HistogramOpts,
    HistogramVec, IntCounterVec, Registry,
};
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    rand_core::CryptoRngCore,
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

#[allow(clippy::disallowed_types)]
use tokio::{sync::Mutex, time::sleep};

const SALT_SIZE: usize = 64;
const RSA_KEY_SIZE: usize = 2048;

#[derive(Clone, Debug)]
pub struct MetricParams {
    pub action: String,
    pub counter: IntCounterVec,
    pub recorder: HistogramVec,
}

impl MetricParams {
    pub fn new(registry: &Registry, action: &str) -> Self {
        Self::new_with_opts(registry, action, &["status"], None)
    }

    pub fn new_with_opts(
        registry: &Registry,
        action: &str,
        labels: &[&str],
        buckets: Option<&[f64]>,
    ) -> Self {
        let mut recorder_opts = HistogramOpts::new(
            format!("{action}_duration_sec"),                             // name
            format!("Records the duration of {action} calls in seconds"), // description
        );

        // Set histogram buckets if given
        buckets.inspect(|bs| {
            recorder_opts.buckets = bs.to_vec();
        });

        Self {
            action: action.to_string(),

            // Count
            counter: register_int_counter_vec_with_registry!(
                format!("{action}_total"),                       // name
                format!("Counts occurrences of {action} calls"), // description
                labels,                                          // labels
                registry,                                        // registry
            )
            .expect("failed to register counter"),

            // Duration
            recorder: register_histogram_vec_with_registry!(
                recorder_opts, // options
                labels,        // labels
                registry,      // registry
            )
            .expect("failed to register histogram"),
        }
    }
}

struct WithMetrics<T>(T, Option<MetricParams>);

pub struct ThrottleParams {
    pub d: Duration,

    #[allow(clippy::disallowed_types)]
    pub next: Arc<Mutex<Option<Instant>>>,
}

impl ThrottleParams {
    pub fn new(d: Duration) -> Self {
        Self {
            d,

            #[allow(clippy::disallowed_types)]
            next: Arc::new(Mutex::new(None)),
        }
    }
}

struct WithThrottle<T>(T, ThrottleParams);

impl<T> WithThrottle<T> {
    async fn throttle(&self) {
        // Start
        let cur = Instant::now();

        let mut next = self.1.next.lock().await;

        // Check
        if let Some(next) = *next {
            if next > cur {
                sleep(next - cur).await;
            }
        }

        // Reset
        *next = Some(Instant::now() + self.1.d);
    }
}

#[async_trait]
impl<T: Register> Register for WithThrottle<T> {
    async fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        self.throttle().await;
        self.0.register(pubkey).await
    }
}

#[async_trait]
impl<T: Query> Query for WithThrottle<T> {
    async fn query(&self) -> Result<Vec<u8>, QueryError> {
        self.throttle().await;
        self.0.query().await
    }
}

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

#[async_trait]
impl<T: Register> Register for WithMetrics<T> {
    async fn register(&self, pubkey: &[u8]) -> Result<(), RegisterError> {
        let start_time = Instant::now();

        let out = self.0.register(pubkey).await;

        let status = match &out {
            Ok(_) => "ok",
            Err(err) => match err {
                RegisterError::Unauthorized => "unauthorized",
                RegisterError::UnexpectedError(_) => "fail",
            },
        };

        let duration = start_time.elapsed().as_secs_f64();

        // Log
        println!(
            "action = 'register', status = {status}, duration = {duration}, error = {:?}",
            out.as_ref().err()
        );

        // Metrics
        if let Some(MetricParams {
            counter, recorder, ..
        }) = &self.1
        {
            // Count
            counter.with_label_values(&[status]).inc();

            // Latency
            recorder.with_label_values(&[status]).observe(duration);
        }

        return out;
    }
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

#[async_trait]
impl<T: Query> Query for WithMetrics<T> {
    async fn query(&self) -> Result<Vec<u8>, QueryError> {
        let start_time = Instant::now();

        let out = self.0.query().await;

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

        let duration = start_time.elapsed().as_secs_f64();

        // Log
        println!(
            "action = 'query', status = {status}, duration = {duration}, error = {:?}",
            out.as_ref().err()
        );

        // Metrics
        if let Some(MetricParams {
            counter, recorder, ..
        }) = &self.1
        {
            // Count
            counter.with_label_values(&[status]).inc();

            // Latency
            recorder.with_label_values(&[status]).observe(duration);
        }

        return out;
    }
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

#[async_trait]
impl<T: Submit> Submit for WithMetrics<T> {
    async fn submit(&self, vs: &[Pair]) -> Result<(), SubmitError> {
        let start_time = Instant::now();

        let out = self.0.submit(vs).await;

        let status = match &out {
            Ok(_) => "ok",
            Err(err) => match err {
                SubmitError::Unauthorized => "unauthorized",
                SubmitError::UnexpectedError(_) => "fail",
            },
        };

        let duration = start_time.elapsed().as_secs_f64();

        // Log
        println!(
            "action = 'submit', status = {status}, duration = {duration}, error = {:?}",
            out.as_ref().err()
        );

        // Metrics
        if let Some(MetricParams {
            counter, recorder, ..
        }) = &self.1
        {
            // Count
            counter.with_label_values(&[status]).inc();

            // Latency
            recorder.with_label_values(&[status]).observe(duration);
        }

        return out;
    }
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

pub struct CanisterMethodsBuilder<'a> {
    canister: Canister,
    registry: Option<&'a Registry>,
}

impl<'a> CanisterMethodsBuilder<'a> {
    pub fn new(c: Canister) -> Self {
        Self {
            canister: c,
            registry: None,
        }
    }

    pub fn with_metrics(mut self, r: &'a Registry) -> Self {
        self.registry = Some(r);
        self
    }

    pub fn build(self) -> CanisterMethods {
        CanisterMethods {
            register: {
                let v = self.canister.clone();
                let v = WithMetrics(v, self.registry.map(|r| MetricParams::new(r, "register")));
                let v = WithThrottle(v, ThrottleParams::new(Duration::from_secs(10)));
                Arc::new(v)
            },
            query: {
                let v = self.canister.clone();
                let v = WithMetrics(v, self.registry.map(|r| MetricParams::new(r, "query")));
                let v = WithThrottle(v, ThrottleParams::new(Duration::from_secs(10)));
                Arc::new(v)
            },
            submit: {
                let v = self.canister.clone();
                let v = WithMetrics(v, self.registry.map(|r| MetricParams::new(r, "submit")));
                Arc::new(v)
            },
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
                Err(QueryError::LeaderDuty(mode, pairs)) => {
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
