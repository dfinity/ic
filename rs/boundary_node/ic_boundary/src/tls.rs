use std::{
    fs,
    fs::File,
    io::{self, ErrorKind},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum::{
    extract::{Host, OriginalUri, State},
    http::{uri::PathAndQuery, Uri},
    response::{IntoResponse, Redirect},
};
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use futures_util::future::BoxFuture;
use instant_acme::{Account, AccountCredentials, LetsEncrypt, NewAccount};
use mockall::automock;
use prometheus::Registry;
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use regex::Regex;
use rustls::{
    cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
    server::{ServerConfig, ServerSessionMemoryCache},
    version::TLS13,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::RwLock,
};
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};
use x509_parser::prelude::{Pem, Validity};
use zeroize::Zeroize;

use crate::{
    acme::{Acme, Finalize, Obtain, Order, Ready},
    cli::Cli,
    configuration::{ConfigurationRunner, Configurator, TlsConfigurator},
    core::{Run, ThrottleParams, WithRetry, WithThrottle, SECOND},
    metrics::{MetricParams, WithMetrics},
};

const DAY: Duration = Duration::from_secs(24 * 3600);

// Public + Private key pair
#[derive(Clone, Debug, PartialEq)]
pub struct TLSCert(pub String, pub String);

#[derive(Clone, Debug, PartialEq)]
pub enum ProvisionResult {
    StillValid(TLSCert),
    Issued(TLSCert),
}

#[derive(Clone)]
pub struct CustomAcceptor {
    inner: Arc<ArcSwapOption<RustlsAcceptor>>,
}

impl CustomAcceptor {
    pub fn new(inner: Arc<ArcSwapOption<RustlsAcceptor>>) -> Self {
        Self { inner }
    }
}

impl<I, S> Accept<I, S> for CustomAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = S;
    type Future = BoxFuture<'static, io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.load_full().clone();

        Box::pin(async move {
            match acceptor {
                Some(acceptor) => acceptor.accept(stream, service).await,
                None => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Acceptor is not available",
                )),
            }
        })
    }
}

pub struct TokenOwner(Arc<RwLock<Option<String>>>);

impl TokenOwner {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(None)))
    }

    pub async fn set(&self, v: Option<String>) {
        let mut token = self.0.write().await;
        *token = v;
    }

    pub async fn get(&self) -> Option<String> {
        self.0.read().await.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("not found")]
    NotFound,

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[automock]
pub trait Load<T: Send + Sync>: Sync + Send {
    fn load(&self) -> Result<T, LoadError>;
}

impl<T: Send + Sync, L: Load<T>> Load<T> for Arc<L> {
    fn load(&self) -> Result<T, LoadError> {
        self.as_ref().load()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[automock]
trait Store<T: Send + Sync>: Sync + Send {
    fn store(&self, v: T) -> Result<(), StoreError>;
}

impl<T: 'static + Send + Sync, S: Store<T>> Store<T> for Arc<S> {
    fn store(&self, v: T) -> Result<(), StoreError> {
        self.as_ref().store(v)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("failed to load certificate")]
    LoadFailure(#[from] LoadError),

    #[error("failed to store certificate")]
    StoreFailure(#[from] StoreError),

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[automock]
#[async_trait]
pub trait Provision: Sync + Send {
    async fn provision(&mut self, name: &str) -> Result<ProvisionResult, ProvisionError>;
}

pub struct Provisioner {
    // Token
    token_owner: Arc<TokenOwner>,

    // Acme
    acme_order: Box<dyn Order>,
    acme_ready: Box<dyn Ready>,
    acme_finalize: Box<dyn Finalize>,
    acme_obtain: Box<dyn Obtain>,
}

impl Provisioner {
    pub fn new(
        token_owner: Arc<TokenOwner>,
        acme_order: Box<dyn Order>,
        acme_ready: Box<dyn Ready>,
        acme_finalize: Box<dyn Finalize>,
        acme_obtain: Box<dyn Obtain>,
    ) -> Self {
        Self {
            token_owner,
            acme_order,
            acme_ready,
            acme_finalize,
            acme_obtain,
        }
    }
}

#[async_trait]
impl Provision for Provisioner {
    async fn provision(&mut self, name: &str) -> Result<ProvisionResult, ProvisionError> {
        warn!("TLS: Provisioning new certificate for '{name}'");

        // Create a new ACME order
        let (mut order, challenge_key) = self
            .acme_order
            .order(name)
            .await
            .context("failed to create ACME order")?;
        debug!("TLS: Order created");

        // Set the challenge token
        self.token_owner
            .set(Some(challenge_key.key_authorization))
            .await;

        // Notify the ACME provider that the order is ready to be validated
        self.acme_ready
            .ready(&mut order)
            .await
            .context("failed to mark ACME order as ready")?;
        debug!("TLS: Order marked as ready");

        let mut key_pair = KeyPair::generate().context("failed to create key pair")?;

        // Create a Certificate Signing Request for the ACME provider
        let csr = {
            let mut params = CertificateParams::new(vec![name.to_string()])
                .context("failed to create certificate params")?;
            params.distinguished_name = DistinguishedName::new();
            params.serialize_request(&key_pair)
        }
        .context("failed to generate certificate signing request")?;
        debug!("TLS: CSR created");

        // Attempt to finalize the order by having the ACME provider sign our certificate
        self.acme_finalize
            .finalize(&mut order, csr.der().as_ref())
            .await
            .context("failed to finalize ACME order")?;
        debug!("TLS: Order finalized");

        // Obtain the signed certificate chain from the ACME provider
        let cert_chain_pem = self
            .acme_obtain
            .obtain(&mut order)
            .await
            .context("failed to obtain ACME certificate")?;

        // Unset the challenge token
        self.token_owner.set(None).await;

        warn!("TLS: Certificate for {name} successfully provisioned");

        let key_pair_pem = key_pair.serialize_pem();
        key_pair.zeroize();
        Ok(ProvisionResult::Issued(TLSCert(
            cert_chain_pem, // Certificate Chain
            key_pair_pem,   // Key pair
        )))
    }
}

// Used in case ACME client is not required
pub struct ProvisionerStatic(pub TLSCert);

#[async_trait]
impl Provision for ProvisionerStatic {
    async fn provision(&mut self, _name: &str) -> Result<ProvisionResult, ProvisionError> {
        return Ok(ProvisionResult::StillValid(self.0.clone()));
    }
}

pub struct Loader {
    pub cert_path: PathBuf,
    pub pkey_path: PathBuf,
}

impl Load<TLSCert> for Loader {
    fn load(&self) -> Result<TLSCert, LoadError> {
        let (cert, pkey) = (
            fs::read_to_string(&self.cert_path),
            fs::read_to_string(&self.pkey_path),
        );

        match (cert, pkey) {
            // Certificates Found
            (Ok(cert), Ok(pkey)) => Ok(TLSCert(cert, pkey)),

            // No certificates found
            (Err(err1), Err(err2))
                if [&err1, &err2]
                    .iter()
                    .any(|err| err.kind() == ErrorKind::NotFound) =>
            {
                Err(LoadError::NotFound)
            }

            // Other error cases
            (Err(err), _) | (_, Err(err)) => {
                Err(anyhow!("failed to load certificate: {err}").into())
            }
        }
    }
}

impl Store<TLSCert> for Loader {
    fn store(&self, v: TLSCert) -> Result<(), StoreError> {
        fs::write(&self.cert_path, v.0).context("failed to write certificate to file")?;
        fs::write(&self.pkey_path, v.1).context("failed to write private-key to file")?;

        Ok(())
    }
}

/// WithLoad attempts to load an existing set of certificates and verify them
/// and if none exist, or if they were invalid, attempts to provision new ones
pub struct WithLoad<P, L>(pub P, pub L, pub Duration);

#[async_trait]
impl<P: Provision, L: Load<TLSCert>> Provision for WithLoad<P, L> {
    async fn provision(&mut self, name: &str) -> Result<ProvisionResult, ProvisionError> {
        match self.1.load() {
            Ok(tls_cert) => {
                // An existing set of certificates was found
                // attempt to ensure they are valid
                // otherwise proceed to provision new ones
                let validity = extract_cert_validity(name, tls_cert.0.as_bytes())
                    .context("failed to extract certificate validity")?;

                if let Some(validity) = validity {
                    let (expiration, now) = (
                        validity.not_after.timestamp() as u64,
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("failed to get current time")
                            .as_secs(),
                    );

                    if (now + self.2.as_secs()) < expiration {
                        return Ok(ProvisionResult::StillValid(tls_cert));
                    }
                }
            }
            Err(LoadError::NotFound) => {}
            Err(err) => return Err(err.into()),
        }

        // No pre-existing certificates were found
        // proceed to provision new ones
        self.0.provision(name).await
    }
}

/// WithStore provisions a new set of certificates before storing them
/// via the provided the Store impl
pub struct WithStore<P, S>(pub P, pub S);

#[async_trait]
impl<P: Provision, S: Store<TLSCert>> Provision for WithStore<P, S> {
    async fn provision(&mut self, name: &str) -> Result<ProvisionResult, ProvisionError> {
        // Provision a new set of certificates
        let out = self.0.provision(name).await?;

        // Persist the certificates if they were renewed
        if let ProvisionResult::Issued(tls_cert) = out.clone() {
            self.1.store(tls_cert)?;
        }

        Ok(out)
    }
}

/// extract_cert_validity attempts to find a certificate for a given common-name
/// and pem-file data, and returns it's validity
fn extract_cert_validity(name: &str, data: &[u8]) -> Result<Option<Validity>, Error> {
    for pem in Pem::iter_from_buffer(data) {
        let pem = pem?;
        let cert = pem.parse_x509()?;

        for cn in cert.subject().iter_common_name() {
            if cn.as_str()? == name {
                return Ok(Some(cert.validity().to_owned()));
            }
        }
    }

    Ok(None)
}

pub async fn load_or_create_acme_account(
    path: &PathBuf,
    acme_provider_url: &str,
) -> Result<Account, Error> {
    let f = File::open(path).context("failed to open credentials file for reading");

    // Credentials already exist
    if let Ok(f) = f {
        let creds: AccountCredentials =
            serde_json::from_reader(f).context("failed to json parse existing acme credentials")?;

        let account = Account::from_credentials(creds)
            .await
            .context("failed to load account from credentials")?;

        return Ok(account);
    }

    // Create new account
    warn!("TLS: Creating new ACME account");
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        acme_provider_url,
        None,
    )
    .await
    .context("failed to create acme account")?;

    // Store credentials
    let f = File::create(path).context("failed to open credentials file for writing")?;

    serde_json::to_writer_pretty(f, &credentials)
        .context("failed to serialize acme credentials")?;

    Ok(account)
}

pub async fn acme_challenge(State(token): State<Arc<TokenOwner>>) -> impl IntoResponse {
    token.get().await.clone().unwrap_or_default()
}

pub async fn redirect_to_https(
    Host(host): Host,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let fallback_path = PathAndQuery::from_static("/");
    let pq = uri.path_and_query().unwrap_or(&fallback_path).as_str();

    Redirect::permanent(
        &Uri::builder()
            .scheme("https") // redirect to https
            .authority(host) // re-use the same host
            .path_and_query(pq) // re-use the same path and query
            .build()
            .unwrap()
            .to_string(),
    )
}

async fn prepare_acme_provisioner(
    acme_credentials: &PathBuf,
    renew_before: Duration,
    tls_loader: Loader,
    token_owner: Arc<TokenOwner>,
) -> Result<Box<dyn Provision>, Error> {
    warn!("TLS: Using ACME provisioner");

    let acme_account = load_or_create_acme_account(acme_credentials, LetsEncrypt::Production.url())
        .await
        .context("failed to load acme credentials")?;

    warn!("TLS: Trying to provision certificate");
    let acme_client = Acme::new(acme_account);

    let acme_order = acme_client.clone();
    let acme_order = Box::new(acme_order);

    let acme_ready = acme_client.clone();
    let acme_ready = Box::new(acme_ready);

    let acme_finalize = acme_client.clone();
    let acme_finalize = WithThrottle(acme_finalize, ThrottleParams::new(Duration::from_secs(5)));
    let acme_finalize = WithRetry(acme_finalize, Duration::from_secs(60));
    let acme_finalize = Box::new(acme_finalize);

    let acme_obtain = acme_client;
    let acme_obtain = WithThrottle(acme_obtain, ThrottleParams::new(Duration::from_secs(5)));
    let acme_obtain = WithRetry(acme_obtain, Duration::from_secs(60));
    let acme_obtain = Box::new(acme_obtain);

    // TLS Provisioner
    let tls_loader = Arc::new(tls_loader);
    let tls_provisioner = Provisioner::new(
        token_owner,
        acme_order,
        acme_ready,
        acme_finalize,
        acme_obtain,
    );
    let tls_provisioner = WithStore(tls_provisioner, tls_loader.clone());
    let tls_provisioner = WithLoad(tls_provisioner, tls_loader, renew_before);
    let tls_provisioner = Box::new(tls_provisioner);

    warn!("TLS: Successfully set up ACME provisioner");
    Ok(tls_provisioner)
}

fn prepare_static_provisioner(loader: Loader) -> Result<Box<dyn Provision>, Error> {
    warn!("TLS: Using static provisioner");
    Ok(Box::new(ProvisionerStatic(loader.load()?)))
}

pub async fn prepare_tls(
    cli: &Cli,
    registry: &Registry,
) -> Result<(impl Run, CustomAcceptor, Arc<TokenOwner>), Error> {
    // TLS Certificates Loader (Ingress)
    let tls_loader = Loader {
        cert_path: cli.tls.tls_cert_path.clone(),
        pkey_path: cli.tls.tls_pkey_path.clone(),
    };

    let token_owner = Arc::new(TokenOwner::new());

    // Use the ACME provisioner if the credentials file was specified.
    // Otherwise use static provisioner that just uses the certificates from the files on disk.
    let tls_provisioner = if let Some(v) = &cli.tls.acme_credentials_path {
        let meta = fs::metadata(v);

        // If the file exists and is empty - then use static provisioner also.
        // This is needed to run integration tests where we can't manipulate arguments easily.
        if meta.is_ok() && meta.unwrap().len() == 0 {
            prepare_static_provisioner(tls_loader)
                .context("unable to prepare static provisioner")?
        } else {
            let hostname_regex = Regex::new(
                r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$",
            )?;

            if !hostname_regex.is_match(&cli.tls.hostname) {
                return Err(anyhow!(
                    "'{}' does not look like a valid hostname",
                    cli.tls.hostname,
                ));
            }

            prepare_acme_provisioner(
                v,
                cli.tls.renew_days_before * DAY,
                tls_loader,
                token_owner.clone(),
            )
            .await
            .context("unable to prepare ACME provisioner")?
        }
    } else {
        prepare_static_provisioner(tls_loader).context("unable to prepare static provisioner")?
    };

    // TLS (Ingress) Configurator
    let tls_acceptor = Arc::new(ArcSwapOption::new(None));

    let tls_configurator = TlsConfigurator::new(tls_acceptor.clone(), tls_provisioner);
    let tls_configurator = WithMetrics(
        tls_configurator,
        MetricParams::new(registry, "configure_tls"),
    );

    let tls_acceptor = CustomAcceptor::new(tls_acceptor);

    // Service Configurator
    let svc_configurator = Configurator {
        tls: Box::new(tls_configurator),
    };

    // Configuration
    let configuration_runner = ConfigurationRunner::new(cli.tls.hostname.clone(), svc_configurator);
    let configuration_runner = WithMetrics(
        configuration_runner,
        MetricParams::new(registry, "run_configuration"),
    );
    let configuration_runner =
        WithThrottle(configuration_runner, ThrottleParams::new(600 * SECOND));

    Ok((configuration_runner, tls_acceptor, token_owner))
}

pub fn load_pem(
    certs: Vec<u8>,
    key: Vec<u8>,
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), Error> {
    use rustls_pemfile::Item;

    // Convert certificate & key from PEM format
    let mut temp = certs.as_ref();
    let certs = rustls_pemfile::certs(&mut temp);
    let key = match rustls_pemfile::read_one(&mut key.as_ref())? {
        Some(Item::Pkcs1Key(v)) => v.secret_pkcs1_der().to_vec(),
        Some(Item::Pkcs8Key(v)) => v.secret_pkcs8_der().to_vec(),
        Some(Item::Sec1Key(v)) => v.secret_sec1_der().to_vec(),
        _ => return Err(anyhow!("private key format not supported")),
    };

    // Cast into Rustls types
    let certs = certs
        .filter_map(Result::ok)
        .map(|cert| rustls::Certificate(cert.to_vec()))
        .collect();
    let key = rustls::PrivateKey(key);

    Ok((certs, key))
}

pub fn generate_rustls_config(
    certs: Vec<rustls::Certificate>,
    key: rustls::PrivateKey,
) -> Result<ServerConfig, Error> {
    let mut cfg = ServerConfig::builder()
        .with_cipher_suites(&[TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Create custom session storage with higher limit to allow effective TLS session resumption
    cfg.session_storage = ServerSessionMemoryCache::new(131072);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(cfg)
}

#[cfg(test)]
pub mod test;
