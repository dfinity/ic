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
use instant_acme::{Account, AccountCredentials, NewAccount};
use mockall::automock;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use std::{
    fs,
    fs::File,
    io::{self, ErrorKind},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::RwLock,
};
use tokio_rustls::server::TlsStream;
use x509_parser::prelude::{Pem, Validity};

use crate::acme::{Finalize, Obtain, Order, Ready};

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
        let inner = &*self.inner;
        let acceptor = inner.load().clone();

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

pub struct TokenOwner(pub Arc<RwLock<Option<String>>>);

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
#[async_trait]
trait Load<T: Send + Sync>: Sync + Send {
    async fn load(&self) -> Result<T, LoadError>;
}

#[async_trait]
impl<T: Send + Sync, L: Load<T>> Load<T> for Arc<L> {
    async fn load(&self) -> Result<T, LoadError> {
        self.as_ref().load().await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[automock]
#[async_trait]
trait Store<T: Send + Sync>: Sync + Send {
    async fn store(&self, v: T) -> Result<(), StoreError>;
}

#[async_trait]
impl<T: 'static + Send + Sync, S: Store<T>> Store<T> for Arc<S> {
    async fn store(&self, v: T) -> Result<(), StoreError> {
        self.as_ref().store(v).await
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
        // Create a new ACME order
        let (mut order, challenge_key) = self
            .acme_order
            .order(name)
            .await
            .context("failed to create ACME order")?;

        // Set the challenge token
        self.token_owner
            .set(Some(challenge_key.key_authorization))
            .await;

        // Notify the ACME provider that the order is ready to be validated
        self.acme_ready
            .ready(&mut order)
            .await
            .context("failed to mark ACME order as ready")?;

        // Create a certificate for the ACME provider to sign
        let cert = Certificate::from_params({
            let mut params = CertificateParams::new(vec![name.to_string()]);
            params.distinguished_name = DistinguishedName::new();
            params
        })
        .context("failed to generate certificate")?;

        // Create a Certificate Signing Request for the ACME provider
        let csr = cert
            .serialize_request_der()
            .context("failed to create certificate signing request")?;

        // Attempt to finalize the order by having the ACME provider sign our certificate
        self.acme_finalize
            .finalize(&mut order, &csr)
            .await
            .context("failed to finalize ACME order")?;

        // Obtain the signed certificate chain from the ACME provider
        let cert_chain_pem = self
            .acme_obtain
            .obtain(&mut order)
            .await
            .context("failed to obtain ACME certificate")?;

        // Unset the challenge token
        self.token_owner.set(None).await;

        Ok(ProvisionResult::Issued(TLSCert(
            cert_chain_pem,                   // Certificate Chain
            cert.serialize_private_key_pem(), // Private Key
        )))
    }
}

pub struct Loader {
    pub cert_path: PathBuf,
    pub pkey_path: PathBuf,
}

#[async_trait]
impl Load<TLSCert> for Loader {
    async fn load(&self) -> Result<TLSCert, LoadError> {
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

#[async_trait]
impl Store<TLSCert> for Loader {
    async fn store(&self, v: TLSCert) -> Result<(), StoreError> {
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
        match self.1.load().await {
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
            self.1.store(tls_cert).await?;
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
    http_client: Box<dyn instant_acme::HttpClient>,
) -> Result<Account, Error> {
    let f = File::open(path).context("failed to open credentials file for reading");

    // Credentials already exist
    if let Ok(f) = f {
        let creds: AccountCredentials =
            serde_json::from_reader(f).context("failed to json parse existing acme credentials")?;

        let account =
            Account::from_credentials(creds).context("failed to load account from credentials")?;

        return Ok(account);
    }

    // Create new account
    let account = Account::create_with_http(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        acme_provider_url,
        None,
        http_client,
    )
    .await
    .context("failed to create acme account")?;

    // Store credentials
    let f = File::create(path).context("failed to open credentials file for writing")?;

    serde_json::to_writer_pretty(f, &account.credentials())
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

#[cfg(test)]
pub mod test;
