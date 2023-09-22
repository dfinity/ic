use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use axum_server::{accept::Accept, tls_rustls::RustlsAcceptor};
use futures_util::future::BoxFuture;
use mockall::automock;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use std::{
    fs,
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

#[derive(Debug, thiserror::Error)]
pub enum SetError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Set<T>: Sync + Send {
    async fn set(&mut self, v: T) -> Result<(), SetError>;
}

pub struct TokenSetter(pub Arc<RwLock<Option<String>>>);

#[async_trait]
impl Set<Option<String>> for TokenSetter {
    async fn set(&mut self, v: Option<String>) -> Result<(), SetError> {
        println!("setting token: {v:?}");

        let mut token = self.0.write().await;
        *token = v;

        Ok(())
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
        self.load().await
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
        self.store(v).await
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
    async fn provision(&mut self, name: &str) -> Result<(String, String), ProvisionError>;
}

pub struct Provisioner {
    // Token
    token_setter: Box<dyn Set<Option<String>>>,

    // Acme
    acme_order: Box<dyn Order>,
    acme_ready: Box<dyn Ready>,
    acme_finalize: Box<dyn Finalize>,
    acme_obtain: Box<dyn Obtain>,
}

impl Provisioner {
    pub fn new(
        token_setter: Box<dyn Set<Option<String>>>,
        acme_order: Box<dyn Order>,
        acme_ready: Box<dyn Ready>,
        acme_finalize: Box<dyn Finalize>,
        acme_obtain: Box<dyn Obtain>,
    ) -> Self {
        Self {
            token_setter,
            acme_order,
            acme_ready,
            acme_finalize,
            acme_obtain,
        }
    }
}

#[async_trait]
impl Provision for Provisioner {
    async fn provision(&mut self, name: &str) -> Result<(String, String), ProvisionError> {
        // Create a new ACME order
        let (mut order, challenge_key) = self
            .acme_order
            .order(name)
            .await
            .context("failed to create acme order")?;

        // Set the challenge token
        self.token_setter
            .set(Some(challenge_key.key_authorization))
            .await
            .context("failed to set token")?;

        // Notify the ACME provider that the order is ready to be validated
        self.acme_ready
            .ready(&mut order)
            .await
            .context("failed to mark acme order as ready")?;

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
            .context("failed to finalize acme order")?;

        // Obtain the signed certificate chain from the ACME provider
        let cert_chain_pem = self
            .acme_obtain
            .obtain(&mut order)
            .await
            .context("failed to obtain acme certificate")?;

        // Unset the challenge token
        self.token_setter
            .set(None)
            .await
            .context("failed to set token")?;

        Ok((
            cert_chain_pem,                   // Certificate Chain
            cert.serialize_private_key_pem(), // Private Key
        ))
    }
}

pub struct Loader {
    pub cert_path: PathBuf,
    pub pkey_path: PathBuf,
}

#[async_trait]
impl Load<(String, String)> for Loader {
    async fn load(&self) -> Result<(String, String), LoadError> {
        let (cert, pkey) = (
            fs::read_to_string(&self.cert_path),
            fs::read_to_string(&self.pkey_path),
        );

        match (cert, pkey) {
            // Certificates Found
            (Ok(cert), Ok(pkey)) => Ok((cert, pkey)),

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
impl Store<(String, String)> for Loader {
    async fn store(&self, v: (String, String)) -> Result<(), StoreError> {
        fs::write(&self.cert_path, v.0).context("failed to write certificate to file")?;
        fs::write(&self.pkey_path, v.1).context("failed to write private-key to file")?;

        Ok(())
    }
}

/// WithLoad attempts to load an existing set of certificates and verify them
/// and if none exist, or if they were invalid, attempts to provision new ones
pub struct WithLoad<P, L>(pub P, pub L, pub Duration);

#[async_trait]
impl<P: Provision, L: Load<(String, String)>> Provision for WithLoad<P, L> {
    async fn provision(&mut self, name: &str) -> Result<(String, String), ProvisionError> {
        match self.1.load().await {
            Ok((cert, pkey)) => {
                // An existing set of certificates was found
                // attempt to ensure they are valid
                // otherwise proceed to provision new ones
                let validity = extract_cert_validity(name, cert.as_bytes())
                    .context("failed to extract certificiate validity")?;

                if let Some(validity) = validity {
                    let (expiration, now) = (
                        validity.not_after.timestamp() as u64,
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("failed to get current time")
                            .as_secs(),
                    );

                    if (now + self.2.as_secs()) < expiration {
                        return Ok((cert, pkey));
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
impl<P: Provision, S: Store<(String, String)>> Provision for WithStore<P, S> {
    async fn provision(&mut self, name: &str) -> Result<(String, String), ProvisionError> {
        // Provision a new set of certificates
        let out = self.0.provision(name).await?;

        // Store the certificates before returning them
        self.1.store(out.clone()).await?;

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

#[cfg(test)]
mod test {
    use std::time::Duration;

    use anyhow::{bail, Error};
    use mockall::predicate;
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, DnValue};

    use crate::tls::{
        extract_cert_validity, LoadError, MockLoad, MockProvision, MockStore, Provision, WithLoad,
        WithStore,
    };

    fn generate_certificate_chain(
        name: &str,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> Result<Vec<u8>, Error> {
        // Root
        let root_cert = Certificate::from_params(CertificateParams::new(vec![
            "root.example.com".into(), // SAN
        ]))?;

        // Intermediate
        let intermediate_cert = Certificate::from_params(CertificateParams::new(vec![
            "intermediate.example.com".into(), // SAN
        ]))?;

        // Leaf
        let leaf_cert = Certificate::from_params({
            let mut params = CertificateParams::new(vec![
                name.into(), // SAN
            ]);

            // Set common name
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, DnValue::PrintableString(name.into()));
            params.distinguished_name = dn;

            // Set validity
            params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
            params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);

            params
        })?;

        Ok([
            root_cert.serialize_pem()?.into_bytes(),
            intermediate_cert.serialize_pem()?.into_bytes(),
            leaf_cert.serialize_pem()?.into_bytes(),
        ]
        .concat())
    }

    #[tokio::test]
    async fn extract_cert_validity_found_test() -> Result<(), Error> {
        // Create a certificate
        let not_before = (2000, 1, 1);
        let not_after = (2001, 1, 1);

        let cert_chain = generate_certificate_chain(
            "leaf-1.example.com", // name
            not_before,           // not_before
            not_after,            // not_after
        )?;

        // Extract validity
        let v = extract_cert_validity(
            "leaf-1.example.com", // name
            &cert_chain,          // cert_chain
        )?
        .expect("validity not found");

        let not_before =
            rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2).unix_timestamp();

        let not_after =
            rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2).unix_timestamp();

        assert_eq!(not_before, v.not_before.timestamp());
        assert_eq!(not_after, v.not_after.timestamp());

        Ok(())
    }

    #[tokio::test]
    async fn extract_cert_validity_not_found_test() -> Result<(), Error> {
        // Create a certificate
        let not_before = (2000, 1, 1);
        let not_after = (2001, 1, 1);

        let cert_chain = generate_certificate_chain(
            "leaf-1.example.com", // name
            not_before,           // not_before
            not_after,            // not_after
        )?;

        // Extract validity
        let v = extract_cert_validity(
            "leaf-2.example.com", // name
            &cert_chain,          // cert_chain
        )?;

        if v.is_some() {
            bail!("expected certificate to not be found");
        }

        Ok(())
    }

    #[tokio::test]
    async fn with_load_not_found_test() -> Result<(), Error> {
        let mut p = MockProvision::new();
        p.expect_provision()
            .times(1)
            .with(predicate::eq("example.com"))
            .returning(|_| Ok(("cert".into(), "pkey".into())));

        let mut l = MockLoad::new();
        l.expect_load()
            .times(1)
            .returning(|| Err(LoadError::NotFound));

        let mut p = WithLoad(
            p,                      // provisioner
            l,                      // loader
            Duration::from_secs(1), // remaining cert validity
        );

        let out = p.provision("example.com").await?;
        assert_eq!(out, ("cert".into(), "pkey".into()));

        Ok(())
    }

    #[tokio::test]
    async fn with_load_expired_test() -> Result<(), Error> {
        // Generate expired certificate
        let not_before = (2000, 1, 1);
        let not_after = (2001, 1, 1);

        let cert_chain = generate_certificate_chain(
            "example.com", // name
            not_before,    // not_before
            not_after,     // not_after
        )?;
        let cert_chain = String::from_utf8(cert_chain)?;

        let mut p = MockProvision::new();
        p.expect_provision()
            .times(1)
            .with(predicate::eq("example.com"))
            .returning(|_| Ok(("cert".into(), "pkey".into())));

        let mut l = MockLoad::new();
        l.expect_load()
            .times(1)
            .returning(move || Ok((cert_chain.clone(), "pkey".into())));

        let mut p = WithLoad(
            p,                      // provisioner
            l,                      // loader
            Duration::from_secs(1), // remaining cert validity
        );

        let out = p.provision("example.com").await?;
        assert_eq!(out, ("cert".into(), "pkey".into()));

        Ok(())
    }

    #[tokio::test]
    async fn with_load_valid_test() -> Result<(), Error> {
        // Generate expired certificate
        let not_before = (2000, 1, 1);
        let not_after = (3000, 1, 1);

        let cert_chain = generate_certificate_chain(
            "example.com", // name
            not_before,    // not_before
            not_after,     // not_after
        )?;
        let cert_chain = String::from_utf8(cert_chain)?;

        let mut p = MockProvision::new();
        p.expect_provision().times(0);

        let mut l = MockLoad::new();

        let cert_chain_cpy = cert_chain.clone();
        l.expect_load()
            .times(1)
            .returning(move || Ok((cert_chain_cpy.clone(), "pkey".into())));

        let mut p = WithLoad(
            p,                      // provisioner
            l,                      // loader
            Duration::from_secs(1), // remaining cert validity
        );

        let out = p.provision("example.com").await?;
        assert_eq!(out, (cert_chain, "pkey".into()));

        Ok(())
    }

    #[tokio::test]
    async fn with_store_test() -> Result<(), Error> {
        let mut p = MockProvision::new();
        p.expect_provision()
            .times(1)
            .with(predicate::eq("example.com"))
            .returning(|_| Ok(("cert".into(), "pkey".into())));

        let mut s = MockStore::new();
        s.expect_store()
            .times(1)
            .with(predicate::eq(("cert".into(), "pkey".into())))
            .returning(|_| Ok(()));

        let mut p = WithStore(p, s);

        let out = p.provision("example.com").await?;
        assert_eq!(out, ("cert".into(), "pkey".into()));

        Ok(())
    }
}
