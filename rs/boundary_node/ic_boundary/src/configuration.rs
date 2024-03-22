use std::{sync::Arc, time::Instant};

use {
    anyhow::{anyhow, Context, Error},
    arc_swap::ArcSwapOption,
    async_trait::async_trait,
    axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig},
    tracing::info,
};

use crate::{
    core::Run,
    metrics::{MetricParams, WithMetrics},
    tls::{self, generate_rustls_config, load_pem, Provision, ProvisionResult, TLSCert},
};

#[non_exhaustive]
#[derive(Clone, PartialEq)]
pub enum ServiceConfiguration {
    Tls(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigureError {
    #[error(transparent)]
    ProvisionError(#[from] tls::ProvisionError),

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Configure: Send + Sync {
    async fn configure(&mut self, cfg: &ServiceConfiguration) -> Result<(), ConfigureError>;
}

#[async_trait]
impl<T: Configure> Configure for WithMetrics<T> {
    async fn configure(&mut self, cfg: &ServiceConfiguration) -> Result<(), ConfigureError> {
        let start_time = Instant::now();

        let out = self.0.configure(cfg).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.with_label_values(&[status]).inc();
        recorder.with_label_values(&[status]).observe(duration);

        info!(action, status, duration, error = ?out.as_ref().err());

        out
    }
}

pub struct Configurator {
    pub tls: Box<dyn Configure>,
}

#[async_trait]
impl Configure for Configurator {
    async fn configure(&mut self, cfg: &ServiceConfiguration) -> Result<(), ConfigureError> {
        match cfg {
            ServiceConfiguration::Tls(..) => self.tls.configure(cfg).await,
        }
    }
}

pub struct TlsConfigurator {
    acceptor: Arc<ArcSwapOption<RustlsAcceptor>>,
    provisioner: Box<dyn Provision>,
}

impl TlsConfigurator {
    pub fn new(
        acceptor: Arc<ArcSwapOption<RustlsAcceptor>>,
        provisioner: Box<dyn Provision>,
    ) -> Self {
        Self {
            acceptor,
            provisioner,
        }
    }

    async fn apply(&self, tls_cert: TLSCert) -> Result<(), ConfigureError> {
        let (certs, key) = load_pem(tls_cert.0.into_bytes(), tls_cert.1.into_bytes())
            .map_err(|e| anyhow!("unable to load PEM: {e:?}"))?;

        let cfg = generate_rustls_config(certs, key)?;
        let cfg = RustlsConfig::from_config(Arc::new(cfg));

        // Construct new acceptor
        let acceptor = Some(Arc::new(RustlsAcceptor::new(cfg)));

        // Replace current acceptor
        self.acceptor.store(acceptor);

        Ok(())
    }
}

#[async_trait]
impl Configure for TlsConfigurator {
    async fn configure(&mut self, cfg: &ServiceConfiguration) -> Result<(), ConfigureError> {
        let ServiceConfiguration::Tls(name) = cfg;

        // Try to provision a certificate
        match self.provisioner.provision(name).await? {
            // If there was a new certificate issued - apply it
            ProvisionResult::Issued(tls_cert) => self.apply(tls_cert).await,

            // If it's still valid - apply it only if we don't have one yet loaded
            ProvisionResult::StillValid(tls_cert) => {
                if self.acceptor.load().is_none() {
                    self.apply(tls_cert).await
                } else {
                    Ok(())
                }
            }
        }
    }
}

pub struct ConfigurationRunner<C> {
    hostname: String,
    configurator: C,
}

impl<C> ConfigurationRunner<C> {
    pub fn new(hostname: String, configurator: C) -> Self {
        Self {
            hostname,
            configurator,
        }
    }
}

#[async_trait]
impl<C: Configure> Run for ConfigurationRunner<C> {
    async fn run(&mut self) -> Result<(), Error> {
        // TLS
        self.configurator
            .configure(&ServiceConfiguration::Tls(self.hostname.clone()))
            .await
            .context("failed to apply tls configuration")?;

        Ok(())
    }
}
