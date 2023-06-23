use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Error};
use arc_swap::{access::Access, ArcSwapOption};
use async_trait::async_trait;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use ic_registry_client::client::RegistryClient;
use tokio::sync::Mutex;
use tracing::info;

use crate::{
    firewall::Rule,
    metrics::{MetricParams, WithMetrics},
    tls::{self, Provision},
    Run,
};

#[derive(Clone, PartialEq)]
pub enum ServiceConfiguration {
    Tls(String),
    Firewall(Vec<Rule>),
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

        let MetricParams { action } = &self.1;

        info!(action, status, duration, error = ?out.as_ref().err());

        out
    }
}

pub struct WithDeduplication<T>(T, Option<ServiceConfiguration>);

impl<T> WithDeduplication<T> {
    pub fn wrap(v: T) -> Self {
        Self(v, None)
    }
}

#[async_trait]
impl<T: Configure> Configure for WithDeduplication<T> {
    async fn configure(&mut self, cfg: &ServiceConfiguration) -> Result<(), ConfigureError> {
        if self.1.as_ref() == Some(cfg) {
            return Ok(());
        }

        let out = self.0.configure(cfg).await?;
        self.1 = Some(cfg.to_owned());
        Ok(out)
    }
}

pub struct Configurator {
    pub tls: Box<dyn Configure>,
    pub firewall: Box<dyn Configure>,
}

#[async_trait]
impl Configure for Configurator {
    async fn configure(&mut self, cfg: &ServiceConfiguration) -> Result<(), ConfigureError> {
        match cfg {
            ServiceConfiguration::Tls(..) => self.tls.configure(cfg).await,
            ServiceConfiguration::Firewall(..) => self.firewall.configure(cfg).await,
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
}

#[async_trait]
impl Configure for TlsConfigurator {
    async fn configure(&mut self, cfg: &ServiceConfiguration) -> Result<(), ConfigureError> {
        if let ServiceConfiguration::Tls(name) = cfg {
            // Provision new certificate
            let (cert, pkey) = self.provisioner.provision(name).await?;

            // Replace with new acceptor
            let cfg = RustlsConfig::from_pem(cert.into_bytes(), pkey.into_bytes())
                .await
                .context("failed to create rustls config")?;

            let acceptor = RustlsAcceptor::new(cfg);
            let acceptor = Arc::new(acceptor);
            let acceptor = Some(acceptor);

            self.acceptor.store(acceptor);
        }

        Ok(())
    }
}

pub struct FirewallConfigurator {}

#[async_trait]
impl Configure for FirewallConfigurator {
    async fn configure(&mut self, cfg: &ServiceConfiguration) -> Result<(), ConfigureError> {
        if let ServiceConfiguration::Firewall(rules) = cfg {
            println!("configuring firewall: {rules:?}");
        }

        Ok(())
    }
}
