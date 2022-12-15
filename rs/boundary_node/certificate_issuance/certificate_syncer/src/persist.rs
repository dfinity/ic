use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Instant,
};

use anyhow::{Context as AnyhowContext, Error};
use async_trait::async_trait;
use opentelemetry::{Context as OtContext, KeyValue};
use tracing::info;

use crate::{
    import::Package,
    metrics::{MetricParams, WithMetrics},
    reload::{Reload, WithReload},
    render::{Context, Render},
};

pub enum PersistStatus {
    Completed,
    SkippedUnchanged,
    SkippedEmpty,
}

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Persist: Send + Sync {
    async fn persist(&self, pkgs: &[Package]) -> Result<PersistStatus, PersistError>;
}

pub struct Persister {
    // // Dependencies
    renderer: Arc<dyn Render>,

    // Configuration
    certificates_path: PathBuf,
    configuration_path: PathBuf,
}

impl Persister {
    pub fn new(
        renderer: Arc<dyn Render>,
        certificates_path: PathBuf,
        configuration_path: PathBuf,
    ) -> Self {
        Self {
            renderer,
            certificates_path,
            configuration_path,
        }
    }
}

#[async_trait]
impl Persist for Persister {
    async fn persist(&self, pkgs: &[Package]) -> Result<PersistStatus, PersistError> {
        let cfgs = pkgs
            .iter()
            .map(|pkg| {
                // Certificates
                std::fs::create_dir_all(&self.certificates_path)
                    .context("failed to create certificates directory")?;

                let ssl_certificate_key_path = format!(
                    "{}/{}-key.pem",
                    self.certificates_path.to_string_lossy(),
                    pkg.name.to_owned()
                );
                let ssl_certificate_path = format!(
                    "{}/{}.pem",
                    self.certificates_path.to_string_lossy(),
                    pkg.name.to_owned()
                );

                std::fs::write(&ssl_certificate_key_path, &pkg.pair.0)
                    .context("failed to write private key")?;
                std::fs::write(&ssl_certificate_path, &pkg.pair.1)
                    .context("failed to write certificate")?;

                // Server
                self.renderer
                    .render(&Context {
                        name: &pkg.name,
                        ssl_certificate_key_path: &ssl_certificate_key_path,
                        ssl_certificate_path: &ssl_certificate_path,
                    })
                    .context("failed to render server block")
            })
            .collect::<Result<Vec<String>, Error>>()?;

        std::fs::write(&self.configuration_path, cfgs.join("\n"))
            .context("failed to write configuration")?;

        Ok(PersistStatus::Completed)
    }
}

#[async_trait]
impl<T: Persist> Persist for WithMetrics<T> {
    async fn persist(&self, pkgs: &[Package]) -> Result<PersistStatus, PersistError> {
        let start_time = Instant::now();

        let out = self.0.persist(pkgs).await;

        let status = match out {
            Ok(PersistStatus::Completed) => "completed",
            Ok(PersistStatus::SkippedUnchanged) => "skipped-unchanged",
            Ok(PersistStatus::SkippedEmpty) => "skipped-empty",
            Err(_) => "fail",
        };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        let cx = OtContext::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[async_trait]
impl<T: Persist, R: Reload> Persist for WithReload<T, R> {
    async fn persist(&self, pkgs: &[Package]) -> Result<PersistStatus, PersistError> {
        let out = self.0.persist(pkgs).await?;
        self.1.reload().await?;
        Ok(out)
    }
}

pub struct WithDedup<T, U>(pub T, pub Arc<RwLock<Option<U>>>);

#[async_trait]
impl<T: Persist> Persist for WithDedup<T, Vec<Package>> {
    async fn persist(&self, pkgs: &[Package]) -> Result<PersistStatus, PersistError> {
        if self
            .1
            .read()
            .map(|v| match &*v {
                None => false,
                Some(v) => *v == *pkgs,
            })
            .unwrap()
        {
            return Ok(PersistStatus::SkippedUnchanged);
        }

        let out = self.0.persist(pkgs).await;
        if out.is_ok() {
            self.1
                .write()
                .map(|mut v| *v = Some(pkgs.to_vec()))
                .unwrap();
        }

        out
    }
}

pub struct WithEmpty<T>(pub T);

#[async_trait]
impl<T: Persist> Persist for WithEmpty<T> {
    async fn persist(&self, pkgs: &[Package]) -> Result<PersistStatus, PersistError> {
        if pkgs.is_empty() {
            return Ok(PersistStatus::SkippedEmpty);
        }
        self.0.persist(pkgs).await
    }
}
