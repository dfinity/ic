use std::{
    collections::HashMap,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Instant,
};

use anyhow::{Context as AnyhowContext, Error};
use async_trait::async_trait;
use opentelemetry::KeyValue;
use tracing::info;

use crate::{
    import::Package,
    metrics::{MetricParams, WithMetrics},
    reload::{Reload, WithReload},
    render::{Context, Render},
};

#[derive(Debug, PartialEq)]
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
    domain_mappings_path: PathBuf,
}

impl Persister {
    pub fn new(
        renderer: Arc<dyn Render>,
        certificates_path: PathBuf,
        configuration_path: PathBuf,
        domain_mappings_path: PathBuf,
    ) -> Self {
        Self {
            renderer,
            certificates_path,
            configuration_path,
            domain_mappings_path,
        }
    }
}

#[async_trait]
impl Persist for Persister {
    async fn persist(&self, pkgs: &[Package]) -> Result<PersistStatus, PersistError> {
        // Certificates
        std::fs::create_dir_all(&self.certificates_path)
            .context("failed to create certificates directory")?;

        pkgs.iter().try_for_each(|pkg| {
            // Private Key
            let ssl_certificate_key_path = format!(
                "{}/{}-key.pem",
                self.certificates_path.to_string_lossy(),
                pkg.name.to_owned()
            );

            std::fs::write(ssl_certificate_key_path, &pkg.pair.0)
                .context("failed to write private key")?;

            // Certificate
            let ssl_certificate_path = format!(
                "{}/{}.pem",
                self.certificates_path.to_string_lossy(),
                pkg.name.to_owned()
            );

            std::fs::write(ssl_certificate_path, &pkg.pair.1)
                .context("failed to write certificate")?;

            Ok::<_, Error>(())
        })?;

        // Server blocks
        let cfgs = pkgs
            .iter()
            .map(|pkg| {
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

        // Domain mappings
        let mut domains: HashMap<String, String> = HashMap::new();

        pkgs.iter().for_each(|pkg| {
            domains.insert(pkg.name.to_owned(), pkg.canister.to_string());
        });

        let cntnt = (|| {
            let mut inner: Vec<u8> = Vec::new();
            let mut buf = BufWriter::new(&mut inner);

            buf.write_all("let domain_mappings = ".as_bytes())?;
            serde_json::to_writer(&mut buf, &domains)?;
            buf.write_all("; export default domain_mappings;".as_bytes())?;

            buf.flush()?;
            drop(buf);

            Ok::<_, Error>(inner)
        })()?;

        std::fs::write(&self.domain_mappings_path, cntnt)
            .context("failed to write domain mappings")?;

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

        counter.add(1, labels);
        recorder.record(duration, labels);

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

#[cfg(test)]
mod tests {
    use super::*;

    use candid::Principal;
    use std::sync::Arc;

    use crate::import::Pair;
    use crate::render::Renderer;

    #[tokio::test]
    async fn test_persist() -> Result<(), Error> {
        use tempfile::tempdir;

        let tmp_dir = tempdir()?;

        let renderer = Renderer::new(
            "{name}|{ssl_certificate_key_path}|{ssl_certificate_path}",
            "{name}|{ssl_certificate_key_path}|{ssl_certificate_path}",
            vec!["X".to_string(), "Y".to_string(), "Z".to_string()],
        );

        let persister = Persister::new(
            Arc::new(renderer),              // renderer
            tmp_dir.path().join("certs"),    // certificates_path
            tmp_dir.path().join("conf"),     // configuration_path
            tmp_dir.path().join("mappings"), // domain_mappings_path
        );

        // Run persister
        let out = persister
            .persist(&[Package {
                name: "test".into(),
                canister: Principal::from_text("aaaaa-aa")?,
                pair: Pair(
                    "key".to_string().into_bytes(),
                    "cert".to_string().into_bytes(),
                ),
            }])
            .await?;

        assert_eq!(out, PersistStatus::Completed);

        // Check certs
        assert_eq!(
            std::fs::read_to_string(tmp_dir.path().join("certs/test-key.pem"))?,
            "key"
        );

        assert_eq!(
            std::fs::read_to_string(tmp_dir.path().join("certs/test.pem"))?,
            "cert"
        );

        // Check config
        assert_eq!(
            std::fs::read_to_string(tmp_dir.path().join("conf"))?,
            format!(
                "test|{}|{}",
                tmp_dir.path().join("certs/test-key.pem").display(),
                tmp_dir.path().join("certs/test.pem").display(),
            )
        );

        // Check mappings
        assert_eq!(
            std::fs::read_to_string(tmp_dir.path().join("mappings"))?,
            "let domain_mappings = {\"test\":\"aaaaa-aa\"}; export default domain_mappings;",
        );

        Ok(())
    }
}
