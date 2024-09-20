use std::{
    path::{Component, Path, PathBuf},
    sync::{Arc, RwLock},
    time::Instant,
};

use anyhow::{anyhow, Context as AnyhowContext, Error};
use async_trait::async_trait;
use mockall::automock;
use opentelemetry::KeyValue;
use tracing::info;

use crate::{
    import::Package,
    metrics::{MetricParams, WithMetrics},
    reload::{Reload, WithReload},
    render::{Context, Render},
};

#[derive(PartialEq, Debug)]
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

#[automock]
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

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

#[async_trait]
impl Persist for Persister {
    async fn persist(&self, pkgs: &[Package]) -> Result<PersistStatus, PersistError> {
        // Certificates
        std::fs::create_dir_all(&self.certificates_path)
            .context("failed to create certificates directory")?;

        pkgs.iter().try_for_each(|pkg| {
            // Certificate

            let ssl_certificate_path = normalize_path(
                Path::new(&self.certificates_path.to_string_lossy().to_string())
                    .join(format!("{}.pem", &pkg.name)),
            );

            if ssl_certificate_path.as_path().parent()
                != Some(Path::new(
                    &self.certificates_path.to_string_lossy().to_string(),
                ))
            {
                return Err(anyhow!(format!(
                    "error making a key path:{}/{}.pem",
                    &self.certificates_path.to_string_lossy().to_string(),
                    pkg.name
                )));
            }

            std::fs::write(ssl_certificate_path, &pkg.pair.1)
                .context("failed to write certificate")?;

            // Private Key
            let ssl_certificate_key_path = normalize_path(
                Path::new(&self.certificates_path.to_string_lossy().to_string())
                    .join(format!("{}-key.pem", &pkg.name)),
            );

            std::fs::write(ssl_certificate_key_path, &pkg.pair.0)
                .context("failed to write private key")?;

            Ok::<_, Error>(())
        })?;

        // Server blocks
        let cfgs = pkgs
            .iter()
            .map(|pkg| {
                let ssl_certificate_path = normalize_path(
                    Path::new(&self.certificates_path.to_string_lossy().to_string())
                        .join(format!("{}.pem", &pkg.name)),
                )
                .to_string_lossy()
                .to_string();

                let ssl_certificate_key_path = normalize_path(
                    Path::new(&self.certificates_path.to_string_lossy().to_string())
                        .join(format!("{}-key.pem", &pkg.name)),
                )
                .to_string_lossy()
                .to_string();

                self.renderer
                    .render(&Context {
                        name: &pkg.name,
                        canister_id: pkg.canister.to_string().as_str(),
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
        if self.1.read().unwrap().is_none() && pkgs.is_empty() {
            return Ok(PersistStatus::SkippedEmpty);
        }

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

        let renderer = Renderer::new("{name}|{ssl_certificate_key_path}|{ssl_certificate_path}");

        let persister = Persister::new(
            Arc::new(renderer),           // renderer
            tmp_dir.path().join("certs"), // certificates_path
            tmp_dir.path().join("conf"),  // configuration_path
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

        Ok(())
    }

    #[tokio::test]
    async fn test_dedup_empty() -> Result<(), Error> {
        let mut mock = MockPersist::new();
        mock.expect_persist()
            .returning(|_| Ok(PersistStatus::Completed));

        let initial_value: Option<Vec<Package>> = None;
        let persister = WithDedup(mock, Arc::new(RwLock::new(initial_value)));

        let empty_package: &[Package] = &[];
        let out = persister.persist(empty_package).await?;

        assert_eq!(out, PersistStatus::SkippedEmpty,);

        Ok(())
    }

    #[tokio::test]
    async fn test_dedup_unchanged() -> Result<(), Error> {
        let mut mock = MockPersist::new();
        mock.expect_persist()
            .returning(|_| Ok(PersistStatus::Completed));

        let initial_value: Option<Vec<Package>> = None;
        let persister = WithDedup(mock, Arc::new(RwLock::new(initial_value)));

        let single_package: &[Package] = &[Package {
            name: "test1".into(),
            canister: Principal::from_text("aaaaa-aa")?,
            pair: Pair(
                "key1".to_string().into_bytes(),
                "cert1".to_string().into_bytes(),
            ),
        }];

        let double_package: &[Package] = &[
            Package {
                name: "test1".into(),
                canister: Principal::from_text("aaaaa-aa")?,
                pair: Pair(
                    "key1".to_string().into_bytes(),
                    "cert1".to_string().into_bytes(),
                ),
            },
            Package {
                name: "test2".into(),
                canister: Principal::from_text("aaaaa-aa")?,
                pair: Pair(
                    "key2".to_string().into_bytes(),
                    "cert2".to_string().into_bytes(),
                ),
            },
        ];

        let out = persister.persist(single_package).await?;
        assert_eq!(out, PersistStatus::Completed,);

        let out = persister.persist(single_package).await?;
        assert_eq!(out, PersistStatus::SkippedUnchanged,);

        let out = persister.persist(double_package).await?;
        assert_eq!(out, PersistStatus::Completed,);

        let out = persister.persist(double_package).await?;
        assert_eq!(out, PersistStatus::SkippedUnchanged,);

        let out = persister.persist(single_package).await?;
        assert_eq!(out, PersistStatus::Completed,);

        Ok(())
    }
}
