use std::{sync::Arc, time::Instant};

use anyhow::{anyhow, Context as AnyhowContext};
use async_trait::async_trait;
use candid::Principal;
use mockall::automock;
use opentelemetry::KeyValue;
use reqwest::{Method, Request, StatusCode, Url};
use serde::Deserialize;
use tracing::info;

use crate::{
    http::HttpClient,
    metrics::{MetricParams, WithMetrics},
    verify::{Verify, VerifyError, WithVerify},
};

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),

    #[error(transparent)]
    VerificationError(#[from] VerifyError),
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize)]
pub struct Pair(
    pub Vec<u8>, // Private Key
    pub Vec<u8>, // Certificate Chain
);

#[derive(Clone, Eq, PartialEq, Debug, Deserialize)]
pub struct Package {
    pub name: String,
    pub canister: Principal,
    pub pair: Pair,
}

#[automock]
#[async_trait]
pub trait Import: Sync + Send {
    async fn import(&self) -> Result<Vec<Package>, ImportError>;
}

pub struct CertificatesImporter {
    // Dependencies
    http_client: Arc<dyn HttpClient>,

    // Configuration
    exporter_url: Url,
}

impl CertificatesImporter {
    pub fn new(http_client: Arc<dyn HttpClient>, exporter_url: Url) -> Self {
        Self {
            http_client,
            exporter_url,
        }
    }
}

#[async_trait]
impl Import for CertificatesImporter {
    async fn import(&self) -> Result<Vec<Package>, ImportError> {
        let req = Request::new(Method::GET, self.exporter_url.clone());
        let response = self
            .http_client
            .execute(req)
            .await
            .context("failed to make http request")?;
        if response.status() != StatusCode::OK {
            return Err(anyhow!(format!("request failed: {}", response.status())).into());
        }

        let bs = response
            .bytes()
            .await
            .context("failed to consume response")?
            .to_vec();
        let pkgs: Vec<Package> =
            serde_json::from_slice(&bs).context("failed to parse json body")?;

        Ok(pkgs)
    }
}

#[async_trait]
impl<T: Import> Import for WithMetrics<T> {
    async fn import(&self) -> Result<Vec<Package>, ImportError> {
        let start_time = Instant::now();

        let out = self.0.import().await;

        let status = if out.is_ok() { "ok" } else { "fail" };
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

// Wraps an importer with a verifier
// The importer imports a set of packages as usual, but then passes the packages to the verifier.
// The verifier parses out the public certificate and compares the common name to the name in the package to make sure they match.
// This should help eliminate risk of the replica returning a malicious package.
#[async_trait]
impl<T: Import, V: Verify> Import for WithVerify<T, V> {
    async fn import(&self) -> Result<Vec<Package>, ImportError> {
        let pkgs = self.0.import().await?;

        for pkg in &pkgs {
            self.1.verify(pkg)?;
        }

        Ok(pkgs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Error;
    use axum::http::Response;
    use mockall::predicate;
    use reqwest::Body;
    use std::{str::FromStr, sync::Arc};

    use crate::{http::MockHttpClient, verify::MockVerify};

    #[tokio::test]
    async fn import_ok() -> Result<(), Error> {
        let mut http_client = MockHttpClient::new();
        http_client
            .expect_execute()
            .times(1)
            .with(predicate::function(|req: &Request| {
                req.method().as_str().eq("GET") && req.url().to_string().eq("http://certificates/")
            }))
            .returning(|_| {
                Ok(Response::builder()
                    .body(Body::from(
                        r#"[
                {
                    "name": "name",
                    "canister": "aaaaa-aa",
                    "pair": [
                        [1, 2, 3],
                        [4, 5, 6]
                    ]
                }
            ]"#,
                    ))
                    .unwrap()
                    .into())
            });

        let importer = CertificatesImporter::new(
            Arc::new(http_client),                 // http_client
            Url::from_str("http://certificates")?, // exporter_uri
        );

        let out = importer.import().await?;

        assert_eq!(
            out,
            vec![Package {
                name: "name".into(),
                canister: Principal::from_text("aaaaa-aa")?,
                pair: Pair(vec![1, 2, 3], vec![4, 5, 6]),
            }],
        );

        Ok(())
    }

    #[tokio::test]
    async fn import_verify_multiple() {
        let mut verifier = MockVerify::new();
        verifier
            .expect_verify()
            .times(3)
            .with(predicate::in_iter(vec![
                Package {
                    name: "name-1".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
                Package {
                    name: "name-2".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
                Package {
                    name: "name-3".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
            ]))
            .returning(|_| Ok(()));

        let mut importer = MockImport::new();
        importer.expect_import().times(1).returning(|| {
            Ok(vec![
                Package {
                    name: "name-1".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
                Package {
                    name: "name-2".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
                Package {
                    name: "name-3".into(),
                    canister: Principal::from_text("aaaaa-aa").unwrap(),
                    pair: Pair(vec![], vec![]),
                },
            ])
        });

        let importer = WithVerify(importer, verifier);

        match importer.import().await {
            Ok(_) => {}
            other => panic!("expected Ok but got {other:?}"),
        }
    }

    #[tokio::test]
    async fn import_verify_mismatch() {
        let mut verifier = MockVerify::new();
        verifier
            .expect_verify()
            .times(1)
            .with(predicate::eq(Package {
                name: "name-1".into(),
                canister: Principal::from_text("aaaaa-aa").unwrap(),
                pair: Pair(vec![], vec![]),
            }))
            .returning(|_| {
                // Mock an error
                Err(VerifyError::CommonNameMismatch(
                    "name-1".into(),
                    "name-2".into(),
                ))
            });

        let mut importer = MockImport::new();
        importer.expect_import().times(1).returning(|| {
            Ok(vec![Package {
                name: "name-1".into(),
                canister: Principal::from_text("aaaaa-aa").unwrap(),
                pair: Pair(vec![], vec![]),
            }])
        });

        let importer = WithVerify(importer, verifier);

        match importer.import().await {
            Err(ImportError::VerificationError(_)) => {}
            other => panic!("expected VerificationError but got {other:?}"),
        }
    }
}
