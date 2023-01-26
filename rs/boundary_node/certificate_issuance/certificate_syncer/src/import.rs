use std::{sync::Arc, time::Instant};

use anyhow::{anyhow, Context as AnyhowContext};
use async_trait::async_trait;
use candid::Principal;
use hyper::{Body, Request, StatusCode, Uri};
use opentelemetry::{Context, KeyValue};
use serde::Deserialize;
use tracing::info;

use crate::{
    http::HttpClient,
    metrics::{MetricParams, WithMetrics},
};

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Pair(
    pub Vec<u8>, // Private Key
    pub Vec<u8>, // Certificate Chain
);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Package {
    pub name: String,
    pub canister: Principal,
    pub pair: Pair,
}

#[async_trait]
pub trait Import: Sync + Send {
    async fn import(&self) -> Result<Vec<Package>, ImportError>;
}

pub struct CertificatesImporter {
    // Dependencies
    http_client: Arc<dyn HttpClient>,

    // Configuration
    exporter_uri: Uri,
}

impl CertificatesImporter {
    pub fn new(http_client: Arc<dyn HttpClient>, exporter_uri: Uri) -> Self {
        Self {
            http_client,
            exporter_uri,
        }
    }
}

#[async_trait]
impl Import for CertificatesImporter {
    async fn import(&self) -> Result<Vec<Package>, ImportError> {
        let req = Request::builder()
            .method("GET")
            .uri(&self.exporter_uri)
            .body(Body::empty())
            .context("failed to create http request")?;

        let mut response = self
            .http_client
            .request(req)
            .await
            .context("failed to make http request")?;

        if response.status() != StatusCode::OK {
            return Err(anyhow!(format!("request failed: {}", response.status())).into());
        }

        let bs = hyper::body::to_bytes(response.body_mut())
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

        let cx = Context::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Error;
    use hyper::Response;
    use mockall::predicate;
    use std::{str::FromStr, sync::Arc};

    use crate::http::MockHttpClient;

    #[tokio::test]
    async fn test_import() -> Result<(), Error> {
        let mut http_client = MockHttpClient::new();
        http_client
            .expect_request()
            .times(1)
            .with(predicate::function(|req: &Request<Body>| {
                req.method().eq("GET") && req.uri().to_string().eq("http://certificates/")
            }))
            .returning(|_| {
                Ok(Response::new(Body::from(
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
                )))
            });

        let importer = CertificatesImporter::new(
            Arc::new(http_client),                 // http_client
            Uri::from_str("http://certificates")?, // exporter_uri
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
}
