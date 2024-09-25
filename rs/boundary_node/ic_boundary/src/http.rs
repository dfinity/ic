use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use ic_bn_lib::http::{
    client::{Client, ClientGenerator, Options, ReqwestClient, ReqwestClientDynamic},
    http_version,
};
use rustls::Error as RustlsError;

use crate::{
    core::error_source,
    dns::DnsError,
    metrics::{MetricParams, WithMetrics},
    routes::ErrorCause,
};

#[derive(Clone, Debug)]
pub struct StubClient;

#[async_trait]
impl Client for StubClient {
    async fn execute(&self, _req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        let resp = ::http::Response::new(vec![]);
        Ok(resp.into())
    }
}

#[derive(Debug, Clone)]
pub struct ClientGeneratorSingle<R: reqwest::dns::Resolve + Clone + fmt::Debug + 'static>(
    pub Options<R>,
    pub MetricParams,
);

impl<R: reqwest::dns::Resolve + Clone + fmt::Debug + 'static> ClientGenerator
    for ClientGeneratorSingle<R>
{
    fn generate(&self) -> Result<Arc<dyn Client>, ic_bn_lib::http::Error> {
        Ok(Arc::new(WithMetrics(
            ReqwestClient::new(self.0.clone())?,
            self.1.clone(),
        )))
    }
}

#[derive(Debug)]
pub struct ClientGeneratorDynamic<R: reqwest::dns::Resolve + Clone + fmt::Debug + 'static>(
    pub ClientGeneratorSingle<R>,
);

impl<R: reqwest::dns::Resolve + Clone + fmt::Debug + 'static> ClientGenerator
    for ClientGeneratorDynamic<R>
{
    fn generate(&self) -> Result<Arc<dyn Client>, ic_bn_lib::http::Error> {
        Ok(Arc::new(ReqwestClientDynamic::new(
            self.0.clone(),
            10,
            200,
            Duration::from_secs(90),
        )?))
    }
}

#[async_trait]
impl<T: Client> Client for WithMetrics<T> {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        let start = Instant::now();
        let res = self.0.execute(req).await;
        let dur = start.elapsed().as_secs_f64();

        let success = if res.is_ok() { "yes" } else { "no" };

        // TODO try to avoid allocating String here?
        // Not sure how, status() returns non-static &str for some reason though CODE_DIGITS is static
        let (status_code, http_version) = res
            .as_ref()
            .map(|x| (x.status().as_str().to_string(), http_version(x.version())))
            .unwrap_or(("0".into(), "-"));

        let labels = &[success, status_code.as_str(), http_version];
        self.1.counter.with_label_values(labels).inc();
        self.1.recorder.with_label_values(labels).observe(dur);

        res
    }
}

// Try to categorize the error that we got from Reqwest call
pub fn error_infer(e: &impl std::error::Error) -> ErrorCause {
    if let Some(e) = error_source::<reqwest::Error>(&e) {
        if e.is_connect() {
            return ErrorCause::ReplicaErrorConnect;
        }

        if e.is_timeout() {
            return ErrorCause::ReplicaTimeout;
        }
    }

    // Check if it's a DNS error
    if let Some(e) = error_source::<DnsError>(&e) {
        return ErrorCause::ReplicaErrorDNS(e.to_string());
    }

    // Check if it's a Rustls error
    if let Some(e) = error_source::<RustlsError>(&e) {
        return match e {
            RustlsError::InvalidCertificate(v) => {
                ErrorCause::ReplicaTLSErrorCert(format!("{:?}", v))
            }
            RustlsError::NoCertificatesPresented => {
                ErrorCause::ReplicaTLSErrorCert("no certificate presented".into())
            }
            _ => ErrorCause::ReplicaTLSErrorOther(e.to_string()),
        };
    }

    ErrorCause::ReplicaErrorOther(e.to_string())
}
