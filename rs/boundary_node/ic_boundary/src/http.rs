use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use ic_bn_lib::http::{
    client::{
        Client, ClientStats, ClientWithStats, CloneableDnsResolver, GeneratesClients,
        GeneratesClientsWithStats, Options, ReqwestClient, ReqwestClientDynamic, Stats,
    },
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

impl Stats for StubClient {
    fn stats(&self) -> ClientStats {
        ClientStats {
            pool_size: 0,
            outstanding: 0,
        }
    }
}

impl ClientWithStats for StubClient {
    fn to_client(self: Arc<Self>) -> Arc<dyn Client> {
        self
    }
}

#[derive(Debug, Clone)]
pub struct ClientGeneratorSingle<R: CloneableDnsResolver>(pub Options<R>, pub MetricParams);

impl<R: CloneableDnsResolver> GeneratesClients for ClientGeneratorSingle<R> {
    fn generate(&self) -> Result<Arc<dyn Client>, ic_bn_lib::http::Error> {
        Ok(Arc::new(WithMetrics(
            ReqwestClient::new(self.0.clone())?,
            self.1.clone(),
        )))
    }
}

#[derive(Debug)]
pub struct ClientGeneratorDynamic<R: CloneableDnsResolver> {
    pub g: ClientGeneratorSingle<R>,
    pub min_clients: usize,
    pub max_clients: usize,
    pub max_outstanding: usize,
    pub idle_timeout: Duration,
}

impl<R: CloneableDnsResolver> GeneratesClientsWithStats for ClientGeneratorDynamic<R> {
    fn generate(&self) -> Result<Arc<dyn ClientWithStats>, ic_bn_lib::http::Error> {
        Ok(Arc::new(ReqwestClientDynamic::new(
            self.g.clone(),
            self.min_clients,
            self.max_clients,
            self.max_outstanding,
            self.idle_timeout,
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
