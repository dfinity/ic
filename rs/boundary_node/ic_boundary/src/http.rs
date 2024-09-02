use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Error};
use async_trait::async_trait;
use bytes::Bytes;
use http::Version;
use http_body::{combinators::UnsyncBoxBody, Body as HttpBody, LengthLimitError, Limited};
use hyper::body;
use reqwest::{Error as ReqwestError, Request, Response};
use rustls::Error as RustlsError;

use crate::{
    cli::Cli,
    core::{error_source, SERVICE_NAME},
    dns::{DnsError, DnsResolver},
    metrics::WithMetrics,
    routes::ErrorCause,
};

/// Standard response used to pass between middlewares
pub type AxumResponse = http::Response<UnsyncBoxBody<bytes::Bytes, axum::Error>>;

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, req: Request) -> Result<Response, ReqwestError>;
}

pub struct ReqwestClient(Vec<reqwest::Client>, AtomicUsize);

impl ReqwestClient {
    pub fn new(
        cli: &Cli,
        rustls_config: rustls::ClientConfig,
        dns_resolver: Arc<DnsResolver>,
    ) -> Result<Self, Error> {
        // Create a number of HTTP clients
        let mut clients = vec![];
        for _ in 0..cli.listen.http_client_count {
            clients.push(Self::create_client(
                cli,
                rustls_config.clone(),
                dns_resolver.clone(),
            )?);
        }

        Ok(Self(clients, AtomicUsize::new(0)))
    }

    fn create_client(
        cli: &Cli,
        rustls_config: rustls::ClientConfig,
        dns_resolver: Arc<DnsResolver>,
    ) -> Result<reqwest::Client, Error> {
        let keepalive = Duration::from_secs(cli.listen.http_keepalive);

        let cli = reqwest::Client::builder()
            .timeout(Duration::from_millis(cli.listen.http_timeout))
            .connect_timeout(Duration::from_millis(cli.listen.http_timeout_connect))
            .pool_idle_timeout(Some(Duration::from_secs(cli.listen.http_idle_timeout))) // After this duration the idle connection is closed (default 90s)
            .http2_keep_alive_interval(Some(keepalive)) // Keepalive interval for http2 connections
            .http2_keep_alive_timeout(Duration::from_secs(cli.listen.http_keepalive_timeout)) // Close connection if no reply after timeout
            .http2_keep_alive_while_idle(true) // Also ping connections that have no streams open
            .http2_adaptive_window(true) // Enable HTTP2 adaptive window size control
            .tcp_nodelay(true) // Disable Nagle algorithm
            .tcp_keepalive(Some(keepalive)) // Enable TCP keepalives
            .user_agent(SERVICE_NAME)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .use_preconfigured_tls(rustls_config)
            .dns_resolver(dns_resolver)
            .build()
            .context("unable to build HTTP client")?;

        Ok(cli)
    }

    // Pick a client in a round-robin fashion
    fn pick_client(&self) -> &reqwest::Client {
        let next = self.1.fetch_add(1, Ordering::SeqCst) % self.0.len();
        &self.0[next]
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn execute(&self, req: Request) -> Result<Response, ReqwestError> {
        self.pick_client().execute(req).await
    }
}

pub fn http_version(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "-",
    }
}

#[async_trait]
impl<T: HttpClient> HttpClient for WithMetrics<T> {
    async fn execute(&self, req: Request) -> Result<Response, ReqwestError> {
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
pub fn reqwest_error_infer(e: ReqwestError) -> ErrorCause {
    if e.is_connect() {
        return ErrorCause::ReplicaErrorConnect;
    }

    if e.is_timeout() {
        return ErrorCause::ReplicaTimeout;
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

// Read the body from the available stream enforcing a size limit
pub async fn read_streaming_body<H: HttpBody>(
    body_stream: H,
    size_limit: usize,
) -> Result<Bytes, ErrorCause>
where
    <H as HttpBody>::Error: std::error::Error + Send + Sync + 'static,
{
    let limited_body = Limited::new(body_stream, size_limit);

    let data = body::to_bytes(limited_body).await.map_err(|err| {
        if err.downcast_ref::<LengthLimitError>().is_some() {
            ErrorCause::PayloadTooLarge(size_limit)
        } else {
            ErrorCause::UnableToReadBody(format!("unable to read response body: {err}"))
        }
    })?;

    Ok(data)
}
