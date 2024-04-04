use std::time::Instant;

use async_trait::async_trait;
use http::Version;
use http_body::{combinators::UnsyncBoxBody, Body as HttpBody, LengthLimitError, Limited};
use hyper::body;
use reqwest::{Error as ReqwestError, Request, Response};
use rustls::Error as RustlsError;

use crate::{core::error_source, dns::DnsError, metrics::WithMetrics, routes::ErrorCause};

/// Standard response used to pass between middlewares
pub type AxumResponse = http::Response<UnsyncBoxBody<bytes::Bytes, axum::Error>>;

// TODO remove this wrapper?
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, req: Request) -> Result<Response, ReqwestError>;
}

pub struct ReqwestClient(pub reqwest::Client);

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn execute(&self, req: Request) -> Result<Response, ReqwestError> {
        self.0.execute(req).await
    }
}

fn http_version(v: Version) -> &'static str {
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
) -> Result<Vec<u8>, ErrorCause>
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

    Ok(data.to_vec())
}
