use std::time::Instant;

use async_trait::async_trait;
use ic_bn_lib::http::{http_version, Client};
use rustls::Error as RustlsError;

#[cfg(feature = "tls")]
use axum::{
    extract::{Host, OriginalUri},
    response::{IntoResponse, Redirect},
};

use crate::{core::error_source, dns::DnsError, metrics::WithMetrics, routes::ErrorCause};

#[cfg(feature = "tls")]
pub async fn redirect_to_https(
    Host(host): Host,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    use http::uri::{PathAndQuery, Uri};

    let fallback_path = PathAndQuery::from_static("/");
    let pq = uri.path_and_query().unwrap_or(&fallback_path).as_str();

    Redirect::permanent(
        &Uri::builder()
            .scheme("https") // redirect to https
            .authority(host) // re-use the same host
            .path_and_query(pq) // re-use the same path and query
            .build()
            .unwrap()
            .to_string(),
    )
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
pub fn reqwest_error_infer(e: reqwest::Error) -> ErrorCause {
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
