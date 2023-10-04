use async_trait::async_trait;
use reqwest::{Error as ReqwestError, Request, Response};
use rustls::Error as RustlsError;

use crate::{core::error_source, dns::DnsError, routes::ErrorCause};

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
