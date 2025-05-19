pub mod handlers;
pub(crate) mod middleware;

use rustls::Error as RustlsError;

use crate::{core::error_source, dns::DnsError, errors::ErrorCause};

// Rust const/static concat is non-existent, so we have to repeat
pub const PATH_STATUS: &str = "/api/v2/status";
pub const PATH_QUERY: &str = "/api/v2/canister/{canister_id}/query";
pub const PATH_CALL: &str = "/api/v2/canister/{canister_id}/call";
pub const PATH_CALL_V3: &str = "/api/v3/canister/{canister_id}/call";
pub const PATH_READ_STATE: &str = "/api/v2/canister/{canister_id}/read_state";
pub const PATH_SUBNET_READ_STATE: &str = "/api/v2/subnet/{subnet_id}/read_state";
pub const PATH_HEALTH: &str = "/health";

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
