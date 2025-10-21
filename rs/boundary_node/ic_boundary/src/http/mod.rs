pub mod handlers;
pub(crate) mod middleware;

use rustls::Error as RustlsError;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, IntoStaticStr};

use crate::{core::error_source, dns::DnsError, errors::ErrorCause};

// Rust const/static concat is non-existent, so we have to repeat
pub const PATH_STATUS: &str = "/api/v2/status";
pub const PATH_QUERY_V2: &str = "/api/v2/canister/{canister_id}/query";
pub const PATH_QUERY_V3: &str = "/api/v3/canister/{canister_id}/query";
pub const PATH_CALL_V2: &str = "/api/v2/canister/{canister_id}/call";
pub const PATH_CALL_V3: &str = "/api/v3/canister/{canister_id}/call";
pub const PATH_CALL_V4: &str = "/api/v4/canister/{canister_id}/call";
pub const PATH_READ_STATE_V2: &str = "/api/v2/canister/{canister_id}/read_state";
pub const PATH_READ_STATE_V3: &str = "/api/v3/canister/{canister_id}/read_state";
pub const PATH_SUBNET_READ_STATE_V2: &str = "/api/v2/subnet/{subnet_id}/read_state";
pub const PATH_SUBNET_READ_STATE_V3: &str = "/api/v3/subnet/{subnet_id}/read_state";
pub const PATH_HEALTH: &str = "/health";

/// Type of IC API request
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    IntoStaticStr,
    EnumString,
    Serialize,
    Deserialize,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    #[default]
    Unknown,
    Status,
    QueryV2,
    QueryV3,
    CallV2,
    CallV3,
    CallV4,
    ReadStateV2,
    ReadStateV3,
    ReadStateSubnetV2,
    ReadStateSubnetV3,
}

impl RequestType {
    pub const fn is_query(&self) -> bool {
        matches!(self, Self::QueryV2 | Self::QueryV3)
    }

    pub const fn is_call(&self) -> bool {
        matches!(self, Self::CallV2 | Self::CallV3 | Self::CallV4)
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
            RustlsError::InvalidCertificate(v) => ErrorCause::ReplicaTLSErrorCert(format!("{v:?}")),
            RustlsError::NoCertificatesPresented => {
                ErrorCause::ReplicaTLSErrorCert("no certificate presented".into())
            }
            _ => ErrorCause::ReplicaTLSErrorOther(e.to_string()),
        };
    }

    ErrorCause::ReplicaErrorOther(e.to_string())
}
