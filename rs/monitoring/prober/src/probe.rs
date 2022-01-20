//! Catalog of probe definitions.

use crate::prober::{
    encode, ParamIterator, STATUS_CODE_BAD_REQUEST, STATUS_CODE_INTERNAL_SERVER_ERROR,
    STATUS_CODE_NOT_FOUND, STATUS_CODE_OK,
};
use ic_metrics::MetricsRegistry;
use slog::Logger;
use std::io::Cursor;
use std::{
    borrow::Cow,
    convert::TryFrom,
    time::{Duration, Instant},
};
use tiny_http::{Response, StatusCode};

mod http;
mod ic;

/// Enumeration of all implemented probe types.
pub enum Probe {
    Http,
    Ic,
}

impl Probe {
    /// Executes the probe with the given parameters and deadline.
    ///
    /// Probes only return an error (consisting of an HTTP error status and a
    /// text message) if the provided parameters are invalid of if they
    /// encounter an internal error. In all other situations (e.g. exceeded
    /// deadline or probe target error) the probe will return a metrics
    /// registry containing metrics reflecting the specific outcome.
    pub async fn run(
        &self,
        params: ParamIterator<'_>,
        deadline: Instant,
        log: &Logger,
    ) -> ProbeResult {
        match self {
            Probe::Http => http::probe(params, deadline).await,
            Probe::Ic => ic::probe(params, deadline, log).await,
        }
    }
}

impl TryFrom<&str> for Probe {
    type Error = ProbeError;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        match name {
            "http" => Ok(Probe::Http),
            "ic" => Ok(Probe::Ic),
            _ => Err(not_found(format!("Unknown probe: {}", name))),
        }
    }
}

/// One of the possible responses that a probe can return: completion (wrapping
/// a registry containing the collected metrics); or an error HTTP status plus a
/// text error message.
pub type ProbeResult = Result<MetricsRegistry, ProbeError>;

/// Error type returned by probes on invalid inputs (e.g. missing parameters) or
/// internal errors.
pub type ProbeError = (StatusCode, String);

/// A trait implementing helper methods for `ProbeResult`.
pub trait ProbeResultHelper {
    fn status_code(&self) -> StatusCode;

    fn into_response(self) -> Response<Cursor<Vec<u8>>>;
}

impl ProbeResultHelper for ProbeResult {
    fn status_code(&self) -> StatusCode {
        match self {
            Ok(_) => STATUS_CODE_OK,
            Err((status_code, _)) => *status_code,
        }
    }

    fn into_response(self) -> Response<Cursor<Vec<u8>>> {
        match self {
            Ok(registry) => encode(&registry),
            Err((status_code, msg)) => Response::from_data(msg).with_status_code(status_code),
        }
    }
}

fn bad_request(msg: String) -> ProbeError {
    (STATUS_CODE_BAD_REQUEST, msg)
}

fn internal_server_error(msg: String) -> ProbeError {
    (STATUS_CODE_INTERNAL_SERVER_ERROR, msg)
}

fn not_found(msg: String) -> ProbeError {
    (STATUS_CODE_NOT_FOUND, msg)
}

/// Returns the duration left to the given instant; or zero if the instant has
/// passed.
pub fn duration_to(then: Instant) -> Duration {
    let now = Instant::now();
    then.saturating_duration_since(now)
}

/// Helper function to ensure a parameter is only set once.
fn set_once<'a>(
    param: &mut Option<Cow<'a, str>>,
    name: &str,
    value: Cow<'a, str>,
) -> Result<(), ProbeError> {
    if let Some(old) = param.replace(value) {
        return Err(bad_request(format!(
            "Duplicate query param: `{}`: {} and {}",
            name,
            old,
            param.as_ref().unwrap()
        )));
    }
    Ok(())
}

/// Helper function that checks a required query parameter is present.
fn unwrap_param<'a>(param: Option<Cow<'a, str>>, name: &str) -> Result<Cow<'a, str>, ProbeError> {
    param.ok_or_else(|| bad_request(format!("Missing required query param: `{}`", name)))
}
