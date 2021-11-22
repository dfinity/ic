//! Module that deals with requests to /api/v2/canister/.../query

use crate::{common, map_box_error_to_canonical_error, ReplicaHealthStatus};
use hyper::{Body, Response};
use ic_interfaces::{
    crypto::IngressSigVerifier, execution_environment::QueryExecutionService,
    registry::RegistryClient,
};
use ic_logger::{trace, ReplicaLogger};
use ic_types::{
    canonical_error::{
        invalid_argument_error, permission_denied_error, unavailable_error, CanonicalError,
    },
    malicious_flags::MaliciousFlags,
    messages::{
        CertificateDelegation, HttpReadContent, HttpRequest, HttpRequestEnvelope,
        SignedRequestBytes, UserQuery,
    },
    time::current_time,
};
use ic_validator::get_authorized_canisters;
use std::convert::TryFrom;
use std::sync::{Arc, RwLock};
use tower::{Service, ServiceExt};

/// Handles a call to /api/v2/canister/.../query
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    log: &ReplicaLogger,
    health_status: Arc<RwLock<ReplicaHealthStatus>>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    mut query_handler: QueryExecutionService,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    body: Vec<u8>,
    malicious_flags: MaliciousFlags,
) -> Result<Response<Body>, CanonicalError> {
    trace!(log, "in handle query");
    if *health_status.read().unwrap() != ReplicaHealthStatus::Healthy {
        return Err(unavailable_error(
            "Replica is starting. Check the /api/v2/status for more information.",
        ));
    }
    let delegation_from_nns = delegation_from_nns.read().unwrap().clone();

    let request =
        match <HttpRequestEnvelope<HttpReadContent>>::try_from(&SignedRequestBytes::from(body)) {
            Ok(request) => request,
            Err(e) => {
                return Err(invalid_argument_error(
                    format!("Could not parse body as read request: {}", e).as_str(),
                ));
            }
        };

    // Convert the message to a strongly-typed struct, making structural validations
    // on the way.
    let request = match HttpRequest::<UserQuery>::try_from(request) {
        Ok(request) => request,
        Err(e) => {
            return Err(invalid_argument_error(
                format!("Malformed request: {:?}", e).as_str(),
            ));
        }
    };
    let query = request.content();

    match get_authorized_canisters(
        &request,
        validator.as_ref(),
        current_time(),
        registry_client.get_latest_version(),
        &malicious_flags,
    ) {
        Ok(targets) => {
            if !targets.contains(&query.receiver) {
                return Err(permission_denied_error(""));
            }
        }
        Err(err) => {
            return Err(common::make_response_on_validation_error(
                request.id(),
                err,
                log,
            ));
        }
    };

    // Here we want to hold the mutex only for the duration of the non-blocking
    // call, and not for duration until the query completes. Hence the await on
    // the callback is after the mutex was released.
    let query_result = query_handler
        .ready()
        .await
        .expect("The service must always be able to process requests")
        .call((query.clone(), delegation_from_nns))
        .await
        .map_err(|err| map_box_error_to_canonical_error(err))?;
    Ok(common::cbor_response(&query_result))
}
