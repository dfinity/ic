//! Module that deals with requests to /api/v2/canister/.../call

use crate::{common, metrics::HttpHandlerMetrics, types::*};
use hyper::{Body, Response, StatusCode};
use ic_interfaces::crypto::IngressSigVerifier;
use ic_interfaces::execution_environment::IngressMessageFilter;
use ic_interfaces::execution_environment::{HypervisorError, MessageAcceptanceError};
use ic_interfaces::p2p::IngressEventHandler;
use ic_interfaces::registry::RegistryClient;
use ic_interfaces::state_manager::StateReader;
use ic_logger::{error, info_sample, warn, ReplicaLogger};
use ic_registry_client::helper::{
    provisional_whitelist::ProvisionalWhitelistRegistry, subnet::SubnetRegistry,
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    malicious_flags::MaliciousFlags,
    messages::{HttpHandlerError, SignedIngress, SignedRequestBytes},
    time::current_time,
    CountBytes, SubnetId,
};
use ic_validator::validate_request;
use std::convert::TryInto;
use std::sync::Arc;

fn into_http_status_code(
    acceptance_error: MessageAcceptanceError,
    metrics: &HttpHandlerMetrics,
) -> (StatusCode, String) {
    match acceptance_error {
        MessageAcceptanceError::CanisterNotFound => (
            StatusCode::NOT_FOUND,
            "Requested canister does not exist".to_string(),
        ),
        MessageAcceptanceError::CanisterHasNoWasmModule => (
            StatusCode::NOT_FOUND,
            "Requested canister has no wasm module".to_string(),
        ),
        MessageAcceptanceError::CanisterRejected => {
            metrics.observe_forbidden_request(&RequestType::Submit, "CanisterRejected");
            (
                StatusCode::FORBIDDEN,
                "Requested canister rejected the message".to_string(),
            )
        }
        MessageAcceptanceError::CanisterOutOfCycles => {
            metrics.observe_forbidden_request(&RequestType::Submit, "CanisterOutOfCycles");
            (
                StatusCode::FORBIDDEN,
                "Requested canister doesn't have enough cycles".to_string(),
            )
        }
        MessageAcceptanceError::CanisterExecutionFailed(err) => match err {
            HypervisorError::MethodNotFound(_) => (
                StatusCode::NOT_FOUND,
                "Attempt to execute non-existent method on the canister".to_string(),
            ),
            HypervisorError::CalledTrap(_) => {
                metrics.observe_forbidden_request(&RequestType::Submit, "CalledTrap");
                (
                    StatusCode::FORBIDDEN,
                    "Requested canister rejected the message".to_string(),
                )
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Requested canister failed to process the message acceptance request".to_string(),
            ),
        },
    }
}

/// Handles a call to /api/v2/canister/../call
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    metrics: Arc<HttpHandlerMetrics>,
    log: ReplicaLogger,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
    ingress_sender: Arc<dyn IngressEventHandler>,
    malicious_flags: MaliciousFlags,
    ingress_message_filter: Arc<dyn IngressMessageFilter<State = ReplicatedState>>,
    body: Vec<u8>,
) -> (Response<Body>, ApiReqType) {
    use ApiReqType::*;
    // Actual parsing.
    let msg: SignedIngress = match SignedRequestBytes::from(body).try_into() {
        Ok(msg) => msg,
        Err(e) => {
            let error_code = match e {
                HttpHandlerError::InvalidEncoding(_) => StatusCode::UNPROCESSABLE_ENTITY,
                _ => StatusCode::BAD_REQUEST,
            };
            return (
                common::make_response(
                    error_code,
                    format!("Could not parse body as submit message: {}", e).as_str(),
                ),
                Unknown,
            );
        }
    };
    metrics.observe_unreliable_request_acceptance_duration(
        RequestType::Submit,
        Call,
        msg.expiry_time(),
    );

    let message_id = msg.id();
    let registry_version = registry_client.get_latest_version();

    match registry_client.get_ingress_message_settings(subnet_id, registry_version) {
        Ok(Some(settings)) => {
            if msg.count_bytes() > settings.max_ingress_bytes_per_message {
                return (
                    common::make_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!("Request {} is too large. Message bytes {} is bigger than the max allowed {}.",
                            message_id, msg.count_bytes(), settings.max_ingress_bytes_per_message).as_str(),
                    ),
                    Call,
                );
            }
        }
        Ok(None) => {
            let err_msg = format!(
                "No subnet record found for the latest registry version and subnet_id={:?}",
                subnet_id
            );
            warn!(log, "{}", err_msg);
            return (
                common::make_response(StatusCode::PRECONDITION_FAILED, &err_msg),
                Call,
            );
        }
        Err(err) => {
            let err_msg = format!(
                "Couldn't retrieve max_ingress_bytes_per_message from the registry: {:?}",
                err
            );
            error!(log, "{}", err_msg);
            return (
                common::make_response(StatusCode::INTERNAL_SERVER_ERROR, &err_msg),
                Call,
            );
        }
    };

    if let Err(err) = validate_request(
        msg.as_ref(),
        validator.as_ref(),
        current_time(),
        registry_version,
        &malicious_flags,
    ) {
        let response = common::make_response_on_validation_error(message_id, err, &log);
        metrics.observe_forbidden_request(&RequestType::Submit, "SubmitReqAuthFailed");
        return (response, Call);
    }

    {
        let provisional_whitelist = match registry_client
            .get_provisional_whitelist(registry_version)
        {
            Ok(Some(list)) => list,
            Ok(None) => {
                error!(log, "At registry version {}, get_provisional_whitelist() returned Ok(None).  Using empty list",
                           registry_version);
                ProvisionalWhitelist::new_empty()
            }
            Err(err) => {
                error!(log, "At registry version {}, get_provisional_whitelist() failed with {}.  Using empty list",
                           registry_version, err);
                ProvisionalWhitelist::new_empty()
            }
        };
        let state = state_reader.get_latest_state().take();
        if let Err(err) = ingress_message_filter.should_accept_ingress_message(
            state,
            &provisional_whitelist,
            msg.content(),
        ) {
            let (status_code, error_msg) = into_http_status_code(err, metrics.as_ref());
            return (common::make_response(status_code, &error_msg), Call);
        }
    }

    let ingress_log_entry = msg.log_entry();
    // TODO: remove the spawn blocking once the ingress sender API allows
    // non-blocking op.
    match tokio::task::spawn_blocking(move || ingress_sender.on_ingress_message(msg)).await {
        Err(err) => {
            metrics.observe_internal_error(
                &RequestType::Submit,
                InternalError::ConcurrentTaskExecution,
            );
            error!(log, "route_to_handlers failed with: {}", err);
            (common::empty_response(), ApiReqType::Unknown)
        }
        Ok(Err(_e)) => (
            common::make_response(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable!"),
            Call,
        ),
        Ok(Ok(_)) => {
            // We're pretty much done, just need to send the message to ingress and
            // make_response to the client
            info_sample!(
                "message_id" => &message_id,
                log,
                "ingress_message_submit";
                ingress_message => ingress_log_entry
            );
            (common::make_response(StatusCode::ACCEPTED, ""), Call)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_types::{
        messages::{Blob, HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent},
        time::current_time_and_expiry_time,
    };
    use std::convert::TryFrom;

    #[test]
    fn check_request_id() {
        let expiry_time = current_time_and_expiry_time().1;
        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "".to_string(),
                arg: Blob(b"".to_vec()),
                nonce: None,
                sender: Blob(vec![0x04]),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request1 = HttpRequestEnvelope::<HttpSubmitContent> {
            content,
            sender_sig: Some(Blob(vec![])),
            sender_pubkey: Some(Blob(vec![])),
            sender_delegation: None,
        };

        let content = HttpSubmitContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "".to_string(),
                arg: Blob(b"".to_vec()),
                nonce: None,
                sender: Blob(vec![0x04]),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request2 = HttpRequestEnvelope::<HttpSubmitContent> {
            content,
            sender_sig: Some(Blob(b"yes this is a signature".to_vec())),
            sender_pubkey: Some(Blob(b"yes this is a public key: prove it is not!".to_vec())),
            sender_delegation: None,
        };

        let message_id = SignedIngress::try_from(request1).unwrap().id();
        let message_id_2 = SignedIngress::try_from(request2).unwrap().id();
        assert_eq!(message_id_2, message_id);
    }
}
