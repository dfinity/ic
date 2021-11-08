//! Module that deals with requests to /api/v2/canister/.../call

use crate::{common, IngressFilterService};
use hyper::{Body, Response, StatusCode};
use ic_interfaces::crypto::IngressSigVerifier;
use ic_interfaces::{p2p::IngressIngestionService, registry::RegistryClient};
use ic_logger::{error, info_sample, warn, ReplicaLogger};
use ic_registry_client::helper::{
    provisional_whitelist::ProvisionalWhitelistRegistry,
    subnet::{IngressMessageSettings, SubnetRegistry},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_types::{
    canonical_error::{internal_error, invalid_argument_error, out_of_range_error, CanonicalError},
    malicious_flags::MaliciousFlags,
    messages::{SignedIngress, SignedRequestBytes},
    time::current_time,
    CountBytes, RegistryVersion, SubnetId,
};
use ic_validator::validate_request;
use std::convert::TryInto;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::{Service, ServiceExt};

fn get_registry_data(
    log: &ReplicaLogger,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: Arc<dyn RegistryClient>,
) -> Result<(IngressMessageSettings, ProvisionalWhitelist), CanonicalError> {
    let settings = match registry_client.get_ingress_message_settings(subnet_id, registry_version) {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            let err_msg = format!(
                "No subnet record found for registry_version={:?} and subnet_id={:?}",
                registry_version, subnet_id
            );
            warn!(log, "{}", err_msg);
            return Err(internal_error(&err_msg));
        }
        Err(err) => {
            let err_msg = format!(
                "max_ingress_bytes_per_message not found for registry_version={:?} and subnet_id={:?}. {:?}",
                registry_version, subnet_id, err
            );
            error!(log, "{}", err_msg);
            return Err(internal_error(&err_msg));
        }
    };

    let provisional_whitelist = match registry_client.get_provisional_whitelist(registry_version) {
        Ok(Some(list)) => list,
        Ok(None) => {
            error!(log, "At registry version {}, get_provisional_whitelist() returned Ok(None). Using empty list.",
                       registry_version);
            ProvisionalWhitelist::new_empty()
        }
        Err(err) => {
            error!(log, "At registry version {}, get_provisional_whitelist() failed with {}.  Using empty list.",
                       registry_version, err);
            ProvisionalWhitelist::new_empty()
        }
    };
    Ok((settings, provisional_whitelist))
}

/// Handles a call to /api/v2/canister/../call
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    log: ReplicaLogger,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
    ingress_sender: Arc<Mutex<IngressIngestionService>>,
    ingress_filter: Arc<Mutex<IngressFilterService>>,
    malicious_flags: MaliciousFlags,
    body: Vec<u8>,
) -> Result<Response<Body>, CanonicalError> {
    // Actual parsing.
    let msg: SignedIngress = match SignedRequestBytes::from(body).try_into() {
        Ok(msg) => msg,
        Err(e) => {
            return Err(invalid_argument_error(
                format!("Could not parse body as submit message: {}", e).as_str(),
            ));
        }
    };
    let message_id = msg.id();
    let registry_version = registry_client.get_latest_version();
    let (ingress_registry_settings, provisional_whitelist) =
        get_registry_data(&log, subnet_id, registry_version, registry_client)?;
    if msg.count_bytes() > ingress_registry_settings.max_ingress_bytes_per_message {
        return Err(out_of_range_error(
            format!(
                "Request {} is too large. Message bytes {} is bigger than the max allowed {}.",
                message_id,
                msg.count_bytes(),
                ingress_registry_settings.max_ingress_bytes_per_message
            )
            .as_str(),
        ));
    }

    if let Err(err) = validate_request(
        msg.as_ref(),
        validator.as_ref(),
        current_time(),
        registry_version,
        &malicious_flags,
    ) {
        return Err(common::make_response_on_validation_error(
            message_id, err, &log,
        ));
    }

    let ingress_filter_callback = ingress_filter
        .lock()
        .await
        .ready()
        .await
        .expect("The service must always be able to process requests")
        .call((provisional_whitelist, msg.content().clone()));

    ingress_filter_callback.await?;
    let ingress_log_entry = msg.log_entry();
    let ingress_sender_callback = ingress_sender
        .lock()
        .await
        .ready()
        .await
        .expect("The service must always be able to process requests")
        .call(msg);

    ingress_sender_callback.await?;
    // We're pretty much done, just need to send the message to ingress and
    // make_response to the client
    info_sample!(
        "message_id" => &message_id,
        log,
        "ingress_message_submit";
        ingress_message => ingress_log_entry
    );

    let mut response = Response::new(Body::from(""));
    *response.status_mut() = StatusCode::ACCEPTED;
    *response.headers_mut() = common::get_cors_headers();
    Ok(response)
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
