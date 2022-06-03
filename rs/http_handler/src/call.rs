//! Module that deals with requests to /api/v2/canister/.../call

use crate::{
    common::{get_cors_headers, make_plaintext_response, make_response, map_box_error_to_response},
    types::{to_legacy_request_type, ApiReqType},
    validator_executor::ValidatorExecutor,
    HttpError, HttpHandlerMetrics, IngressFilterService, UNKNOWN_LABEL,
};
use hyper::{Body, Response, StatusCode};
use ic_interfaces::registry::RegistryClient;
use ic_interfaces_p2p::{IngressError, IngressIngestionService};
use ic_logger::{error, info_sample, warn, ReplicaLogger};
use ic_registry_client_helpers::{
    provisional_whitelist::ProvisionalWhitelistRegistry,
    subnet::{IngressMessageSettings, SubnetRegistry},
};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_types::{
    malicious_flags::MaliciousFlags,
    messages::{SignedIngress, SignedRequestBytes},
    CountBytes, RegistryVersion, SubnetId,
};
use std::convert::TryInto;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{load_shed::LoadShed, BoxError, Service, ServiceBuilder, ServiceExt};

#[derive(Clone)]
pub(crate) struct CallService {
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    validator_executor: ValidatorExecutor,
    ingress_sender: IngressIngestionService,
    ingress_filter: LoadShed<IngressFilterService>,
    malicious_flags: MaliciousFlags,
}

impl CallService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        log: ReplicaLogger,
        metrics: HttpHandlerMetrics,
        subnet_id: SubnetId,
        registry_client: Arc<dyn RegistryClient>,
        validator_executor: ValidatorExecutor,
        ingress_sender: IngressIngestionService,
        ingress_filter: IngressFilterService,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        Self {
            log,
            metrics,
            subnet_id,
            registry_client,
            validator_executor,
            ingress_sender,
            ingress_filter: ServiceBuilder::new().load_shed().service(ingress_filter),
            malicious_flags,
        }
    }
}

fn get_registry_data(
    log: &ReplicaLogger,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
) -> Result<(IngressMessageSettings, ProvisionalWhitelist), HttpError> {
    let settings = match registry_client.get_ingress_message_settings(subnet_id, registry_version) {
        Ok(Some(settings)) => settings,
        Ok(None) => {
            let message = format!(
                "No subnet record found for registry_version={:?} and subnet_id={:?}",
                registry_version, subnet_id
            );
            warn!(log, "{}", message);
            return Err(HttpError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message,
            });
        }
        Err(err) => {
            let message = format!(
                "max_ingress_bytes_per_message not found for registry_version={:?} and subnet_id={:?}. {:?}",
                registry_version, subnet_id, err
            );
            error!(log, "{}", message);
            return Err(HttpError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message,
            });
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
impl Service<Vec<u8>> for CallService {
    type Response = Response<Body>;
    type Error = BoxError;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.ingress_sender.poll_ready(cx)
    }

    fn call(&mut self, body: Vec<u8>) -> Self::Future {
        // Actual parsing.
        self.metrics
            .requests_body_size_bytes
            .with_label_values(&[
                to_legacy_request_type(ApiReqType::Call),
                ApiReqType::Call.into(),
                UNKNOWN_LABEL,
            ])
            .observe(body.len() as f64);
        let msg: SignedIngress = match SignedRequestBytes::from(body).try_into() {
            Ok(msg) => msg,
            Err(e) => {
                let res = make_plaintext_response(
                    StatusCode::BAD_REQUEST,
                    format!("Could not parse body as call message: {}", e),
                );
                return Box::pin(async move { Ok(res) });
            }
        };
        let message_id = msg.id();
        let registry_version = self.registry_client.get_latest_version();
        let (ingress_registry_settings, provisional_whitelist) = match get_registry_data(
            &self.log,
            self.subnet_id,
            registry_version,
            self.registry_client.as_ref(),
        ) {
            Ok((s, p)) => (s, p),
            Err(HttpError { status, message }) => {
                return Box::pin(async move { Ok(make_plaintext_response(status, message)) });
            }
        };
        if msg.count_bytes() > ingress_registry_settings.max_ingress_bytes_per_message {
            let res = make_plaintext_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "Request {} is too large. Message byte size {} is larger than the max allowed {}.",
                    message_id,
                    msg.count_bytes(),
                    ingress_registry_settings.max_ingress_bytes_per_message
                ),
            );
            return Box::pin(async move { Ok(res) });
        }

        let ingress_sender = self.ingress_sender.clone();

        // In case the inner service has state that's driven to readiness and
        // not tracked by clones (such as `Buffer`), pass the version we have
        // already called `poll_ready` on into the future, and leave its clone
        // behind.
        //
        // The types implementing the Service trait are not necessary thread-safe.
        // So the unless the caller is sure that the service implementation is
        // thread-safe we must make sure 'poll_ready' is always called before 'call'
        // on the same object. Hence if 'poll_ready' is called and not tracked by
        // the 'Clone' implementation the following sequence of events may panic.
        //
        //  s1.call_ready()
        //  s2 = s1.clone()
        //  s2.call()
        //
        // NOTE: Buffer::Clone does not track readiness across clones.

        let mut ingress_sender = std::mem::replace(&mut self.ingress_sender, ingress_sender);

        let mut ingress_filter = self.ingress_filter.clone();
        let log = self.log.clone();
        let validator_executor = self.validator_executor.clone();
        let malicious_flags = self.malicious_flags.clone();

        Box::pin(async move {
            if let Err(http_err) = validator_executor
                .validate_signed_ingress(&msg, registry_version, &malicious_flags)
                .await
            {
                let res = make_plaintext_response(http_err.status, http_err.message);
                return Ok(res);
            }

            match ingress_filter
                .ready()
                .await
                .expect("The service must always be able to process requests")
                .call((provisional_whitelist, msg.content().clone()))
                .await
            {
                Err(err) => {
                    return Ok(map_box_error_to_response(err));
                }
                Ok(Err(err)) => {
                    return Ok(make_response(err));
                }
                Ok(Ok(())) => (),
            }

            let ingress_log_entry = msg.log_entry();
            let response = match ingress_sender.call(msg).await {
                Err(err) => map_box_error_to_response(err),
                Ok(Err(IngressError::Overloaded)) => make_plaintext_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service is overloaded, try again later.".to_string(),
                ),
                Ok(Ok(())) => {
                    // We're pretty much done, just need to send the message to ingress and
                    // make_response to the client
                    info_sample!(
                        "message_id" => &message_id,
                        log,
                        "ingress_message_submit";
                        ingress_message => ingress_log_entry
                    );
                    make_accepted_response()
                }
            };
            Ok(response)
        })
    }
}

fn make_accepted_response() -> Response<Body> {
    let mut response = Response::new(Body::from(""));
    *response.status_mut() = StatusCode::ACCEPTED;
    *response.headers_mut() = get_cors_headers();
    response
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_types::{
        messages::{Blob, HttpCallContent, HttpCanisterUpdate, HttpRequestEnvelope},
        time::current_time_and_expiry_time,
    };
    use std::convert::TryFrom;

    #[test]
    fn check_request_id() {
        let expiry_time = current_time_and_expiry_time().1;
        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "".to_string(),
                arg: Blob(b"".to_vec()),
                nonce: None,
                sender: Blob(vec![0x04]),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request1 = HttpRequestEnvelope::<HttpCallContent> {
            content,
            sender_sig: Some(Blob(vec![])),
            sender_pubkey: Some(Blob(vec![])),
            sender_delegation: None,
        };

        let content = HttpCallContent::Call {
            update: HttpCanisterUpdate {
                canister_id: Blob(vec![42; 8]),
                method_name: "".to_string(),
                arg: Blob(b"".to_vec()),
                nonce: None,
                sender: Blob(vec![0x04]),
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request2 = HttpRequestEnvelope::<HttpCallContent> {
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
