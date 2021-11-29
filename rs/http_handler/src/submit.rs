//! Module that deals with requests to /api/v2/canister/.../call

use crate::{
    common::{
        get_cors_headers, make_response, make_response_on_validation_error,
        map_box_error_to_response,
    },
    types::{ApiReqType, RequestType},
    HttpHandlerMetrics, IngressFilterService, UNKNOWN_LABEL,
};
use hyper::{Body, Response, StatusCode};
use ic_interfaces::{
    crypto::IngressSigVerifier,
    {p2p::IngressIngestionService, registry::RegistryClient},
};
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
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
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
        validator: Arc<dyn IngressSigVerifier + Send + Sync>,
        ingress_sender: IngressIngestionService,
        ingress_filter: IngressFilterService,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        Self {
            log,
            metrics,
            subnet_id,
            registry_client,
            validator,
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
                RequestType::Submit.as_str(),
                ApiReqType::Call.as_str(),
                UNKNOWN_LABEL,
            ])
            .observe(body.len() as f64);
        let msg: SignedIngress = match SignedRequestBytes::from(body).try_into() {
            Ok(msg) => msg,
            Err(e) => {
                let res = make_response(invalid_argument_error(
                    format!("Could not parse body as submit message: {}", e).as_str(),
                ));
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
            Err(err) => {
                return Box::pin(async move { Ok(make_response(err)) });
            }
        };
        if msg.count_bytes() > ingress_registry_settings.max_ingress_bytes_per_message {
            let res = make_response(out_of_range_error(
                format!(
                    "Request {} is too large. Message bytes {} is bigger than the max allowed {}.",
                    message_id,
                    msg.count_bytes(),
                    ingress_registry_settings.max_ingress_bytes_per_message
                )
                .as_str(),
            ));
            return Box::pin(async move { Ok(res) });
        }

        if let Err(err) = validate_request(
            msg.as_ref(),
            self.validator.as_ref(),
            current_time(),
            registry_version,
            &self.malicious_flags,
        ) {
            let res = make_response_on_validation_error(message_id, err, &self.log);
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
        let mut ingress_sender = std::mem::replace(&mut self.ingress_sender, ingress_sender);

        let mut ingress_filter = self.ingress_filter.clone();
        let log = self.log.clone();

        Box::pin(async move {
            if let Err(err) = ingress_filter
                .ready()
                .await
                .expect("The service must always be able to process requests")
                .call((provisional_whitelist, msg.content().clone()))
                .await
            {
                return Ok(map_box_error_to_response(err));
            }

            let ingress_log_entry = msg.log_entry();
            if let Err(err) = ingress_sender.call(msg).await {
                return Ok(map_box_error_to_response(err));
            }

            // We're pretty much done, just need to send the message to ingress and
            // make_response to the client
            info_sample!(
                "message_id" => &message_id,
                log,
                "ingress_message_submit";
                ingress_message => ingress_log_entry
            );
            Ok(make_accepted_response())
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
