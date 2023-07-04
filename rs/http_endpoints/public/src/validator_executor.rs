// The validator executor provides non blocking access to the crypto services needed in the http handler.
use crate::{common::validation_error_to_http_error, HttpError};
use futures::FutureExt;
use http::StatusCode;
use ic_interfaces::crypto::IngressSigVerifier;
use ic_logger::ReplicaLogger;
use ic_types::messages::{HttpRequest, HttpRequestContent};
use ic_types::{malicious_flags::MaliciousFlags, time::current_time, RegistryVersion, Time};
use ic_validator::{
    CanisterIdSet, HttpRequestVerifier, HttpRequestVerifierImpl, RequestValidationError,
};
use std::future::Future;
use std::sync::Arc;
use threadpool::ThreadPool;
use tokio::sync::oneshot;

// Number of threads used for the ingress validator executor.
const VALIDATOR_EXECUTOR_THREADS: usize = 1;

#[derive(Clone)]
pub(crate) struct ValidatorExecutor<C> {
    validator: Arc<dyn HttpRequestVerifier<C>>,
    threadpool: ThreadPool,
    logger: ReplicaLogger,
}

impl<C: HttpRequestContent> ValidatorExecutor<C>
where
    HttpRequestVerifierImpl: HttpRequestVerifier<C>,
{
    pub fn new(
        ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
        malicious_flags: &MaliciousFlags,
        logger: ReplicaLogger,
    ) -> Self {
        let validator = if malicious_flags.maliciously_disable_ingress_validation {
            pub struct DisabledHttpRequestVerifier;

            impl<C: HttpRequestContent> HttpRequestVerifier<C> for DisabledHttpRequestVerifier {
                fn validate_request(
                    &self,
                    _request: &HttpRequest<C>,
                    _current_time: Time,
                    _registry_version: RegistryVersion,
                ) -> Result<CanisterIdSet, RequestValidationError> {
                    Ok(CanisterIdSet::all())
                }
            }

            Arc::new(DisabledHttpRequestVerifier) as Arc<_>
        } else {
            Arc::new(HttpRequestVerifierImpl::new(ingress_verifier)) as Arc<_>
        };
        Self::new_internal(validator, logger)
    }

    fn new_internal(validator: Arc<dyn HttpRequestVerifier<C>>, logger: ReplicaLogger) -> Self {
        ValidatorExecutor {
            validator,
            threadpool: ThreadPool::new(VALIDATOR_EXECUTOR_THREADS),
            logger,
        }
    }
}

impl<C: HttpRequestContent + Send + Sync + 'static> ValidatorExecutor<C> {
    pub fn validate_request(
        &self,
        request: HttpRequest<C>,
        registry_version: RegistryVersion,
    ) -> impl Future<Output = Result<CanisterIdSet, HttpError>> {
        let (tx, rx) = oneshot::channel();

        let message_id = request.id();
        let validator = self.validator.clone();
        self.threadpool.execute(move || {
            if !tx.is_closed() {
                let _ =
                    tx.send(validator.validate_request(&request, current_time(), registry_version));
            }
        });
        let log = self.logger.clone();
        rx.map(move |v| match v {
            Err(recv_err) => Err(HttpError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: format!("Internal Error: {:?}.", recv_err),
            }),
            Ok(Ok(canister_id_set)) => Ok(canister_id_set),
            Ok(Err(val_err)) => Err(validation_error_to_http_error(message_id, val_err, &log)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{validation_error_to_http_error, ValidatorExecutor};
    use ic_logger::replica_logger::no_op_logger;
    use ic_test_utilities::{
        crypto::temp_crypto_component_with_fake_registry,
        types::{
            ids::{canister_test_id, node_test_id},
            messages::SignedIngressBuilder,
        },
    };
    use ic_types::time::current_time;
    use ic_types::RegistryVersion;
    use ic_types::{
        messages::{
            Blob, HttpQueryContent, HttpRequest, HttpRequestEnvelope, HttpUserQuery, UserQuery,
        },
        time::expiry_time_from_now,
    };
    use ic_validator::{HttpRequestVerifier, HttpRequestVerifierImpl};
    use std::convert::TryFrom;
    use std::sync::Arc;

    #[tokio::test]
    async fn async_validate_user_query() {
        let expiry_time = expiry_time_from_now();
        let content = HttpQueryContent::Query {
            query: HttpUserQuery {
                canister_id: Blob(vec![67, 3]),
                method_name: "foo".to_string(),
                arg: Blob(vec![23, 19, 4]),
                sender: Blob(vec![4]), // the anonymous user.
                nonce: None,
                ingress_expiry: expiry_time.as_nanos_since_unix_epoch(),
            },
        };
        let request = HttpRequestEnvelope::<HttpQueryContent> {
            content,
            sender_sig: Some(Blob(vec![])),
            sender_pubkey: Some(Blob(vec![])),
            sender_delegation: None,
        };
        let request = HttpRequest::<UserQuery>::try_from(request).unwrap();
        let sig_verifier = Arc::new(temp_crypto_component_with_fake_registry(node_test_id(0)));
        let validator = Arc::new(HttpRequestVerifierImpl::new(sig_verifier.clone()));
        let async_validator = ValidatorExecutor::new_internal(validator.clone(), no_op_logger());

        assert_eq!(
            async_validator
                .validate_request(request.clone(), RegistryVersion::from(0),)
                .await,
            validator
                .validate_request(&request, current_time(), RegistryVersion::from(0),)
                .map_err(|val_err| validation_error_to_http_error(
                    request.id(),
                    val_err,
                    &no_op_logger()
                ))
        )
    }

    #[tokio::test]
    async fn async_validate_signed_ingress() {
        let request = SignedIngressBuilder::new()
            .canister_id(canister_test_id(420))
            .nonce(42)
            .build();
        let sig_verifier = Arc::new(temp_crypto_component_with_fake_registry(node_test_id(0)));
        let validator = Arc::new(HttpRequestVerifierImpl::new(sig_verifier.clone()));
        let async_validator = ValidatorExecutor::new_internal(validator.clone(), no_op_logger());

        assert_eq!(
            async_validator
                .validate_request(request.as_ref().clone(), RegistryVersion::from(0),)
                .await,
            validator
                .validate_request(request.as_ref(), current_time(), RegistryVersion::from(0),)
                .map_err(|val_err| validation_error_to_http_error(
                    request.id(),
                    val_err,
                    &no_op_logger()
                ))
        )
    }
}
