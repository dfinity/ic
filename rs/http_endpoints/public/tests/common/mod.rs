use ic_error_types::UserError;
use ic_interfaces::execution_environment::{IngressFilterService, QueryExecutionService};
use ic_interfaces_p2p::{IngressError, IngressIngestionService};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_types::messages::{
    CertificateDelegation, HttpQueryResponse, SignedIngress, SignedIngressContent, UserQuery,
};
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

pub(crate) fn setup_query_execution_mock() -> (
    QueryExecutionService,
    Handle<(UserQuery, Option<CertificateDelegation>), HttpQueryResponse>,
) {
    let (service, handle) =
        tower_test::mock::pair::<(UserQuery, Option<CertificateDelegation>), HttpQueryResponse>();

    let infallible_service =
        tower::service_fn(move |request: (UserQuery, Option<CertificateDelegation>)| {
            let mut service_clone = service.clone();
            async move {
                Ok::<HttpQueryResponse, std::convert::Infallible>({
                    service_clone
                        .ready()
                        .await
                        .expect("Mocking Infallible service. Waiting for readiness failed.")
                        .call(request)
                        .await
                        .expect("Mocking Infallible service and can therefore not return an error.")
                })
            }
        });
    (
        tower::ServiceBuilder::new()
            .concurrency_limit(1)
            .service(BoxCloneService::new(infallible_service)),
        handle,
    )
}

#[allow(clippy::type_complexity)]
pub(crate) fn setup_ingress_filter_mock() -> (
    IngressFilterService,
    Handle<(ProvisionalWhitelist, SignedIngressContent), Result<(), UserError>>,
) {
    let (service, handle) = tower_test::mock::pair::<
        (ProvisionalWhitelist, SignedIngressContent),
        Result<(), UserError>,
    >();

    let infallible_service = tower::service_fn(
        move |request: (ProvisionalWhitelist, SignedIngressContent)| {
            let mut service_clone = service.clone();
            async move {
                Ok::<Result<(), UserError>, std::convert::Infallible>({
                    service_clone
                        .ready()
                        .await
                        .expect("Mocking Infallible service. Waiting for readiness failed.")
                        .call(request)
                        .await
                        .expect("Mocking Infallible service and can therefore not return an error.")
                })
            }
        },
    );
    (
        tower::ServiceBuilder::new()
            .concurrency_limit(1)
            .service(BoxCloneService::new(infallible_service)),
        handle,
    )
}

pub(crate) fn setup_ingress_ingestion_mock() -> (
    IngressIngestionService,
    Handle<SignedIngress, Result<(), IngressError>>,
) {
    let (service, handle) = tower_test::mock::pair::<SignedIngress, Result<(), IngressError>>();

    let infallible_service = tower::service_fn(move |request: SignedIngress| {
        let mut service_clone = service.clone();
        async move {
            Ok::<Result<(), IngressError>, std::convert::Infallible>({
                service_clone
                    .ready()
                    .await
                    .expect("Mocking Infallible service. Waiting for readiness failed.")
                    .call(request)
                    .await
                    .expect("Mocking Infallible service and can therefore not return an error.")
            })
        }
    });
    (
        tower::ServiceBuilder::new().service(BoxCloneService::new(infallible_service)),
        handle,
    )
}
