#![no_main]
use bytes::Bytes;
use hyper::{Body, Method, Request, Response};
use ic_config::http_handler::Config;
use ic_error_types::UserError;
use ic_http_endpoints_public::call::CallService;
use ic_http_endpoints_public::metrics::HttpHandlerMetrics;
use ic_http_endpoints_public::validator_executor::ValidatorExecutor;
use ic_interfaces::{
    execution_environment::QueryExecutionResponse, ingress_pool::IngressPoolThrottler,
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_test_utilities::{
    crypto::temp_crypto_component_with_fake_registry,
    types::ids::{node_test_id, subnet_test_id},
};
use ic_types::{
    malicious_flags::MaliciousFlags,
    messages::{CertificateDelegation, SignedIngressContent, UserQuery},
    PrincipalId,
};
use libfuzzer_sys::fuzz_target;
use mockall::mock;
use std::{
    convert::Infallible,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, RwLock},
};
use tokio::runtime::Runtime;
use tower::{util::BoxCloneService, Service, ServiceExt};
use tower_test::mock::Handle;

#[path = "../../public/tests/common/mod.rs"]
pub mod common;
use common::{basic_registry_client, get_free_localhost_socket_addr, setup_ingress_filter_mock};

pub type IngressFilterHandle =
    Handle<(ProvisionalWhitelist, SignedIngressContent), Result<(), UserError>>;
pub type QueryExecutionHandle =
    Handle<(UserQuery, Option<CertificateDelegation>), QueryExecutionResponse>;

mock! {
    pub IngressPoolThrottler {}

    impl IngressPoolThrottler for IngressPoolThrottler {
        fn exceeds_threshold(&self) -> bool;
    }
}

// This fuzzer attempts to execute the CallService call method. The input to the call method
// is an HTTP request. Currently only the HTTP request body is fuzzed. The HTTP requests
// headers are fixed.
//
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// bazel run --config=fuzzing //rs/http_endpoints/fuzz:execute_call_service_libfuzzer -- corpus/
//
// TODO (PSEC-1654): Implement Arbitrary for the request body. Details:
// This initial version of the fuzzer is currently likely ineffective. This is because as soon as the data
// can't be CBOR decoded, is incorrectly signed, or contains a mismatching effective canister id, `call`
// will fail, and such a failure will happen for most mutations of `data`.
// To address this, the next MR (PSEC-1654) will implement Arbitrary so that mutations of the data more
// effectively explore interesting inputs.
fuzz_target!(|data: &[u8]| {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();
    let effective_canister_id = "223xb-saaaa-aaaaf-arlqa-cai";

    let mut call_service = new_call_service(addr);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "http://{}/api/v2/canister/{}/call",
            addr, effective_canister_id,
        ))
        .header("Content-Type", "application/cbor")
        .body(Bytes::from(data.to_vec()))
        .expect("Failed to build the request");

    // The effective_canister_id is added to the request during routing
    // and then removed from the request parts (see `remove_effective_principal_id`
    // in http_endponts/public/src/common.rs).
    // We simulate that behaviour in this line.
    req.extensions_mut()
        .insert(PrincipalId::from_str(effective_canister_id).unwrap());

    rt.block_on(async move {
        call_service
            .ready()
            .await
            .expect("could not create call service")
            .call(req)
            .await
            .unwrap()
    });
});

fn new_call_service(
    addr: SocketAddr,
) -> BoxCloneService<Request<Bytes>, Response<Body>, Infallible> {
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };
    let log = no_op_logger();
    let metrics_registry = MetricsRegistry::new();
    let mock_registry_client: Arc<dyn RegistryClient> = Arc::new(basic_registry_client());

    let (ingress_filter, _ingress_filter_handle) = setup_ingress_filter_mock();
    let mut ingress_pool_throttler = MockIngressPoolThrottler::new();
    ingress_pool_throttler
        .expect_exceeds_threshold()
        .returning(|| false);

    let ingress_throttler = Arc::new(RwLock::new(ingress_pool_throttler));

    let (ingress_tx, _ingress_rx) = crossbeam::channel::unbounded();

    let sig_verifier = Arc::new(temp_crypto_component_with_fake_registry(node_test_id(1)));

    CallService::new_service(
        config,
        log.clone(),
        HttpHandlerMetrics::new(&metrics_registry),
        node_test_id(1),
        subnet_test_id(1),
        Arc::clone(&mock_registry_client),
        ValidatorExecutor::new(
            Arc::clone(&mock_registry_client),
            sig_verifier,
            &MaliciousFlags::default(),
            log,
        ),
        ingress_filter,
        ingress_throttler,
        ingress_tx,
    )
}
