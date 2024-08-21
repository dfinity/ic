#![no_main]
use arbitrary::Arbitrary;
use axum::body::Body;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response};
use ic_agent::{
    agent::{http_transport::reqwest_transport::ReqwestTransport, UpdateBuilder},
    export::Principal,
    identity::AnonymousIdentity,
    Agent,
};
use ic_config::http_handler::Config;
use ic_error_types::{ErrorCode, UserError};
use ic_http_endpoints_public::{CallServiceV2, IngressValidatorBuilder};
use ic_interfaces::ingress_pool::IngressPoolThrottler;
use ic_interfaces_registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_test_utilities::crypto::temp_crypto_component_with_fake_registry;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{messages::SignedIngressContent, PrincipalId};
use ic_validator_http_request_arbitrary::AnonymousContent;
use libfuzzer_sys::fuzz_target;
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
};
use tokio::{
    runtime::Runtime,
    sync::mpsc::{channel, Receiver},
};
use tower::{
    limit::GlobalConcurrencyLimitLayer, util::BoxCloneService, Service, ServiceBuilder, ServiceExt,
};
use tower_test::mock::Handle;

#[path = "../../public/tests/common/mod.rs"]
pub mod common;
use common::{basic_registry_client, get_free_localhost_socket_addr, setup_ingress_filter_mock};

type IngressFilterHandle =
    Handle<(ProvisionalWhitelist, SignedIngressContent), Result<(), UserError>>;
type CallServiceEndpoint = BoxCloneService<Request<Body>, Response<Body>, Infallible>;

#[derive(Arbitrary, Clone, Debug)]
struct CallServiceImpl {
    content: AnonymousContent,
    allow_ingress_filter: bool,
    allow_ingress_throttler: bool,
}

struct MockIngressPoolThrottler {
    rx: RwLock<Receiver<bool>>,
}

impl MockIngressPoolThrottler {
    fn new(rx: Receiver<bool>) -> Self {
        MockIngressPoolThrottler {
            rx: RwLock::new(rx),
        }
    }
}

impl IngressPoolThrottler for MockIngressPoolThrottler {
    fn exceeds_threshold(&self) -> bool {
        self.rx.write().unwrap().try_recv().unwrap_or(false)
    }
}

// This fuzzer attempts to execute the CallService call method. The input to the call method
// is an HTTP request. Currently only the HTTP request body is fuzzed. The HTTP requests
// headers are fixed.
//
// The fuzz test is only compiled but not executed by CI.
//
// To execute the fuzzer run
// bazel run --config=afl //rs/http_endpoints/fuzz:execute_call_service_afl -- corpus/

fuzz_target!(|call_impls: Vec<CallServiceImpl>| {
    if !call_impls.is_empty() {
        let rt = Runtime::new().unwrap();
        let (throttler_tx, throttler_rx) = channel(call_impls.len());
        let addr = get_free_localhost_socket_addr();
        let (mut ingress_filter_handle, call_service) = new_call_service(addr, throttler_rx);
        let (filter_flags, throttler_flags) = extract_flags(&call_impls);

        // Mock ingress filter
        rt.spawn(async move {
            for flag in filter_flags {
                while let Some((_, resp)) = ingress_filter_handle.next_request().await {
                    if flag {
                        resp.send_response(Ok(()))
                    } else {
                        resp.send_response(Err(UserError::new(
                            ErrorCode::CanisterNotFound,
                            "Fuzzing ingress filter error",
                        )))
                    }
                }
            }
        });

        // Mock ingress throttler
        rt.block_on(async move {
            for flag in throttler_flags {
                if let Err(err) = throttler_tx.send(flag).await {
                    eprintln!("Error sending message: {}", err);
                }
            }
        });

        for call_impl in call_impls {
            let canister_id =
                match Principal::try_from_slice(call_impl.content.canister_id.0.as_slice()) {
                    Ok(v) => v,
                    // The arbitrary impl for canister ids in AnonymousContent makes it posible to have more than 29 bytes
                    // which makes Principal::try_from_slice return an error, in such cases ignore this call_impl.
                    _ => continue,
                };
            let signed_update_call = new_update_call(addr, call_impl.content, canister_id);
            let mut call_service_clone = call_service.clone();
            let mut req = Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://{}/api/v2/canister/{}/call",
                    addr,
                    canister_id.to_text(),
                ))
                .header("Content-Type", "application/cbor")
                .body(Body::new(Full::new(Bytes::from(signed_update_call))))
                .expect("Failed to build the request");

            // The effective_canister_id is added to the request during routing
            // and then removed from the request parts (see `remove_effective_principal_id`
            // in http_endponts/public/src/common.rs). We simulate that behaviour in this line.
            req.extensions_mut().insert(PrincipalId::from(canister_id));

            let _res = rt.block_on(async move {
                call_service_clone
                    .ready()
                    .await
                    .expect("could not create call service")
                    .call(req)
                    .await
                    .unwrap()
            });
        }
    }
});

fn extract_flags(calls: &[CallServiceImpl]) -> (Vec<bool>, Vec<bool>) {
    let (filter_flags, throttler_flags): (Vec<bool>, Vec<bool>) = calls
        .iter()
        .map(|call| (call.allow_ingress_filter, call.allow_ingress_throttler))
        .unzip();

    (filter_flags, throttler_flags)
}

fn new_update_call(
    addr: SocketAddr,
    content: AnonymousContent,
    effective_canister_id: Principal,
) -> Vec<u8> {
    let agent = Agent::builder()
        .with_identity(AnonymousIdentity)
        .with_transport(ReqwestTransport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();
    let update = UpdateBuilder::new(&agent, effective_canister_id, content.method_name)
        .with_effective_canister_id(effective_canister_id)
        .with_arg(content.arg.0)
        .sign()
        .unwrap();
    update.signed_update
}

fn new_call_service(
    addr: SocketAddr,
    throttler_rx: Receiver<bool>,
) -> (IngressFilterHandle, CallServiceEndpoint) {
    let config = Config {
        listen_addr: addr,
        ..Default::default()
    };
    let log = no_op_logger();
    let mock_registry_client: Arc<dyn RegistryClient> = Arc::new(basic_registry_client());

    let (ingress_filter, ingress_filter_handle) = setup_ingress_filter_mock();
    let ingress_pool_throttler = MockIngressPoolThrottler::new(throttler_rx);

    let ingress_throttler = Arc::new(RwLock::new(ingress_pool_throttler));
    #[allow(clippy::disallowed_methods)]
    let (ingress_tx, _ingress_rx) = tokio::sync::mpsc::unbounded_channel();

    let sig_verifier = Arc::new(temp_crypto_component_with_fake_registry(node_test_id(1)));
    let call_handler = IngressValidatorBuilder::builder(
        log.clone(),
        node_test_id(1),
        subnet_test_id(1),
        Arc::clone(&mock_registry_client),
        sig_verifier,
        Arc::new(Mutex::new(ingress_filter)),
        ingress_throttler,
        ingress_tx,
    )
    .build();
    let call_service = BoxCloneService::new(
        ServiceBuilder::new()
            .layer(GlobalConcurrencyLimitLayer::new(
                config.max_call_concurrent_requests,
            ))
            .service(CallServiceV2::new_service(call_handler)),
    );
    (ingress_filter_handle, call_service)
}
