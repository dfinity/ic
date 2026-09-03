/* tag::catalog[]
Title:: Test correctness of feature according to spec.

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister.

Success::
1. Received http response with status 200.

end::catalog[] */

use anyhow::Result;
use assert_matches::assert_matches;
use candid::{CandidType, Deserialize, Encode, Principal, decode_one};
use canister_http::*;
use canister_test::{Canister, Runtime};
use dfn_candid::candid_one;
use ic_agent::{
    Agent, AgentError,
    agent::{CallResponse, RejectCode, RejectResponse},
};
use ic_base_types::{CanisterId, NumBytes, PrincipalId};
use ic_config::subnet_config::DEFAULT_REFERENCE_SUBNET_SIZE;
use ic_cycles_account_manager::CyclesAccountManagerSubnetConfig;
use ic_management_canister_types_private::{
    HttpHeader, HttpMethod, PRICING_VERSION_LEGACY, PRICING_VERSION_PAY_AS_YOU_GO,
    TransformContext, TransformFunc,
};
use ic_system_test_driver::{
    canister_agent::HasCanisterAgentCapability,
    driver::{
        group::{SystemTestGroup, SystemTestSubGroup},
        test_env::TestEnv,
        test_env_api::IcNodeSnapshot,
    },
    retry_agent_on_transport_errors, systest,
    util::block_on,
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::{
    RegistryVersion,
    canister_http::{CanisterHttpRequestContext, MAX_CANISTER_HTTP_RESPONSE_BYTES},
    time::UNIX_EPOCH,
};
use ic_types_cycles::{CanisterCyclesCostSchedule, Cycles};
use proxy_canister::{
    RejectionCode, RemoteHttpRequest, RemoteHttpResponse, RemoteHttpStressRequest,
    RemoteHttpStressResponse, ResponseWithRefundedCycles, UnvalidatedCanisterHttpRequestArgs,
};
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant};

/// The body the pay-as-you-go cases ask the server for.
///
/// Deliberately well above `MAX_CANISTER_HTTP_REJECT_BYTES`, which is 1025 bytes:
/// below that, an outcall's consensus fee is quoted for a maximally large reject
/// being delivered in its place.
const PAYG_BODY_BYTES: usize = 8 * 1024;

const MAX_REQUEST_BYTES_LIMIT: usize = 2_000_000;
const MAX_MAX_RESPONSE_BYTES: usize = 2_000_000;
const DEFAULT_MAX_RESPONSE_BYTES: u64 = 2_000_000;
const MAX_CANISTER_HTTP_URL_SIZE: usize = 8 * 1024;
const MAX_HEADER_NAME_LENGTH: usize = 8 * 1024;
const MAX_HEADER_VALUE_LENGTH: usize = 8 * 1024;
const TOTAL_HEADER_NAME_AND_VALUE_LENGTH: usize = 48 * 1024;
const HTTP_HEADERS_MAX_NUMBER: usize = 64;
const HTTP_REQUEST_CYCLE_PAYMENT: u64 = 500_000_000_000;

// httpbin-rs returns 5 headers in addition to the requested headers:
// content-type, access-control-allow-origin, access-control-allow-credentials, date, content-length.
const HTTPBIN_OVERHEAD_RESPONSE_HEADERS: usize = 5;

/// The subnet a test talks to, and the proxy canister installed on it.
struct Handlers<'a> {
    subnet_size: usize,
    runtime: Runtime,
    node: IcNodeSnapshot,
    proxy_canister_id: PrincipalId,
    env: &'a TestEnv,
}

impl<'a> Handlers<'a> {
    /// Handlers for the application subnet, which charges for HTTP outcalls.
    fn new(env: &'a TestEnv) -> Handlers<'a> {
        Self::on_subnet(env, get_node_snapshots(env), get_proxy_canister_id(env))
    }

    /// Handlers for the system subnet, which charges nothing for HTTP outcalls.
    fn on_system_subnet(env: &'a TestEnv) -> Handlers<'a> {
        Self::on_subnet(
            env,
            get_system_subnet_node_snapshots(env),
            get_system_proxy_canister_id(env),
        )
    }

    fn on_subnet(
        env: &'a TestEnv,
        nodes: impl Iterator<Item = IcNodeSnapshot>,
        proxy_canister_id: PrincipalId,
    ) -> Handlers<'a> {
        let nodes: Vec<_> = nodes.collect();
        let node = nodes.first().expect("the subnet has no nodes").clone();

        Handlers {
            runtime: get_runtime_from_node(&node),
            subnet_size: nodes.len(),
            node,
            proxy_canister_id,
            env,
        }
    }

    /// Prices `request` the way the subnet these handlers talk to will.
    fn fees_for(&self, request: UnvalidatedCanisterHttpRequestArgs) -> PaygFees {
        fees_for(
            CanisterId::unchecked_from_principal(self.proxy_canister_id),
            request,
            self.subnet_size,
        )
    }

    fn proxy_canister(&self) -> Canister<'_> {
        let canister_id = CanisterId::unchecked_from_principal(self.proxy_canister_id);
        Canister::new(&self.runtime, canister_id)
    }

    async fn agent(&self) -> Agent {
        self.node.build_canister_agent().await.agent
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(test_enforce_https))
                .add_test(systest!(test_no_cycles_attached))
                .add_test(systest!(test_2mb_response_cycle_for_rejection_path))
                .add_test(systest!(test_4096_max_response_cycle_case_1))
                .add_test(systest!(test_4096_max_response_cycle_case_2))
                .add_test(systest!(test_post_request))
                .add_test(systest!(
                    test_http_endpoint_with_delayed_response_is_rejected
                ))
                .add_test(systest!(test_that_redirects_are_not_followed))
                .add_test(systest!(test_http_calls_to_ic_fails))
                .add_test(systest!(test_get_hello_world_call))
                .add_test(systest!(test_post_call))
                .add_test(systest!(test_head_call))
                .add_test(systest!(test_put_call))
                .add_test(systest!(test_put_without_non_replicated_rejected))
                .add_test(systest!(test_delete_call))
                .add_test(systest!(test_delete_without_non_replicated_rejected))
                .add_test(systest!(test_patch_call))
                .add_test(systest!(test_patch_without_non_replicated_rejected))
                .add_test(systest!(test_max_possible_request_size))
                .add_test(systest!(test_max_possible_request_size_exceeded))
                // This section tests the request headers limits scenarios
                .add_test(systest!(test_request_header_name_and_value_within_limits))
                .add_test(systest!(test_request_header_name_too_long))
                .add_test(systest!(test_request_header_value_too_long))
                .add_test(systest!(
                    test_request_header_total_size_within_the_48_kib_limit
                ))
                .add_test(systest!(
                    test_request_header_total_size_over_the_48_kib_limit
                ))
                // This section tests the response headers limits scenarios
                .add_test(systest!(test_response_header_name_within_limit))
                .add_test(systest!(test_response_header_name_over_limit))
                .add_test(systest!(test_response_header_value_within_limit))
                .add_test(systest!(test_response_header_value_over_limit))
                .add_test(systest!(
                    test_response_header_total_size_within_the_48_kib_limit
                ))
                .add_test(systest!(
                    test_response_header_total_size_over_the_48_kib_limit
                ))
                // This section tests the url and ip scenarios
                .add_test(systest!(test_non_ascii_url_is_accepted))
                .add_test(systest!(test_invalid_ip))
                .add_test(systest!(test_invalid_domain_name))
                .add_test(systest!(test_max_url_length))
                .add_test(systest!(test_max_url_length_exceeded))
                // This section tests the transform function scenarios
                .add_test(systest!(test_transform_function_is_executed))
                .add_test(systest!(no_data_certificate_in_transform_function))
                .add_test(systest!(test_composite_transform_function_is_not_allowed))
                .add_test(systest!(check_caller_id_on_transform_function))
                .add_test(systest!(
                    test_transform_that_bloats_response_above_2mb_limit
                ))
                .add_test(systest!(test_transform_that_bloats_on_the_2mb_limit))
                .add_test(systest!(
                    test_transform_that_bloats_on_the_2mb_limit_with_custom_max_response_bytes
                ))
                .add_test(systest!(
                    reference_transform_function_exposed_by_different_canister
                ))
                .add_test(systest!(test_non_existent_transform_function))
                // This section tests the max number of request or response headers scenarios
                .add_test(systest!(test_max_number_of_request_headers))
                .add_test(systest!(test_max_number_of_request_headers_exceeded))
                .add_test(systest!(test_max_number_of_response_headers))
                .add_test(systest!(test_max_number_of_response_headers_exceeded))
                // This section tests the max_response_bytes scenarios
                .add_test(systest!(
                    test_http_endpoint_response_is_too_large_with_custom_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_within_limits_with_custom_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_too_large_with_default_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_within_limits_with_default_max_response_bytes
                ))
                .add_test(systest!(test_only_headers_with_custom_max_response_bytes))
                .add_test(systest!(
                    test_only_headers_with_custom_max_response_bytes_exceeded
                ))
                .add_test(systest!(test_max_response_bytes_too_large))
                .add_test(systest!(test_max_response_bytes_2_mb_returns_ok)),
        )
        // Pay-as-you-go pricing, which a caller opts into per request. These run sequentially,
        // because they measure the proxy canister's balance across a single outcall, which any
        // concurrent outcall from the same canister would perturb.
        .add_test(systest!(test_legacy_charges_the_estimate_and_nothing_else))
        .add_test(systest!(test_pay_as_you_go_charges_and_refunds))
        .add_test(systest!(test_pay_as_you_go_non_replicated))
        .add_test(systest!(test_pay_as_you_go_charges_for_response_time))
        .add_test(systest!(
            test_pay_as_you_go_response_cap_shrinks_what_is_withheld
        ))
        .add_test(systest!(test_pay_as_you_go_funded_by_the_quote))
        .add_test(systest!(test_pay_as_you_go_refunds_concurrent_outcalls))
        .add_test(systest!(test_pay_as_you_go_base_fee_threshold))
        .add_test(systest!(test_pay_as_you_go_out_of_cycles))
        .add_test(systest!(test_free_subnet_charges_nothing))
        .execute_from_args()?;

    Ok(())
}

fn test_enforce_https(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("http://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_transform_function_is_executed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let transform_context = "transform_context".as_bytes().to_vec();

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "test_transform".to_string(),
            }),
            context: transform_context.clone(),
        }),
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };
    let estimate = expected_cycle_cost(
        handlers.proxy_canister().canister_id(),
        request.clone(),
        handlers.subnet_size,
    );

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request,
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    // Legacy pricing charges its estimate up front and returns the rest of the
    // payment on the reply. Unlike a pay-as-you-go charge the estimate turns on no
    // measurement, so this is exact rather than a bracket.
    assert_eq!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT - estimate),
        "expected the reply to return everything left of a {HTTP_REQUEST_CYCLE_PAYMENT}-cycle \
         payment once the {estimate}-cycle estimate was charged"
    );

    let response = response.expect("Http call should succeed");

    assert_eq!(response.headers.len(), 2, "Headers: {:?}", response.headers);
    assert_eq!(response.headers[0].0, "hello");
    assert_eq!(response.headers[0].1, "bonjour");
    assert_eq!(response.headers[1].0, "caller");
    assert_eq!(response.headers[1].1, "aaaaa-aa");
    assert_eq!(
        response.body.as_str(),
        "transform_context",
        "Transform function did not set the body to the provided context."
    );
    assert_eq!(response.status, 202);
}

fn no_data_certificate_in_transform_function(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "data_certificate_in_transform".to_string(),
                    }),
                    context: vec![],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    let response = response.expect("Http call should succeed");

    assert_eq!(response.headers.len(), 2, "Headers: {:?}", response.headers);
    assert_eq!(response.headers[0].0, "data_certificate_present");
    assert_eq!(response.headers[0].1, "false");
    assert_eq!(response.headers[1].0, "in_replicated_execution");
    assert_eq!(response.headers[1].1, "false");
}

fn test_non_existent_transform_function(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let transform_context = "transform_context".as_bytes().to_vec();

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "non_existent_transform_function".to_string(),
                    }),
                    context: transform_context.clone(),
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterError,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_composite_transform_function_is_not_allowed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "test_composite_transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    let err = response.unwrap_err();
    assert_eq!(err.reject_code, RejectCode::CanisterError);
    assert!(
        err.reject_message
            .contains("Composite query cannot be used as transform in canister http outcalls.")
    );
}

/// An outcall with nothing attached is rejected where outcalls are paid for,
/// whichever pricing version it asks for: legacy has to cover the full request
/// fee up front, pay-as-you-go the base fee.
///
/// See [`test_free_subnet_charges_nothing`] for the free counterpart.
fn test_no_cycles_attached(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    for pricing_version in [PRICING_VERSION_LEGACY, PRICING_VERSION_PAY_AS_YOU_GO] {
        let request = UnvalidatedCanisterHttpRequestArgs {
            url: format!("http://[{webserver_ipv6}]"),
            headers: vec![],
            method: HttpMethod::GET,
            body: Some("".as_bytes().to_vec()),
            transform: Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: get_proxy_canister_id(&env).into(),
                    method: "transform".to_string(),
                }),
                context: vec![0, 1, 2],
            }),
            max_response_bytes: None,
            is_replicated: None,
            pricing_version: Some(pricing_version),
        };
        // How much the caller is told it should have attached.
        let proxy = handlers.proxy_canister().canister_id();
        let required = Cycles::new(match pricing_version {
            PRICING_VERSION_LEGACY => u128::from(expected_cycle_cost(
                proxy,
                request.clone(),
                handlers.subnet_size,
            )),
            _ => handlers.fees_for(request.clone()).base_fee,
        });

        let (response, _) = block_on(submit_outcall(
            &handlers,
            RemoteHttpRequest { request, cycles: 0 },
        ));

        assert_matches!(
            &response,
            Err(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message,
                ..
            }) if reject_message.contains(&required.to_string()),
            "expected pricing version {pricing_version} to reject an unpaid outcall as needing \
             {required} cycles, got {response:?}"
        );
    }
}

fn test_max_possible_request_size(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let headers_list = vec![
        ("name1".to_string(), "value1".to_string()),
        ("name2".to_string(), "value2".to_string()),
    ];

    let header_list_size = headers_list
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum::<usize>();

    let headers = headers_list
        .into_iter()
        .map(|(name, value)| HttpHeader { name, value })
        .collect();

    let body = vec![0; MAX_REQUEST_BYTES_LIMIT - header_list_size];

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]/request_size"),
                headers,
                method: HttpMethod::POST,
                body: Some(body),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Ok(r) if r.status==200);
}

fn test_max_possible_request_size_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let headers_list = vec![
        ("name1".to_string(), "value1".to_string()),
        ("name2".to_string(), "value2".to_string()),
    ];

    let header_list_size = headers_list
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum::<usize>();

    let headers = headers_list
        .into_iter()
        .map(|(name, value)| HttpHeader { name, value })
        .collect();

    let body = vec![0; MAX_REQUEST_BYTES_LIMIT - header_list_size + 1];

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]/request_size"),
                headers,
                method: HttpMethod::POST,
                body: Some(body),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
    assert_eq!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_2mb_response_cycle_for_rejection_path(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(async move {
        submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request: request.clone(),
                cycles: expected_cycle_cost(
                    handlers.proxy_canister().canister_id(),
                    request,
                    handlers.subnet_size,
                ) - 1,
            },
        )
        .await
    });

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_4096_max_response_cycle_case_1(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        max_response_bytes: Some(16384),
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(async move {
        submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request: request.clone(),
                cycles: expected_cycle_cost(
                    handlers.proxy_canister().canister_id(),
                    request.clone(),
                    handlers.subnet_size,
                ),
            },
        )
        .await
    });

    assert_matches!(response, Ok(r) if r.status==200);
}

fn test_4096_max_response_cycle_case_2(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        max_response_bytes: Some(16384),
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(async move {
        submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request: request.clone(),
                cycles: expected_cycle_cost(
                    handlers.proxy_canister().canister_id(),
                    request.clone(),
                    handlers.subnet_size,
                ) - 1,
            },
        )
        .await
    });
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_max_response_bytes_2_mb_returns_ok(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: None,
                max_response_bytes: Some((MAX_MAX_RESPONSE_BYTES) as u64),
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Ok(r) if r.status==200);
}

fn test_max_response_bytes_too_large(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: None,
                max_response_bytes: Some((MAX_MAX_RESPONSE_BYTES + 1) as u64),
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
    assert_eq!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_transform_that_bloats_on_the_2mb_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "very_large_but_allowed_transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Ok(r) if r.status==200);
}

fn test_transform_that_bloats_on_the_2mb_limit_with_custom_max_response_bytes(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let max_response_bytes = 1_000_000;

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "very_large_but_allowed_transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: Some(max_response_bytes),
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_transform_that_bloats_response_above_2mb_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "bloat_transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_post_request(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]/post"),
                headers: vec![HttpHeader {
                    name: "content-type".to_string(),
                    value: "application/x-www-form-urlencoded".to_string(),
                }],
                method: HttpMethod::POST,
                body: Some("satoshi".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Ok(r) if r.body.contains("satoshi"));
}

fn test_http_endpoint_response_is_within_limits_with_custom_max_response_bytes(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let n = 1_000_000;

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 1xxxxxx
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }
    let header_size = 148;
    let max_response_bytes: u64 = n + header_size;

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]/bytes/{n}"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: None,
                max_response_bytes: Some(max_response_bytes),
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
}

fn test_http_endpoint_response_is_too_large_with_custom_max_response_bytes(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let n = 1_000_000;

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 1xxxxxx
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }
    let header_size = 148;
    let max_response_bytes = n + header_size;

    let const_transform = TransformContext {
        function: TransformFunc(candid::Func {
            principal: get_proxy_canister_id(&env).into(),
            method: "transform".to_string(),
        }),
        context: vec![0, 1, 2],
    };

    for transform in [None, Some(const_transform)] {
        let (response, _) = block_on(submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request: UnvalidatedCanisterHttpRequestArgs {
                    url: format!("https://[{webserver_ipv6}]/bytes/{}", n + 1),
                    headers: vec![],
                    method: HttpMethod::GET,
                    body: Some("".as_bytes().to_vec()),
                    transform,
                    max_response_bytes: Some(max_response_bytes),
                    is_replicated: None,
                    pricing_version: None,
                },
                cycles: HTTP_REQUEST_CYCLE_PAYMENT,
            },
        ));

        assert_matches!(
            response,
            Err(RejectResponse {
                reject_code: RejectCode::SysFatal,
                ..
            })
        );
    }
}

fn test_http_endpoint_response_is_within_limits_with_default_max_response_bytes(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 1xxxxxx
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }
    let header_size = 148;
    let n = DEFAULT_MAX_RESPONSE_BYTES - header_size;

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]/bytes/{n}"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: None,
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
}

fn test_http_endpoint_response_is_too_large_with_default_max_response_bytes(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 1xxxxxx
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }
    let header_size = 148;
    let n = DEFAULT_MAX_RESPONSE_BYTES - header_size;

    let const_transform = TransformContext {
        function: TransformFunc(candid::Func {
            principal: get_proxy_canister_id(&env).into(),
            method: "transform".to_string(),
        }),
        context: vec![0, 1, 2],
    };

    for transform in [None, Some(const_transform)] {
        let (response, _) = block_on(submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request: UnvalidatedCanisterHttpRequestArgs {
                    url: format!("https://[{webserver_ipv6}]/bytes/{}", n + 1),
                    headers: vec![],
                    method: HttpMethod::GET,
                    body: Some("".as_bytes().to_vec()),
                    transform,
                    max_response_bytes: None,
                    is_replicated: None,
                    pricing_version: None,
                },
                cycles: HTTP_REQUEST_CYCLE_PAYMENT,
            },
        ));

        assert_matches!(
            response,
            Err(RejectResponse {
                reject_code: RejectCode::SysFatal,
                ..
            })
        );
    }
}

fn test_http_endpoint_with_delayed_response_is_rejected(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]/delay/40"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

/// The adapter should not follow HTTP redirects.
fn test_that_redirects_are_not_followed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]/redirect/10"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Ok(r) if r.status == 303);
}

/// The adapter should reject HTTP calls that are made to other IC replicas' HTTPS endpoints.
fn test_http_calls_to_ic_fails(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:9090"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    // Newer `hyper_util` versions embed the target socket address in the
    // `ConnectError`, so we only check the stable prefix and suffix.
    let expected_error_message_prefix = "Error(Connect, ConnectError(\"tcp connect error\", ";
    let expected_error_message_suffix =
        "Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" }))";
    let err_response = response.clone().unwrap_err();

    assert_matches!(err_response.reject_code, RejectCode::SysTransient);

    assert!(
        err_response
            .reject_message
            .contains(expected_error_message_prefix)
            && err_response
                .reject_message
                .contains(expected_error_message_suffix),
        "Expected error message to contain {} and {}, got: {}",
        expected_error_message_prefix,
        expected_error_message_suffix,
        err_response.reject_message
    );
}

fn test_invalid_domain_name(env: TestEnv) {
    let handlers = Handlers::new(&env);

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: "https://xwWPqqbNqxxHmLXdguF4DN9xGq22nczV.com".to_string(),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysTransient,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_invalid_ip(env: TestEnv) {
    let handlers = Handlers::new(&env);

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                // `2001:db8::1` is a reserved ipv6 address used in documentation and example source code.
                // See https://www.rfc-editor.org/rfc/rfc3849
                url: "https://[2001:db8::1]".to_string(),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysTransient,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

/// Test that the response body returned is the same as the requested path.
fn test_get_hello_world_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let expected_body = "hello_world";

    let url = format!("https://[{}]/{}/{}", webserver_ipv6, "ascii", expected_body);

    let max_response_bytes = 666;

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: Some(max_response_bytes),
        is_replicated: None,
        pricing_version: None,
    };

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if body == expected_body);
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
    assert_http_response(&response);
}

fn test_request_header_total_size_within_the_48_kib_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    // Header count is 3, as our current total limit is 48KiB and the tuple of header name and value is 16KiB.
    let header_count =
        TOTAL_HEADER_NAME_AND_VALUE_LENGTH / (MAX_HEADER_NAME_LENGTH + MAX_HEADER_VALUE_LENGTH);
    let mut headers = vec![];

    for i in 0..header_count {
        headers.push(HttpHeader {
            name: format!("{i}").repeat(MAX_HEADER_NAME_LENGTH),
            value: "y".repeat(MAX_HEADER_VALUE_LENGTH),
        });
    }

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers,
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request succeeds.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_request_header_total_size_over_the_48_kib_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    // Header count is 3, as our current total limit is 48KiB and the tuple of header name and value is 16KiB.
    let header_count =
        TOTAL_HEADER_NAME_AND_VALUE_LENGTH / (MAX_HEADER_NAME_LENGTH + MAX_HEADER_VALUE_LENGTH);
    let mut headers = vec![];

    for i in 0..header_count {
        headers.push(HttpHeader {
            name: format!("{i}").repeat(MAX_HEADER_NAME_LENGTH),
            value: "y".repeat(MAX_HEADER_VALUE_LENGTH),
        });
    }
    // The last header will push the total size over the limit.
    headers.push(HttpHeader {
        name: "x".to_string(),
        value: "y".to_string(),
    });

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers,
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
    assert_eq!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_response_header_total_size_within_the_48_kib_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    // We use the /large_response_headers_size endpoint which should return headers
    // with the specified value length, after accounting also for the
    // overhead headers (e.g. content-length, date, etc.)
    let url = format!(
        "https://[{webserver_ipv6}]/large_response_total_header_size/{MAX_HEADER_NAME_LENGTH}/{TOTAL_HEADER_NAME_AND_VALUE_LENGTH}",
    );

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes: Some(DEFAULT_MAX_RESPONSE_BYTES),
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(&response, Ok(RemoteHttpResponse { status: 200, .. }));
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );

    // Compute exactly the size of the response headers to account also for overhead.
    let total_header_size: usize = response
        .unwrap()
        .headers
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum();

    // Ensure that the successful response contains the expected response headers.
    assert!(
        total_header_size <= 48 * 1024,
        "Total header size ({total_header_size} bytes) exceeds 48KiB limit"
    );
}

fn test_response_header_total_size_over_the_48_kib_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    // We use the /large_response_total_header_size endpoint which should return headers
    // with the specified value length, after accounting also for the
    // overhead headers (e.g. content-length, date, etc.)
    let url = format!(
        "https://[{}]/large_response_total_header_size/{}/{}",
        webserver_ipv6,
        MAX_HEADER_NAME_LENGTH,
        TOTAL_HEADER_NAME_AND_VALUE_LENGTH + 1,
    );

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes: Some(DEFAULT_MAX_RESPONSE_BYTES),
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        &response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_request_header_name_and_value_within_limits(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let headers = vec![HttpHeader {
        name: "x".repeat(MAX_HEADER_NAME_LENGTH),
        value: "y".repeat(MAX_HEADER_VALUE_LENGTH),
    }];

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers,
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request succeeds.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
}

fn test_request_header_name_too_long(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let headers = vec![HttpHeader {
        name: "x".repeat(MAX_HEADER_NAME_LENGTH + 1),
        value: "value".to_string(),
    }];

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers,
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
    assert_eq!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_request_header_value_too_long(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let headers = vec![HttpHeader {
        name: "name".to_string(),
        value: "y".repeat(MAX_HEADER_VALUE_LENGTH + 1),
    }];

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]"),
        headers,
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
    assert_eq!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_response_header_name_within_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url =
        format!("https://[{webserver_ipv6}]/long_response_header_name/{MAX_HEADER_NAME_LENGTH}",);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: None,
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(&response, Ok(RemoteHttpResponse { status: 200, .. }));
}

fn test_response_header_name_over_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!(
        "https://[{}]/long_response_header_name/{}",
        webserver_ipv6,
        MAX_HEADER_NAME_LENGTH + 1,
    );

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: None,
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );

    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_response_header_value_within_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url =
        format!("https://[{webserver_ipv6}]/long_response_header_value/{MAX_HEADER_VALUE_LENGTH}",);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(&response, Ok(RemoteHttpResponse { status: 200, .. }));
}

fn test_response_header_value_over_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!(
        "https://[{}]/long_response_header_value/{}",
        webserver_ipv6,
        MAX_HEADER_VALUE_LENGTH + 1,
    );

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_post_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let expected_body = "POST";

    let url = format!("https://[{}]/{}", webserver_ipv6, "anything");
    let body = Some("hello_world".as_bytes().to_vec());
    let headers = vec![
        HttpHeader {
            name: "name1".to_string(),
            value: "value1".to_string(),
        },
        HttpHeader {
            name: "name2".to_string(),
            value: "value2".to_string(),
        },
    ];
    let max_response_bytes = Some(666);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers,
        method: HttpMethod::POST,
        body,
        transform: None,
        max_response_bytes,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request succeeds.");

    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if body.contains(expected_body));
    assert_distinct_headers(&response);
    assert_http_json_response(&request, &response);
}

/// Send 6666 repeating `x` to /anything endpoint.
/// Use HEAD http method. It only asks for the head, not the body.
/// Set max response size to 666 (order of magnitude smaller)
fn test_head_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let long_x_string = "x".repeat(6666);
    let url = format!(
        "https://[{}]/{}/{}",
        webserver_ipv6, "anything", long_x_string
    );
    let body = Some("hello_world".as_bytes().to_vec());
    let headers = vec![
        HttpHeader {
            name: "name1".to_string(),
            value: "value1".to_string(),
        },
        HttpHeader {
            name: "name2".to_string(),
            value: "value2".to_string(),
        },
    ];
    let max_response_bytes = Some(666);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers,
        method: HttpMethod::HEAD,
        body,
        transform: None,
        max_response_bytes,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request succeeds.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_distinct_headers(&response);
    let header_size = response
        .headers
        .iter()
        .map(|(header, value)| header.len() + value.len())
        .sum::<usize>();
    assert!(header_size <= 666);
    assert!(
        response.body.is_empty(),
        "Head request does not return a body."
    );
}

fn test_put_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!("https://[{webserver_ipv6}]/anything");
    let body = Some("put_request_body".as_bytes().to_vec());
    let headers = vec![HttpHeader {
        name: "name1".to_string(),
        value: "value1".to_string(),
    }];

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers,
        method: HttpMethod::PUT,
        body,
        transform: None,
        max_response_bytes: None,
        is_replicated: Some(false),
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Ok(response) => {
        assert_matches!(response, RemoteHttpResponse { status: 200, .. });
        assert_distinct_headers(&response);
        assert_http_json_response(&request, &response);
    });
}

fn test_put_without_non_replicated_rejected(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!("https://[{webserver_ipv6}]/anything");
    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::PUT,
        body: Some(vec![]),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request,
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    assert_matches!(response, Err(RejectResponse { reject_message, .. }) => {
        assert!(reject_message.contains("only allowed for non-replicated requests"));
    });
}

fn test_delete_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!("https://[{webserver_ipv6}]/anything");
    let headers = vec![HttpHeader {
        name: "name1".to_string(),
        value: "value1".to_string(),
    }];

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers,
        method: HttpMethod::DELETE,
        body: None,
        transform: None,
        max_response_bytes: None,
        is_replicated: Some(false),
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Ok(response) => {
        assert_matches!(response, RemoteHttpResponse { status: 200, .. });
        assert_distinct_headers(&response);
        assert_http_json_response(&request, &response);
    });
}

fn test_delete_without_non_replicated_rejected(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!("https://[{}]/{}", webserver_ipv6, "anything");
    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::DELETE,
        body: None,
        transform: None,
        max_response_bytes: Some(1024),
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request,
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Err(RejectResponse { reject_message, .. }) => {
        assert!(reject_message.contains("only allowed for non-replicated requests"));
    });
}

fn test_patch_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!("https://[{webserver_ipv6}]/anything");
    let body = Some("patch_request_body".as_bytes().to_vec());
    let headers = vec![HttpHeader {
        name: "name1".to_string(),
        value: "value1".to_string(),
    }];

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers,
        method: HttpMethod::PATCH,
        body,
        transform: None,
        max_response_bytes: None,
        is_replicated: Some(false),
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Ok(response) => {
        assert_matches!(response, RemoteHttpResponse { status: 200, .. });
        assert_distinct_headers(&response);
        assert_http_json_response(&request, &response);
    });
}

fn test_patch_without_non_replicated_rejected(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!("https://[{}]/{}", webserver_ipv6, "anything");
    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::PATCH,
        body: Some(vec![]),
        transform: None,
        max_response_bytes: Some(1024),
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request,
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(response, Err(RejectResponse { reject_message, .. }) => {
        assert!(reject_message.contains("only allowed for non-replicated requests"));
    });
}

fn test_only_headers_with_custom_max_response_bytes(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let n = 0;
    let url = format!("https://[{}]/{}/{}", webserver_ipv6, "equal_bytes", n);

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 11
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }

    let header_size = 142;
    let max_response_bytes = Some(header_size + n);

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
}

fn test_only_headers_with_custom_max_response_bytes_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let n = 0;
    let url = format!("https://[{}]/{}/{}", webserver_ipv6, "equal_bytes", n);

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 0
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }

    let header_size = 142;
    let max_response_bytes = Some(header_size + n - 1);

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_non_ascii_url_is_accepted(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let expected_body = "안녕하세요";

    let url = format!("https://[{}]/{}/{}", webserver_ipv6, "ascii", expected_body);

    let max_response_bytes = 666;

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: Some(max_response_bytes),
        is_replicated: None,
        pricing_version: None,
    };

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request is successful");

    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if *body == expected_body);
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_max_url_length(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let base_url = format!("https://[{}]/{}/", webserver_ipv6, "ascii");
    let remaining_space = MAX_CANISTER_HTTP_URL_SIZE - base_url.len();
    let expected_body = "x".repeat(remaining_space);

    let url = format!("{base_url}{expected_body}");
    assert_eq!(url.len(), MAX_CANISTER_HTTP_URL_SIZE);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if *body == expected_body);
    assert_http_response(&response);
}

fn test_max_url_length_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let base_url = format!("https://[{}]/{}/", webserver_ipv6, "ascii");
    let remaining_space = MAX_CANISTER_HTTP_URL_SIZE - base_url.len();
    // Add one more character to exceed the limit.
    let expected_body = "x".repeat(remaining_space + 1);

    let url = format!("{base_url}{expected_body}");

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
    };

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
    assert_eq!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn reference_transform_function_exposed_by_different_canister(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let url = format!("https://[{}]/{}/{}", webserver_ipv6, "ascii", "hello_world");

    let proxy_canister_id_1 = get_proxy_canister_id(&env);
    // Create another proxy canister;
    // Get application subnet node to deploy canister to.
    let mut nodes = get_node_snapshots(&env);
    let node = nodes.next().expect("there is no application node");
    let runtime = get_runtime_from_node(&node);
    let _ = create_proxy_canister_with_name(&env, &runtime, &node, "proxy_canister_2");
    let proxy_canister_id_2 = get_proxy_canister_id_with_name(&env, "proxy_canister_2");

    assert_ne!(
        proxy_canister_id_1, proxy_canister_id_2,
        "create_proxy_canister() should create a new proxy canister with a new canister id."
    );

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: proxy_canister_id_2.into(),
                method: "test_transform".to_string(),
            }),
            context: vec![],
        }),
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_max_number_of_response_headers(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response_headers = HTTP_HEADERS_MAX_NUMBER - HTTPBIN_OVERHEAD_RESPONSE_HEADERS;
    let url = format!(
        "https://[{}]/{}/{}",
        webserver_ipv6, "many_response_headers", response_headers
    );

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
    assert_eq!(
        response.headers.len(),
        HTTP_HEADERS_MAX_NUMBER,
        "Expected {} headers, got {}",
        response_headers,
        response.headers.len()
    );
}

fn test_max_number_of_response_headers_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response_headers = HTTP_HEADERS_MAX_NUMBER - HTTPBIN_OVERHEAD_RESPONSE_HEADERS + 1;
    let url = format!(
        "https://[{}]/{}/{}",
        webserver_ipv6, "many_response_headers", response_headers
    );

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes: None,
                is_replicated: None,
                pricing_version: None,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
    assert_ne!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn test_max_number_of_request_headers(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let headers = (0..HTTP_HEADERS_MAX_NUMBER)
        .map(|i| HttpHeader {
            name: format!("name{i}"),
            value: format!("value{i}"),
        })
        .collect();

    let request = RemoteHttpRequest {
        request: UnvalidatedCanisterHttpRequestArgs {
            url: format!("https://[{webserver_ipv6}]/anything"),
            headers,
            method: HttpMethod::POST,
            body: None,
            transform: None,
            max_response_bytes: None,
            is_replicated: None,
            pricing_version: None,
        },
        cycles: HTTP_REQUEST_CYCLE_PAYMENT,
    };
    let (response, _) = block_on(submit_outcall(&handlers, request.clone()));
    let response = response.expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
    assert_http_json_response(&request.request, &response);
}

fn test_max_number_of_request_headers_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let url = format!("https://[{webserver_ipv6}]/anything");

    let headers = (0..HTTP_HEADERS_MAX_NUMBER + 1)
        .map(|i| HttpHeader {
            name: format!("name{i}"),
            value: format!("value{i}"),
        })
        .collect();

    #[derive(Clone, Debug, CandidType, Deserialize)]
    struct TestRequest {
        url: String,
        headers: Vec<HttpHeader>,
        method: HttpMethod,
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    struct TestRemoteHttpRequest {
        pub request: TestRequest,
        pub cycles: u64,
    }

    let (response, refunded_cycles) = block_on(submit_outcall(
        &handlers,
        TestRemoteHttpRequest {
            request: TestRequest {
                url,
                headers,
                method: HttpMethod::POST,
            },
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
    assert_eq!(
        refunded_cycles,
        RefundedCycles::Cycles(HTTP_REQUEST_CYCLE_PAYMENT)
    );
}

fn check_caller_id_on_transform_function(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let url = format!("https://[{}]/{}/{}", webserver_ipv6, "ascii", "hello_world");

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        max_response_bytes: None,
        is_replicated: None,
        pricing_version: None,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "test_transform".to_string(),
            }),
            context: vec![],
        }),
    };

    let (response, _) = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    ));
    let response = response.expect("Request is successful.");

    // Check caller id injected into header.
    let caller_id = &response
        .headers
        .iter()
        .find(|(name, _)| name.to_lowercase() == "caller")
        .expect("caller header is present after transformation.")
        .1;

    assert_eq!(caller_id, "aaaaa-aa");
}

// ---- HELPER FUNCTIONS -------

/// Case insensitive header names are distinct.
fn assert_distinct_headers(http_response: &RemoteHttpResponse) {
    let response_header_set: HashSet<String> = http_response
        .headers
        .clone()
        .iter()
        .map(|(name, _)| name.to_lowercase())
        .collect();

    assert_eq!(
        response_header_set.len(),
        http_response.headers.len(),
        "Found duplicate headers: {:?}",
        http_response.headers
    );
}

/// Assert that content-length header matches the body length, and that the headers are distinct.
fn assert_http_response(
    // http_request: &CanisterHttpRequestArgs,
    http_response: &RemoteHttpResponse,
) {
    assert_distinct_headers(http_response);

    let content_length_header = http_response
        .headers
        .iter()
        .find(|(name, _)| name.to_lowercase() == "content-length")
        .map(|(_, value)| value.parse::<usize>())
        .unwrap_or_else(|| {
            panic!(
                "HTTP response contains `content-length` header. Headers: {:?}",
                http_response.headers
            )
        })
        .expect("content-length is a number");

    assert_eq!(
        content_length_header,
        http_response.body.len(),
        "Content length header does not match the body length."
    );
}

/// Checks if two sets of headers match according to specific rules:
/// 1. All headers in `outcall_headers` must exist in `http_bin_server_received_headers`
/// 2. All headers in `http_bin_server_received_headers` must exist in `outcall_headers`, unless they are special cases:
/// - "host"
/// - "content-length"
/// - "accept-encoding"
/// - "user-agent" with value "ic/1.0"
/// 3. Request method must match the method in the response.
/// 4. Request body must match the body in the response.
fn assert_http_json_response(
    request: &UnvalidatedCanisterHttpRequestArgs,
    http_response: &RemoteHttpResponse,
) {
    let request_headers = request
        .headers
        .iter()
        .map(|HttpHeader { name, value }| (name.clone(), value.clone()))
        .collect::<Vec<_>>();

    let response_body: Value =
        serde_json::from_str(&http_response.body).expect("Response body is JSON formatted.");

    let http_bin_server_received_headers: Vec<_> = response_body["headers"]
        .as_array()
        .expect("Headers is an array")
        .iter()
        .map(|name_value| {
            let name_value_tuple = name_value
                .as_array()
                .expect("Headers is tuple of name and value.");
            let name = name_value_tuple[0].as_str().unwrap().to_string();
            let value = name_value_tuple[1].as_str().unwrap().to_string();
            (name, value)
        })
        .collect();

    // Rule 1: Check that all left headers exist in right
    let http_bin_server_received_all_outcall_headers = request_headers
        .iter()
        .all(|x| http_bin_server_received_headers.contains(x));

    assert!(
        http_bin_server_received_all_outcall_headers,
        "1. HTTP bin server did not receive all headers specified in the outcall. Specified headers: {request_headers:?}, received headers: {http_bin_server_received_headers:?}"
    );

    // Rule 2: Check that all headers received by the server was specified in outcall.
    let http_bin_server_only_received_headers_specified_by_outcall =
        http_bin_server_received_headers
            .iter()
            .filter(|(name, value)| {
                !matches!(
                    (name.as_str(), value.as_str()),
                    ("host", _)
                        | ("content-length", _)
                        | ("accept-encoding", _)
                        | ("user-agent", "ic/1.0")
                )
            })
            .all(|(name, value)| request_headers.contains(&(name.clone(), value.clone())));

    assert!(
        http_bin_server_only_received_headers_specified_by_outcall,
        "2. Http bin server received headers that were not specified in the outcall. Specified headers: {request_headers:?}, received headers: {http_bin_server_received_headers:?}"
    );

    // Rule 3: Request method must match the method in the response.
    let request_method = match request.method {
        HttpMethod::GET => "GET",
        HttpMethod::POST => "POST",
        HttpMethod::HEAD => "HEAD",
        HttpMethod::PUT => "PUT",
        HttpMethod::DELETE => "DELETE",
        HttpMethod::PATCH => "PATCH",
    };

    assert_eq!(
        request_method,
        response_body["method"].as_str().unwrap(),
        "3. Mismatch in HTTP method."
    );

    // Rule 4: Request body must match the body in the response.
    let server_received_body = response_body["data"].as_str().unwrap();
    let outcall_sent_body = String::from_utf8(request.body.clone().unwrap_or_default()).unwrap();

    assert_eq!(
        server_received_body, &outcall_sent_body,
        "4. HTTP bin server received body does not match the outcall sent body."
    );
}

#[derive(Debug, Eq, PartialEq)]
enum RefundedCycles {
    NotApplicable,
    Cycles(u64),
}

type ProxyCanisterResponseWithRefund = ResponseWithRefundedCycles;

// This type represents the result of an IC http_request and the refunded cycles.
// The refund is returned regardless of whether the outcall succeeded (Ok) or failed (Err),
// allowing tests to verify proper cycle refund behavior in both success and error cases.
type OutcallsResponseWithRefund = (Result<RemoteHttpResponse, RejectResponse>, RefundedCycles);

async fn submit_outcall<Request>(
    handlers: &Handlers<'_>,
    request: Request,
) -> OutcallsResponseWithRefund
where
    Request: Clone + CandidType,
{
    let args = Encode!(&request).unwrap();
    let agent = handlers.agent().await;

    let principal_id: PrincipalId = handlers.proxy_canister().effective_canister_id();
    let principal: Principal = principal_id.into();

    let log = handlers.env.logger();
    let canister_response = match retry_agent_on_transport_errors!(
        "submit_outcall: call",
        &log,
        agent
            .update(&principal, "send_request_with_refund_callback")
            .with_arg(args.clone())
            .call()
    )
    .await
    .expect("submit_outcall retries exhausted")
    {
        Ok(CallResponse::Response(response)) => Ok(response),
        Ok(CallResponse::Poll(request_id)) => retry_agent_on_transport_errors!(
            "submit_outcall: wait",
            &log,
            agent.wait(&request_id, principal)
        )
        .await
        .expect("submit_outcall retries exhausted"),
        Err(err) => Err(err),
    };

    match canister_response {
        Err(agent_error) => {
            let err_resp = match agent_error {
                AgentError::CertifiedReject {
                    reject: response, ..
                }
                | AgentError::UncertifiedReject {
                    reject: response, ..
                } => response,
                _ => panic!("Unexpected error: {agent_error:?}"),
            };
            // If an agent_error is returned then it means that the http_request failed before
            // performing the outcall on the canister, therefore the refund is not applicable.
            (Err(err_resp), RefundedCycles::NotApplicable)
        }
        Ok(serialized_bytes) => {
            let response_with_refund =
                decode_one::<ProxyCanisterResponseWithRefund>(&serialized_bytes.0)
                    .expect("Decoding the canister serialized response should succeed.");

            let refunded_cycles = response_with_refund.refunded_cycles;
            let result = response_with_refund
                .result
                .map_err(|(reject_code, reject_message)| {
                    let reject_code = match reject_code {
                        RejectionCode::SysFatal => RejectCode::SysFatal,
                        RejectionCode::SysTransient => RejectCode::SysTransient,
                        RejectionCode::DestinationInvalid => RejectCode::DestinationInvalid,
                        RejectionCode::CanisterReject => RejectCode::CanisterReject,
                        RejectionCode::CanisterError => RejectCode::CanisterError,
                        RejectionCode::NoError | RejectionCode::Unknown => {
                            panic!("Invalid rejection code.")
                        }
                    };

                    RejectResponse {
                        reject_code,
                        reject_message,
                        error_code: None,
                    }
                });
            (result, RefundedCycles::Cycles(refunded_cycles))
        }
    }
}

/// The body httpbin answers `/bytes/{PAYG_BODY_BYTES}` with: that many `x`s.
fn payg_body() -> String {
    "x".repeat(PAYG_BODY_BYTES)
}

/// Unwrap the given result
fn fatal<T>(read: anyhow::Result<T>) -> T {
    read.unwrap_or_else(|err| panic!("{err:#}"))
}

/// The proxy canister's balance right now.
async fn proxy_cycle_balance(handlers: &Handlers<'_>) -> u128 {
    fatal(cycle_balance(&handlers.node, handlers.proxy_canister_id).await)
}

/// Makes a pay-as-you-go outcall and checks how the caller was charged for it.
///
/// The payment leaves the balance up front; everything it covered beyond the base
/// fee and the per-replica allowances comes back on the reply, and the unspent part
/// of the allowances is credited to the balance once the response is delivered. So
/// what stays charged is the base fee plus what the outcall really spent — more
/// than a lower bound dervied from the delivered response, and no more than
/// `ic0.cost_http_request_v2` quotes for the resources it consumed.
///
/// Returns the fees and what the outcall actually cost, for whatever the caller
/// wants to assert on top.
async fn assert_charged_as_quoted(
    handlers: &Handlers<'_>,
    description: &str,
    request: UnvalidatedCanisterHttpRequestArgs,
    expected_body: &str,
) -> (PaygFees, SettledCharge) {
    let payment = u128::from(HTTP_REQUEST_CYCLE_PAYMENT);
    let fees = handlers.fees_for(request.clone());

    let baseline = settled_baseline(handlers).await;
    let started = Instant::now();
    let (response, refunded_cycles) = submit_outcall(
        handlers,
        RemoteHttpRequest {
            request,
            cycles: HTTP_REQUEST_CYCLE_PAYMENT,
        },
    )
    .await;
    // Bounds the HTTP round trip of the request.
    let elapsed = started.elapsed();
    assert_matches!(
        &response,
        Ok(ok) if ok.status == 200 && ok.body == expected_body,
        "{description} did not come back as a 200 carrying '{expected_body}': {response:?}"
    );
    let charge = settled_charge(handlers, &baseline).await;
    // The response is what it was asserted to be just above, so the bytes consensus
    // charged for are known exactly.
    let delivered = DeliveredResponse::transformed(expected_body.as_bytes());
    // Ensure the real consumption is within the quoted bounds.
    if let Err(wrong) = fees.check_consumption(&charge.consumed, &delivered, elapsed) {
        panic!("{description} {wrong}");
    }
    // Everything that wasn't withheld should heve been refunded with the response.
    let RefundedCycles::Cycles(refunded) = refunded_cycles else {
        panic!("{description} reported no refund on its reply at all");
    };
    if let Err(wrong) = fees.check_reply_refund(payment, u128::from(refunded)) {
        panic!("{description} {wrong}");
    }
    (fees, charge)
}

/// Opens a measurement window on the proxy canister — see [`canister_http::settled_baseline`].
async fn settled_baseline(handlers: &Handlers<'_>) -> Baseline {
    fatal(canister_http::settled_baseline(&handlers.node, handlers.proxy_canister_id).await)
}

/// Closes the measurement window — see [`canister_http::settled_charge`].
async fn settled_charge(handlers: &Handlers<'_>, baseline: &Baseline) -> SettledCharge {
    fatal(canister_http::settled_charge(&handlers.node, handlers.proxy_canister_id, baseline).await)
}

/// Reads what the proxy canister has been charged for, broken down by use case.
async fn proxy_consumed_cycles(handlers: &Handlers<'_>) -> ConsumedCycles {
    fatal(consumed_cycles(&handlers.node, handlers.proxy_canister_id).await)
}

/// A fully-replicated outcall priced pay-as-you-go: every replica of the subnet
/// fetches the response and they share the allowances between them.
fn test_pay_as_you_go_charges_and_refunds(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let request = pay_as_you_go_args(
        handlers.proxy_canister_id,
        format!("https://[{webserver_ipv6}]/bytes/{PAYG_BODY_BYTES}"),
    );

    let (fees, _) = block_on(assert_charged_as_quoted(
        &handlers,
        "a fully-replicated pay-as-you-go outcall",
        request,
        &payg_body(),
    ));
    assert_eq!(
        fees.node_count, handlers.subnet_size,
        "a fully-replicated outcall is served by every replica of the subnet"
    );
}

/// A non-replicated outcall priced pay-as-you-go: a single replica
/// fetches the response.
fn test_pay_as_you_go_non_replicated(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let request = UnvalidatedCanisterHttpRequestArgs {
        is_replicated: Some(false),
        ..pay_as_you_go_args(
            handlers.proxy_canister_id,
            format!("https://[{webserver_ipv6}]/bytes/{PAYG_BODY_BYTES}"),
        )
    };

    let (fees, _) = block_on(assert_charged_as_quoted(
        &handlers,
        "a non-replicated pay-as-you-go outcall",
        request,
        &payg_body(),
    ));
    assert_eq!(
        fees.node_count, 1,
        "a non-replicated outcall is served by exactly one replica"
    );
}

/// A slow response costs more than a quick one: what a replica spends is charged
/// per millisecond of round trip, not just per byte downloaded.
fn test_pay_as_you_go_charges_for_response_time(env: TestEnv) {
    const DELAY: Duration = Duration::from_secs(10);

    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let request = pay_as_you_go_args(
        handlers.proxy_canister_id,
        format!("https://[{webserver_ipv6}]/delay/{}", DELAY.as_secs()),
    );

    let (fees, charge) = block_on(assert_charged_as_quoted(
        &handlers,
        "a pay-as-you-go outcall the server sat on",
        request,
        // `/delay/<d>` answers with an empty body after `d` seconds.
        "",
    ));
    // Every replica that delivered the response waited out the delay, so each was
    // charged for at least that much time on top of everything the price is already
    // bracketed by.
    let delivered = DeliveredResponse::transformed(b"");
    let floor = fees.floor_of(&delivered) + fees.time_floor(&delivered, DELAY);
    assert!(
        charge.consumed.http_outcalls >= floor,
        "a {DELAY:?} round trip consumed {} cycles, less than the expected {floor} floor",
        charge.consumed.http_outcalls
    );
}

/// A `max_response_bytes` cap shrinks what is withheld up front, because it
/// shrinks the worst case the allowances have to cover.
fn test_pay_as_you_go_response_cap_shrinks_what_is_withheld(env: TestEnv) {
    /// Comfortably above the body this outcall asks for, far below the 2 MB an
    /// uncapped request may fetch.
    const CAP: u64 = 2 * PAYG_BODY_BYTES as u64;

    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let url = format!("https://[{webserver_ipv6}]/bytes/{PAYG_BODY_BYTES}");
    let uncapped = pay_as_you_go_args(handlers.proxy_canister_id, url.clone());
    let capped = UnvalidatedCanisterHttpRequestArgs {
        max_response_bytes: Some(CAP),
        ..uncapped.clone()
    };

    let payment = u128::from(HTTP_REQUEST_CYCLE_PAYMENT);
    let withheld_capped = handlers.fees_for(capped.clone()).withheld(payment);
    let withheld_uncapped = handlers.fees_for(uncapped).withheld(payment);
    assert!(withheld_capped < withheld_uncapped);

    let (fees, _) = block_on(assert_charged_as_quoted(
        &handlers,
        "a pay-as-you-go outcall that capped its response size",
        capped,
        &payg_body(),
    ));
    assert!(
        fees.payment_is_ample(payment),
        "a payment of {payment} does not cover the {} base fee plus the {} worst-case usage fee, \
        so the allowances would be sized by the payment rather than by the worst-case usage fee",
        fees.base_fee,
        fees.max_usage_fee
    );
}

/// An outcall funded from `ic0.cost_http_request_v2` — the way a canister is meant
/// to fund one — succeeds, and is charged no more than it was quoted.
fn test_pay_as_you_go_funded_by_the_quote(env: TestEnv) {
    // What the caller expects of the round trip, and so what it quotes for.
    // `PaygFees::quote` prices a short response; the time is quoted with room to
    // spare for a loaded test network.
    const QUOTED_ROUND_TRIP: Duration = Duration::from_secs(5);
    // A body that will not be affordable to download.
    const OVERSIZED_BODY: u64 = 1_000_000;

    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let request = pay_as_you_go_args(
        handlers.proxy_canister_id,
        format!("https://[{webserver_ipv6}]/ascii/quoted"),
    );
    let fees = handlers.fees_for(request.clone());
    let payment = fees.quote(QUOTED_ROUND_TRIP);
    let quoted_payment = u64::try_from(payment).unwrap();
    assert!(
        !fees.payment_is_ample(payment),
        "a payment of {payment} already covers the worst-case usage fee of {}, so the \
         allowances are sized by that rather than by the payment",
        fees.max_usage_fee
    );
    let allowance = fees.allowance(payment);
    assert_eq!(
        allowance,
        (payment - fees.base_fee) / fees.node_count as u128,
        "the payment, not the worst-case usage fee, should be what sizes the allowances"
    );

    block_on(async {
        let baseline = settled_baseline(&handlers).await;
        let started = Instant::now();
        let (response, refunded_cycles) = submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request: request.clone(),
                cycles: quoted_payment,
            },
        )
        .await;
        let elapsed = started.elapsed();
        assert_matches!(
            &response,
            Ok(ok) if ok.status == 200 && ok.body == "quoted"
        );
        let charge = settled_charge(&handlers, &baseline).await;
        let RefundedCycles::Cycles(refunded) = refunded_cycles else {
            panic!("an outcall funded by its quote reported no refund on its reply at all");
        };
        if let Err(wrong) = fees.check_reply_refund(payment, u128::from(refunded)) {
            panic!("an outcall funded by its quote {wrong}");
        }
        // All of the payment beyond the base fee is withheld as allowances, so what
        // comes back on the reply is only the remainder that would not divide.
        assert!(u128::from(refunded) < fees.node_count as u128);

        let delivered = DeliveredResponse::transformed(b"quoted");
        if let Err(wrong) = fees.check_consumption(&charge.consumed, &delivered, elapsed) {
            panic!("an outcall funded by its quote {wrong}");
        }
        assert!(
            charge.consumed.http_outcalls <= payment,
            "an outcall funded with the {payment} cycles it was quoted cost {}",
            charge.consumed.http_outcalls
        );

        // The same funding, against a response it cannot afford to download. The
        // outcall should terminate with an out of cycles error.
        let oversized_request = UnvalidatedCanisterHttpRequestArgs {
            url: format!("https://[{webserver_ipv6}]/bytes/{OVERSIZED_BODY}"),
            ..request
        };
        let oversized_fees = handlers.fees_for(oversized_request.clone());
        let oversized_allowance = oversized_fees.allowance(payment);
        let baseline = settled_baseline(&handlers).await;
        let (oversized, _) = submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request: oversized_request,
                cycles: quoted_payment,
            },
        )
        .await;
        let rejection = oversized.expect_err(&format!(
            "an allowance of {oversized_allowance} cycles buys nowhere near the {OVERSIZED_BODY} \
            bytes this outcall asked for, so it should not have come back with a response"
        ));
        assert_eq!(rejection.reject_code, RejectCode::CanisterReject);
        // The allowance does not merely cap the download, it pays for it: every
        // replica spends its share down to the cycle before giving up, and the
        // receipt each one reports is capped at exactly that share.
        let spent = fatal(reported_spend(&rejection.reject_message).map_err(anyhow::Error::msg));
        let withheld_for_replicas = oversized_allowance * oversized_fees.node_count as u128;
        assert_eq!(spent, withheld_for_replicas);

        let charge = settled_charge(&handlers, &baseline).await;
        let expected = oversized_fees.base_fee + spent;
        assert_eq!(charge.consumed.http_outcalls, expected);
    });
}

/// Pay-as-you-go admits a request exactly when the payment covers the base fee,
/// and not a cycle below it.
fn test_pay_as_you_go_base_fee_threshold(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let request = pay_as_you_go_args(
        handlers.proxy_canister_id,
        format!("https://[{webserver_ipv6}]/ascii/threshold"),
    );
    let base_fee = handlers.fees_for(request.clone()).base_fee;
    let base_fee = u64::try_from(base_fee)
        .unwrap_or_else(|_| panic!("a base fee of {base_fee} cycles does not fit the proxy's API"));
    // The reject message renders the figure the way `Cycles` displays it, with
    // underscore separators, so match on that rather than on the bare integer.
    let base_fee_shown = Cycles::new(u128::from(base_fee)).to_string();

    block_on(async {
        // A cycle short: refused up front, with the payment returned untouched.
        let refused_baseline = settled_baseline(&handlers).await;
        let (response, refunded_cycles) = submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request: request.clone(),
                cycles: base_fee - 1,
            },
        )
        .await;
        assert_matches!(
            &response,
            Err(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message,
                ..
            }) if reject_message.contains(&base_fee_shown),
            "expected a rejection naming the {base_fee_shown}-cycle base fee, got {response:?}"
        );
        assert_eq!(
            refunded_cycles,
            RefundedCycles::Cycles(base_fee - 1),
            "a request that was never admitted should have its whole payment returned"
        );
        let refused = settled_charge(&handlers, &refused_baseline).await;
        assert_eq!(refused.consumed.http_outcalls, 0);

        // Exactly the base fee: admitted, and the base fee is kept.
        let baseline = settled_baseline(&handlers).await;
        let (response, refunded_cycles) = submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request,
                cycles: base_fee,
            },
        )
        .await;
        match &response {
            Err(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message,
                ..
            }) => assert!(
                reject_message.contains("Out of cycles"),
                "expected an out-of-cycles rejection, got '{reject_message}'"
            ),
            other => panic!(
                "expected the outcall to be admitted and then run out of cycles, got {other:?}"
            ),
        }
        assert_eq!(
            refunded_cycles,
            RefundedCycles::Cycles(0),
            "a payment of exactly the base fee leaves nothing to refund"
        );
        let charge = settled_charge(&handlers, &baseline).await;
        assert_eq!(charge.consumed.http_outcalls, u128::from(base_fee));
    });
}

/// Several pay-as-you-go outcalls in flight at once are each refunded what they
/// did not spend.
fn test_pay_as_you_go_refunds_concurrent_outcalls(env: TestEnv) {
    const CONCURRENT: u64 = 4;

    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let request = pay_as_you_go_args(
        handlers.proxy_canister_id,
        format!("https://[{webserver_ipv6}]/bytes/{PAYG_BODY_BYTES}"),
    );
    let fees = handlers.fees_for(request.clone());

    block_on(async {
        let baseline = settled_baseline(&handlers).await;
        let started = Instant::now();
        let proxy = handlers.proxy_canister();
        let response = proxy
            .update_(
                "send_requests_in_parallel",
                candid_one::<
                    Result<RemoteHttpStressResponse, (RejectionCode, String)>,
                    RemoteHttpStressRequest,
                >,
                RemoteHttpStressRequest {
                    request: RemoteHttpRequest {
                        request,
                        cycles: HTTP_REQUEST_CYCLE_PAYMENT,
                    },
                    count: CONCURRENT,
                },
            )
            .await
            .expect("calling the proxy canister failed")
            .unwrap_or_else(|err| panic!("not all {CONCURRENT} outcalls succeeded: {err:?}"));
        // Bounds the round trip the replicas that delivered them were charged for:
        // those all happened strictly inside this call.
        let elapsed = started.elapsed();
        let expected_body = payg_body();
        assert_eq!(
            (response.response.status, &response.response.body),
            (200, &expected_body)
        );
        let delivered = DeliveredResponse::transformed(expected_body.as_bytes());

        // Wait for the balance and consumption counters to agree.
        let charge = settled_charge(&handlers, &baseline).await;
        let outcalls = charge.consumed.http_outcalls;
        // Made together, they should cost what they would have cost one at a time.
        let floor = u128::from(CONCURRENT) * fees.floor_of(&delivered);
        assert!(
            outcalls >= floor,
            "{CONCURRENT} outcalls made at once consumed {outcalls} cycles, less than the {floor} floor"
        );
        let bound = u128::from(CONCURRENT) * fees.quote_of(&delivered, elapsed);
        assert!(
            outcalls <= bound,
            "{CONCURRENT} outcalls made at once consumed {outcalls} cycles, more than the {bound} quote"
        );
    });
}

/// Legacy pricing takes its estimate out of the caller's balance and puts nothing
/// back.
fn test_legacy_charges_the_estimate_and_nothing_else(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    // Exactly the request the pay-as-you-go tests make, transform included, so that
    // the only difference between the two is the pricing version.
    let request = UnvalidatedCanisterHttpRequestArgs {
        pricing_version: Some(PRICING_VERSION_LEGACY),
        ..pay_as_you_go_args(
            handlers.proxy_canister_id,
            format!("https://[{webserver_ipv6}]/ascii/legacy"),
        )
    };
    let estimate = u128::from(expected_cycle_cost(
        handlers.proxy_canister().canister_id(),
        request.clone(),
        handlers.subnet_size,
    ));

    block_on(async {
        let baseline = settled_baseline(&handlers).await;
        let (response, refunded_cycles) = submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request,
                cycles: HTTP_REQUEST_CYCLE_PAYMENT,
            },
        )
        .await;
        assert_matches!(
            &response,
            Ok(ok) if ok.status == 200 && ok.body == "legacy",
            "a legacy outcall did not come back as a 200 carrying 'legacy': {response:?}"
        );

        let payment = u128::from(HTTP_REQUEST_CYCLE_PAYMENT);
        assert_eq!(
            refunded_cycles,
            RefundedCycles::Cycles((payment - estimate) as u64),
            "expected the reply to return the {} cycles left of a {payment}-cycle payment \
             once the {estimate}-cycle estimate was charged",
            payment - estimate
        );

        // Settling reconciles the balance against the counters, so nothing can have
        // credited this outcall cycles it never paid.
        let charge = settled_charge(&handlers, &baseline).await;
        // Legacy is charged up front exactly as quoted, and nothing about the
        // outcall's actual resource usage moves it afterwards.
        assert_eq!(charge.consumed.http_outcalls, estimate);
    });
}

/// A non-flexible outcall that can pay its replicas for fetching a response but
/// not for putting one into a block fails as out of cycles, rather than hanging
/// until it times out.
fn test_pay_as_you_go_out_of_cycles(env: TestEnv) {
    const BODY_SIZE: usize = 500_000;
    const PAYMENT: u64 = 400_000_000;

    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let request = pay_as_you_go_args(
        handlers.proxy_canister_id,
        format!("https://[{webserver_ipv6}]/bytes/{BODY_SIZE}"),
    );
    let payment = u128::from(PAYMENT);
    let fees = handlers.fees_for(request.clone());

    block_on(async {
        let baseline = settled_baseline(&handlers).await;
        let (response, refunded_cycles) = submit_outcall(
            &handlers,
            RemoteHttpRequest {
                request,
                cycles: PAYMENT,
            },
        )
        .await;

        let spent = match &response {
            Err(RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message,
                ..
            }) => {
                assert!(
                    reject_message.contains("Out of cycles"),
                    "unexpected rejection message: '{reject_message}'"
                );
                fatal(reported_spend(reject_message).map_err(anyhow::Error::msg))
            }
            other => panic!("expected an out-of-cycles rejection, got: {other:?}"),
        };

        // Nearly the whole payment goes out as allowances, so the reply carries back
        // only what would not divide between them.
        let RefundedCycles::Cycles(refunded) = refunded_cycles else {
            panic!("an out-of-cycles outcall reported no refund on its reply at all");
        };
        if let Err(wrong) = fees.check_reply_refund(payment, u128::from(refunded)) {
            panic!("an out-of-cycles outcall {wrong}");
        }
        assert!(u128::from(refunded) < fees.node_count as u128);

        // Running out of cycles does not forfeit the allowances. Each replica is
        // charged what it reported spending on the response it could not afford to
        // deliver, and the rest is credited back.
        let charge = settled_charge(&handlers, &baseline).await;
        let expected = fees.base_fee + spent;
        assert_eq!(charge.consumed.http_outcalls, expected);
    });
}

/// Where HTTP outcalls are free, an outcall succeeds whatever it attaches —
/// nothing at all, or a payment that comes back in full — and the caller's
/// balance is left untouched. Holds under both pricing versions.
///
/// The free subnet here is the system subnet.
fn test_free_subnet_charges_nothing(env: TestEnv) {
    let handlers = Handlers::on_system_subnet(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    block_on(async {
        for pricing_version in [PRICING_VERSION_LEGACY, PRICING_VERSION_PAY_AS_YOU_GO] {
            for payment in [0, HTTP_REQUEST_CYCLE_PAYMENT] {
                // The same request the paying tests make, transform included, so
                // that the only difference between the two is the cost schedule.
                let request = UnvalidatedCanisterHttpRequestArgs {
                    pricing_version: Some(pricing_version),
                    ..pay_as_you_go_args(
                        handlers.proxy_canister_id,
                        format!("https://[{webserver_ipv6}]/ascii/free"),
                    )
                };
                let fees = handlers.fees_for(request.clone());

                let before_consumed = proxy_consumed_cycles(&handlers).await;
                let before = proxy_cycle_balance(&handlers).await;

                let started = Instant::now();
                let (response, refunded_cycles) = submit_outcall(
                    &handlers,
                    RemoteHttpRequest {
                        request,
                        cycles: payment,
                    },
                )
                .await;
                let elapsed = started.elapsed();

                let context = format!(
                    "a free outcall paying {payment} cycles under pricing version \
                     {pricing_version}"
                );
                assert_matches!(
                    &response,
                    Ok(ok) if ok.status == 200 && ok.body == "free",
                    "{context} did not come back as a 200 carrying 'free': {response:?}"
                );
                // Nothing is charged, so the whole payment is refunded with the
                // response rather than any of it being kept or withheld as an
                // allowance.
                assert_eq!(
                    refunded_cycles,
                    RefundedCycles::Cycles(payment),
                    "{context} was not refunded in full"
                );
                let after = proxy_cycle_balance(&handlers).await;
                assert_eq!(after, before, "{context} moved the caller's balance");

                let consumed = proxy_consumed_cycles(&handlers)
                    .await
                    .since(&before_consumed);
                if pricing_version == PRICING_VERSION_PAY_AS_YOU_GO {
                    // Priced exactly as it would be on a subnet that charges: the
                    // consumption counters record the nominal fee whatever the cost
                    // schedule, and only the charge itself is waived.
                    let delivered = DeliveredResponse::transformed(b"free");
                    if let Err(wrong) = fees.check_consumption(&consumed, &delivered, elapsed) {
                        panic!("{context} {wrong}");
                    }
                } else {
                    // Legacy pricing on a system subnet is priced by the subnet's own
                    // cycles account manager, whose HTTP fees are all zero, so there
                    // is no nominal figure to record either.
                    assert_eq!(
                        consumed.http_outcalls, 0,
                        "{context} recorded {} cycles as consumed, when a system subnet \
                         prices legacy outcalls at nothing at all",
                        consumed.http_outcalls
                    );
                }
            }
        }
    });
}

/// Pricing function of canister http requests.
fn expected_cycle_cost(
    proxy_canister: CanisterId,
    request: UnvalidatedCanisterHttpRequestArgs,
    subnet_size: usize,
) -> u64 {
    let cm = CyclesAccountManagerBuilder::new().build();
    let response_size = request
        .max_response_bytes
        .unwrap_or(MAX_CANISTER_HTTP_RESPONSE_BYTES);

    let dummy_context = CanisterHttpRequestContext::generate_from_args(
        UNIX_EPOCH,
        &RequestBuilder::default()
            .receiver(CanisterId::from(1))
            .sender(proxy_canister)
            .build(),
        request.into(),
        &BTreeSet::from([PrincipalId::new_node_test_id(0).into()]),
        RegistryVersion::from(1),
        CanisterCyclesCostSchedule::Normal,
        &mut rand::thread_rng(),
        // Only the request size is read off this context, so the pricing model it
        // would be charged with does not matter.
        /* pay_as_you_go_enabled = */
        false,
    )
    .unwrap();
    let req_size = dummy_context.variable_parts_size();
    let cycle_fee = cm.http_request_fee(
        req_size,
        Some(NumBytes::from(response_size)),
        CyclesAccountManagerSubnetConfig::new(
            subnet_size,
            CanisterCyclesCostSchedule::Normal,
            DEFAULT_REFERENCE_SUBNET_SIZE,
        ),
    );
    cycle_fee.real().get().try_into().unwrap()
}
