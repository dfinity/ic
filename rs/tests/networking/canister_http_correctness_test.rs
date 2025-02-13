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
use candid::{decode_one, CandidType, Deserialize, Encode, Principal};
use canister_http::*;
use canister_test::{Canister, Runtime};
use ic_agent::{
    agent::{RejectCode, RejectResponse},
    Agent, AgentError,
};
use ic_base_types::{CanisterId, NumBytes};
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{
    HttpHeader, HttpMethod, TransformContext, TransformFunc,
};
use ic_system_test_driver::{
    canister_agent::HasCanisterAgentCapability,
    driver::{
        group::{SystemTestGroup, SystemTestSubGroup},
        test_env::TestEnv,
        test_env_api::HasTopologySnapshot,
    },
    systest,
    util::{block_on, get_app_subnet_and_node},
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::{
    canister_http::{CanisterHttpRequestContext, MAX_CANISTER_HTTP_REQUEST_BYTES},
    time::UNIX_EPOCH,
};
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse, UnvalidatedCanisterHttpRequestArgs};
use serde_json::Value;
use std::{collections::HashSet, convert::TryFrom};

const MAX_REQUEST_BYTES_LIMIT: usize = 2_000_000;
const MAX_CANISTER_HTTP_URL_SIZE: usize = 8192;
const HTTP_HEADERS_MAX_NUMBER: usize = 64;

struct Handlers<'a> {
    subnet_size: usize,
    runtime: Runtime,
    env: &'a TestEnv,
}

impl<'a> Handlers<'a> {
    fn new(env: &'a TestEnv) -> Handlers<'a> {
        let subnet_size = get_node_snapshots(env).count();

        let runtime = {
            let mut nodes = get_node_snapshots(env);
            let node = nodes.next().expect("there is no application node");
            get_runtime_from_node(&node)
        };

        Handlers {
            runtime,
            subnet_size,
            env,
        }
    }

    fn proxy_canister(&self) -> Canister<'_> {
        let principal_id = get_proxy_canister_id(self.env);
        let canister_id = CanisterId::unchecked_from_principal(principal_id);
        Canister::new(&self.runtime, canister_id)
    }

    async fn agent(&self) -> Agent {
        let topology_snapshot = self.env.topology_snapshot();
        let (_, app_node) = get_app_subnet_and_node(&topology_snapshot);

        app_node.build_canister_agent().await.agent
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_parallel(
            SystemTestSubGroup::new()
                .add_test(systest!(test_enforce_https))
                .add_test(systest!(test_transform_function_is_executed))
                .add_test(systest!(test_composite_transform_function_is_executed))
                .add_test(systest!(test_no_cycles_attached))
                .add_test(systest!(test_2mb_response_cycle_for_rejection_path))
                .add_test(systest!(test_4096_max_response_cycle_case_1))
                .add_test(systest!(test_4096_max_response_cycle_case_2))
                .add_test(systest!(test_max_response_limit_too_large))
                .add_test(systest!(
                    test_transform_that_bloats_response_above_2mb_limit
                ))
                .add_test(systest!(test_non_existing_transform_function))
                .add_test(systest!(test_post_request))
                .add_test(systest!(test_http_endpoint_response_is_too_large))
                .add_test(systest!(
                    test_http_endpoint_with_delayed_response_is_rejected
                ))
                .add_test(systest!(test_that_redirects_are_not_followed))
                .add_test(systest!(test_http_calls_to_ic_fails))
                .add_test(systest!(test_invalid_domain_name))
                .add_test(systest!(test_invalid_ip))
                .add_test(systest!(test_get_hello_world_call))
                .add_test(systest!(test_post_call))
                .add_test(systest!(test_head_call))
                .add_test(systest!(test_max_possible_request_size))
                .add_test(systest!(test_max_possible_request_size_exceeded))
                .add_test(systest!(test_non_ascii_url_is_rejected))
                .add_test(systest!(test_max_url_length))
                .add_test(systest!(test_max_url_length_exceeded))
                .add_test(systest!(
                    test_small_maximum_possible_response_size_only_headers
                ))
                .add_test(systest!(
                    test_small_maximum_possible_response_size_exceeded_only_headers
                ))
                .add_test(systest!(test_large_maximum_response_size))
                .add_test(systest!(test_maximum_possible_value_of_max_response_bytes))
                .add_test(systest!(
                    test_maximum_possible_value_of_max_response_bytes_exceeded
                ))
                .add_test(systest!(check_caller_id_on_transform_function))
                .add_test(systest!(
                    reference_transform_function_exposed_by_different_canister
                ))
                .add_test(systest!(test_max_number_of_request_headers))
                .add_test(systest!(test_max_number_of_request_headers_exceeded))
                .add_test(systest!(test_max_number_of_response_headers))
                .add_test(systest!(test_max_number_of_response_headers_exceeded)),
        )
        .execute_from_args()?;

    Ok(())
}

pub fn test_enforce_https(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("http://[{webserver_ipv6}]:20443"),
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
            },
            cycles: 500_000_000_000,
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

pub fn test_transform_function_is_executed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let transform_context = "transform_context".as_bytes().to_vec();

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
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
            },
            cycles: 500_000_000_000,
        },
    ));

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

pub fn test_non_existent_transform_function(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let transform_context = "transform_context".as_bytes().to_vec();

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
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
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterError,
            ..
        })
    );
}

pub fn test_composite_transform_function_is_executed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
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
            },
            cycles: 500_000_000_000,
        },
    ));

    let response = response.expect("Http call should succeed");

    assert_eq!(response.headers.len(), 2, "Headers: {:?}", response.headers);
    assert_eq!(response.headers[0].0, "hello");
    assert_eq!(response.headers[0].1, "bonjour");
    assert_eq!(response.headers[1].0, "caller");
    assert_eq!(response.headers[1].1, "aaaaa-aa");
}

pub fn test_no_cycles_attached(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("http://[{webserver_ipv6}]:20443"),
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
            },
            cycles: 0,
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

pub fn test_max_possible_request_size(env: TestEnv) {
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

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/request_size"),
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
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Ok(r) if r.status==200);
}

pub fn test_max_possible_request_size_exceeded(env: TestEnv) {
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

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/request_size"),
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
            },
            cycles: 500_000_000_000,
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

pub fn test_2mb_response_cycle_for_rejection_path(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]:20443"),
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
    };

    let response = block_on(async move {
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

pub fn test_4096_max_response_cycle_case_1(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]:20443"),
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
    };

    let response = block_on(async move {
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

pub fn test_4096_max_response_cycle_case_2(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]:20443"),
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
    };

    let response = block_on(async move {
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

pub fn test_max_response_limit_too_large(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
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
                max_response_bytes: Some(4 * 1024 * 1024),
            },
            cycles: 0,
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

pub fn test_transform_that_bloats_response_above_2mb_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
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
            },
            cycles: 500_000_000_000,
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

pub fn test_non_existing_transform_function(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
                headers: vec![],
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "idontexist".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterError,
            ..
        })
    )
}

pub fn test_post_request(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/post"),
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
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Ok(r) if r.body.contains("satoshi"));
}

pub fn test_http_endpoint_response_is_too_large(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/bytes/100000"),
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
                max_response_bytes: Some(8 * 1024),
            },
            cycles: 500_000_000_000,
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

pub fn test_http_endpoint_with_delayed_response_is_rejected(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/delay/40"),
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
            },
            cycles: 500_000_000_000,
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
pub fn test_that_redirects_are_not_followed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/redirect/10"),
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
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Ok(r) if r.status == 303);
}

/// The adapter should reject HTTP calls that are made to other IC replicas' HTTPS endpoints.
pub fn test_http_calls_to_ic_fails(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: format!("https://[{}]:9090", webserver_ipv6),
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
            },
            cycles: 500_000_000_000,
        },
    ));

    let expected_error_message = "Error(Connect, ConnectError(\"tcp connect error\", Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" }))";
    let err_response = response.clone().unwrap_err();

    assert_matches!(err_response.reject_code, RejectCode::SysTransient);

    assert!(
        err_response.reject_message.contains(expected_error_message),
        "Expected error message to contain, {}, got: {}",
        expected_error_message,
        err_response.reject_message
    );
}

// ---- BEGIN SPEC COMPLIANCE TESTS ----
fn test_invalid_domain_name(env: TestEnv) {
    let handlers = Handlers::new(&env);

    let response = block_on(submit_outcall(
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
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysTransient,
            ..
        })
    );
}

fn test_invalid_ip(env: TestEnv) {
    let handlers = Handlers::new(&env);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url: "https://240.0.0.0".to_string(),
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
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysTransient,
            ..
        })
    );
}

/// Test that the response body returned is the same as the requested path.
fn test_get_hello_world_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let expected_body = "hello_world";

    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", expected_body
    );

    let max_response_bytes = 666;

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: Some(max_response_bytes),
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if body == expected_body);
    assert_http_response(&response);
}

fn test_post_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let expected_body = "POST";

    let url = format!("https://[{}]:20443/{}", webserver_ipv6, "anything");
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
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request succeeds.");

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
        "https://[{}]:20443/{}/{}",
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
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request succeeds.");

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

fn test_small_maximum_possible_response_size_only_headers(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let n = 0;
    let url = format!("https://[{}]:20443/{}/{}", webserver_ipv6, "equal_bytes", n);

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 11
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }

    let header_size = 142;
    let max_response_bytes = Some(header_size + n);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes,
            },
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
}

fn test_small_maximum_possible_response_size_exceeded_only_headers(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let n = 0;
    let url = format!("https://[{}]:20443/{}/{}", webserver_ipv6, "equal_bytes", n);

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 0
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }

    let header_size = 142;
    let max_response_bytes = Some(header_size + n - 1);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes,
            },
            cycles: 500_000_000_000,
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

fn test_non_ascii_url_is_rejected(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let expected_body = "안녕하세요";

    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", expected_body
    );

    let max_response_bytes = 666;

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: Some(max_response_bytes),
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
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

/// Test that the response body returned is the same as the requested path.
fn test_max_url_length(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let base_url = format!("https://[{}]:20443/{}/", webserver_ipv6, "ascii");
    let remaining_space = MAX_CANISTER_HTTP_URL_SIZE - base_url.len();
    let expected_body = "x".repeat(remaining_space);

    let url = format!("{}{}", base_url, expected_body);
    assert_eq!(url.len(), MAX_CANISTER_HTTP_URL_SIZE);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if *body == expected_body);
    assert_http_response(&response);
}

/// Test that the response body returned is the same as the requested path.
fn test_max_url_length_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let base_url = format!("https://[{}]:20443/{}/", webserver_ipv6, "ascii");
    let remaining_space = MAX_CANISTER_HTTP_URL_SIZE - base_url.len();
    // Add one more character to exceed the limit.
    let expected_body = "x".repeat(remaining_space + 1);

    let url = format!("{}{}", base_url, expected_body);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
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

/// Test that the response body returned is the same as the requested path.
fn test_large_maximum_response_size(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let base_url = format!("https://[{}]:20443/{}/", webserver_ipv6, "ascii");
    let remaining_space = MAX_CANISTER_HTTP_URL_SIZE - base_url.len();
    // Add one more character to exceed the limit.
    let expected_body = "x".repeat(remaining_space + 1);

    let url = format!("{}{}", base_url, expected_body);

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: None,
        max_response_bytes: None,
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
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

fn test_maximum_possible_value_of_max_response_bytes(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", "hello_world"
    );

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 11
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }
    let header_size = 143;
    let max_response_bytes = Some(header_size + "hello_world".len() as u64);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes,
            },
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
}

fn test_maximum_possible_value_of_max_response_bytes_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", "hello_world"
    );

    //   { Response headers
    //       date: Jan 1 1970 00:00:00 GMT
    //       content-type: application/octet-stream
    //       content-length: 11
    //       access-control-allow-origin: *
    //       access-control-allow-credentials: true
    //   }

    let header_size = 143;
    let max_response_bytes = Some(header_size + "hello_world".len() as u64 - 1);

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes,
            },
            cycles: 500_000_000_000,
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

fn reference_transform_function_exposed_by_different_canister(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", "hello_world"
    );

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
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: proxy_canister_id_2.into(),
                method: "test_transform".to_string(),
            }),
            context: vec![],
        }),
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
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

    // HTTP server returns 5 headers in addition to the requested headers.
    let response_headers = HTTP_HEADERS_MAX_NUMBER - 5;
    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "many_response_headers", response_headers
    );

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request is successful.");

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

    // HTTP server returns 5 headers in addition to the requested headers.
    let response_headers = HTTP_HEADERS_MAX_NUMBER - 5 + 1;
    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "many_response_headers", response_headers
    );

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: UnvalidatedCanisterHttpRequestArgs {
                url,
                headers: vec![],
                method: HttpMethod::GET,
                body: None,
                transform: None,
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
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

fn test_max_number_of_request_headers(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let headers = (0..HTTP_HEADERS_MAX_NUMBER)
        .map(|i| HttpHeader {
            name: format!("name{}", i),
            value: format!("value{}", i),
        })
        .collect();

    let request = RemoteHttpRequest {
        request: UnvalidatedCanisterHttpRequestArgs {
            url: format!("https://[{webserver_ipv6}]:20443/anything"),
            headers,
            method: HttpMethod::POST,
            body: None,
            transform: None,
            max_response_bytes: None,
        },
        cycles: 500_000_000_000,
    };
    let response =
        block_on(submit_outcall(&handlers, request.clone())).expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
    assert_http_json_response(&request.request, &response);
}

fn test_max_number_of_request_headers_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let url = format!("https://[{webserver_ipv6}]:20443/anything");

    let headers = (0..HTTP_HEADERS_MAX_NUMBER + 1)
        .map(|i| HttpHeader {
            name: format!("name{}", i),
            value: format!("value{}", i),
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

    let response = block_on(submit_outcall(
        &handlers,
        TestRemoteHttpRequest {
            request: TestRequest {
                url,
                headers,
                method: HttpMethod::POST,
            },
            cycles: 500_000_000_000,
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

fn check_caller_id_on_transform_function(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", "hello_world"
    );

    let request = UnvalidatedCanisterHttpRequestArgs {
        url,
        headers: vec![],
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        max_response_bytes: None,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "test_transform".to_string(),
            }),
            context: vec![],
        }),
    };

    let response = block_on(submit_outcall(
        &handlers,
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request is successful.");

    // Check caller id injected into header.
    let caller_id = &response
        .headers
        .iter()
        .find(|(name, _)| name.to_lowercase() == "caller")
        .expect("caller header is present after transformation.")
        .1;

    assert_eq!(caller_id, "aaaaa-aa");
}

// ---- END SPEC COMPLIANCE TESTS -------

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
        "1. HTTP bin server did not receive all headers specified in the outcall. Specified headers: {:?}, received headers: {:?}",
        request_headers,
        http_bin_server_received_headers
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

    assert!(http_bin_server_only_received_headers_specified_by_outcall,
        "2. Http bin server received headers that were not specified in the outcall. Specified headers: {:?}, received headers: {:?}",
        request_headers,
        http_bin_server_received_headers);

    let request_method = match request.method {
        HttpMethod::GET => "GET",
        HttpMethod::POST => "POST",
        HttpMethod::HEAD => "HEAD",
    };

    assert_eq!(
        request_method,
        response_body["method"].as_str().unwrap(),
        "3. Mismatch in HTTP method."
    );

    let server_received_body = response_body["data"].as_str().unwrap();
    let outcall_sent_body = String::from_utf8(request.body.clone().unwrap_or_default()).unwrap();

    assert_eq!(
        server_received_body, &outcall_sent_body,
        "4. HTTP bin server received body does not match the outcall sent body."
    );
}
type ProxyCanisterResponse = Result<RemoteHttpResponse, (RejectionCode, String)>;
type OutcallsResponse = Result<RemoteHttpResponse, RejectResponse>;

async fn submit_outcall<Request>(handlers: &Handlers<'_>, request: Request) -> OutcallsResponse
where
    Request: Clone + CandidType,
{
    let args = Encode!(&request).unwrap();
    let agent = handlers.agent().await;

    let principal_id: PrincipalId = handlers.proxy_canister().effective_canister_id();
    let principal: Principal = principal_id.into();

    agent
        .update(&principal, "send_request")
        .with_arg(args)
        .call_and_wait()
        .await
        .map_err(|agent_error| match agent_error {
            AgentError::CertifiedReject(response) | AgentError::UncertifiedReject(response) => {
                response
            }
            _ => panic!("Unexpected error: {:?}", agent_error),
        })
        .and_then(|response| {
            decode_one::<ProxyCanisterResponse>(&response)
                .unwrap()
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
                })
        })
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
        .unwrap_or(MAX_CANISTER_HTTP_REQUEST_BYTES);

    let dummy_context = CanisterHttpRequestContext::try_from((
        UNIX_EPOCH,
        &RequestBuilder::default()
            .receiver(CanisterId::from(1))
            .sender(proxy_canister)
            .build(),
        request.into(),
    ))
    .unwrap();
    let req_size = dummy_context.variable_parts_size();
    let cycle_fee = cm.http_request_fee(req_size, Some(NumBytes::from(response_size)), subnet_size);
    cycle_fee.get().try_into().unwrap()
}
