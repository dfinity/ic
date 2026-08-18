/* tag::catalog[]
Title:: Flexible HTTP outcalls.

Goal:: Exhaustively exercise the `flexible_http_request` management canister
endpoint, both where HTTP outcalls are free and where they are actually paid for
under pay-as-you-go.

Every scenario runs against both application subnets: what a caller observes must
not depend on whether it was charged. The scenarios that are *about* being charged
run only against the paying subnet.

Runbook::
0. Instantiate a universal VM with a webserver (httpbin).
1. Instantiate an IC with the HTTP feature enabled on the 1-node system subnet
   (free for outcalls despite a normal cost schedule) and on two 4-node
   application subnets, one on a free and one on a normal cost schedule.
2. Install NNS canisters.
3. Install a proxy canister on each of the three subnets.
4. Make flexible HTTP outcalls through the proxy canisters covering:
   - success across replication parameters and HTTP methods,
   - synchronous validation rejections,
   - runtime errors (too many rejects, responses too large),
   - adapter-level per-node failures,
   - an outcall on the system subnet,
   - pay-as-you-go charging, refunding and running out of cycles,
   - fault tolerance: an outcall still succeeds with a subnet node killed.

Success::
1. Each scenario returns the expected `FlexibleHttpRequestResult` (or rejection).

end::catalog[] */
#![allow(deprecated)]

use anyhow::{Result, bail};
use candid::{Decode, Principal};
use canister_http::*;
use canister_test::{Canister, Runtime};
use dfn_candid::candid_one;
use ic_management_canister_types_private::{
    BoundedHttpHeaders, CanisterHttpResponsePayload, FlexibleCanisterHttpRequestArgs,
    FlexibleHttpGlobalError, FlexibleHttpRequestErr, FlexibleHttpRequestResult, HttpHeader,
    HttpMethod, ReplicationCounts, TransformContext, TransformFunc,
};
use ic_system_test_driver::driver::group::{SystemTestGroup, SystemTestSubGroup};
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{HasPublicApiUrl, HasVm, READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types_cycles::CanisterCyclesCostSchedule;
use proxy_canister::{FlexibleRemoteHttpRequest, RejectionCode};
use slog::info;

/// The cycles attached to each flexible outcall.
///
/// Sized for the worst case in this suite — a 2 MiB response on a 4-node
/// committee, which costs on the order of 10^10 cycles under pay-as-you-go — with
/// ample headroom, while staying small enough that every test in the parallel
/// suite can have one in flight at once against the proxy canister's balance. On
/// a free subnet nothing is charged and the whole payment comes back.
const CYCLES: u64 = 500_000_000_000;

/// The application subnet has 4 nodes (see `setup`). With the default
/// replication (`replication: None`) the committee is all `n` nodes,
/// `max_responses = n` and `min_responses = floor(2n/3) + 1`.
const SUBNET_NODES: u32 = 4;
const DEFAULT_MIN_RESPONSES: usize = 3; // floor(2*4/3) + 1
const DEFAULT_MAX_RESPONSES: usize = SUBNET_NODES as usize;

/// The minimum number of per-node reject details in a `TooManyRejects` error
/// under default replication: the error fires only once more nodes reject than
/// the slack (`total_requests - min_responses`) allows, i.e. at least this many.
const MIN_REJECT_DETAILS: usize = SUBNET_NODES as usize - DEFAULT_MIN_RESPONSES + 1;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup_with_free_and_paying_subnets)
        .add_parallel(
            SystemTestSubGroup::new()
                // Success across replication parameters and HTTP methods.
                .add_test(systest!(test_default_replication))
                .add_test(systest!(test_all_nodes))
                .add_test(systest!(test_partial_responses))
                .add_test(systest!(test_intermediate_range))
                .add_test(systest!(test_post_with_body))
                .add_test(systest!(test_head_method))
                .add_test(systest!(test_put_with_deterministic_replication))
                .add_test(systest!(test_delete_with_deterministic_replication))
                .add_test(systest!(test_patch_with_deterministic_replication))
                .add_test(systest!(test_redirects_are_not_followed))
                .add_test(systest!(test_redirect_zero_no_content))
                .add_test(systest!(test_nondeterministic_responses))
                .add_test(systest!(test_single_request_nondeterministic))
                .add_test(systest!(test_min_responses_fit_max_would_exceed))
                .add_test(systest!(test_single_large_response_ok))
                .add_test(systest!(test_fire_and_forget))
                // System subnet (free for outcalls despite a normal cost schedule).
                .add_test(systest!(test_system_subnet_outcall))
                // Transform behavior.
                .add_test(systest!(test_transform_appends_context))
                .add_test(systest!(test_transform_sets_status_and_headers))
                .add_test(systest!(test_deterministic_transform_normalizes))
                // Synchronous validation rejections.
                .add_test(systest!(test_reject_total_requests_zero))
                .add_test(systest!(test_reject_total_requests_exceed_nodes))
                .add_test(systest!(test_reject_min_exceeds_max))
                .add_test(systest!(test_reject_max_exceeds_total))
                .add_test(systest!(test_reject_put_requires_deterministic))
                .add_test(systest!(test_reject_delete_non_deterministic))
                .add_test(systest!(test_reject_url_too_long))
                .add_test(systest!(test_reject_invalid_transform_principal))
                .add_test(systest!(test_reject_header_name_too_long))
                .add_test(systest!(test_reject_header_value_too_long))
                .add_test(systest!(test_reject_request_too_large))
                // Runtime errors and adapter-level per-node failures.
                .add_test(systest!(test_too_many_rejects_connection_refused))
                .add_test(systest!(test_too_many_rejects_invalid_domain))
                .add_test(systest!(test_too_many_rejects_non_https))
                .add_test(systest!(test_too_many_rejects_response_over_node_limit))
                .add_test(systest!(test_too_many_rejects_transform_over_node_limit))
                .add_test(systest!(test_too_many_rejects_composite_transform))
                .add_test(systest!(test_responses_too_large))
                // Caller-supplied per-node response size cap.
                .add_test(systest!(test_custom_max_response_bytes_exceeded))
                .add_test(systest!(test_custom_max_response_bytes_within_limits)),
        )
        // Only meaningful where outcalls are paid for, so these run against the
        // paying subnet alone. `test_charged_and_refunded` measures the proxy
        // canister's balance across a single outcall, which any concurrent outcall
        // from the same canister would perturb, so they run sequentially.
        .add_test(systest!(test_charged_and_refunded))
        .add_test(systest!(test_out_of_cycles))
        // Fault tolerance kills a node, so it has to come last.
        .add_test(systest!(test_fault_tolerance))
        .execute_from_args()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns a runtime for a node of the application subnet on `schedule`.
fn app_runtime_on(env: &TestEnv, schedule: CanisterCyclesCostSchedule) -> Runtime {
    let node = get_app_subnet_node_snapshots_with_schedule(env, schedule)
        .next()
        .expect("there is no application node");
    get_runtime_from_node(&node)
}

/// The principal of the proxy canister on the application subnet running on
/// `schedule`.
fn proxy_principal_on(env: &TestEnv, schedule: CanisterCyclesCostSchedule) -> PrincipalId {
    get_proxy_canister_id_for(env, schedule)
}

/// Returns the proxy canister on the application subnet running on `schedule`.
fn proxy_canister_on<'a>(
    env: &TestEnv,
    runtime: &'a Runtime,
    schedule: CanisterCyclesCostSchedule,
) -> Canister<'a> {
    let principal_id = proxy_principal_on(env, schedule);
    Canister::new(runtime, CanisterId::unchecked_from_principal(principal_id))
}

/// Points a transform that names the default proxy canister at the proxy the
/// scenario is actually running against.
///
/// A transform has to be a method on the calling canister, and each application
/// subnet has its own proxy. Scenarios name their own canister with
/// [`proxy_principal`], so exactly those are retargeted; one that names a different
/// principal on purpose — see `test_reject_invalid_transform_principal` — is left
/// alone, which is what keeps it a negative test.
fn retarget_transform(
    args: &mut FlexibleCanisterHttpRequestArgs,
    env: &TestEnv,
    proxy: PrincipalId,
) {
    if let Some(transform) = args.transform.as_mut()
        && transform.function.0.principal == proxy_principal(env)
    {
        transform.function.0.principal = proxy.0;
    }
}

/// Returns a runtime for the (single) system-subnet node.
fn system_runtime(env: &TestEnv) -> Runtime {
    let node = get_system_subnet_node_snapshots(env)
        .next()
        .expect("there is no system-subnet node");
    get_runtime_from_node(&node)
}

/// Returns the proxy canister installed on the system subnet during setup.
fn system_proxy_canister<'a>(env: &TestEnv, runtime: &'a Runtime) -> Canister<'a> {
    let principal_id = get_system_proxy_canister_id(env);
    Canister::new(runtime, CanisterId::unchecked_from_principal(principal_id))
}

/// The principal of the proxy canister (the sender of the outcalls), used as the
/// valid transform principal.
fn proxy_principal(env: &TestEnv) -> Principal {
    proxy_principal_on(env, CanisterCyclesCostSchedule::Free).0
}

fn webserver_base(env: &TestEnv) -> String {
    format!("https://[{}]", get_universal_vm_address(env))
}

/// Base flexible request arguments: a `GET` with no headers, body, transform, or
/// explicit replication.
fn get_args(url: String) -> FlexibleCanisterHttpRequestArgs {
    FlexibleCanisterHttpRequestArgs {
        url,
        max_response_bytes: None,
        headers: BoundedHttpHeaders::new(vec![]),
        body: None,
        method: HttpMethod::GET,
        transform: None,
        replication: None,
    }
}

/// Sends a flexible outcall through the proxy canister. The outer `Result` is
/// `Err` on a (retryable) transport failure of the proxy call itself; the inner
/// `Result` is the outcall outcome — the decoded [`FlexibleHttpRequestResult`]
/// on a handled outcall, or the synchronous rejection on a validation failure.
async fn send_flexible(
    proxy: &Canister<'_>,
    args: FlexibleCanisterHttpRequestArgs,
    cycles: u64,
) -> Result<Result<FlexibleHttpRequestResult, (RejectionCode, String)>> {
    // A failure here is a transport-level error talking to the proxy canister,
    // not an outcall outcome; return it so the retry loop can absorb blips.
    let res = proxy
        .update_(
            "send_flexible_request",
            candid_one::<Result<Vec<u8>, (RejectionCode, String)>, FlexibleRemoteHttpRequest>,
            FlexibleRemoteHttpRequest {
                request: args,
                cycles,
            },
        )
        .await
        .map_err(|err| anyhow::anyhow!("update call to proxy canister failed: {err}"))?;

    Ok(res.map(|bytes| {
        Decode!(&bytes, FlexibleHttpRequestResult)
            .expect("Failed to decode FlexibleHttpRequestResult")
    }))
}

/// Runs `assert_result` against the outcome of the flexible outcall built by
/// `make_args`, retrying (to absorb transient startup/network flakiness) until
/// the expected outcome is observed or the retry budget is exhausted.
fn run_flexible_test<M, A>(env: TestEnv, description: &str, make_args: M, assert_result: A)
where
    M: Fn(&TestEnv) -> FlexibleCanisterHttpRequestArgs,
    A: Fn(Result<FlexibleHttpRequestResult, (RejectionCode, String)>) -> Result<()>,
{
    run_flexible_test_with_cycles(env, description, CYCLES, make_args, assert_result)
}

/// Like [`run_flexible_test`], but attaches `cycles` to the outcall instead of
/// the default payment — for scenarios that are about the payment itself.
fn run_flexible_test_with_cycles<M, A>(
    env: TestEnv,
    description: &str,
    cycles: u64,
    make_args: M,
    assert_result: A,
) where
    M: Fn(&TestEnv) -> FlexibleCanisterHttpRequestArgs,
    A: Fn(Result<FlexibleHttpRequestResult, (RejectionCode, String)>) -> Result<()>,
{
    // Run against both application subnets. The outcome a caller sees must not
    // depend on whether it was charged, so a scenario that only holds on one of
    // them is a bug either way.
    for schedule in [
        CanisterCyclesCostSchedule::Free,
        CanisterCyclesCostSchedule::Normal,
    ] {
        run_flexible_test_on(
            &env,
            schedule,
            description,
            cycles,
            &make_args,
            &assert_result,
        );
    }
}

/// Like [`run_flexible_test_with_cycles`], but only against the application subnet
/// on the given cost schedule — for the scenarios whose outcome does depend on
/// whether the outcall is paid for.
fn run_flexible_test_on<M, A>(
    env: &TestEnv,
    schedule: CanisterCyclesCostSchedule,
    description: &str,
    cycles: u64,
    make_args: &M,
    assert_result: &A,
) where
    M: Fn(&TestEnv) -> FlexibleCanisterHttpRequestArgs,
    A: Fn(Result<FlexibleHttpRequestResult, (RejectionCode, String)>) -> Result<()>,
{
    let logger = env.logger();
    let runtime = app_runtime_on(env, schedule);
    let proxy = proxy_canister_on(env, &runtime, schedule);
    let proxy_id = proxy_principal_on(env, schedule);
    let description = format!("{description} (on a {schedule:?} cost schedule)");

    block_on(async {
        ic_system_test_driver::retry_with_msg_async!(
            description.clone(),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let mut args = make_args(env);
                retarget_transform(&mut args, env, proxy_id);
                let result = send_flexible(&proxy, args, cycles).await?;
                assert_result(result)
            }
        )
        .await
        .unwrap_or_else(|err| panic!("'{description}' did not reach the expected outcome: {err}"));
    });
}

/// Returns the value of the (case-insensitive) response header `name`, if present.
fn header_value<'a>(payload: &'a CanisterHttpResponsePayload, name: &str) -> Option<&'a str> {
    payload
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

/// Asserts the result is `Ok` with a payload count in `[min, max]` and returns
/// the payloads for further inspection.
fn expect_ok(
    result: Result<FlexibleHttpRequestResult, (RejectionCode, String)>,
    min: usize,
    max: usize,
) -> Result<Vec<CanisterHttpResponsePayload>> {
    match result {
        Ok(FlexibleHttpRequestResult::Ok(payloads)) => {
            if payloads.len() < min || payloads.len() > max {
                bail!(
                    "expected between {min} and {max} response payloads, got {}",
                    payloads.len()
                );
            }
            Ok(payloads)
        }
        other => bail!("expected Ok response payloads, got: {other:?}"),
    }
}

/// Asserts every payload has the given HTTP status.
fn expect_all_status(payloads: &[CanisterHttpResponsePayload], status: u128) -> Result<()> {
    for payload in payloads {
        if payload.status != status {
            bail!(
                "expected status {status} for every payload, got {}",
                payload.status
            );
        }
    }
    Ok(())
}

/// Asserts every payload body equals `expected`.
fn expect_all_bodies(payloads: &[CanisterHttpResponsePayload], expected: &[u8]) -> Result<()> {
    for payload in payloads {
        if payload.body.as_slice() != expected {
            bail!(
                "expected body {:?}, got {:?}",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(&payload.body)
            );
        }
    }
    Ok(())
}

/// Asserts every payload body (interpreted as UTF-8) contains `needle`.
fn expect_all_bodies_contain(payloads: &[CanisterHttpResponsePayload], needle: &str) -> Result<()> {
    for payload in payloads {
        let body = String::from_utf8_lossy(&payload.body);
        if !body.contains(needle) {
            bail!("expected body to contain '{needle}', got {body:?}");
        }
    }
    Ok(())
}

/// Asserts every payload has no response headers (e.g. after a header-stripping
/// transform).
fn expect_all_headers_empty(payloads: &[CanisterHttpResponsePayload]) -> Result<()> {
    for payload in payloads {
        if !payload.headers.is_empty() {
            bail!("expected no headers, got {:?}", payload.headers);
        }
    }
    Ok(())
}

/// Asserts the result is a synchronous rejection with reject code
/// `CanisterReject` (argument validation fails with `CanisterRejectedMessage`,
/// a 4xx error code) and a message containing `expected_substring`.
fn expect_rejection(
    result: Result<FlexibleHttpRequestResult, (RejectionCode, String)>,
    expected_substring: &str,
) -> Result<()> {
    match result {
        Err((code, message)) => {
            if !matches!(code, RejectionCode::CanisterReject) {
                bail!("expected reject code CanisterReject, got {code:?} (message: '{message}')");
            }
            if !message.contains(expected_substring) {
                bail!("rejection message '{message}' does not contain '{expected_substring}'");
            }
            Ok(())
        }
        other => bail!("expected a synchronous rejection, got: {other:?}"),
    }
}

/// Asserts the result is a runtime `FlexibleHttpRequestResult::Err` with the
/// given global error and a message containing `expected_substring`, and returns
/// the error for further inspection.
fn expect_global_error(
    result: Result<FlexibleHttpRequestResult, (RejectionCode, String)>,
    expected: &FlexibleHttpGlobalError,
    expected_substring: &str,
) -> Result<FlexibleHttpRequestErr> {
    match result {
        Ok(FlexibleHttpRequestResult::Err(err)) => {
            if err.global_error.as_ref() != Some(expected) {
                bail!(
                    "expected global error {expected:?}, got {:?} (message: '{}')",
                    err.global_error,
                    err.message
                );
            }
            if !err.message.contains(expected_substring) {
                bail!(
                    "error message '{}' does not contain '{expected_substring}'",
                    err.message
                );
            }
            Ok(err)
        }
        other => bail!("expected a FlexibleHttpRequestResult::Err, got: {other:?}"),
    }
}

/// Asserts a runtime error carries at least `min_details` per-node details, each
/// with the given `code` and a message containing `message_substring`.
fn expect_all_node_errors(
    err: &FlexibleHttpRequestErr,
    min_details: usize,
    code: &str,
    message_substring: &str,
) -> Result<()> {
    if err.node_details.len() < min_details {
        bail!(
            "expected at least {min_details} per-node error details, got {}",
            err.node_details.len()
        );
    }
    for detail in &err.node_details {
        match &detail.error {
            Some(node_error)
                if node_error.code == code && node_error.message.contains(message_substring) => {}
            other => bail!(
                "node error {other:?} does not match code '{code}' / message '{message_substring}'"
            ),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Success: replication parameters and HTTP methods
// ---------------------------------------------------------------------------

/// Default replication (`None`) returns between `min_responses` and
/// `max_responses` identical payloads for a deterministic endpoint.
fn test_default_replication(env: TestEnv) {
    let logger = env.logger();
    run_flexible_test(
        env,
        "default replication returns min..=max identical payloads",
        |env| get_args(format!("{}/ascii/hello_world", webserver_base(env))),
        move |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            expect_all_bodies(&payloads, b"hello_world")?;
            info!(
                logger,
                "default replication returned {} payloads",
                payloads.len()
            );
            Ok(())
        },
    );
}

/// Requiring all nodes (`min == max == total == n`) returns exactly `n` payloads.
fn test_all_nodes(env: TestEnv) {
    run_flexible_test(
        env,
        "all-nodes replication returns exactly n payloads",
        |env| {
            let mut args = get_args(format!("{}/ascii/all", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: SUBNET_NODES,
                max_responses: SUBNET_NODES,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, SUBNET_NODES as usize, SUBNET_NODES as usize)?;
            expect_all_status(&payloads, 200)?;
            expect_all_bodies(&payloads, b"all")?;
            Ok(())
        },
    );
}

/// A partial range (`min < max < total`) returns between `min` and `max` payloads.
fn test_partial_responses(env: TestEnv) {
    run_flexible_test(
        env,
        "partial replication returns min..=max payloads",
        |env| {
            let mut args = get_args(format!("{}/ascii/partial", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 4,
                min_responses: 2,
                max_responses: 3,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, 3)?;
            expect_all_status(&payloads, 200)?;
            expect_all_bodies(&payloads, b"partial")?;
            Ok(())
        },
    );
}

/// A `POST` with a body succeeds.
fn test_post_with_body(env: TestEnv) {
    run_flexible_test(
        env,
        "POST with a body succeeds",
        |env| {
            let mut args = get_args(format!("{}/post", webserver_base(env)));
            args.method = HttpMethod::POST;
            args.body = Some(b"flexible-body".to_vec());
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            // The endpoint echoes the request method and body as JSON.
            expect_all_bodies_contain(&payloads, "\"method\":\"POST\"")?;
            expect_all_bodies_contain(&payloads, "flexible-body")?;
            Ok(())
        },
    );
}

/// The transform function is applied to each response (here it appends the
/// context to the body and strips headers).
fn test_transform_appends_context(env: TestEnv) {
    run_flexible_test(
        env,
        "transform is applied to each response",
        |env| {
            let mut args = get_args(format!("{}/ascii/base", webserver_base(env)));
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform_with_context".to_string(),
                }),
                context: b"-ctx".to_vec(),
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            // The transform appends the context to the body and strips headers.
            expect_all_bodies(&payloads, b"base-ctx")?;
            expect_all_headers_empty(&payloads)?;
            Ok(())
        },
    );
}

/// `PUT` (like `DELETE`/`PATCH`) is only allowed with deterministic replication
/// (`min == max == total`); this exercises the allowed case.
fn test_put_with_deterministic_replication(env: TestEnv) {
    run_flexible_test(
        env,
        "PUT with deterministic replication succeeds",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::PUT;
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: SUBNET_NODES,
                max_responses: SUBNET_NODES,
            });
            // Strip the echoed request headers.
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, SUBNET_NODES as usize, SUBNET_NODES as usize)?;
            expect_all_status(&payloads, 200)?;
            expect_all_bodies_contain(&payloads, "\"method\":\"PUT\"")?;
            Ok(())
        },
    );
}

/// The adapter does not follow redirects: a redirecting endpoint yields a 303.
fn test_redirects_are_not_followed(env: TestEnv) {
    run_flexible_test(
        env,
        "redirects are not followed (status 303)",
        |env| get_args(format!("{}/redirect/10", webserver_base(env))),
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 303)?;
            // The redirect target is returned in the location header, not followed.
            for payload in &payloads {
                match header_value(payload, "location") {
                    Some(location) if location.contains("relative-redirect") => {}
                    other => bail!("expected a redirect location header, got {other:?}"),
                }
            }
            Ok(())
        },
    );
}

/// Flexible outcalls can aggregate differing responses: a non-deterministic
/// endpoint returns several (possibly different) payloads without diverging.
fn test_nondeterministic_responses(env: TestEnv) {
    run_flexible_test(
        env,
        "non-deterministic responses are aggregated",
        |env| {
            let mut args = get_args(format!("{}/random", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: 2,
                max_responses: SUBNET_NODES,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, SUBNET_NODES as usize)?;
            expect_all_status(&payloads, 200)?;
            // Each body is a numeric string.
            for payload in &payloads {
                if payload.body.is_empty() || !payload.body.iter().all(|b| b.is_ascii_digit()) {
                    bail!(
                        "expected a numeric random body, got {:?}",
                        String::from_utf8_lossy(&payload.body)
                    );
                }
            }
            // Flexible outcalls keep the differing per-node responses rather than
            // reconciling them into a single agreed value: collect the bodies
            // into a set and confirm they are all distinct.
            let unique_bodies: std::collections::HashSet<_> =
                payloads.iter().map(|p| &p.body).collect();
            if unique_bodies.len() != payloads.len() {
                bail!(
                    "expected all {} random bodies to be distinct, got {} distinct",
                    payloads.len(),
                    unique_bodies.len()
                );
            }
            Ok(())
        },
    );
}

/// A single-node request to a non-deterministic endpoint succeeds: with one
/// response there is nothing to reconcile. (The flexible replacement for the
/// legacy non-replicated mode.)
fn test_single_request_nondeterministic(env: TestEnv) {
    run_flexible_test(
        env,
        "a single-node request to a non-deterministic endpoint succeeds",
        |env| {
            let mut args = get_args(format!("{}/random", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 1,
                min_responses: 1,
                max_responses: 1,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 1, 1)?;
            expect_all_status(&payloads, 200)?;
            if payloads[0].body.is_empty() || !payloads[0].body.iter().all(|b| b.is_ascii_digit()) {
                bail!(
                    "expected a numeric random body, got {:?}",
                    String::from_utf8_lossy(&payloads[0].body)
                );
            }
            Ok(())
        },
    );
}

/// The response count is capped by the block payload limit: `min_responses`
/// responses fit within the ~2 MiB `MAX_CANISTER_HTTP_PAYLOAD_SIZE`, but
/// `max_responses` of them would exceed it, so the outcall succeeds with exactly
/// `min_responses` responses.
fn test_min_responses_fit_max_would_exceed(env: TestEnv) {
    // Each node returns a 1 MB body: 2 bodies (2.0 MB) fit within the ~2 MiB
    // (2_097_152 B) payload limit, but 3 (3.0 MB) exceed it.
    const BODY_SIZE: usize = 1_000_000;
    run_flexible_test(
        env,
        "response count is capped at min_responses by the payload limit",
        |env| {
            let mut args = get_args(format!("{}/bytes/{BODY_SIZE}", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: 2,
                max_responses: SUBNET_NODES,
            });
            args
        },
        |result| {
            // Exactly min_responses (2) come back, even though max_responses (4)
            // was requested.
            let payloads = expect_ok(result, 2, 2)?;
            expect_all_status(&payloads, 200)?;
            for payload in &payloads {
                if payload.body.len() != BODY_SIZE {
                    bail!(
                        "expected a {BODY_SIZE}-byte body, got {} bytes",
                        payload.body.len()
                    );
                }
            }
            Ok(())
        },
    );
}

/// A "fire-and-forget" outcall (`min_responses = max_responses = 0`) dispatches
/// the request but requires no responses, so it succeeds immediately with an
/// empty result.
fn test_fire_and_forget(env: TestEnv) {
    run_flexible_test(
        env,
        "min = max = 0 fire-and-forget returns an empty result",
        |env| {
            let mut args = get_args(format!("{}/ascii/ignored", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 1,
                min_responses: 0,
                max_responses: 0,
            });
            args
        },
        |result| {
            // No responses are collected or returned.
            expect_ok(result, 0, 0)?;
            Ok(())
        },
    );
}

/// A single response just under the 2 MB per-node limit succeeds. This is the
/// positive counterpart to `test_too_many_rejects_response_over_node_limit`,
/// where a response over the limit is rejected.
fn test_single_large_response_ok(env: TestEnv) {
    const BODY_SIZE: usize = 1_900_000;
    run_flexible_test(
        env,
        "a single response just under the 2 MB per-node limit succeeds",
        |env| {
            let mut args = get_args(format!("{}/bytes/{BODY_SIZE}", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 1,
                min_responses: 1,
                max_responses: 1,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 1, 1)?;
            expect_all_status(&payloads, 200)?;
            if payloads[0].body.len() != BODY_SIZE {
                bail!(
                    "expected a {BODY_SIZE}-byte body, got {} bytes",
                    payloads[0].body.len()
                );
            }
            Ok(())
        },
    );
}

/// An intermediate range (`min < max == total`) returns between `min` and `max`
/// payloads.
fn test_intermediate_range(env: TestEnv) {
    run_flexible_test(
        env,
        "intermediate replication returns min..=max payloads",
        |env| {
            let mut args = get_args(format!("{}/ascii/range", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 4,
                min_responses: 2,
                max_responses: 4,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, 4)?;
            expect_all_status(&payloads, 200)?;
            expect_all_bodies(&payloads, b"range")?;
            Ok(())
        },
    );
}

/// A `HEAD` request succeeds. `HEAD` is not restricted to deterministic
/// replication (unlike `PUT`/`DELETE`/`PATCH`).
fn test_head_method(env: TestEnv) {
    run_flexible_test(
        env,
        "HEAD request succeeds",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::HEAD;
            // Strip the echoed request headers.
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            // A HEAD response carries no body.
            expect_all_bodies(&payloads, b"")?;
            Ok(())
        },
    );
}

/// `DELETE` with deterministic replication (`min == max == total`) succeeds.
fn test_delete_with_deterministic_replication(env: TestEnv) {
    run_flexible_test(
        env,
        "DELETE with deterministic replication succeeds",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::DELETE;
            args.replication = Some(ReplicationCounts {
                total_requests: 2,
                min_responses: 2,
                max_responses: 2,
            });
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, 2)?;
            expect_all_status(&payloads, 200)?;
            expect_all_bodies_contain(&payloads, "\"method\":\"DELETE\"")?;
            Ok(())
        },
    );
}

/// `PATCH` with deterministic replication over a sub-committee succeeds.
fn test_patch_with_deterministic_replication(env: TestEnv) {
    run_flexible_test(
        env,
        "PATCH with deterministic replication succeeds",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::PATCH;
            args.replication = Some(ReplicationCounts {
                total_requests: 2,
                min_responses: 2,
                max_responses: 2,
            });
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, 2)?;
            expect_all_status(&payloads, 200)?;
            expect_all_bodies_contain(&payloads, "\"method\":\"PATCH\"")?;
            Ok(())
        },
    );
}

/// A `redirect/0` endpoint returns a 204 (No Content) that is not followed.
fn test_redirect_zero_no_content(env: TestEnv) {
    run_flexible_test(
        env,
        "redirect/0 returns 204",
        |env| get_args(format!("{}/redirect/0", webserver_base(env))),
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 204)?;
            // 204 No Content carries no body.
            expect_all_bodies(&payloads, b"")?;
            Ok(())
        },
    );
}

/// A transform can set the status, headers, and body of every response.
fn test_transform_sets_status_and_headers(env: TestEnv) {
    run_flexible_test(
        env,
        "transform can set status, headers and body",
        |env| {
            let mut args = get_args(format!("{}/ascii/ignored", webserver_base(env)));
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "test_transform".to_string(),
                }),
                context: b"transform_context".to_vec(),
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 202)?;
            // The transform replaces the body with the context and sets a fixed
            // pair of headers (the caller is the management canister).
            expect_all_bodies(&payloads, b"transform_context")?;
            for payload in &payloads {
                if header_value(payload, "hello") != Some("bonjour") {
                    bail!(
                        "expected header hello=bonjour, got {:?}",
                        header_value(payload, "hello")
                    );
                }
                if header_value(payload, "caller") != Some("aaaaa-aa") {
                    bail!(
                        "expected header caller=aaaaa-aa, got {:?}",
                        header_value(payload, "caller")
                    );
                }
            }
            Ok(())
        },
    );
}

/// A deterministic transform normalizes a non-deterministic endpoint so every
/// node agrees on an identical response.
fn test_deterministic_transform_normalizes(env: TestEnv) {
    run_flexible_test(
        env,
        "a deterministic transform normalizes a non-deterministic endpoint",
        |env| {
            let mut args = get_args(format!("{}/random", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: SUBNET_NODES,
                max_responses: SUBNET_NODES,
            });
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "deterministic_transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, SUBNET_NODES as usize, SUBNET_NODES as usize)?;
            expect_all_status(&payloads, 200)?;
            // Every node is normalized to the same body with no headers.
            expect_all_bodies(&payloads, b"deterministic")?;
            expect_all_headers_empty(&payloads)?;
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Synchronous validation rejections
// ---------------------------------------------------------------------------

fn test_reject_total_requests_zero(env: TestEnv) {
    run_flexible_test(
        env,
        "total_requests = 0 is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 0,
                min_responses: 0,
                max_responses: 0,
            });
            args
        },
        |result| expect_rejection(result, "total_requests (0) must be at least 1"),
    );
}

fn test_reject_total_requests_exceed_nodes(env: TestEnv) {
    run_flexible_test(
        env,
        "total_requests > number of nodes is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES + 1,
                min_responses: 1,
                max_responses: 1,
            });
            args
        },
        |result| expect_rejection(result, "must not exceed the number of available nodes (4)"),
    );
}

fn test_reject_min_exceeds_max(env: TestEnv) {
    run_flexible_test(
        env,
        "min_responses > max_responses is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 4,
                min_responses: 3,
                max_responses: 2,
            });
            args
        },
        |result| {
            expect_rejection(
                result,
                "min_responses (3) must not exceed max_responses (2)",
            )
        },
    );
}

fn test_reject_max_exceeds_total(env: TestEnv) {
    run_flexible_test(
        env,
        "max_responses > total_requests is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 2,
                min_responses: 1,
                max_responses: 3,
            });
            args
        },
        |result| {
            expect_rejection(
                result,
                "max_responses (3) must not exceed total_requests (2)",
            )
        },
    );
}

fn test_reject_put_requires_deterministic(env: TestEnv) {
    run_flexible_test(
        env,
        "PUT with non-deterministic replication is rejected",
        |env| {
            // Default replication has min < total, which is not allowed for PUT.
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::PUT;
            args
        },
        |result| expect_rejection(result, "min_responses = max_responses = total_requests"),
    );
}

fn test_reject_url_too_long(env: TestEnv) {
    run_flexible_test(
        env,
        "an over-long url is rejected",
        |env| {
            // MAX_CANISTER_HTTP_URL_SIZE is 8192.
            let long_path = "a".repeat(8200);
            get_args(format!("{}/ascii/{long_path}", webserver_base(env)))
        },
        |result| expect_rejection(result, "exceeds 8192"),
    );
}

fn test_reject_invalid_transform_principal(env: TestEnv) {
    run_flexible_test(
        env,
        "a transform referencing another principal is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            // The transform must reference the calling (proxy) canister; the
            // management canister principal does not.
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: Principal::management_canister(),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| expect_rejection(result, "transform principal id expected to be"),
    );
}

/// `DELETE` (like `PUT`/`PATCH`) with explicit but non-equal replication counts
/// is rejected (distinct from the default-replication case).
fn test_reject_delete_non_deterministic(env: TestEnv) {
    run_flexible_test(
        env,
        "DELETE with non-equal replication counts is rejected",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::DELETE;
            args.replication = Some(ReplicationCounts {
                total_requests: 4,
                min_responses: 3,
                max_responses: 4,
            });
            args
        },
        |result| expect_rejection(result, "min_responses = max_responses = total_requests"),
    );
}

fn test_reject_header_name_too_long(env: TestEnv) {
    run_flexible_test(
        env,
        "an over-long header name is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            // Name of 8193 bytes: the element (8193) is within the candid bound
            // (16384) so it decodes, but exceeds the 8192 header name/value limit.
            args.headers = BoundedHttpHeaders::new(vec![HttpHeader {
                name: "a".repeat(8193),
                value: String::new(),
            }]);
            args
        },
        |result| {
            expect_rejection(
                result,
                "number of bytes to represent some http header name 8193 exceeds 8192",
            )
        },
    );
}

fn test_reject_header_value_too_long(env: TestEnv) {
    run_flexible_test(
        env,
        "an over-long header value is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.headers = BoundedHttpHeaders::new(vec![HttpHeader {
                name: "name".to_string(),
                value: "b".repeat(8193),
            }]);
            args
        },
        |result| {
            expect_rejection(
                result,
                "number of bytes to represent some http header value 8193 exceeds 8192",
            )
        },
    );
}

/// A request whose headers plus body exceed the 2 MB request-size limit
/// (`MAX_CANISTER_HTTP_REQUEST_BYTES`) is rejected.
fn test_reject_request_too_large(env: TestEnv) {
    run_flexible_test(
        env,
        "a request exceeding the 2 MB size limit is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            // One byte over the 2_000_000-byte limit (no headers).
            args.body = Some(vec![0_u8; 2_000_001]);
            args
        },
        |result| expect_rejection(result, "exceeds 2000000"),
    );
}

// ---------------------------------------------------------------------------
// Runtime errors and adapter-level per-node failures
// ---------------------------------------------------------------------------

/// When enough nodes fail to reach the endpoint (here: connection refused on a
/// closed port) `min_responses` cannot be met and the outcall reports
/// `too_many_rejects` with per-node details.
fn test_too_many_rejects_connection_refused(env: TestEnv) {
    run_flexible_test(
        env,
        "connection refused on all nodes yields too_many_rejects",
        |env| {
            // Port 9090 on the webserver is closed => connection refused.
            get_args(format!("https://[{}]:9090", get_universal_vm_address(env)))
        },
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            // Every node reports a transient connection failure whose message
            // carries the refused connection.
            expect_all_node_errors(
                &err,
                MIN_REJECT_DETAILS,
                "SysTransient",
                "Connection refused",
            )?;
            Ok(())
        },
    );
}

/// An unresolvable domain fails at the adapter on every node, again yielding
/// `too_many_rejects`.
fn test_too_many_rejects_invalid_domain(env: TestEnv) {
    run_flexible_test(
        env,
        "an invalid domain yields too_many_rejects",
        |_env| get_args("https://xwWPqqbNqxxHmLXdguF4DN9xGq22nczV.invalid".to_string()),
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            // DNS resolution fails on every node during connection setup.
            expect_all_node_errors(&err, MIN_REJECT_DETAILS, "SysTransient", "Connecting to")?;
            Ok(())
        },
    );
}

/// The adapter enforces HTTPS: a non-`https` url is rejected on every node, so
/// the outcall reports `too_many_rejects`.
fn test_too_many_rejects_non_https(env: TestEnv) {
    run_flexible_test(
        env,
        "a non-https url is rejected on every node",
        |env| get_args(format!("http://[{}]", get_universal_vm_address(env))),
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            expect_all_node_errors(
                &err,
                MIN_REJECT_DETAILS,
                "SysFatal",
                "Url need to specify https scheme",
            )?;
            Ok(())
        },
    );
}

/// When the aggregated responses are too large to fit in a block, the outcall
/// reports `responses_too_large`. Each node returns a ~1 MB body (below the
/// per-node 2 MB limit), but `min_responses` (3) of them exceed the ~2 MiB
/// block payload limit.
fn test_responses_too_large(env: TestEnv) {
    run_flexible_test(
        env,
        "oversized aggregated responses yield responses_too_large",
        |env| get_args(format!("{}/bytes/1000000", webserver_base(env))),
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::ResponsesTooLarge(candid::Reserved),
                "Responses too large",
            )?;
            // Each node returned an OK response; the details report their sizes.
            expect_all_node_errors(&err, DEFAULT_MIN_RESPONSES, "ok", "bytes")?;
            Ok(())
        },
    );
}

/// A single per-node response that exceeds the 2 MB per-node limit is rejected
/// by the adapter (download limit), so every node rejects and the outcall
/// reports `too_many_rejects`.
fn test_too_many_rejects_response_over_node_limit(env: TestEnv) {
    run_flexible_test(
        env,
        "a per-node response over the 2 MB limit yields too_many_rejects",
        |env| get_args(format!("{}/bytes/2100000", webserver_base(env))),
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            expect_all_node_errors(
                &err,
                MIN_REJECT_DETAILS,
                "SysFatal",
                "Http body exceeds size limit of 2000000 bytes",
            )?;
            Ok(())
        },
    );
}

/// A transform whose output exceeds the 2 MB per-node limit is rejected by the
/// adapter (transform-output limit) on every node, again yielding
/// `too_many_rejects`.
fn test_too_many_rejects_transform_over_node_limit(env: TestEnv) {
    run_flexible_test(
        env,
        "a transform output over the 2 MB limit yields too_many_rejects",
        |env| {
            let mut args = get_args(format!("{}/bytes/16", webserver_base(env)));
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "bloat_transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            expect_all_node_errors(
                &err,
                MIN_REJECT_DETAILS,
                "SysFatal",
                "Transformed http response exceeds limit: 2000000",
            )?;
            Ok(())
        },
    );
}

/// A composite query cannot be used as a transform: it fails per node, so every
/// node rejects and the outcall reports `too_many_rejects`.
fn test_too_many_rejects_composite_transform(env: TestEnv) {
    run_flexible_test(
        env,
        "a composite-query transform yields too_many_rejects",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "test_composite_transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            // The transform query is rejected on every node.
            expect_all_node_errors(
                &err,
                MIN_REJECT_DETAILS,
                "CanisterError",
                "Composite query cannot be used as transform",
            )?;
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Custom `max_response_bytes` (per-node response size cap)
// ---------------------------------------------------------------------------

/// A caller-supplied `max_response_bytes` caps each node's response size. A
/// response larger than a small custom cap is rejected by the adapter on every
/// node, yielding `too_many_rejects` — proving the caller's cap (not just the
/// 2 MB default) is plumbed through per node.
fn test_custom_max_response_bytes_exceeded(env: TestEnv) {
    const MAX_RESPONSE_BYTES: u64 = 1_000;
    run_flexible_test(
        env,
        "a response over a small custom max_response_bytes yields too_many_rejects",
        |env| {
            let mut args = get_args(format!("{}/bytes/2000", webserver_base(env)));
            args.max_response_bytes = Some(MAX_RESPONSE_BYTES);
            args
        },
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            expect_all_node_errors(
                &err,
                MIN_REJECT_DETAILS,
                "SysFatal",
                &format!("Http body exceeds size limit of {MAX_RESPONSE_BYTES} bytes"),
            )?;
            Ok(())
        },
    );
}

/// A response that fits within a caller-supplied `max_response_bytes` (but that
/// would be rejected under a smaller cap) succeeds normally.
fn test_custom_max_response_bytes_within_limits(env: TestEnv) {
    const BODY_SIZE: usize = 50_000;
    run_flexible_test(
        env,
        "a response within a custom max_response_bytes succeeds",
        |env| {
            let mut args = get_args(format!("{}/bytes/{BODY_SIZE}", webserver_base(env)));
            // Comfortably above the response size, but well below the 2 MB max.
            args.max_response_bytes = Some(100_000);
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            for payload in &payloads {
                if payload.body.len() != BODY_SIZE {
                    bail!(
                        "expected a {BODY_SIZE}-byte body, got {} bytes",
                        payload.body.len()
                    );
                }
            }
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// System subnet
// ---------------------------------------------------------------------------

/// Flexible outcalls work on a system subnet too: system subnets are free for
/// HTTP outcalls (despite a normal cost schedule), so the request is routed
/// through legacy pricing. The system subnet has a single node, so exactly one
/// response comes back.
fn test_system_subnet_outcall(env: TestEnv) {
    let logger = env.logger();
    let runtime = system_runtime(&env);
    let proxy = system_proxy_canister(&env, &runtime);

    block_on(async {
        ic_system_test_driver::retry_with_msg_async!(
            "flexible outcall on a system subnet succeeds".to_string(),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let args = get_args(format!("{}/ascii/system", webserver_base(&env)));
                let result = send_flexible(&proxy, args, CYCLES).await?;
                // A single-node subnet returns exactly one response.
                let payloads = expect_ok(result, 1, 1)?;
                expect_all_status(&payloads, 200)?;
                expect_all_bodies(&payloads, b"system")?;
                Ok(())
            }
        )
        .await
        .expect("flexible outcall on the system subnet did not succeed");
    });
}

// ---------------------------------------------------------------------------
// Fault tolerance (destructive: runs sequentially after the parallel suite)
// ---------------------------------------------------------------------------

/// A flexible outcall with `min_responses < total_requests` still succeeds when
/// one of the committee's nodes is down — the defining reliability property of
/// flexible outcalls. This test kills a node and leaves it down, so it is
/// registered as a trailing sequential test rather than in the parallel suite
/// (nothing must run on the crippled subnet afterwards).
fn test_fault_tolerance(env: TestEnv) {
    let logger = env.logger();

    // Pinned to the free subnet: killing a node is orthogonal to pricing, and with
    // two application subnets around the choice should not depend on their order.
    const SCHEDULE: CanisterCyclesCostSchedule = CanisterCyclesCostSchedule::Free;
    let mut nodes = get_app_subnet_node_snapshots_with_schedule(&env, SCHEDULE);
    let killed_node = nodes.next().expect("no application nodes");
    let healthy_node = nodes.next().expect("need at least two application nodes");

    // The proxy canister lives on the subnet, so reach it through a node that
    // stays up.
    let runtime = get_runtime_from_node(&healthy_node);
    let proxy = proxy_canister_on(&env, &runtime, SCHEDULE);

    info!(logger, "Killing one application node.");
    killed_node.vm().kill();
    killed_node
        .await_status_is_unavailable()
        .expect("the killed node did not become unavailable");
    info!(
        logger,
        "Node is down; a flexible outcall requiring fewer responses than nodes must still succeed."
    );

    block_on(async {
        ic_system_test_driver::retry_with_msg_async!(
            "flexible outcall succeeds with a node down".to_string(),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let mut args = get_args(format!("{}/ascii/tolerate", webserver_base(&env)));
                // Target all nodes but require only 2 responses: the surviving
                // nodes are enough to meet min_responses.
                args.replication = Some(ReplicationCounts {
                    total_requests: SUBNET_NODES,
                    min_responses: 2,
                    max_responses: SUBNET_NODES,
                });
                let result = send_flexible(&proxy, args, CYCLES).await?;
                // At most the surviving nodes (n - 1) can respond.
                let payloads = expect_ok(result, 2, (SUBNET_NODES - 1) as usize)?;
                expect_all_status(&payloads, 200)?;
                expect_all_bodies(&payloads, b"tolerate")?;
                Ok(())
            }
        )
        .await
        .expect("the flexible outcall did not succeed while a node was down");
    });
}

// ---------------------------------------------------------------------------
// Pay-as-you-go pricing
// ---------------------------------------------------------------------------

/// Reads the proxy canister's own cycle balance.
async fn cycle_balance(proxy: &Canister<'_>) -> Result<u128> {
    proxy
        .query_("cycle_balance", candid_one::<u128, ()>, ())
        .await
        .map_err(|err| anyhow::anyhow!("querying the proxy canister's balance failed: {err}"))
}

/// A successful outcall costs the caller something, but nowhere near the payment
/// it attached: the unspent part of the per-replica allowances is refunded.
///
/// Under pay-as-you-go the whole payment leaves the balance up front and the
/// refund is credited afterwards, so this watches the balance rather than the
/// reply's refunded cycles.
fn test_charged_and_refunded(env: TestEnv) {
    let logger = env.logger();
    let runtime = app_runtime_on(&env, CanisterCyclesCostSchedule::Normal);
    let proxy = proxy_canister_on(&env, &runtime, CanisterCyclesCostSchedule::Normal);

    block_on(async {
        ic_system_test_driver::retry_with_msg_async!(
            "a paid outcall charges its cost and refunds the rest".to_string(),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let before = cycle_balance(&proxy).await?;
                let args = get_args(format!("{}/ascii/priced", webserver_base(&env)));
                let payloads = expect_ok(
                    send_flexible(&proxy, args, CYCLES).await?,
                    DEFAULT_MIN_RESPONSES,
                    DEFAULT_MAX_RESPONSES,
                )?;
                expect_all_bodies(&payloads, b"priced")?;
                let after = cycle_balance(&proxy).await?;

                // The refund is credited after the response is delivered, so the
                // balance may still be settling; the retry loop absorbs that.
                let Some(charged) = before.checked_sub(after) else {
                    bail!("balance grew from {before} to {after} across a paid outcall");
                };
                if charged == 0 {
                    bail!("a paid outcall on a normal cost schedule charged nothing");
                }
                // A small outcall costs orders of magnitude less than the payment
                // that was attached, so most of it has to have come back.
                if charged >= u128::from(CYCLES) / 10 {
                    bail!(
                        "expected the refund to return most of the {CYCLES}-cycle payment, \
                         but {charged} cycles were kept"
                    );
                }
                Ok(())
            }
        )
        .await
        .expect("the outcall was not charged and refunded as expected");
    });
}

/// An outcall that can pay its replicas for fetching a response, but cannot pay
/// for putting one into a block, fails as out of cycles rather than hanging until
/// it times out.
///
/// Delivering a response costs roughly `N * (10N + 600)` cycles per byte
/// (~2_560 at `N = 4`) against ~50 cycles per byte to download it, so a payment
/// sized to comfortably cover the downloads still falls far short of the
/// consensus cost for a large enough response.
fn test_out_of_cycles(env: TestEnv) {
    const BODY_SIZE: usize = 500_000;
    // The payment has to land in a window. Each replica spends ~50 cycles/byte to
    // download (~25M here) and its receipt is discarded unless its allowance `A`
    // covers that, so `A` must exceed ~25M. Delivering `min_responses` responses
    // costs at least `min_responses * N * (10N + 600)` cycles/byte — upwards of
    // 3.8B here — and the outcall is only out of cycles if what is left of the
    // collective allowance falls short of that. Writing `A = k * S`, anything from
    // `k` a little above 1 up to well past 10 qualifies; `k = 4` gives ~4x margin
    // on the receipt side and ~13x on the affordability side.
    //
    // Note the direction: paying *more* buys a bigger allowance and so makes the
    // outcall affordable, not less so.
    const PAYMENT: u64 = 400_000_000;

    run_flexible_test_on(
        &env,
        CanisterCyclesCostSchedule::Normal,
        "an outcall that cannot pay to deliver a response is out of cycles",
        PAYMENT,
        &|env| {
            let mut args = get_args(format!("{}/bytes/{BODY_SIZE}", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: DEFAULT_MIN_RESPONSES as u32,
                max_responses: SUBNET_NODES,
            });
            args
        },
        &|result| match result {
            Ok(FlexibleHttpRequestResult::Err(FlexibleHttpRequestErr {
                global_error: Some(FlexibleHttpGlobalError::OutOfCycles(_)),
                message,
                ..
            })) => {
                // The caller is told what it had and what a response would cost,
                // so it can tell how much more to attach.
                if !message.contains("Out of cycles") {
                    bail!("unexpected out-of-cycles message: '{message}'");
                }
                Ok(())
            }
            other => bail!("expected an OutOfCycles error, got: {other:?}"),
        },
    );
}
