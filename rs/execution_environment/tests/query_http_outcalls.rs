//! HTTP outcalls from composite queries, driven through the asynchronous query
//! service: what the unit tests cannot cover, i.e. the driver, the scheduler,
//! and a suspended query giving its execution thread back.

use candid::Decode;
use ic_config::{
    execution_environment::Config as HypervisorConfig, flag_status::FlagStatus,
    subnet_config::SubnetConfig,
};
use ic_management_canister_types_private::{
    BoundedHttpHeaders, CanisterHttpRequestArgs, CanisterHttpResponsePayload, HttpMethod, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use ic_test_utilities_metrics::{HistogramStats, fetch_histogram_vec_stats, fetch_int_gauge};
use ic_types::{
    CanisterId,
    canister_http::{CanisterHttpReject, QueryOutcallOutcome, QueryOutcallRequest},
    ingress::WasmResult,
};
use ic_types_cycles::Cycles;
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const T: Cycles = Cycles::new(1_000_000_000_000);

fn hypervisor_config_with_query_outcalls(max_suspended: usize) -> HypervisorConfig {
    HypervisorConfig {
        query_http_requests: FlagStatus::Enabled,
        // Raised out of the way: these tests are about the *thread* limits.
        max_concurrent_query_outcalls: max_suspended,
        max_concurrent_query_outcalls_per_canister: max_suspended,
        ..Default::default()
    }
}

fn subnet_config() -> StateMachineConfig {
    subnet_config_allowing(1)
}

fn subnet_config_allowing(max_suspended: usize) -> StateMachineConfig {
    StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        hypervisor_config_with_query_outcalls(max_suspended),
    )
}

/// The `http_request` arguments a composite query uses for an outcall.
fn outcall_args() -> Vec<u8> {
    CanisterHttpRequestArgs {
        url: "https://example.com".to_string(),
        max_response_bytes: Some(1_024),
        headers: BoundedHttpHeaders::new(vec![]),
        body: None,
        method: HttpMethod::GET,
        transform: None,
        is_replicated: Some(false),
        pricing_version: None,
    }
    .encode()
}

fn outcall_query() -> Vec<u8> {
    wasm()
        .call_simple(
            CanisterId::ic_00(),
            "http_request",
            call_args()
                .other_side(outcall_args())
                .on_reject(wasm().reject_message().append_and_reply()),
        )
        .build()
}

fn install_universal_canister(env: &StateMachine) -> CanisterId {
    env.install_canister_with_cycles(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None, T)
        .unwrap()
}

fn http_response(body: &[u8]) -> CanisterHttpResponsePayload {
    CanisterHttpResponsePayload {
        status: 200,
        headers: vec![],
        body: body.to_vec(),
    }
}

#[test]
fn composite_query_outcall_reaches_the_canister() {
    let env = StateMachineBuilder::new()
        .with_config(Some(subnet_config()))
        .build();
    let canister_id = install_universal_canister(&env);
    env.set_query_outcall_handler(|_| Ok(http_response(b"hello")));

    let result = env
        .query(canister_id, "composite_query", outcall_query())
        .unwrap();

    let WasmResult::Reply(reply) = result else {
        panic!("expected a reply");
    };
    assert_eq!(
        Decode!(&reply, CanisterHttpResponsePayload).unwrap().body,
        b"hello".to_vec()
    );

    let outcalls = env.take_query_outcalls();
    assert_eq!(outcalls.len(), 1);
    assert_eq!(outcalls[0].url, "https://example.com");
    assert_eq!(outcalls[0].requester, canister_id);
}

#[test]
fn composite_query_outcall_reject_reaches_the_canister() {
    let env = StateMachineBuilder::new()
        .with_config(Some(subnet_config()))
        .build();
    let canister_id = install_universal_canister(&env);
    env.set_query_outcall_handler(|_| {
        Err(CanisterHttpReject {
            reject_code: ic_error_types::RejectCode::SysTransient,
            message: "connection refused".to_string(),
        })
    });

    let result = env
        .query(canister_id, "composite_query", outcall_query())
        .unwrap();

    assert_eq!(result, WasmResult::Reply(b"connection refused".to_vec()));
}

/// A query outcall creates no request context, so the consensus machinery has
/// nothing to do.
#[test]
fn composite_query_outcall_does_not_enter_the_replicated_state() {
    let env = StateMachineBuilder::new()
        .with_config(Some(subnet_config()))
        .build();
    let canister_id = install_universal_canister(&env);
    env.set_query_outcall_handler(|_| Ok(http_response(b"hello")));

    env.query(canister_id, "composite_query", outcall_query())
        .unwrap();

    assert!(
        env.canister_http_request_contexts().is_empty(),
        "an outcall from a query must not create a request context"
    );
    // The subnet keeps making progress; nothing is waiting on a response.
    env.tick();
}

/// The default current-thread runtime serializes concurrent `block_on` calls,
/// which would serialize the queries in the harness and hide what is measured.
fn multi_thread_runtime() -> Arc<tokio::runtime::Runtime> {
    Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("failed to build a runtime"),
    )
}

/// The point of the whole design: a query waiting for an outcall holds no
/// query-execution thread. If it did, at most two outcalls could be in flight
/// per canister and the rendezvous below would never complete.
#[test]
fn suspended_queries_do_not_hold_query_execution_threads() {
    // Well above `query_execution_threads_per_canister` (2).
    const CONCURRENT_QUERIES: usize = 16;

    // A barrier cannot miss a participant, unlike `Notify`.
    let all_arrived = Arc::new(tokio::sync::Barrier::new(CONCURRENT_QUERIES));
    let peak_in_flight = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));

    let outcall_service = {
        let all_arrived = Arc::clone(&all_arrived);
        let peak_in_flight = Arc::clone(&peak_in_flight);
        let in_flight = Arc::clone(&in_flight);
        tower::util::BoxCloneService::new(tower::service_fn(
            move |_request: QueryOutcallRequest| {
                let all_arrived = Arc::clone(&all_arrived);
                let peak_in_flight = Arc::clone(&peak_in_flight);
                let in_flight = Arc::clone(&in_flight);
                async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak_in_flight.fetch_max(now, Ordering::SeqCst);
                    // Bounded, so a regression fails rather than hangs.
                    let _ = tokio::time::timeout(Duration::from_secs(60), all_arrived.wait()).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, Infallible>(QueryOutcallOutcome {
                        result: Ok(http_response(b"hello")),
                        spent: Cycles::zero(),
                    })
                }
            },
        ))
    };

    let env = Arc::new(
        StateMachineBuilder::new()
            .with_runtime(multi_thread_runtime())
            .with_config(Some(subnet_config_allowing(CONCURRENT_QUERIES)))
            .with_query_outcall_service(outcall_service)
            .build(),
    );
    let canister_id = install_universal_canister(&env);
    // `StateMachine::query` certifies on every call, and does so without
    // locking; certifying here leaves the query threads nothing to race over.
    env.certify_latest_state();

    let threads: Vec<_> = (0..CONCURRENT_QUERIES)
        .map(|_| {
            let env = Arc::clone(&env);
            std::thread::spawn(move || env.query(canister_id, "composite_query", outcall_query()))
        })
        .collect();

    for thread in threads {
        let result = thread
            .join()
            .expect("a query thread panicked")
            .expect("the query failed");
        let WasmResult::Reply(reply) = result else {
            panic!("expected a reply");
        };
        assert_eq!(
            Decode!(&reply, CanisterHttpResponsePayload).unwrap().body,
            b"hello".to_vec()
        );
    }

    assert_eq!(
        peak_in_flight.load(Ordering::SeqCst),
        CONCURRENT_QUERIES,
        "all queries must be able to wait for their outcall at the same time"
    );
}

/// An ordinary query and an update call are still served while many queries are
/// suspended. The update call matters as much: the ingress filter draws on the
/// same thread pool.
#[test]
fn suspended_queries_do_not_block_other_work() {
    const SUSPENDED_QUERIES: usize = 16;

    let in_flight = Arc::new(AtomicUsize::new(0));
    // Permits outlive the waiter's arrival, unlike `Notify`.
    let release = Arc::new(tokio::sync::Semaphore::new(0));

    let outcall_service = {
        let in_flight = Arc::clone(&in_flight);
        let release = Arc::clone(&release);
        tower::util::BoxCloneService::new(tower::service_fn(
            move |_request: QueryOutcallRequest| {
                let in_flight = Arc::clone(&in_flight);
                let release = Arc::clone(&release);
                async move {
                    in_flight.fetch_add(1, Ordering::SeqCst);
                    let permit = release.acquire().await.expect("the semaphore was closed");
                    permit.forget();
                    Ok::<_, Infallible>(QueryOutcallOutcome {
                        result: Ok(http_response(b"hello")),
                        spent: Cycles::zero(),
                    })
                }
            },
        ))
    };

    let env = Arc::new(
        StateMachineBuilder::new()
            .with_runtime(multi_thread_runtime())
            .with_config(Some(subnet_config_allowing(SUSPENDED_QUERIES)))
            .with_query_outcall_service(outcall_service)
            .build(),
    );
    let canister_id = install_universal_canister(&env);
    // `StateMachine::query` certifies on every call, and does so without
    // locking; certifying here leaves the query threads nothing to race over.
    env.certify_latest_state();

    let suspended: Vec<_> = (0..SUSPENDED_QUERIES)
        .map(|_| {
            let env = Arc::clone(&env);
            std::thread::spawn(move || env.query(canister_id, "composite_query", outcall_query()))
        })
        .collect();

    // Wait until every query is parked on its outcall.
    let deadline = Instant::now() + Duration::from_secs(120);
    while in_flight.load(Ordering::SeqCst) < SUSPENDED_QUERIES {
        assert!(
            Instant::now() < deadline,
            "only {} of {SUSPENDED_QUERIES} queries reached their outcall",
            in_flight.load(Ordering::SeqCst)
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // With every query suspended, an ordinary query is still served.
    let reply = env
        .query(
            canister_id,
            "query",
            wasm().reply_data(b"still serving").build(),
        )
        .unwrap();
    assert_eq!(reply, WasmResult::Reply(b"still serving".to_vec()));

    // And so is an update call, which the ingress filter has to admit.
    let update = env
        .execute_ingress(canister_id, "update", wasm().reply().build())
        .unwrap();
    assert_eq!(update, WasmResult::Reply(vec![]));

    release.add_permits(SUSPENDED_QUERIES);
    for thread in suspended {
        thread
            .join()
            .expect("a query thread panicked")
            .expect("the query failed");
    }
}

/// The metrics separating executing from waiting are actually recorded: without
/// them a slow query is indistinguishable from one parked on an outcall.
#[test]
fn outcall_metrics_separate_waiting_from_executing() {
    const WAIT: Duration = Duration::from_millis(200);

    let outcall_service = tower::util::BoxCloneService::new(tower::service_fn(
        move |_request: QueryOutcallRequest| async move {
            tokio::time::sleep(WAIT).await;
            Ok::<_, Infallible>(QueryOutcallOutcome {
                result: Ok(http_response(b"hello")),
                spent: Cycles::zero(),
            })
        },
    ));

    let env = StateMachineBuilder::new()
        .with_runtime(multi_thread_runtime())
        .with_config(Some(subnet_config_allowing(1)))
        .with_query_outcall_service(outcall_service)
        .build();
    let canister_id = install_universal_canister(&env);

    assert_eq!(
        fetch_int_gauge(&env.metrics_registry, "execution_query_suspended_queries"),
        Some(0),
        "nothing is suspended before the query runs"
    );

    env.query(canister_id, "composite_query", outcall_query())
        .expect("the query failed");

    let stats = |name: &str| -> HistogramStats {
        let mut per_label = fetch_histogram_vec_stats(&env.metrics_registry, name);
        per_label
            // The namespace the regular query service registers under.
            .remove(&[("query_type".to_string(), "regular".to_string())].into())
            .unwrap_or_else(|| panic!("{name} recorded no samples for the query service"))
    };

    assert_eq!(stats("execution_query_outcalls_per_query").sum, 1.0);

    let waited = stats("execution_query_outcall_wait_duration_seconds");
    assert_eq!(waited.count, 1);
    assert!(
        waited.sum >= WAIT.as_secs_f64(),
        "the outcall wait ({}s) must cover the time the adapter took ({}s)",
        waited.sum,
        WAIT.as_secs_f64()
    );

    let total = stats("execution_query_total_walltime_seconds");
    assert_eq!(total.count, 1);
    assert!(
        total.sum >= waited.sum,
        "the end-to-end walltime ({}s) includes the wait ({}s)",
        total.sum,
        waited.sum
    );

    // The waiting is not charged to execution.
    let executed = stats_of_query_duration(&env);
    assert!(
        executed < WAIT.as_secs_f64(),
        "executing took {executed}s, which means the outcall wait leaked into it"
    );

    assert_eq!(
        stats("execution_query_resume_scheduling_delay_seconds").count,
        1,
        "the resume must be timed, since it is the alarm for queueing delay"
    );

    assert_eq!(
        fetch_int_gauge(&env.metrics_registry, "execution_query_suspended_queries"),
        Some(0),
        "the suspension slot must be released once the query finishes"
    );
}

fn stats_of_query_duration(env: &StateMachine) -> f64 {
    fetch_histogram_vec_stats(&env.metrics_registry, "execution_query_duration_seconds")
        .into_values()
        .map(|stats| stats.sum)
        .sum()
}
