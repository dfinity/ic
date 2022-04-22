use crate::{
    collector,
    content_length::ContentLength,
    message::Message,
    metrics::{FUTURE_STARTED, REQUEST_STARTING},
    plan::{EngineCall, Plan},
    stats::Fact,
    RequestType,
};
use backoff::backoff::Backoff;
use ic_canister_client::{update_path, Agent, HttpClientConfig, Sender as AgentSender};
use ic_types::{
    messages::{Blob, MessageId, SignedRequestBytes},
    time::current_time_and_expiry_time,
    CanisterId,
};

use byte_unit::Byte;
use leaky_bucket::RateLimiter;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::TryFrom,
    env, fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        OwnedSemaphorePermit, Semaphore,
    },
    time::{sleep, sleep_until},
};
use url::Url;

use crate::metrics::{
    LATENCY_HISTOGRAM, QUERY_REPLY, UPDATE_SENT, UPDATE_SENT_REPLY, UPDATE_WAIT_REPLY,
};

#[derive(Serialize, Deserialize, Debug)]
struct WaitRequest {
    request_id: MessageId,
    request_type: String,
}

// Time to wait until the first request is issued
const START_OFFSET: Duration = Duration::from_millis(500);

// The initial number of permits = (--rps) * INITIAL_PERMITS_MULTIPLIER.
// This allows an initial burst @rps for INITIAL_PERMITS_MULTIPLIER secs,
// so that the ingress pool is sufficiently built up. After that, the
// permits are scaled down based on the response from the replicas.
const INITIAL_PERMITS_MULTIPLIER: usize = 10;

const QUERY_TIMEOUT: Duration = Duration::from_secs(60 * 5);

#[derive(PartialEq, Eq, Hash)]
enum CallFailure {
    None,
    OnSubmit,
    OnWait,
}

pub struct CallResult {
    fact: Fact,
    counter: Option<u32>,
    call_failure: CallFailure,
    err_msg: Option<String>,
}

/// The engine of making requests. The engine implements making the requests and
/// producing facts for the stats collector to process.
#[derive(Clone)]
pub struct Engine {
    agents: Vec<Agent>, // List of agents to be used in round-robin fashion when sending requests.
}

impl Engine {
    /// Creates a new engine
    pub fn new(
        agent_sender: AgentSender,
        sender_field: Blob,
        urls: &[String],
        http_client_config: HttpClientConfig,
    ) -> Engine {
        let mut agents = Vec::with_capacity(urls.len());
        let current_batch = urls.iter().map(|url| {
            let mut agent = Agent::new_with_http_client_config(
                Url::parse(url.as_str()).unwrap(),
                agent_sender.clone(),
                http_client_config,
            )
            .with_query_timeout(QUERY_TIMEOUT);
            agent.sender_field = sender_field.clone();
            agent
        });

        agents.extend(current_batch);
        Engine { agents }
    }

    // Goes over all agents and makes sure they are connected and the corresponding
    // replicas are healthy.
    pub async fn wait_for_all_agents_to_be_healthy(&self) {
        println!("Waiting for all replicas to be healthy!");
        for agent in &self.agents {
            while !agent.is_replica_healthy().await {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        println!("All replicas are healthy!");
    }

    /// Execute requests in rps mode with the given number of requests per
    /// second
    ///
    ///   Currently, we
    /// use a single runtime. Not specifying this yields better throughput.
    /// - `rps` - Request rate to issue against the IC
    /// - `time_secs` - The time in seconds that the workload should be kept up
    /// - `nonce` - Nonce to use for update calls
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_rps(
        &self,
        rps: usize,
        request_type: RequestType,
        canister_method_name: String,
        time_secs: usize,
        nonce: String,
        call_payload_size: Byte,
        call_payload: Vec<u8>,
        canister_id: &CanisterId,
        periodic_output: bool,
    ) -> Vec<Fact> {
        let requests: usize = time_secs * rps;
        debug!("⏱️  Executing {} requests at {} rps", requests, rps);

        let plan = Plan::new(
            requests,
            nonce,
            call_payload_size,
            call_payload,
            *canister_id,
            request_type,
            canister_method_name,
        );
        let (collector, rec_handle) = collector::start::<Fact>(plan.clone(), periodic_output);

        let (tx, rx) = channel(requests);
        let time_origin = Instant::now();

        let rx_handle = tokio::task::spawn(Engine::evaluate_requests(
            rx,
            collector,
            Some(rps),
            time_origin,
        ));

        // Time between each two consecutive requests
        let inter_arrival_time = 1. / rps as f64;
        let mut tx_handles = vec![];
        for n in 0..requests {
            // Calculate the time at which the request should be running from start time
            // and inter arrival time.
            let target_instant =
                time_origin + START_OFFSET + Duration::from_secs_f64(inter_arrival_time * n as f64);
            sleep_until(tokio::time::Instant::from_std(target_instant)).await;
            println!("Running {:?}", (Instant::now() - time_origin).as_secs_f64());
            let tx = tx.clone();
            let plan = plan.clone();
            let agent = self.agents[n % self.agents.len()].clone();
            FUTURE_STARTED.inc();
            tx_handles.push(tokio::task::spawn(async move {
                REQUEST_STARTING.inc();
                Engine::execute_request(agent, tx, time_origin, &plan, n).await;
            }));
        }
        for tx_handle in tx_handles {
            tx_handle.await.unwrap_or_else(|_| {
                panic!("Await the tx failed.");
            });
        }
        std::mem::drop(tx);
        rx_handle.await.unwrap_or_else(|_| {
            panic!("Await the rx failed.");
        });

        rec_handle.join().unwrap()
    }

    /// Finds the max rps currently possible with the given set of replicas.
    /// - `rps` - Initial estimate of the max rps
    /// - `time_secs` - The time in seconds that the workload should be kept up
    /// - `nonce` - Nonce to use for update calls
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_max_rps(
        &self,
        rps: usize,
        request_type: RequestType,
        canister_method_name: String,
        time_secs: usize,
        nonce: String,
        call_payload_size: Byte,
        call_payload: Vec<u8>,
        canister_id: &CanisterId,
        periodic_output: bool,
    ) -> Vec<Fact> {
        println!(
            "⏱️  Evaluating rps: initial_rps = {}, duration = {} sec",
            rps, time_secs
        );

        let requests: usize = time_secs * rps; // This is just an upper estimate
        let plan = Plan::new(
            requests,
            nonce,
            call_payload_size,
            call_payload,
            *canister_id,
            request_type,
            canister_method_name,
        );
        let (collector, rec_handle) = collector::start::<Fact>(plan.clone(), periodic_output);
        let (tx, rx) = channel(requests);

        let rate_limiter = RateLimiter::builder()
            .initial(rps)
            .interval(Duration::from_secs(1))
            .refill(rps)
            .build();
        // Initially holds (rps * INITIAL_PERMITS_MULTIPLIER) permits
        let request_manager = RequestManager::new(rps * INITIAL_PERMITS_MULTIPLIER);

        let time_origin = Instant::now();
        let rx_handle = tokio::task::spawn(Engine::evaluate_requests(
            rx,
            collector,
            Some(rps),
            time_origin,
        ));
        let end_time = time_origin
            .checked_add(Duration::from_secs(time_secs as u64))
            .unwrap();
        let end_time = tokio::time::Instant::from_std(end_time);

        let mut tx_handles = vec![];
        let mut n = 0;
        sleep(START_OFFSET).await;
        let mut last_print = SystemTime::now();
        while tokio::time::Instant::now() < end_time {
            // Wait for the rate limiter to allow the next request
            rate_limiter.acquire_one().await;
            // Wait for a free slot based on the current rps estimate
            let permit =
                match tokio::time::timeout_at(end_time, request_manager.alloc_permit()).await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };

            let tx = tx.clone();
            let plan = plan.clone();
            let request_manager_cl = request_manager.clone();
            let agent = self.agents[n % self.agents.len()].clone();
            FUTURE_STARTED.inc();
            tx_handles.push(tokio::task::spawn(async move {
                REQUEST_STARTING.inc();
                let ret = Engine::execute_request(agent, tx, time_origin, &plan, n).await;
                request_manager_cl.free_permit(permit, ret);
            }));

            n += 1;
            if last_print.elapsed().unwrap() > Duration::from_secs(10) {
                request_manager.show();
                last_print = SystemTime::now();
            }
        }
        println!("⏱️  Evaluating rps done: {:?}", time_origin.elapsed());

        for tx_handle in tx_handles {
            tx_handle.await.unwrap_or_else(|_| {
                panic!("Await the tx failed.");
            });
        }
        std::mem::drop(tx);
        rx_handle.await.unwrap_or_else(|_| {
            panic!("Await the rx failed.");
        });

        rec_handle.join().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_request(
        agent: Agent,
        tx: Sender<CallResult>,
        time_origin: Instant,
        plan: &Plan,
        n: usize,
    ) -> bool {
        match plan.generate_call(n) {
            EngineCall::Read { method, arg } => {
                Engine::execute_query(&agent, tx, time_origin, plan, method, arg, n)
                    .await
                    .is_some()
            }
            EngineCall::Write { method, arg } => {
                Engine::execute_update(&agent, tx, time_origin, plan, method, arg, n).await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_query(
        agent: &Agent,
        tx: Sender<CallResult>,
        _time_origin: Instant,
        plan: &Plan,
        method: String,
        arg: Vec<u8>,
        n: usize,
    ) -> Option<u32> {
        let time_query_start = Instant::now();
        let response = agent.execute_query(&plan.canister_id, &*method, arg).await;
        let time_query_end = Instant::now();
        debug!("Sent query ({}). Response was: {:?}", n, response);

        match response {
            Ok(r) => {
                QUERY_REPLY.with_label_values(&["replied"]).inc();

                if let Ok(f) = env::var("RESULT_FILE") {
                    let bytes: Vec<u8> = r.clone().unwrap_or_default();
                    eprintln!("Writing results file: {}", &f);
                    fs::write(f, bytes).unwrap();
                }

                Engine::check_query(r, tx, time_query_start, time_query_end).await
            }
            Err(e) => {
                let err = format!("{:?}", e).to_string();
                QUERY_REPLY.with_label_values(&[&err]).inc();

                // This is broken. The issue is that the Error type returned by execute_query is
                // not nicely structured, it's just a string.
                let http_status = 0_u16;

                tx.send(CallResult {
                    fact: Fact::record(
                        ContentLength::new(0),
                        http_status,
                        time_query_start,
                        time_query_end,
                        false,
                    ),
                    counter: None,
                    call_failure: CallFailure::OnWait,
                    err_msg: Some(err),
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("Sending a fact failed.");
                });
                None
            }
        }
    }

    /// Make this return T, where T is produced by a fn given as argument from
    /// the body of the reply
    #[allow(clippy::too_many_arguments)]
    async fn execute_update(
        agent: &Agent,
        tx: Sender<CallResult>,
        time_origin: Instant,
        plan: &Plan,
        method: String,
        arg: Vec<u8>,
        n: usize,
    ) -> bool {
        let nonce = plan.nonce.clone();
        let deadline = Instant::now() + agent.ingress_timeout;
        let (request, request_id) = agent
            .prepare_update_raw(
                &plan.canister_id,
                method,
                arg,
                format!("inc {} {}", nonce, n).into_bytes(),
                current_time_and_expiry_time().1,
            )
            .unwrap();

        debug!(
            "Sending signed update. request id: {}. Message\n{:?}",
            request_id, request
        );

        let content = SignedRequestBytes::try_from(request).unwrap().into();
        let path = update_path(plan.canister_id);
        let time_start = std::time::Instant::now();
        debug!(
            "Sending update() call ({}) after {}ms since origin",
            n,
            Instant::now().duration_since(time_origin).as_millis()
        );

        // TODO: for now, this uses MAX_WAIT_INGRESS as timeout for sending the request.
        // This should be adjusted to a more appropriate value for posting update
        // requests.
        UPDATE_SENT.inc();
        let res = agent
            .http_client()
            .send_post_request(
                agent.url.join(path.as_str()).unwrap().as_str(),
                content,
                tokio::time::Instant::from_std(deadline),
            )
            .await;
        match res {
            Err(e) => {
                let err_msg = format!("[{:?}]: Update send failed{:?}", request_id, e);
                UPDATE_SENT_REPLY
                    .with_label_values(&["update_send_failed"])
                    .inc();
                tx.send(CallResult {
                    fact: Fact::record(
                        ContentLength::new(0),
                        11,
                        time_start,
                        Instant::now(),
                        false,
                    ),
                    counter: None,
                    call_failure: CallFailure::OnSubmit,
                    err_msg: Some(err_msg),
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("Sending a fact failed.");
                });
                false
            }
            Ok((body, status)) => {
                debug!(
                    "update() request success ({}): {:?}, {}ms after origin",
                    n,
                    status,
                    Instant::now().duration_since(time_start).as_millis()
                );

                UPDATE_SENT_REPLY
                    .with_label_values(&[&format!("{:?}", status)])
                    .inc();

                let update_status_code = status.as_u16();
                if update_status_code != 202 {
                    let err_msg = format!(
                        "[{:?}]: Update returned non-202: {}",
                        request_id, update_status_code
                    );
                    UPDATE_SENT_REPLY
                        .with_label_values(&["update_send_failed"])
                        .inc();
                    tx.send(CallResult {
                        fact: Fact::record(
                            ContentLength::new(0),
                            update_status_code,
                            time_start,
                            Instant::now(),
                            false,
                        ),
                        counter: None,
                        call_failure: CallFailure::OnSubmit,
                        err_msg: Some(err_msg),
                    })
                    .await
                    .unwrap_or_else(|_| {
                        panic!("Sending a fact failed.");
                    });
                    return false;
                }

                let mut finished = false;

                // https://docs.rs/backoff/latest/backoff/exponential/struct.ExponentialBackoff.html#structfield.initial_interval
                let mut backoff = backoff::ExponentialBackoff {
                    initial_interval: Duration::from_millis(50),
                    current_interval: Duration::from_millis(50), // Should probably be the same as initial_interval
                    // See fomula here:
                    // https://docs.rs/backoff/latest/backoff/
                    randomization_factor: 0.01,
                    multiplier: 1.2,
                    start_time: std::time::Instant::now(),
                    // Stop increasing at this value
                    max_interval: Duration::from_secs(10),
                    max_elapsed_time: None,
                    clock: backoff::SystemClock::default(),
                };

                // Check request status for the first time after 2s (~ time between blocks)
                let mut next_poll_time = Instant::now() + Duration::from_millis(500);

                while !finished && next_poll_time < deadline {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(next_poll_time)).await;
                    next_poll_time = Instant::now() + backoff.next_backoff().unwrap();
                    let wait = Engine::wait_ingress_for_counter_canister(
                        agent,
                        request_id.clone(),
                        &plan.canister_id,
                        deadline,
                    )
                    .await;
                    match wait {
                        Ok((result, counter)) => {
                            UPDATE_WAIT_REPLY
                                .with_label_values(&[&format!("{:?}", result)])
                                .inc();

                            match result.as_ref() {
                                "replied" => {
                                    assert!(result == "replied");

                                    let counter = counter.expect("Did not receive counter value");
                                    let http_status = status.as_u16();

                                    debug!(
                                        "🚀 Got return code ({}): {} - {} after since start {}ms since origin {}ms",
                                        n,
                                        result,
                                        counter,
                                        Instant::now().duration_since(time_start).as_millis(),
                                        Instant::now().duration_since(time_origin).as_millis()
                                    );
                                    tx.send(CallResult {
                                        fact: Fact::record(
                                            ContentLength::new(body.len() as u64),
                                            http_status,
                                            time_start,
                                            Instant::now(),
                                            true,
                                        ),
                                        counter: Some(counter),
                                        call_failure: CallFailure::None,
                                        err_msg: None,
                                    })
                                    .await
                                    .unwrap_or_else(|_| {
                                        panic!("Sending a fact failed.");
                                    });

                                    finished = true;
                                }
                                "unknown" | "processing" | "received" => {
                                    debug!(
                                        "Received ({}) {} ingress status after {}ms since origin",
                                        n,
                                        result,
                                        Instant::now().duration_since(time_origin).as_millis()
                                    );
                                }
                                _ => {
                                    let err_msg = format!(
                                        "[{:?}]: Update failed: other status {:?}",
                                        request_id, result
                                    )
                                    .to_string();
                                    tx.send(CallResult {
                                        fact: Fact::record(
                                            ContentLength::new(body.len() as u64),
                                            33,
                                            time_start,
                                            Instant::now(),
                                            false,
                                        ),
                                        counter: None,
                                        call_failure: CallFailure::OnWait,
                                        err_msg: Some(err_msg),
                                    })
                                    .await
                                    .unwrap_or_else(|_| {
                                        panic!("Sending a fact failed.");
                                    });

                                    finished = true;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[{:?}]: Update poll failed: {:?}", request_id, e);
                            UPDATE_WAIT_REPLY
                                .with_label_values(&[&format!("{:?}", e)])
                                .inc();
                        }
                    }
                }

                if !finished {
                    let err_msg = format!("[{:?}]: Update did not finish in time", request_id);
                    tx.send(CallResult {
                        fact: Fact::record(
                            ContentLength::new(0),
                            44,
                            time_start,
                            Instant::now(),
                            false,
                        ),
                        counter: None,
                        call_failure: CallFailure::OnWait,
                        err_msg: Some(err_msg),
                    })
                    .await
                    .unwrap_or_else(|_| {
                        panic!("Sending a fact failed.");
                    });
                }
                finished
            }
        }
    }

    async fn check_query(
        resp: Option<Vec<u8>>,
        tx: Sender<CallResult>,
        time_query_start: Instant,
        time_query_end: Instant,
    ) -> Option<u32> {
        let latency = time_query_end.duration_since(time_query_start);
        debug!("Response: {:?}", resp);
        let counter = resp
            .as_ref()
            .map(|r| Engine::interpret_counter_canister_response(r));
        debug!("🚀 Got counter value: {:?}", counter);

        LATENCY_HISTOGRAM
            .with_label_values(&["query", "replied"])
            .observe(latency.as_secs() as f64 + latency.subsec_nanos() as f64 * 1e-9);

        tx.send(CallResult {
            fact: Fact::record(
                ContentLength::new(resp.unwrap_or_default().len() as u64),
                200_u16,
                time_query_start,
                time_query_end,
                true,
            ),
            counter,
            call_failure: CallFailure::None,
            err_msg: None,
        })
        .await
        .unwrap_or_else(|_| {
            panic!("Sending a fact failed.");
        });

        counter
    }

    async fn evaluate_requests(
        mut rx: Receiver<CallResult>,
        collector: std::sync::mpsc::Sender<Message<Fact>>,
        rps: Option<usize>,
        _time_start: Instant,
    ) {
        let mut max_counter = 0;
        let mut failures = HashMap::new();

        while let Some(result) = rx.recv().await {
            collector
                .send(Message::Body(result.fact))
                .expect("Failed to collect facts for rps/update() calls");

            if let Some(err_msg) = result.err_msg {
                eprintln!("{}", err_msg);
            }

            // Increment counter for failures
            let stat = failures.entry(result.call_failure).or_insert(0);
            *stat += 1;

            if let Some(counter) = result.counter {
                max_counter = std::cmp::max(max_counter, counter);
                crate::metrics::COUNTER_VALUE.inc();
            }
        }

        collector
            .send(Message::Log(format!(
                "requested: {} - 🚀 Max counter value seen: {} - submit failures: {} - wait failures: {}",
                rps.unwrap_or(0),
                max_counter,
                failures.get(&CallFailure::OnSubmit).unwrap_or(&0),
                failures.get(&CallFailure::OnWait).unwrap_or(&0),
            )))
            .unwrap();
        collector.send(Message::Eof).unwrap();
    }

    /// Given the raw bytes of the "arg" counter canister response (NOT the
    /// top-level response), returns the corresponding counter value.
    fn interpret_counter_canister_response(bytes: &[u8]) -> u32 {
        if bytes.len() >= 4 {
            let first_four_bytes: &[u8] = &bytes[0..4];
            let mut bytes_as_num = [0; 4];
            bytes_as_num.copy_from_slice(first_four_bytes);
            u32::from_le_bytes(bytes_as_num)
        } else {
            0
        }
    }

    async fn wait_ingress_for_counter_canister(
        agent: &Agent,
        request_id: MessageId,
        canister_id: &CanisterId,
        deadline: Instant,
    ) -> Result<(String, Option<u32>), String> {
        let call_response = agent
            .wait_ingress(request_id, deadline, canister_id)
            .await?;

        if let Ok(f) = env::var("RESULT_FILE") {
            let bytes: Vec<u8> = call_response.reply.clone().unwrap_or_default();
            eprintln!("Writing results file: {}", &f);
            fs::write(f, bytes).unwrap();
        }

        let counter_value = call_response
            .reply
            .as_ref()
            .map(|bytes| Engine::interpret_counter_canister_response(bytes));
        Ok((call_response.status, counter_value))
    }
}

// Manages the number of outstanding requests in flight
#[derive(Clone)]
struct RequestManager {
    // Number of requests to start with
    initial_requests: usize,

    // The semaphore to acquire/release permits
    permits: Arc<Semaphore>,

    allocs: Arc<AtomicUsize>,
    success: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
}

impl RequestManager {
    fn new(initial_requests: usize) -> Self {
        Self {
            initial_requests,
            permits: Arc::new(Semaphore::new(initial_requests)),
            allocs: Arc::new(AtomicUsize::new(0)),
            success: Arc::new(AtomicUsize::new(0)),
            errors: Arc::new(AtomicUsize::new(0)),
        }
    }

    // Waits for one permit to become available
    async fn alloc_permit(&self) -> OwnedSemaphorePermit {
        self.allocs.fetch_add(1, Ordering::SeqCst);
        self.permits.clone().acquire_owned().await.unwrap()
    }

    // Called on request completion.
    // If the request was successful, the token is returned to the
    // free pool so that more requests can be issued in its place.
    // If the request failed, the token is dropped without returning
    // to the pool. This dynamically adjusts the pool size/max
    // outstanding requests.
    fn free_permit(&self, permit: OwnedSemaphorePermit, request_success: bool) {
        if !request_success {
            // TODO: keep a min threshold, look at the specific
            // HTTP status code
            permit.forget();
            self.errors.fetch_add(1, Ordering::SeqCst);
        } else {
            self.success.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn show(&self) {
        let allocs = self.allocs.load(Ordering::SeqCst);
        let success = self.success.load(Ordering::SeqCst);
        let errors = self.errors.load(Ordering::SeqCst);
        println!(
            "RequestManager: initial_capacity = {}, allocs = {}, success = {}, errors = {},\
                    current capacity = {}, free permits = {}",
            self.initial_requests,
            allocs,
            success,
            errors,
            self.initial_requests - errors,
            self.permits.available_permits()
        );
    }
}
