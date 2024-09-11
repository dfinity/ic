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
use ic_canister_client::{
    prepare_update, update_path, Agent, HttpClientConfig, Sender as AgentSender,
};
use ic_types::{
    messages::{Blob, MessageId},
    time::expiry_time_from_now,
    CanisterId,
};

use byte_unit::Byte;
use futures::StreamExt;
use itertools::Either;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc::{channel, Receiver, Sender},
    time::sleep_until,
};
use url::{Host, Url};

use crate::metrics::{
    LATENCY_HISTOGRAM, QUERY_REPLY, UPDATE_SENT, UPDATE_SENT_REPLY, UPDATE_WAIT_REPLY,
};

#[derive(Debug, Deserialize, Serialize)]
struct WaitRequest {
    request_id: MessageId,
    request_type: String,
}

// Time to wait until the first request is issued
const START_OFFSET: Duration = Duration::from_millis(500);

const QUERY_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const INGRESS_TIMEOUT: Duration = Duration::from_secs(60 * 6);

#[derive(Eq, PartialEq, Hash)]
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
        host: Option<String>,
        query_timeout: Option<Duration>,
        ingress_timeout: Option<Duration>,
    ) -> Engine {
        let mut agents = Vec::with_capacity(urls.len());
        let current_batch = urls.iter().map(|url| {
            let mut url = Url::parse(url.as_str()).unwrap();
            let mut http_client_config = http_client_config.clone();
            if let Some(new_host) = host.as_ref() {
                http_client_config.overrides.insert(
                    new_host.clone(),
                    match url.host() {
                        None => panic!("no host found in {}", url),
                        Some(Host::Domain(host)) => Either::Right(
                            FromStr::from_str(host).expect("failed to convert host to dns name"),
                        ),
                        Some(Host::Ipv4(host)) => {
                            Either::Left((host, url.port_or_known_default().unwrap()).into())
                        }
                        Some(Host::Ipv6(host)) => {
                            Either::Left((host, url.port_or_known_default().unwrap()).into())
                        }
                    },
                );
                url.set_host(Some(new_host.as_str()))
                    .expect("failed to set host");
            }
            let mut agent = Agent::new_with_http_client_config(
                url,
                agent_sender.clone(),
                http_client_config.clone(),
            )
            .with_query_timeout(query_timeout.unwrap_or(QUERY_TIMEOUT))
            .with_ingress_timeout(ingress_timeout.unwrap_or(INGRESS_TIMEOUT));
            agent.sender_field = sender_field.clone();
            agent
        });

        agents.extend(current_batch);
        Engine { agents }
    }

    // Goes over all agents and makes sure they are connected and the corresponding
    // replicas are healthy.
    //
    // This function will never return if one of the agents remains unhealthy.
    pub async fn wait_for_all_agents_to_be_healthy(&self) {
        let before = Instant::now();
        let mut all_healthy = false;
        println!("Waiting for all replicas to be healthy.");
        while !all_healthy {
            all_healthy = true;
            let agents = &self.agents;
            let results =
                futures::stream::iter(agents.iter().map(|agent| agent.is_replica_healthy()))
                    .buffered(self.agents.len())
                    .collect::<Vec<_>>();
            let all_res = results.await;
            for (n, res) in all_res.iter().enumerate() {
                if !res {
                    all_healthy = false;
                    let rep = &agents[n];
                    println!(
                        "Replica {} is not healthy.  Elapsed: {:?}",
                        rep.url,
                        before.elapsed()
                    )
                }
            }
            if !all_healthy {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        println!("All replicas are healthy.  Elapsed: {:?}", before.elapsed());
    }

    /// Execute requests in rps mode with the given number of requests per
    /// second
    ///
    ///   Currently, we
    /// use a single runtime. Not specifying this yields better throughput.
    /// - `rpms` - Request rate (per milliseconds) to issue against the IC
    /// - `time_secs` - The time in seconds that the workload should be kept up
    /// - `nonce` - Nonce to use for update calls
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_rps(
        &self,
        rpms: usize,
        request_type: RequestType,
        canister_method_name: String,
        time_secs: usize,
        nonce: String,
        call_payload_size: Byte,
        call_payload: Vec<u8>,
        canister_id: &CanisterId,
        periodic_output: bool,
        random_query_payload: bool,
    ) -> Vec<Fact> {
        let requests: usize = ((time_secs * rpms) as f64 / 1000f64).ceil() as usize;
        if requests == 0 {
            debug!("Not executing any requests");
            return vec![];
        }
        debug!(
            "⏱️  Executing {} requests at {} rps",
            requests,
            rpms as f64 / 1000f64
        );

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
            Some(rpms),
            time_origin,
        ));

        // Time between each two consecutive requests
        let inter_arrival_time = 1000. / rpms as f64;
        let mut tx_handles = vec![];
        for n in 0..requests {
            // Calculate the time at which the request should be running from start time
            // and inter arrival time.
            let target_instant =
                time_origin + START_OFFSET + Duration::from_secs_f64(inter_arrival_time * n as f64);
            sleep_until(tokio::time::Instant::from_std(target_instant)).await;
            let tx = tx.clone();
            let plan = plan.clone();
            let agent = self.agents[n % self.agents.len()].clone();
            FUTURE_STARTED.inc();
            tx_handles.push(tokio::task::spawn(async move {
                REQUEST_STARTING.inc();
                Engine::execute_request(agent, tx, time_origin, &plan, n, random_query_payload)
                    .await;
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

    #[allow(clippy::too_many_arguments)]
    async fn execute_request(
        agent: Agent,
        tx: Sender<CallResult>,
        time_origin: Instant,
        plan: &Plan,
        n: usize,
        random_query_payload: bool,
    ) -> bool {
        match plan.generate_call(n, random_query_payload) {
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
        let response = agent.execute_query(&plan.canister_id, &method, arg).await;
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

                let http_status = if err.ends_with("502 Bad Gateway</h1></center>\\\\r\\\\n<hr><center>nginx/1.21.3</center>\\\\r\\\\n</body>\\\\r\\\\n</html>\\\\r\\\\n\\\")\"") {
                    502_u16
                } else if err.ends_with("GoAway(b\\\"\\\", NO_ERROR, Remote) })\"") {
                    950_u16
                } else if err.ends_with("REFUSED_STREAM, Remote) })\"") {
                    951_u16
                } else if err.ends_with("runtime dropped the dispatch task\\\")\"") {
                    952_u16
                } else if err.starts_with("\"HttpClient: Request timed out") {
                    953_u16
                } else {
                    0_u16
                };

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
        let nonce =
            ic_crypto_sha2::Sha256::hash(&format!("inc {} {}", plan.nonce.clone(), n).into_bytes());
        let deadline = Instant::now() + agent.ingress_timeout;
        let (content, request_id) = prepare_update(
            &agent.sender,
            &plan.canister_id,
            method,
            arg,
            nonce.to_vec(),
            expiry_time_from_now(),
            agent.sender_field.clone(),
        )
        .unwrap();

        debug!("Sending signed update. request id: {}.", request_id);

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
                content.into(),
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
                    // See formula here:
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
                                    debug!("Error is: {}", err_msg);
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
        rpms: Option<usize>,
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
                rpms.map(|x| x as f64 / 1000f64).unwrap_or(0f64),
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

        if call_response.status == "rejected" {
            eprintln!("Reject message is: {:?}", call_response.reject_message);
        }
        let counter_value = call_response
            .reply
            .as_ref()
            .map(|bytes| Engine::interpret_counter_canister_response(bytes));
        Ok((call_response.status, counter_value))
    }
}
