use ic_agent::{export::Principal, Agent};
use leaky_bucket::RateLimiter;
use slog::info;
use std::{
    cmp::{max, min},
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc::{channel, Receiver, Sender},
    task::{self, JoinHandle},
};

// Interval for a token-bucket rate limiter.
const RATE_LIMITER_INTERVAL: Duration = Duration::from_secs(1);

/// Trait defining execution/scheduling plan of the requests against canisters.
pub trait Plan {
    /// Returns a request object based on the request index.
    /// # Arguments
    ///
    /// * `request_idx` - index of the request.
    fn get_request(&self, request_idx: usize) -> Request;
}

/// A fair (equal choosing) distribution of requests against canisters.
pub struct RoundRobinPlan {
    requests: Vec<Request>,
}

/// Fully specifies load parameters and requests to be executed against canisters.
pub struct Workload<T> {
    /// Agents, which facilitate talking to replica.
    /// Requests are submitted via agents in a round-robin fashion.
    agents: Vec<Agent>,
    /// Number of requests per second.
    rps: usize,
    /// Overall duration of the requests execution.
    duration: Duration,
    /// Execution/scheduling plan of the requests.
    plan: T,
    log: slog::Logger,
}

/// Fully defines a call to be executed against a canister.
/// An Agent is needed to submit this request to a replica.
#[derive(Clone)]
pub enum Request {
    Query(CallSpec),
    Update(CallSpec),
}

/// Part of the canister call ([`Request`]) definition.
#[derive(Clone)]
pub struct CallSpec {
    canister_id: Principal,
    method_name: String,
    payload: Vec<u8>,
}

/// Defines success/failure execution status of the canister call.
/// Part of the [`RequestResult`] definition.
#[derive(Debug)]
pub enum CallStatus {
    Success,
    Failure(String),
}

/// Fully defines execution result of the canister call.
#[derive(Debug)]
pub struct RequestResult {
    /// Duration of the request.
    duration: Duration,
    call_status: CallStatus,
}

type Counter = usize;

#[derive(Debug, Clone)]
pub struct WorkloadError;

/// Defines result of the workload execution.
pub struct Metrics {
    total_calls: Counter,
    success_calls: Counter,
    failure_calls: Counter,
    min_request_duration: Duration,
    max_request_duration: Duration,
}

impl Default for Metrics {
    fn default() -> Metrics {
        Metrics {
            total_calls: 0,
            success_calls: 0,
            failure_calls: 0,
            min_request_duration: Duration::MAX,
            max_request_duration: Duration::default(),
        }
    }
}

impl Metrics {
    pub fn success_calls(&self) -> Counter {
        self.success_calls
    }

    pub fn failure_calls(&self) -> Counter {
        self.failure_calls
    }

    pub fn min_request_duration(&self) -> Duration {
        self.min_request_duration
    }

    pub fn max_request_duration(&self) -> Duration {
        self.max_request_duration
    }
}

impl CallSpec {
    pub fn new(canister_id: Principal, method_name: &str, payload: Vec<u8>) -> Self {
        Self {
            canister_id,
            method_name: method_name.to_string(),
            payload,
        }
    }
}

impl RoundRobinPlan {
    pub fn new(requests: Vec<Request>) -> Self {
        Self { requests }
    }
}

impl Plan for RoundRobinPlan {
    fn get_request(&self, request_idx: usize) -> Request {
        // Distribute requests equally/fairly via round-robin.
        let idx = request_idx % self.requests.len();
        self.requests[idx].clone()
    }
}

impl<T: Plan> Workload<T> {
    pub fn new(
        agents: Vec<Agent>,
        rps: usize,
        duration: Duration,
        plan: T,
        log: slog::Logger,
    ) -> Self {
        if agents.is_empty() {
            panic!("No agents were provided for the workload.");
        }
        Self {
            agents,
            rps,
            duration,
            plan,
            log,
        }
    }

    /// Execute all requests against canisters.
    /// Requests are executed in separate tasks asynchronously.
    /// Each task executes a request and uses a "sender" (producer) object to place result of the request execution into a high-throughput
    /// channel. Another asynchronous task (collector) dequeues results from the channel via "receiver" (consumer) object and processes them.
    pub async fn execute(&self) -> Result<Metrics, WorkloadError> {
        let requests_count = self.rps * self.duration.as_secs() as usize;

        let rate_limiter = RateLimiter::builder()
            .initial(self.rps)
            .interval(RATE_LIMITER_INTERVAL)
            .refill(self.rps)
            .build();

        // Single consumer, multiple producers channel.
        let (sender, receiver) = channel(requests_count);
        let collector_handle =
            tokio::task::spawn(collect_results(self.log.clone(), receiver, requests_count));
        let mut request_handles: Vec<JoinHandle<()>> = Vec::with_capacity(requests_count);

        info!(
            self.log,
            "Starting workload execution with {} requests.", requests_count,
        );
        let start = Instant::now();
        for idx in 0..requests_count {
            rate_limiter.acquire_one().await;
            let request = self.plan.get_request(idx);
            let agent = {
                // Round-robin distribution of requests via agents.
                let agent_idx = idx % self.agents.len();
                self.agents[agent_idx].clone()
            };
            let task = task::spawn(execute_request(request, agent, sender.clone()));
            request_handles.push(task);
        }
        for (idx, handle) in request_handles.iter_mut().enumerate() {
            handle
                .await
                .unwrap_or_else(|_| panic!("Execution of the request with index={} failed.", idx));
        }
        let metrics = collector_handle
            .await
            .expect("Execution of the results collector failed.");
        let duration = start.elapsed();
        info!(
            self.log,
            "Workload execution finished in {} secs and {} ms.",
            duration.as_secs(),
            duration.as_millis() % 1000
        );
        Ok(metrics)
    }
}

/// Executes a method call against a canister via agent.
/// # Arguments
///
/// * `request` - a full definition of the method call against an canister.
/// * `agent` - an Agent to talk to a replica.
/// * `sender` - a producer, which submits the result of request execution to a channel.
async fn execute_request(request: Request, agent: Agent, sender: Sender<RequestResult>) {
    let start = Instant::now();
    let call_status = {
        let request_result = match request {
            Request::Update(spec) => agent
                .update(&spec.canister_id, spec.method_name)
                .with_arg(spec.payload)
                .call()
                .await
                .map(|_| ()),
            Request::Query(spec) => agent
                .query(&spec.canister_id, spec.method_name)
                .with_arg(spec.payload)
                .call()
                .await
                .map(|_| ()),
        };
        match request_result {
            Ok(_) => CallStatus::Success,
            Err(err) => CallStatus::Failure(err.to_string()),
        }
    };
    let duration = start.elapsed();
    sender
        .send(RequestResult {
            duration,
            call_status,
        })
        .await
        .expect("Sending request's result to the channel has failed.");
}

/// A collector, implementing a very simple post-processing/aggregation of the executed requests.
async fn collect_results(
    log: slog::Logger,
    mut receiver: Receiver<RequestResult>,
    requests_count: usize,
) -> Metrics {
    let mut metrics = Metrics::default();
    while let Some(result) = receiver.recv().await {
        metrics.total_calls += 1;
        metrics.min_request_duration = min(metrics.min_request_duration, result.duration);
        metrics.max_request_duration = max(metrics.max_request_duration, result.duration);
        match result.call_status {
            CallStatus::Success => metrics.success_calls += 1,
            CallStatus::Failure(_) => metrics.failure_calls += 1,
        }
        if metrics.total_calls == requests_count {
            info!(
                log,
                "Reached desired number of requests={}.", requests_count
            );
            break;
        }
    }
    metrics
}
