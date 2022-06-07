use ic_agent::{export::Principal, Agent};
use leaky_bucket::RateLimiter;
use slog::info;
use std::collections::HashMap;
use std::{
    cmp::{max, min},
    time::{Duration, Instant},
};
use tokio::time::timeout;
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
    /// All requests should be submitted strictly within this time bound.
    /// This value is the sum of the ([`self.duration`]) field and an additional extra timeout (if provided).
    requests_dispatch_timeout: Duration,
    /// Additional time bound for collecting all the responses, after requests' dispatch completion.
    responses_collection_extra_timeout: Duration,
    /// Duration of each request is bucket-sorted with respect to the predefined threshold values (above or below each threshold).
    /// This enables computing requests ratio (that are above/below predefined thresholds) in O(N) time/memory.
    /// Here N is the number of predefined thresholds/buckets.
    /// If one provides a range of duration thresholds, then approximate computation of percentiles could be done.
    requests_duration_thresholds: Option<Vec<Duration>>,
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
pub enum WorkloadError {
    RequestsDispatchTimeout(String),
    ResponsesCollectionTimeout(String),
    RequestDispatchFailure(String),
    ResponseCollectionFailure(String),
}

/// Defines result of the workload execution.
#[derive(Debug)]
pub struct Metrics {
    errors_max: Counter,
    errors_map: HashMap<String, Counter>,
    success_calls: Counter,
    failure_calls: Counter,
    min_request_duration: Duration,
    max_request_duration: Duration,
    requests_duration_buckets: Option<Vec<RequestDurationBucket>>,
}

impl Default for Metrics {
    fn default() -> Metrics {
        let errors_max = 10000;
        Metrics {
            errors_max,
            errors_map: HashMap::with_capacity(errors_max),
            success_calls: 0,
            failure_calls: 0,
            min_request_duration: Duration::MAX,
            max_request_duration: Duration::default(),
            requests_duration_buckets: None,
        }
    }
}

impl Metrics {
    pub fn with_requests_duration_bucket(&mut self, request_duration_thresholds: Vec<Duration>) {
        self.requests_duration_buckets = Some(
            request_duration_thresholds
                .into_iter()
                .map(|threshold| RequestDurationBucket::new(threshold))
                .collect(),
        );
    }

    pub fn total_calls(&self) -> Counter {
        self.success_calls + self.failure_calls()
    }

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

    pub fn errors(&self) -> &HashMap<String, Counter> {
        &self.errors_map
    }

    pub fn success_ratio(&self) -> f64 {
        self.success_calls as f64 / self.total_calls() as f64
    }

    pub fn failure_ratio(&self) -> f64 {
        1.0 - self.success_ratio()
    }

    pub fn process_request(&mut self, request: RequestResult) {
        self.min_request_duration = min(self.min_request_duration, request.duration);
        self.max_request_duration = max(self.max_request_duration, request.duration);
        if let Some(ref mut request_duration_bucket) = self.requests_duration_buckets {
            for bucket in request_duration_bucket.iter_mut() {
                if request.duration >= bucket.threshold {
                    bucket.requests_above_threshold += 1;
                } else {
                    bucket.requests_below_threshold += 1;
                }
            }
        }

        match request.call_status {
            CallStatus::Success => self.success_calls += 1,
            CallStatus::Failure(err) => {
                self.failure_calls += 1;
                *self.errors_map.entry(err).or_insert(0) += 1;
                if self.errors_map.len() > self.errors_max {
                    panic!(
                        "Hash table holding errors exceeded predefined max_size={}.",
                        self.errors_max
                    );
                }
            }
        }
    }

    pub fn find_request_duration_bucket(
        &self,
        threshold: Duration,
    ) -> Option<RequestDurationBucket> {
        match self.requests_duration_buckets {
            None => None,
            Some(ref x) => x.iter().find(|r| r.threshold == threshold).cloned(),
        }
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

#[derive(Default, Clone, Debug)]
pub struct RequestDurationBucket {
    threshold: Duration,
    requests_above_threshold: Counter,
    requests_below_threshold: Counter,
}

impl RequestDurationBucket {
    pub fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            ..Default::default()
        }
    }

    pub fn requests_ratio_below_threshold(&self) -> f64 {
        self.requests_below_threshold as f64
            / (self.requests_above_threshold + self.requests_below_threshold) as f64
    }

    pub fn requests_ratio_above_threshold(&self) -> f64 {
        1.0 - self.requests_ratio_below_threshold()
    }

    pub fn requests_count_below_threshold(&self) -> Counter {
        self.requests_below_threshold
    }

    pub fn requests_count_above_threshold(&self) -> Counter {
        self.requests_above_threshold
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
            requests_dispatch_timeout: duration,
            responses_collection_extra_timeout: Duration::ZERO,
            requests_duration_thresholds: None,
        }
    }

    pub fn with_requests_duration_bucket(mut self, duration_threshold: Duration) -> Self {
        match self.requests_duration_thresholds {
            Some(ref mut threshold) => threshold.push(duration_threshold),
            None => self.requests_duration_thresholds = Some(vec![duration_threshold]),
        }
        self
    }

    /// This extra timeout should normally not be provided.
    /// As the workload's rate limiter should ensure that requests are dispatched strictly within the specified ([`self.duration`]) time bound.
    /// However, there might be scenarios, where this dispatch time bound should be relaxed.
    pub fn increase_requests_dispatch_timeout(mut self, extra_timeout: Duration) -> Self {
        self.requests_dispatch_timeout += extra_timeout;
        self
    }

    pub fn with_responses_collection_extra_timeout(mut self, timeout: Duration) -> Self {
        self.responses_collection_extra_timeout = timeout;
        self
    }

    async fn dispatch_requests(
        &self,
        sender: Sender<RequestResult>,
        requests_count: usize,
    ) -> Result<(), WorkloadError> {
        let rate_limiter = RateLimiter::builder()
            .initial(self.rps)
            .interval(RATE_LIMITER_INTERVAL)
            .refill(self.rps)
            .build();

        let mut request_handles: Vec<JoinHandle<()>> = Vec::with_capacity(requests_count);

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
            if let Err(err) = handle.await {
                return Err(WorkloadError::RequestDispatchFailure(format!(
                    "Execution of the request with index={} failed with error={}.",
                    idx, err,
                )));
            }
        }
        Ok(())
    }

    /// Execute all requests against canisters.
    /// Requests are executed in separate tasks asynchronously.
    /// Each task executes a request and uses a "sender" (producer) object to place result of the request execution into a high-throughput
    /// channel. Another asynchronous task (collector) dequeues results from the channel via "receiver" (consumer) object and processes them.
    pub async fn execute(&self) -> Result<Metrics, WorkloadError> {
        let requests_count = self.rps * self.duration.as_secs() as usize;
        // Single consumer, multiple producers channel.
        let (sender, receiver) = channel::<RequestResult>(requests_count);
        let collector_handle = task::spawn(collect_results(
            self.log.clone(),
            self.requests_duration_thresholds.clone(),
            receiver,
            requests_count,
        ));
        info!(
            self.log,
            "Starting dispatch of {} requests, to be executed within {} sec.",
            requests_count,
            self.duration.as_secs()
        );
        let start = Instant::now();
        let is_timeout = timeout(
            self.requests_dispatch_timeout,
            self.dispatch_requests(sender, requests_count),
        )
        .await
        .is_err();
        if is_timeout {
            return Err(WorkloadError::RequestsDispatchTimeout(format!(
                "Requests were not submitted within the timeout of {} sec.",
                self.requests_dispatch_timeout.as_secs()
            )));
        }
        let requests_dispatch_duration = start.elapsed();
        info!(
            self.log,
            "Workload finished sending requests in: {} sec/{} ms/{} μs.",
            requests_dispatch_duration.as_secs(),
            requests_dispatch_duration.as_millis() % 1_000,
            requests_dispatch_duration.as_micros() % 1_000_000,
        );
        let metrics = match timeout(self.responses_collection_extra_timeout, collector_handle).await
        {
            Err(_) => {
                return Err(WorkloadError::ResponsesCollectionTimeout(format!(
                    "Responses were not collected within the timeout={} sec, after requests had been dispatched. Consider increasing the response collection timeout.",
                    self.responses_collection_extra_timeout.as_secs()
                )))
            }
            Ok(result) => match result {
                Err(err) => return Err(WorkloadError::ResponseCollectionFailure(err.to_string())),
                Ok(res) => res,
            },
        };
        let additional_resp_collection_duration = start.elapsed() - requests_dispatch_duration;
        info!(
            self.log,
            "It took additional {} sec/{} ms/{} μs to collect all responses, after requests were dispatched.",
            additional_resp_collection_duration.as_secs(),
            additional_resp_collection_duration.as_millis() % 1_000,
            additional_resp_collection_duration.as_micros() % 1_000_000
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
    requests_duration_thresholds: Option<Vec<Duration>>,
    mut receiver: Receiver<RequestResult>,
    requests_count: usize,
) -> Metrics {
    let mut metrics = Metrics::default();
    if let Some(threshold) = requests_duration_thresholds {
        metrics.with_requests_duration_bucket(threshold);
    }
    while let Some(request) = receiver.recv().await {
        metrics.process_request(request);
        if metrics.total_calls() == requests_count {
            info!(
                log,
                "Reached desired number of requests={}.", requests_count
            );
            break;
        }
    }
    metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_request_with_success_result() {
        let mut metrics = Metrics::default();
        let request = RequestResult {
            duration: Duration::from_secs(1),
            call_status: CallStatus::Success,
        };

        metrics.process_request(request);

        assert_eq!(1, metrics.success_calls());
        assert_eq!(0, metrics.failure_calls());
        assert_eq!(0, metrics.errors().len());
        assert_eq!(metrics.min_request_duration, Duration::from_secs(1));
        assert_eq!(metrics.max_request_duration, Duration::from_secs(1));
    }

    #[test]
    fn test_process_request_with_failure_results() {
        let mut metrics = Metrics::default();
        let request_1 = RequestResult {
            duration: Duration::from_secs(3),
            call_status: CallStatus::Failure("some_error".to_string()),
        };
        // Request with max duration.
        let request_2 = RequestResult {
            duration: Duration::from_secs(4),
            call_status: CallStatus::Failure("some_error".to_string()),
        };
        // Request with min duration.
        let request_3 = RequestResult {
            duration: Duration::from_secs(1),
            call_status: CallStatus::Failure("some_other_error".to_string()),
        };

        metrics.process_request(request_1);
        metrics.process_request(request_2);
        metrics.process_request(request_3);

        let errors = metrics.errors();
        assert_eq!(0, metrics.success_calls());
        assert_eq!(3, metrics.failure_calls());
        assert_eq!(errors["some_error"], 2);
        assert_eq!(errors["some_other_error"], 1);
        assert_eq!(metrics.min_request_duration, Duration::from_secs(1));
        assert_eq!(metrics.max_request_duration, Duration::from_secs(4));
    }

    #[test]
    fn test_process_request_with_duration_bucket() {
        let threshold = Duration::from_secs(3);
        let mut metrics = Metrics {
            requests_duration_buckets: Some(vec![RequestDurationBucket::new(threshold)]),
            ..Metrics::default()
        };
        let requests_below_threshold = RequestResult {
            duration: Duration::from_secs(1),
            call_status: CallStatus::Success,
        };
        let request_above_threshold = RequestResult {
            duration: Duration::from_secs(4),
            call_status: CallStatus::Success,
        };

        let bucket = metrics.find_request_duration_bucket(threshold).unwrap();
        assert_eq!(bucket.requests_count_above_threshold(), 0);
        assert_eq!(bucket.requests_count_below_threshold(), 0);
        // Act 1
        metrics.process_request(requests_below_threshold);
        let bucket = metrics.find_request_duration_bucket(threshold).unwrap();
        assert_eq!(bucket.requests_count_above_threshold(), 0);
        assert_eq!(bucket.requests_count_below_threshold(), 1);
        assert_eq!(bucket.requests_ratio_above_threshold(), 0.0);
        assert_eq!(bucket.requests_ratio_below_threshold(), 1.0);
        // Act 2
        metrics.process_request(request_above_threshold);
        let bucket = metrics.find_request_duration_bucket(threshold).unwrap();
        assert_eq!(bucket.requests_count_above_threshold(), 1);
        assert_eq!(bucket.requests_count_below_threshold(), 1);
        assert_eq!(bucket.requests_ratio_above_threshold(), 0.5);
        assert_eq!(bucket.requests_ratio_below_threshold(), 0.5);
        // Additional assertions
        let non_predefined_threshold = Duration::from_secs(5);
        let non_existing_bucket = metrics.find_request_duration_bucket(non_predefined_threshold);
        assert!(non_existing_bucket.is_none());
        assert_eq!(2, metrics.success_calls());
        assert_eq!(0, metrics.failure_calls());
        assert_eq!(0, metrics.errors().len());
        assert_eq!(metrics.min_request_duration, Duration::from_secs(1));
        assert_eq!(metrics.max_request_duration, Duration::from_secs(4));
    }

    #[test]
    #[should_panic(expected = "Hash table holding errors exceeded predefined max_size=1.")]
    fn test_process_request_with_overflow() {
        let mut metrics = Metrics {
            errors_max: 1,
            ..Default::default()
        };
        let request_1 = RequestResult {
            duration: Duration::from_secs(3),
            call_status: CallStatus::Failure("some_error".to_string()),
        };
        let request_2 = RequestResult {
            duration: Duration::from_secs(4),
            call_status: CallStatus::Failure("some_other_error".to_string()),
        };

        metrics.process_request(request_1);
        // This request causes an overflow in the hash table.
        metrics.process_request(request_2);
    }

    #[tokio::test]
    async fn test_collect_result() {
        let requests_count = 1;
        let (sender, receiver) = tokio::sync::mpsc::channel(requests_count);
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let request = RequestResult {
            duration: Duration::from_secs(1),
            call_status: CallStatus::Success,
        };
        sender
            .send(request)
            .await
            .expect("Sending request's result to the channel has failed.");

        let metrics = collect_results(log, None, receiver, requests_count).await;

        assert_eq!(metrics.success_calls(), 1);
    }
}
