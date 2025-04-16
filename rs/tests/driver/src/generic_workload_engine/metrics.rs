use std::fmt::Display;
use std::time::Instant;
use std::{
    cmp::{max, min},
    collections::{BTreeMap, HashMap},
    time::Duration,
};

use async_trait::async_trait;
use itertools::Itertools;
use slog::{info, Logger};

use crate::util::{add_box_drawing_left_border, pad_all_lines_but_first};

use super::engine::Engine;

#[derive(Clone, Debug, Default)]
pub struct RequestDurationBucket {
    threshold: Duration,
    requests_below_threshold: u64,
}

impl RequestDurationBucket {
    pub fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            ..Default::default()
        }
    }

    pub fn requests_count_below_threshold(&self) -> u64 {
        self.requests_below_threshold
    }
}

pub type Counter = usize;

#[derive(Clone, Debug)]
pub struct RequestMetrics {
    errors_max: Counter,
    errors_map: HashMap<String, Counter>,
    min_attempts: Counter,
    total_attempts: Counter,
    max_attempts: Counter,
    success_calls: Counter,
    failure_calls: Counter,
    min_request_duration: Duration,
    max_request_duration: Duration,
    total_requests_duration: Duration,
    requests_duration_buckets: Vec<RequestDurationBucket>,
}

/// Outcome of a request-based workflow, i.e., r_1, r_2, ..., r_N in which each individual request r_i may depend on the outcome of r_{i-1}
pub type LoadTestOutcome<T, S> = Vec<(String, RequestOutcome<T, S>)>;

pub struct LoadTestMetrics {
    inner: BTreeMap<String, RequestMetrics>,
    last_time_emitted: Instant,
    logger: Logger,
    requests_duration_categories: Vec<Duration>,
}

impl LoadTestMetrics {
    pub fn new(logger: Logger) -> Self {
        Self {
            inner: Default::default(),
            last_time_emitted: Instant::now(),
            logger,
            requests_duration_categories: vec![],
        }
    }

    pub fn with_requests_duration_categorizations(
        mut self,
        duration_categories: Vec<Duration>,
    ) -> Self {
        for duration in duration_categories {
            self.requests_duration_categories.push(duration);
        }
        self
    }

    pub fn success_calls(&self) -> Counter {
        self.inner
            .values()
            .fold(0usize, |acc, x| acc + x.success_calls())
    }

    pub fn failure_calls(&self) -> Counter {
        self.inner
            .values()
            .fold(0usize, |acc, x| acc + x.failure_calls())
    }

    pub fn total_calls(&self) -> Counter {
        self.success_calls() + self.failure_calls()
    }

    pub fn errors(&self) -> HashMap<String, Counter> {
        self.inner.values().fold(HashMap::new(), |mut acc, x| {
            for (error, count) in x.errors() {
                acc.entry(error.clone())
                    .and_modify(|total_count| *total_count += *count)
                    .or_insert(*count);
            }
            acc
        })
    }

    pub fn requests_count_below_threshold(&self, threshold: Duration) -> Vec<(String, u64)> {
        self.inner
            .iter()
            .map(|(key, val)| {
                (
                    key.clone(),
                    val.requests_duration_buckets
                        .iter()
                        .find(|bucket| bucket.threshold == threshold)
                        .expect("No bucket with a given threshold exists.")
                        .requests_count_below_threshold(),
                )
            })
            .collect()
    }

    pub fn aggregate_load_testing_metrics<T, S>(mut self, item: LoadTestOutcome<T, S>) -> Self
    where
        T: Clone,
        S: Clone + Display,
    {
        // Initialize empty request metrics with duration buckets.
        let empty_request_metrics = RequestMetrics {
            requests_duration_buckets: self
                .requests_duration_categories
                .iter()
                .cloned()
                .map(RequestDurationBucket::new)
                .collect(),
            ..Default::default()
        };
        item.into_iter().for_each(|(req_name, outcome)| {
            let entry = self
                .inner
                .entry(req_name)
                .or_insert_with(|| empty_request_metrics.clone());
            entry.push(outcome)
        });
        self.log_throttled();
        self
    }

    fn log_throttled(&mut self) {
        if self.last_time_emitted.elapsed() > Duration::from_secs(5) {
            info!(&self.logger, "{self}");
            self.last_time_emitted = Instant::now();
        }
    }

    pub fn aggregator_fn(
        aggr: LoadTestMetrics,
        item: LoadTestOutcome<(), impl ToString>,
    ) -> LoadTestMetrics {
        let item = item
            .into_iter()
            .map(|(s, outcome)| (s, outcome.map_err(|err| err.to_string())))
            .collect::<Vec<_>>();
        aggr.aggregate_load_testing_metrics(item)
    }
}

impl Display for LoadTestMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Compute number of symbols in longest label
        let label_width = self
            .inner
            .iter()
            .map(|x| x.0)
            .max_by(|x, y| x.chars().count().cmp(&y.chars().count()))
            .map(|x| x.chars().count());
        let label_width = label_width.unwrap_or(10);
        writeln!(f, "LoadTestMetrics {{")
            .and(
                self.inner
                    .iter()
                    .fold(write!(f, ""), |acc, (req_name, metrics)| {
                        acc.and(write!(f, "     {req_name:<label_width$} "))
                            .and(metrics.fmt(f))
                    }),
            )
            .and(write!(f, "}}"))
    }
}

impl RequestMetrics {
    pub fn total_calls(&self) -> Counter {
        self.success_calls + self.failure_calls
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

    pub fn avg_request_duration(&self) -> Option<Duration> {
        self.total_requests_duration
            .checked_div(self.total_calls().try_into().unwrap())
    }

    pub fn success_rate(&self) -> f64 {
        (100 * self.success_calls()) as f64 / (self.total_calls() as f64)
    }

    pub fn max_request_duration(&self) -> Duration {
        self.max_request_duration
    }

    pub fn min_attempts(&self) -> Counter {
        self.min_attempts
    }

    pub fn max_attempts(&self) -> Counter {
        self.max_attempts
    }

    pub fn avg_attempts(&self) -> f64 {
        (self.total_attempts as f64) / (self.total_calls() as f64)
    }

    pub fn errors(&self) -> &HashMap<String, Counter> {
        &self.errors_map
    }

    pub fn push<T, S>(&mut self, item: RequestOutcome<T, S>)
    where
        T: Clone,
        S: Clone + ToString,
    {
        self.min_request_duration = min(self.min_request_duration, item.duration);
        self.max_request_duration = max(self.max_request_duration, item.duration);
        self.total_requests_duration += item.duration;

        self.min_attempts = min(self.min_attempts, item.attempts);
        self.max_attempts = max(self.max_attempts, item.attempts);
        self.total_attempts += item.attempts;

        for bucket in self.requests_duration_buckets.iter_mut() {
            if item.duration < bucket.threshold {
                bucket.requests_below_threshold += 1;
            }
        }

        if let Err(error) = item.result {
            self.failure_calls += 1;
            *self.errors_map.entry(error.to_string()).or_insert(0) += 1;
            if self.errors_map.len() > self.errors_max {
                panic!(
                    "Hash table holding errors exceeded predefined max_size={}.",
                    self.errors_max
                );
            }
        } else {
            self.success_calls += 1;
        }
    }
}

impl Default for RequestMetrics {
    fn default() -> Self {
        let errors_max = 10_000;
        RequestMetrics {
            errors_max,
            errors_map: HashMap::with_capacity(errors_max),
            success_calls: 0,
            failure_calls: 0,
            min_request_duration: Duration::MAX,
            max_request_duration: Duration::ZERO,
            total_requests_duration: Duration::ZERO,
            min_attempts: Counter::MAX,
            max_attempts: 0,
            total_attempts: 0,
            requests_duration_buckets: vec![],
        }
    }
}

impl Display for RequestMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RequestMetrics {{ duration=(min:{:>6}ms, avg:{}ms, max:{:>6}ms), attempts=(min:{:>3}, avg:{:>5.1}, max:{:>3}), success_rate:{:>6.2}%, successes:{:>7}, failures:{:>7}",
            self.min_request_duration().as_millis(),
            self.avg_request_duration().map(|x| format!("{:>8.1}", x.as_millis())).unwrap_or_else(|| "     inf".to_string()),
            self.max_request_duration().as_millis(),
            self.min_attempts(),
            self.avg_attempts(),
            self.max_attempts(),
            self.success_rate(),
            self.success_calls(),
            self.failure_calls(),
        ).and(
            if self.errors_map.is_empty() {
                writeln!(f, "}}")
            } else {
                writeln!(f, " errors:").and(
                    self.errors_map.iter().sorted_unstable_by(|(err_a, count_a), (err_b, count_b)| count_a.cmp(count_b).then(err_a.cmp(err_b))).fold(write!(f, ""), |acc, (error, count)| {
                        let error: String = error.replace("\\n", "\n");
                        let prefix = format!("         {count:>7} x ");
                        // Format the error if it's multiple lines, otherwise just print it as is.
                        let error = {
                            if error.contains('\n') {
                                pad_all_lines_but_first(add_box_drawing_left_border(error), prefix.len())
                            } else {
                                error
                            }
                        };

                        acc.and(writeln!(f, "{prefix}{error}"))
                    })
                ).and(writeln!(f, "     }}"))
            }
        )
    }
}

/// Outcome of a **generalized** request, e.g.:
/// - A single canister endpoint request (query or update)
/// - An HTTP request that is expected to return a JSON object of a particular shape
///
/// [`ResultType`] can be instantiated with one of the following:
/// 1. Unit, i.e., [`()`], meaning that we are solely interested in whether there has been an error, and the result value is not used.
/// 2. A concrete type, e.g., [`Value`] for an http_request that serves a JSON object.
///    This is the preferred case, as the client can then match on the structure of [`ResultType`] without needing to decode it.
/// 3. A generic encoding of a response, i.e., [`Vec<u8>`]. This allows aggregating multiple instances of [`RequestOutcome`],
///    even when they correspond to different requests that return responses of incompatible types. For example, this is needed
///    for collecting metrics in a stateful workload generation scenario, when one first calls request A and then (upon its success)
///    request B, and if type(response(A)) != type(response(B)).
#[derive(Clone, Debug)]
pub struct RequestOutcome<ResultType, ErrorType> {
    result: Result<ResultType, ErrorType>,
    /// Each request class can be identified via a [`(workflow_pos, label)`] pair used to aggregate statistical information about outcomes of multiple requests with the same label.
    /// - [`workflow_pos`] is an (optional, unique) position of this request in its workflow. [`None`] is used to classify the overall workflow outcome, in which case the position
    ///   is statically unknown. See [`with_workflow_position`]
    /// - [`label`] is a canister endpoint name, or some other (short) description of the request.
    ///   See [`RequestOutcome.into_test_outcome`].
    workflow_pos: Option<usize>,
    label: String,
    pub duration: Duration,
    pub attempts: Counter,
}

impl<ResultType, ErrorType> RequestOutcome<ResultType, ErrorType> {
    pub fn new(
        result: Result<ResultType, ErrorType>,
        label: String,
        duration: Duration,
        attempts: Counter,
    ) -> Self {
        Self {
            result,
            workflow_pos: None,
            label,
            duration,
            attempts,
        }
    }

    fn map_result<F, NewResultType, NewErrorType>(
        self,
        f: F,
    ) -> RequestOutcome<NewResultType, NewErrorType>
    where
        F: FnOnce(Result<ResultType, ErrorType>) -> Result<NewResultType, NewErrorType>,
    {
        RequestOutcome {
            result: f(self.result),
            workflow_pos: self.workflow_pos,
            label: self.label,
            duration: self.duration,
            attempts: self.attempts,
        }
    }

    /// Maps a `RequestOutcome<ResultType, ErrorType>` to `RequestOutcome<NewResultType, ErrorType>` by applying a function to a contained `Ok` value of `self.result`,
    /// leaving an `Err` value untouched.
    ///
    /// A common pattern is `request_outcome.map(|_| ())`, used for making request outcomes compatible with the provided `RequestMetrics` aggregators.
    pub fn map<F, NewResultType>(self, f: F) -> RequestOutcome<NewResultType, ErrorType>
    where
        F: FnOnce(ResultType) -> NewResultType,
    {
        self.map_result(|result| result.map(f))
    }

    /// Maps a `RequestOutcome<ResultType, ErrorType>` to `RequestOutcome<ResultType, NewErrorType>` by applying a function to a contained `Err` value of `self.result`,
    /// leaving an `Ok` value untouched.
    pub fn map_err<F, NewErrorType>(self, f: F) -> RequestOutcome<ResultType, NewErrorType>
    where
        F: FnOnce(ErrorType) -> NewErrorType,
    {
        self.map_result(|result| result.map_err(f))
    }

    pub fn into_test_outcome(self) -> LoadTestOutcome<ResultType, ErrorType> {
        vec![(self.key(), self)]
    }

    pub fn with_workflow_position(mut self, pos: usize) -> Self {
        self.workflow_pos = Some(pos);
        self
    }

    pub fn result(self) -> Result<ResultType, ErrorType> {
        self.result
    }

    // Pushes the outcome to the provided `test_outcome`, and returns a boolean indicating whether the outcome was `ok`.
    pub fn push_outcome_owned(
        self,
        test_outcome: &mut LoadTestOutcome<ResultType, ErrorType>,
    ) -> bool {
        let is_ok = self.result.is_ok();
        test_outcome.push((self.key(), self));
        is_ok
    }

    fn key(&self) -> String {
        if let Some(workflow_pos) = self.workflow_pos {
            format!("{workflow_pos}_{}", self.label)
        } else {
            self.label.clone()
        }
    }

    /// Map `RequestOutcome<ResultType, ErrorType>` to a new `RequestOutcome<(), ErrorType>` instance by applying `checker` to the `Ok` result of `self`.
    ///
    /// This method is convenient, e.g., for checking a request response.
    pub fn check_response<F>(self, checker: F) -> RequestOutcome<(), ErrorType>
    where
        F: FnOnce(ResultType) -> Result<(), ErrorType>,
    {
        self.map_result(|result| {
            if let Ok(response) = result {
                checker(response)
            } else {
                result.map(|_| ())
            }
        })
    }
}

impl<ResultType> RequestOutcome<ResultType, anyhow::Error> {
    pub fn context(self, context: impl ToString) -> Self {
        self.map_err(|err| err.context(context.to_string()))
    }
}

impl<ResultType: Clone, ErrorType: Clone> RequestOutcome<ResultType, ErrorType> {
    /// A convenience function - equivalent to `RequestOutcome::push_outcome_owned`,
    /// except it clones the result so you don't have to.
    pub fn push_outcome(self, test_outcome: &mut LoadTestOutcome<ResultType, ErrorType>) -> Self {
        self.clone().push_outcome_owned(test_outcome);
        self
    }
}

impl<ResultType: Clone, ErrorType: std::fmt::Debug> RequestOutcome<ResultType, ErrorType> {
    /// Convenience function. Like `push_outcome`, but converts its `ErrorType` to a `String` first.
    pub fn push_outcome_display_error(
        self,
        test_outcome: &mut LoadTestOutcome<ResultType, String>,
    ) -> Self {
        let new = RequestOutcome::<ResultType, String> {
            result: match self.result {
                Ok(ref result) => Ok(result.clone()),
                Err(ref err) => Err(format!("{err:?}")),
            },
            workflow_pos: self.workflow_pos,
            label: self.label.clone(),
            duration: self.duration,
            attempts: self.attempts,
        };
        new.push_outcome_owned(test_outcome);
        self
    }
}

#[async_trait]
pub trait LoadTestMetricsProvider {
    /// Execute and aggregate the outcome into a `LoadTestMetrics` object.
    ///
    /// The `log` argument is used for logging intermediate aggregations, converging to the result of this method.
    async fn execute_simply(mut self, log: Logger) -> LoadTestMetrics;
}

#[async_trait]
impl<F, Fut, E> LoadTestMetricsProvider for Engine<F>
where
    E: ToString + Send + 'static,
    F: FnMut(usize) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = LoadTestOutcome<(), E>> + Send + 'static,
{
    async fn execute_simply(mut self, log: Logger) -> LoadTestMetrics {
        let aggr = LoadTestMetrics::new(log);
        let fun = LoadTestMetrics::aggregator_fn;
        self.execute(aggr, fun)
            .await
            .expect("Execution of the workload failed.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_test_metrics() {
        // Emulate test A
        let outcome_a = {
            let mut outcome: LoadTestOutcome<(), String> = LoadTestOutcome::default();
            {
                let result: Result<(), String> = Ok(());
                let label = "request-0".to_string();
                let duration = Duration::from_millis(20_000);
                let attempts = 2;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .with_workflow_position(0)
            .push_outcome(&mut outcome);
            {
                let result: Result<(), String> = Ok(());
                let label = "request-1".to_string();
                let duration = Duration::from_millis(1_000);
                let attempts = 1;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .with_workflow_position(1)
            .push_outcome(&mut outcome);
            {
                let result: Result<(), String> = Err("request-2-failure".to_string());
                let label = "request-2".to_string();
                let duration = Duration::from_millis(5_000);
                let attempts = 5;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .with_workflow_position(2)
            .push_outcome(&mut outcome);
            outcome
        };

        // Emulate test B
        let outcome_b = {
            let mut outcome: LoadTestOutcome<(), String> = LoadTestOutcome::default();
            {
                let result: Result<(), String> = Ok(());
                let label = "request-0".to_string();
                let duration = Duration::from_millis(30_000);
                let attempts = 3;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .with_workflow_position(0)
            .push_outcome(&mut outcome);
            {
                let result: Result<(), String> = Err("request-1-failure".to_string());
                let label = "request-1".to_string();
                let duration = Duration::from_millis(99_000);
                let attempts = 99;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .with_workflow_position(1)
            .push_outcome(&mut outcome);
            {
                let result: Result<(), String> = Err("request-2-failure".to_string());
                let label = "request-2".to_string();
                let duration = Duration::from_millis(5_000);
                let attempts = 5;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .with_workflow_position(2)
            .push_outcome(&mut outcome);
            outcome
        };

        // Aggregate
        let m = {
            let log = slog::Logger::root(slog::Discard, slog::o!());
            LoadTestMetrics::new(log)
                .aggregate_load_testing_metrics(outcome_a)
                .aggregate_load_testing_metrics(outcome_b)
        };

        // Print metrics
        println!("test_load_test_metrics: {m}");

        // Perform checks
        {
            let (success_calls, expectected_success_calls) = (m.success_calls(), 3usize);
            assert_eq!(
                success_calls, expectected_success_calls,
                "Expected {expectected_success_calls} success calls but observed {success_calls}"
            );
        }
        {
            let (failure_calls, expected_failure_calls) = (m.failure_calls(), 3usize);
            assert_eq!(
                failure_calls, expected_failure_calls,
                "Expected {expected_failure_calls} failure calls but observed {failure_calls}"
            );
        }
        {
            let (total_calls, expected_total_calls) = (m.total_calls(), 6usize);
            assert_eq!(
                total_calls, expected_total_calls,
                "Expected {expected_total_calls} calls but observed {total_calls}"
            );
        }
        {
            let (errors, expected_errors) = (
                m.errors(),
                vec![
                    ("request-1-failure".to_string(), 1usize),
                    ("request-2-failure".to_string(), 2usize),
                ]
                .into_iter()
                .collect::<HashMap<String, usize>>(),
            );
            assert_eq!(
                errors, expected_errors,
                "Observed errors {errors:?} did not match expected errors {expected_errors:?}"
            );
        }
    }

    #[test]
    fn test_load_test_metrics_collision() {
        // Emulate test C
        let outcome_c = {
            let mut outcome: LoadTestOutcome<(), String> = LoadTestOutcome::default();
            {
                let result: Result<(), String> = Ok(());
                let label = "request-3".to_string();
                let duration = Duration::from_millis(1_000);
                let attempts = 1;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .push_outcome(&mut outcome);
            {
                let result: Result<(), String> = Err("failure".to_string());
                let label = "request-4".to_string();
                let duration = Duration::from_millis(5_000);
                let attempts = 5;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .push_outcome(&mut outcome);
            outcome
        };

        // Emulate test D
        let outcome_d = {
            let mut outcome: LoadTestOutcome<(), String> = LoadTestOutcome::default();
            {
                let result: Result<(), String> = Err("failure".to_string());
                let label = "request-3".to_string();
                let duration = Duration::from_millis(99_000);
                let attempts = 99;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .push_outcome(&mut outcome);
            {
                let result: Result<(), String> = Err("failure".to_string());
                let label = "request-4".to_string();
                let duration = Duration::from_millis(5_000);
                let attempts = 5;
                RequestOutcome::new(result, label, duration, attempts)
            }
            .push_outcome(&mut outcome);
            outcome
        };

        // Aggregate
        let m = {
            let log = slog::Logger::root(slog::Discard, slog::o!());
            LoadTestMetrics::new(log)
                .aggregate_load_testing_metrics(outcome_c)
                .aggregate_load_testing_metrics(outcome_d)
        };

        // Print metrics
        println!("test_load_test_metrics: {m}");

        // Perform checks
        {
            let (errors, expected_errors) = (
                m.errors(),
                vec![("failure".to_string(), 3usize)]
                    .into_iter()
                    .collect::<HashMap<String, usize>>(),
            );
            assert_eq!(
                errors, expected_errors,
                "Observed errors {errors:?} did not match expected errors {expected_errors:?}"
            );
        }
    }
}
