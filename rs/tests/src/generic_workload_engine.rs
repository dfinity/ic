use slog::info;
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::task;
use tokio::time::sleep_until;

/// A generic Engine, which executes arbitrary Futures at a desired rate for a specified time period.
pub struct Engine<F> {
    log: slog::Logger,
    /// Callback function generating Futures for the Engine.
    futures_generator: F,
    /// Number of requests per second.
    rps: usize,
    /// Overall duration of the Engine execution.
    duration: Duration,
    /// All futures should be started strictly within this time bound. Note that actual execution can take additional time.
    dispatch_timeout: Duration,
}

impl<F, Fut, Out> Engine<F>
where
    F: FnMut(usize) -> Fut,
    Out: Send + 'static,
    Fut: Future<Output = Out> + Send + 'static,
{
    // Constructor of the Engine.
    pub fn new(log: slog::Logger, future_generator: F, rps: usize, duration: Duration) -> Self {
        Self {
            futures_generator: future_generator,
            rps,
            duration,
            log,
            dispatch_timeout: duration,
        }
    }

    /// This extra timeout (normally very small) could provided if Futures can't be started strictly within the specified ([`self.duration`]) time bound.
    pub fn increase_dispatch_timeout(mut self, extra_timeout: Duration) -> Self {
        self.dispatch_timeout += extra_timeout;
        self
    }

    /// Start executing futures
    pub async fn execute(&mut self) -> Result<Vec<FutureResult<Out>>, EngineError> {
        let futures_count = self.rps * self.duration.as_secs() as usize;
        let mut futures_handles = Vec::with_capacity(futures_count);
        let mut futures_results = Vec::with_capacity(futures_count);
        info!(
            self.log,
            "Starting execution of {} futures, expected to be submitted within {} secs.",
            futures_count,
            self.duration.as_secs()
        );
        let start = Instant::now();
        for idx in 0..futures_count {
            let fut = (self.futures_generator)(idx);
            // Future is expected to start at this time instance.
            let target_instant = start + Duration::from_secs_f64(idx as f64 / self.rps as f64);
            sleep_until(tokio::time::Instant::from_std(target_instant)).await;
            let task = task::spawn(async move {
                let start = Instant::now();
                let result = fut.await;
                let duration = start.elapsed();
                FutureResult {
                    start,
                    duration,
                    result,
                }
            });
            futures_handles.push(task);
        }
        let dispatch_duration = start.elapsed();
        if dispatch_duration > self.dispatch_timeout {
            return Err(EngineError::FuturesDispatchTimeout(format!(
                "Not all futures were started within the timeout of {} secs, actual time {} ms.",
                self.dispatch_timeout.as_secs(),
                dispatch_duration.as_millis()
            )));
        }
        // Collect results of the futures execution.
        for (idx, handle) in futures_handles.iter_mut().enumerate() {
            let result = handle.await;
            if let Ok(res) = result {
                futures_results.push(res);
            } else {
                return Err(EngineError::FuturesExecutionFailure(format!(
                    "Execution of the future with index={} failed with error={}.",
                    idx,
                    result.err().unwrap(),
                )));
            }
        }
        info!(
            self.log,
            "All {} futures started within {} secs and executed to completion within {} secs",
            futures_count,
            dispatch_duration.as_secs(),
            start.elapsed().as_secs(),
        );
        Ok(futures_results)
    }
}

/// Fully defines execution result of the future.
/// Out is the associated Output type of the Future.
pub struct FutureResult<Out> {
    pub start: Instant,
    pub duration: Duration,
    pub result: Out,
}

/// Engine execution errors.
#[derive(Debug, Clone)]
pub enum EngineError {
    FuturesDispatchTimeout(String),
    FuturesExecutionFailure(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    const RPS: usize = 10;
    const DURATION: Duration = Duration::from_secs(5);
    const EXTRA_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn engine_succeeds() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let future_generator = |_| async move { 1 };
        let mut engine = Engine::new(log.clone(), future_generator, RPS, DURATION)
            .increase_dispatch_timeout(EXTRA_TIMEOUT);

        let engine_result = engine.execute().await;

        let futures_results = engine_result.expect("No engine error expected.");
        assert!(futures_results.iter().all(|r| r.result == 1));
    }

    #[tokio::test]
    async fn engine_errors_with_timeout() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let future_generator = |_| async move {};
        let mut engine = Engine::new(log.clone(), future_generator, RPS, DURATION);
        engine.dispatch_timeout -= Duration::from_secs(1); // one sec less than the actual duration

        let engine_result = engine.execute().await;

        match engine_result {
            Err(err) => match err {
                EngineError::FuturesDispatchTimeout(err) => assert!(
                    err.contains("Not all futures were started within the timeout of 4 secs",)
                ),
                EngineError::FuturesExecutionFailure(_) => panic!("Unexpected execution failure."),
            },
            Ok(_) => panic!("EngineError result is expected"),
        }
    }
}
