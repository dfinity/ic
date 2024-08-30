use slog::{info, warn};
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
    rps: f64,
    /// Overall duration of the Engine execution.
    duration: Duration,
    /// All futures should be started strictly within this time bound. Note that actual execution can take additional time.
    dispatch_timeout: Duration,
}

impl<F, Fut, Out> Engine<F>
where
    F: FnMut(usize) -> Fut + Send + 'static,
    Out: Send + 'static,
    Fut: Future<Output = Out> + Send + 'static,
{
    // Constructor of the Engine.
    pub fn new(log: slog::Logger, future_generator: F, rps: f64, duration: Duration) -> Self {
        assert!(rps > 0.0, "Requests per second have to be positive.");
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
    pub async fn execute<A, Fold>(mut self, mut aggr: A, f: Fold) -> Result<A, EngineError>
    where
        Fold: Fn(A, Out) -> A + Send + 'static,
        A: Send + 'static,
    {
        let log = self.log;
        let futures_count = (self.rps * self.duration.as_secs_f64()).floor() as usize;
        #[allow(clippy::disallowed_methods)]
        let (fut_snd, mut fut_rcv) = tokio::sync::mpsc::unbounded_channel();
        info!(
            log,
            "Starting execution of {} futures, expected to be submitted within {} secs.",
            futures_count,
            self.duration.as_secs()
        );
        let start = Instant::now();
        let dispatch_jh = task::spawn({
            let log = log.clone();
            async move {
                for idx in 0..futures_count {
                    let fut = (self.futures_generator)(idx);
                    // Future is expected to start at this time instance.
                    let target_instant = start + Duration::from_secs_f64(idx as f64 / self.rps);
                    sleep_until(tokio::time::Instant::from_std(target_instant)).await;
                    let task_jh = task::spawn(fut);
                    if fut_snd.send((idx, task_jh)).is_err() {
                        warn!(log, "Could not send future handle for index {idx}");
                    }
                }
                start.elapsed()
            }
        });
        let aggr_jh = task::spawn({
            let log = log.clone();
            async move {
                while let Some((idx, jh)) = fut_rcv.recv().await {
                    match jh.await {
                        Ok(res) => {
                            aggr = f(aggr, res);
                        }
                        Err(err) => {
                            warn!(log, "Failed to await join handle for task {idx}: {err:?}");
                        }
                    }
                }
                aggr
            }
        });
        let dispatch_duration = match dispatch_jh.await {
            Ok(v) => v,
            Err(_e) => {
                return Err(EngineError::FuturesExecutionFailure(
                    "Could not await dispatcher task".into(),
                ))
            }
        };
        if dispatch_duration > self.dispatch_timeout {
            return Err(EngineError::FuturesDispatchTimeout(format!(
                "Not all futures were started within the timeout of {} secs, actual time {} ms.",
                self.dispatch_timeout.as_secs(),
                dispatch_duration.as_millis()
            )));
        }
        info!(
            log,
            "All {} futures started within {} secs and executed to completion within {} secs",
            futures_count,
            dispatch_duration.as_secs(),
            start.elapsed().as_secs(),
        );
        aggr_jh.await.map_err(|_| {
            EngineError::FuturesExecutionFailure("Could not await aggregator task.".into())
        })
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
    const RPS: f64 = 10.0;
    const DURATION: Duration = Duration::from_secs(5);
    const EXTRA_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn engine_succeeds() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let future_generator = |_| async move { 1 };
        let engine = Engine::new(log.clone(), future_generator, RPS, DURATION)
            .increase_dispatch_timeout(EXTRA_TIMEOUT);

        let agg = vec![];
        let engine_result = engine.execute(agg, vec_aggr).await;

        let futures_results = engine_result.expect("No engine error expected.");
        assert!(futures_results.iter().all(|r| *r == 1));
    }

    #[tokio::test]
    async fn engine_errors_with_timeout() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let future_generator = |_| async move {};
        let mut engine = Engine::new(log.clone(), future_generator, RPS, DURATION);
        engine.dispatch_timeout -= Duration::from_secs(1); // one sec less than the actual duration

        let agg = vec![];
        let engine_result = engine.execute(agg, vec_aggr).await;

        use EngineError::*;
        match engine_result {
            Err(FuturesDispatchTimeout(err)) => {
                assert!(err.contains("Not all futures were started within the timeout of 4 secs"))
            }
            Err(FuturesExecutionFailure(_e)) => panic!("Unexpected execution failure."),
            Ok(_) => panic!("EngineError result is expected"),
        }
    }

    fn vec_aggr<Out>(mut aggr: Vec<Out>, out: Out) -> Vec<Out> {
        aggr.push(out);
        aggr
    }
}
