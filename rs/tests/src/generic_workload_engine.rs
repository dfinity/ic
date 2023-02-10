use slog::{info, warn};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::task;
use tokio::time::sleep_until;

pub trait Aggregator {
    type Item;

    fn push(&mut self, item: Self::Item);
}

impl<T> Aggregator for Vec<T> {
    type Item = T;

    fn push(&mut self, item: Self::Item) {
        Vec::push(self, item);
    }
}

/// A generic Engine, which executes arbitrary Futures at a desired rate for a specified time period.
pub struct Engine<F, A> {
    log: slog::Logger,
    /// Callback function generating Futures for the Engine.
    futures_generator: F,
    /// Number of requests per second.
    rps: usize,
    /// Overall duration of the Engine execution.
    duration: Duration,
    /// All futures should be started strictly within this time bound. Note that actual execution can take additional time.
    dispatch_timeout: Duration,
    /// A (generally) stateful object that aggregates the results.
    aggregator: A,
}

impl<F, Fut, Out, A> Engine<F, A>
where
    F: FnMut(usize) -> Fut + Send + 'static,
    Out: Send + 'static,
    Fut: Future<Output = Out> + Send + 'static,
    A: Aggregator<Item = Out> + Send + 'static,
{
    // Constructor of the Engine.
    pub fn new(
        log: slog::Logger,
        future_generator: F,
        rps: usize,
        duration: Duration,
        aggregator: A,
    ) -> Self {
        Self {
            futures_generator: future_generator,
            rps,
            duration,
            log,
            dispatch_timeout: duration,
            aggregator,
        }
    }

    /// This extra timeout (normally very small) could provided if Futures can't be started strictly within the specified ([`self.duration`]) time bound.
    pub fn increase_dispatch_timeout(mut self, extra_timeout: Duration) -> Self {
        self.dispatch_timeout += extra_timeout;
        self
    }

    /// Start executing futures
    pub async fn execute(mut self) -> Result<A, EngineError> {
        let futures_count = self.rps * self.duration.as_secs() as usize;
        let (fut_snd, mut fut_rcv) = tokio::sync::mpsc::unbounded_channel();
        let log = self.log;

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
                    let target_instant =
                        start + Duration::from_secs_f64(idx as f64 / self.rps as f64);
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
            let mut aggr = self.aggregator;
            let log = log.clone();
            async move {
                while let Some((idx, jh)) = fut_rcv.recv().await {
                    if let Ok(res) = jh.await {
                        aggr.push(res);
                    } else {
                        warn!(log, "Failed to await join handle for task {idx}.");
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
    const RPS: usize = 10;
    const DURATION: Duration = Duration::from_secs(5);
    const EXTRA_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn engine_succeeds() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let future_generator = |_| async move { 1 };
        let agg = vec![];
        let engine = Engine::new(log.clone(), future_generator, RPS, DURATION, agg)
            .increase_dispatch_timeout(EXTRA_TIMEOUT);

        let engine_result = engine.execute().await;

        let futures_results = engine_result.expect("No engine error expected.");
        assert!(futures_results.iter().all(|r| *r == 1));
    }

    #[tokio::test]
    async fn engine_errors_with_timeout() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let future_generator = |_| async move {};
        let agg = vec![];
        let mut engine = Engine::new(log.clone(), future_generator, RPS, DURATION, agg);
        engine.dispatch_timeout -= Duration::from_secs(1); // one sec less than the actual duration

        let engine_result = engine.execute().await;

        use EngineError::*;
        match engine_result {
            Err(FuturesDispatchTimeout(err)) => {
                assert!(err.contains("Not all futures were started within the timeout of 4 secs"))
            }
            Err(FuturesExecutionFailure(_e)) => panic!("Unexpected execution failure."),
            Ok(_) => panic!("EngineError result is expected"),
        }
    }
}
