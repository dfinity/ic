use std::cell::RefCell;
use std::thread::LocalKey;

pub mod stats;
pub use stats::SpanStats;

pub type SpanName = &'static str;

pub trait ProfilerSink {
    /// Records a new sample for the given span.
    fn record(self, span: SpanName, instructions: u64);
}

impl ProfilerSink for &'static LocalKey<RefCell<SpanStats>> {
    fn record(self, span: SpanName, instructions: u64) {
        self.with(|cell| cell.borrow_mut().record(span, instructions))
    }
}

/// Executes the closure and records the number of measured
/// instructions.
///
/// ```
/// use ic_canister_profiler::{SpanStats, measure_span};
/// use std::cell::{Cell, RefCell};
///
/// thread_local! {
///   static COUNTER: Cell<u64> = Cell::default();
///   static PROFILING_DATA: RefCell<SpanStats> = RefCell::default();
/// }
///
/// fn inc() {
///   measure_span(&PROFILING_DATA, "inc", || {
///     COUNTER.with(|c| c.set(1 + c.get()));
///   });
/// }
/// ```
pub fn measure_span<R>(sink: impl ProfilerSink, name: SpanName, f: impl FnOnce() -> R) -> R {
    #[cfg(target_arch = "wasm32")]
    let (r, measurement) = {
        let start = ic0::performance_counter(0);
        let r = f();
        let measurement = ic0::performance_counter(0).saturating_sub(start);
        (r, measurement as u64)
    };

    #[cfg(not(target_arch = "wasm32"))]
    let (r, measurement) = {
        let start = std::time::Instant::now();
        let r = f();
        let measurement = start.elapsed().as_millis() as u64;
        (r, measurement)
    };

    sink.record(name, measurement);
    r
}

/// Executes the future and records the number of measured
/// instructions.
///
/// ```
/// use ic_canister_profiler::{SpanStats, measure_span_async};
/// use std::cell::{Cell, RefCell};
///
/// thread_local! {
///   static COUNTER: Cell<u64> = Cell::default();
///   static PROFILING_DATA: RefCell<SpanStats> = RefCell::default();
/// }
///
/// async fn inc() {
///   measure_span_async(&PROFILING_DATA, "inc", async {
///     COUNTER.with(|c| c.set(1 + c.get()));
///   }).await;
/// }
/// ```
pub async fn measure_span_async<R, Fut>(sink: impl ProfilerSink, name: SpanName, f: Fut) -> R
where
    Fut: std::future::Future<Output = R>,
{
    #[cfg(target_arch = "wasm32")]
    let (r, measurement) = {
        let start = ic0::performance_counter(1);
        let r = f.await;
        let measurement = ic0::performance_counter(1).saturating_sub(start);
        (r, measurement as u64)
    };

    #[cfg(not(target_arch = "wasm32"))]
    let (r, measurement) = {
        let start = std::time::Instant::now();
        let r = f.await;
        let measurement = start.elapsed().as_millis() as u64;
        (r, measurement)
    };

    sink.record(name, measurement);
    r
}
