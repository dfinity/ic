use lazy_static::lazy_static;
use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, HistogramVec,
    IntCounter, IntCounterVec,
};

// Metrics for Prometheus
// --------------------------------------------------
lazy_static! {
    pub static ref UPDATE_SENT: IntCounter = register_int_counter!(
        "updates_sent",
        "Number of update() calls issued to the replica"
    )
    .unwrap();
    pub static ref UPDATE_SENT_REPLY: IntCounterVec = register_int_counter_vec!(
        "updates_sent_reply",
        "Number of update() calls the IC replied to",
        &["httpstatus"]
    )
    .unwrap();
    pub static ref QUERY_REPLY: IntCounterVec = register_int_counter_vec!(
        "query_reply",
        "Number of query replies received",
        &["httpstatus"]
    )
    .unwrap();
    pub static ref UPDATE_WAIT_REPLY: IntCounterVec = register_int_counter_vec!(
        "updates_wait_reply",
        "Number of wait calls to check for update() processing in ingress history",
        &["status"]
    )
    .unwrap();
    pub static ref FUTURE_STARTED: IntCounter =
        register_int_counter!("future_started", "Number of futures started").unwrap();
    pub static ref REQUEST_STARTING: IntCounter =
        register_int_counter!("request_starting", "Number of requests that are starting").unwrap();
    pub static ref COUNTER_VALUE: IntCounter = register_int_counter!(
        "counter_value",
        "Current value of the counter in the canister"
    )
    .unwrap();
    pub static ref LATENCY_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "request_latency_seconds",
        "The latency of requests as measured from the workload generator in seconds.",
        &["type", "status"]
    )
    .unwrap();
}
