use opentelemetry::metrics::{Counter, Histogram, Meter};

pub struct MetricParams {
    pub action: String,
    pub counter: Counter<u64>,
    pub recorder: Histogram<f64>,
}

impl MetricParams {
    pub fn new(meter: &Meter, namespace: &str, action: &str) -> Self {
        Self {
            action: action.to_string(),
            counter: meter
                .u64_counter(format!("{namespace}.{action}"))
                .with_description(format!("Counts occurrences of {action} calls"))
                .init(),
            recorder: meter
                .f64_histogram(format!("{namespace}.{action}.duration_sec"))
                .with_description(format!("Records the duration of {action} calls in seconds"))
                .init(),
        }
    }
}

pub struct WithMetrics<T>(pub T, pub MetricParams);
