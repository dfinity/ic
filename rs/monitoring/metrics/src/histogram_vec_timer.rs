use prometheus::HistogramVec;
use std::time::Instant;

/// `HistogramTimer` alternative that allows setting label values incrementally.
///
/// Oftentimes we measure latency in a `HistogramVec` where we do not know all
/// label values when starting the timer. This can usually be addressed in
/// synchronous code by recording a start instant and calling `observe()` with
/// the specific label values when the instrumented code completes.
///
/// In asynchronous code, when dealing with cancellations, control may never
/// reach the code where `observe()` is called. The code below aims at tracking
/// latencies while the object is in scope with the posibility to modify label
/// values as they become available.
pub struct HistogramVecTimer<'a, const LABEL_COUNT: usize> {
    hist: HistogramVec,
    label_names: &'static [&'static str; LABEL_COUNT],
    label_values: [&'a str; LABEL_COUNT],
    start: Instant,
}

#[allow(clippy::let_and_return)]
impl<'a, const LABEL_COUNT: usize> HistogramVecTimer<'a, LABEL_COUNT> {
    /// Starts a timer when the instance is created.
    ///
    /// `label_names` must include all label names used in the definition of
    /// `hist`, in the same order. `label_values` defines the initial set of
    /// label values, to be updated incrementally.
    pub fn start_timer(
        hist: HistogramVec,
        label_names: &'static [&'static str; LABEL_COUNT],
        label_values: [&'a str; LABEL_COUNT],
    ) -> HistogramVecTimer<'a, LABEL_COUNT> {
        #[cfg(debug_assertions)]
        let label_map = label_names
            .iter()
            .cloned()
            .zip(label_values.iter().cloned())
            .collect();

        let timer = Self {
            hist,
            label_names,
            label_values,
            start: Instant::now(),
        };

        // Ensure that the set of label names matches that used to create `hist`.
        // Unfortunately there is no way to ensure that their order is the same.
        #[cfg(debug_assertions)]
        timer.hist.with(&label_map);

        timer
    }

    /// Returns the current label values.
    pub fn label_values(&self) -> &[&str] {
        &self.label_values
    }

    /// Updates the value of a single existing label.
    ///
    /// Panics if `k` does not match an existing label name.
    pub fn set_label(&mut self, k: &str, v: &'a str) {
        for (i, label) in self.label_names.iter().enumerate() {
            if *label == k {
                self.label_values[i] = v;
                return;
            }
        }
        panic!("No such label: {}", k);
    }
}

impl<'a, const LABEL_COUNT: usize> Drop for HistogramVecTimer<'a, LABEL_COUNT> {
    fn drop(&mut self) {
        self.hist
            .with_label_values(self.label_values())
            .observe(self.start.elapsed().as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use prometheus::core::Metric;

    use super::*;
    use crate::{buckets::decimal_buckets, MetricsRegistry};

    pub const LABEL_DETAIL: &str = "detail";
    pub const LABEL_OTHER: &str = "other";
    pub const LABEL_STATUS: &str = "status";
    pub const Z_LABEL_NAMES: [&str; 2] = [LABEL_STATUS, LABEL_DETAIL];

    #[test]
    fn test_default_label_values() {
        let registry = MetricsRegistry::new();
        let hist = new_histogram_vec(&registry);

        {
            let timer = HistogramVecTimer::start_timer(hist.clone(), &Z_LABEL_NAMES, ["200", "OK"]);
            assert_eq!(&["200", "OK"], timer.label_values());
        }

        assert_eq!(
            1,
            get_proto_histogram(&hist, &["200", "OK"]).get_sample_count()
        );
    }

    #[test]
    fn test_set_label() {
        let registry = MetricsRegistry::new();
        let hist = new_histogram_vec(&registry);

        {
            let mut timer =
                HistogramVecTimer::start_timer(hist.clone(), &Z_LABEL_NAMES, ["200", "OK"]);
            assert_eq!(&["200", "OK"], timer.label_values());

            timer.set_label(LABEL_STATUS, "202");
            assert_eq!(&["202", "OK"], timer.label_values());

            timer.set_label(LABEL_DETAIL, "Accepted");
            assert_eq!(&["202", "Accepted"], timer.label_values());
        }

        // In release code, there should be no `{status="200",detail="OK"}` metric.
        #[cfg(not(debug_assertions))]
        assert!(hist.remove_label_values(&["200", "OK"]).is_err());
        // In debug code, we create a `{status="200",detail="OK"}` metric in
        // `start_timer()`.
        #[cfg(debug_assertions)]
        assert_eq!(
            0,
            get_proto_histogram(&hist, &["200", "OK"]).get_sample_count()
        );

        // There should never be a `{status="202",detail="OK"}` metric.
        assert!(hist.remove_label_values(&["202", "OK"]).is_err());

        // But there should be a `{status="202",detail="Accepted"}` metric with one
        // sample.
        assert_eq!(
            1,
            get_proto_histogram(&hist, &["202", "Accepted"]).get_sample_count()
        );
    }

    #[test]
    #[should_panic(expected = "No such label: other")]
    fn test_set_nonexistent_label() {
        let registry = MetricsRegistry::new();
        let hist = new_histogram_vec(&registry);

        {
            let mut timer =
                HistogramVecTimer::start_timer(hist.clone(), &Z_LABEL_NAMES, ["200", "OK"]);
            timer.set_label(LABEL_OTHER, "Oops");
        }

        assert_eq!(
            1,
            get_proto_histogram(&hist, &["200", "OK"]).get_sample_count()
        );
    }

    fn new_histogram_vec(registry: &MetricsRegistry) -> HistogramVec {
        registry.histogram_vec(
            "z_duration_seconds",
            "z duration, by status and detail",
            decimal_buckets(-3, 1),
            &Z_LABEL_NAMES,
        )
    }

    fn get_proto_histogram(
        hist: &HistogramVec,
        label_values: &[&str],
    ) -> prometheus::proto::Histogram {
        let metric = hist.with_label_values(label_values).metric();
        metric.get_histogram().clone()
    }
}
