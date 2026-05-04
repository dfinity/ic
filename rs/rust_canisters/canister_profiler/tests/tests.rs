use ic_canister_profiler::{measure_span, stats::SpanStats};
use std::time::Duration;

#[test]
fn test_measurements_are_cumulative() {
    let mut stats = SpanStats::default();
    measure_span(&mut stats, "test_span", || {
        std::thread::sleep(Duration::from_secs(0));
    });

    let span_1 = stats.get_span("test_span").unwrap().clone();
    assert_eq!(span_1.num_samples, 1);

    measure_span(&mut stats, "test_span", || {
        std::thread::sleep(Duration::from_secs(0));
    });

    let span_2 = stats.get_span("test_span").unwrap().clone();

    assert_eq!(span_2.num_samples, 2);
    assert!(span_2.sum >= span_1.sum);
    assert!(span_2.max >= span_1.max);
    for (v1, v2) in span_1.histogram.iter().zip(span_2.histogram.iter()) {
        assert!(v1 <= v2);
    }
}
