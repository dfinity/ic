use super::*;

use ic_metrics_encoder::MetricsEncoder;
use pretty_assertions::assert_eq;
use prometheus_parse::{HistogramCount, Scrape, Value};
use std::collections::HashMap;

#[test]
fn test_add_event() {
    let mut histogram = Histogram::new(vec![10, 15, 20]);

    for event in [10, 14, 15, 16, 999] {
        histogram.add_event(event);
    }

    assert_eq!(
        histogram,
        Histogram {
            bin_inclusive_upper_bound_to_count: BTreeMap::from([
                (10, 1), // events: 10
                (15, 2), // events: 14, 15,
                (20, 1), // events: 16
            ]),
            infinity_bin_count: 1, // events: 999
            sum: 10 + 14 + 15 + 16 + 999,
        },
    );
}

#[test]
fn test_encode_metrics() {
    // Expected value from the previous test.
    let histogram = Histogram {
        bin_inclusive_upper_bound_to_count: BTreeMap::from([(10, 1), (15, 2), (20, 1)]),
        infinity_bin_count: 1,
        sum: 10 + 14 + 15 + 16 + 999,
    };

    let mut out = vec![];
    {
        let now_millis = 123_456;
        let mut metrics_encoder = MetricsEncoder::new(&mut out, now_millis);
        let histogram_encoder = metrics_encoder.histogram_vec("latency_ms", "help").unwrap();
        let labels = BTreeMap::from([("phase".to_string(), "getting_ready".to_string())]);
        histogram
            .encode_metrics(&labels, histogram_encoder)
            .unwrap();
    }

    let out = String::from_utf8(out.to_vec())
        .unwrap()
        .lines()
        .map(|s| Ok(s.to_owned()))
        .collect::<Vec<_>>()
        .into_iter();

    let scrape = Scrape::parse(out).unwrap();

    let name_to_sample = scrape
        .samples
        .into_iter()
        .map(|sample| (sample.metric.clone(), sample))
        .collect::<HashMap<_, _>>();

    let mut names = name_to_sample.keys().cloned().collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        vec![
            "latency_ms".to_string(),
            "latency_ms_count".to_string(),
            "latency_ms_sum".to_string(),
        ],
    );

    let latency_ms = name_to_sample.get("latency_ms").unwrap();
    let Value::Histogram(latency_ms_value) = &latency_ms.value else {
        panic!("{latency_ms:#?}");
    };
    assert_eq!(
        latency_ms_value,
        &vec![
            HistogramCount {
                less_than: 10.0,
                count: 1.0,
            },
            HistogramCount {
                less_than: 15.0,
                count: 3.0, // not 2, because cumulative, I guess.
            },
            HistogramCount {
                less_than: 20.0,
                count: 4.0,
            },
            HistogramCount {
                less_than: f64::INFINITY,
                count: 5.0,
            },
        ],
    )
}
