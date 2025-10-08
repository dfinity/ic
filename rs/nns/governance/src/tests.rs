use super::*;
use ic_nervous_system_common::assert_is_ok;
use ic_nervous_system_common_test_utils::{get_gauge, get_samples};
use maplit::hashmap;

fn get_metric_broken_out_by_dissolve_delay(
    scrape: &prometheus_parse::Scrape,
    name: &str,
) -> HashMap<String, f64> {
    get_samples(scrape, name)
        .iter()
        .map(|sample| {
            assert_eq!(sample.labels.len(), 2);
            let lower_bound = sample.labels.get("dissolve_delay_ge_months").unwrap();
            let upper_bound = sample.labels.get("dissolve_delay_lt_months").unwrap();
            let range = format!("[{lower_bound}, {upper_bound})");
            let value = match &sample.value {
                prometheus_parse::Value::Gauge(value)
                | prometheus_parse::Value::Counter(value)
                | prometheus_parse::Value::Untyped(value) => *value,
                _ => panic!("Unable to determine sample value: {sample:#?}"),
            };

            (range, value)
        })
        .collect()
}

#[test]
fn test_neuron_subset_metrics_pb_encode() {
    // Step 1: Prepare the world.
    let mut metrics_encoder =
        ic_metrics_encoder::MetricsEncoder::new(Vec::<u8>::new(), 987_000_000);

    // Step 2: Call the code under test.
    let subject = NeuronSubsetMetricsPb {
        count: Some(42),

        total_staked_e8s: Some(43_000),
        total_staked_maturity_e8s_equivalent: Some(44_000_000),
        total_maturity_e8s_equivalent: Some(45_000_000_000),

        total_voting_power: Some(46_000_000_000_000),
        total_deciding_voting_power: Some(47_000_000_000_000_000),
        total_potential_voting_power: Some(717_568_738),

        count_buckets: hashmap! {
            3 => 3,
        },

        staked_e8s_buckets: hashmap! {
            4 => 40,
        },
        staked_maturity_e8s_equivalent_buckets: hashmap! {
            5 => 500,
        },
        maturity_e8s_equivalent_buckets: hashmap! {
            6 => 6_000,
        },

        voting_power_buckets: hashmap! {
            7 =>  70_000,
            8 => 800_000,
        },
        deciding_voting_power_buckets: hashmap! {
            9 => 9_000_000,
            10 => 110_000_000,
        },
        potential_voting_power_buckets: hashmap! {
            11 => 12_000_000_000,
            12 => 1_300_000_000_000,
        },
    };
    assert_is_ok!(subject.encode("smart", "has IQ > 120", &mut metrics_encoder));

    // Step 3: Inspect results.
    let result = String::from_utf8(metrics_encoder.into_inner())
        .unwrap()
        .lines()
        .map(|s| Ok(s.to_owned()))
        .collect::<Vec<_>>()
        .into_iter();
    let result = prometheus_parse::Scrape::parse(result).unwrap();

    assert_eq!(get_gauge(&result, "governance_smart_neurons_count"), 42.0);

    assert_eq!(
        get_gauge(&result, "governance_total_staked_e8s_smart"),
        43_000.0
    );
    assert_eq!(
        get_gauge(
            &result,
            "governance_total_staked_maturity_e8s_equivalent_smart"
        ),
        44_000_000.0
    );
    assert_eq!(
        get_gauge(&result, "governance_total_maturity_e8s_equivalent_smart"),
        45_000_000_000.0
    );

    assert_eq!(
        get_gauge(&result, "governance_total_voting_power_smart"),
        46_000_000_000_000.0
    );
    assert_eq!(
        get_gauge(&result, "governance_total_deciding_voting_power_smart"),
        47_000_000_000_000_000.0
    );
    assert_eq!(
        get_gauge(&result, "governance_total_potential_voting_power_smart"),
        717_568_738.0
    );

    assert_eq!(
        get_metric_broken_out_by_dissolve_delay(&result, "governance_smart_neurons_count_buckets",),
        hashmap! { "[18, 24)".to_string() => 3.0 },
    );
    assert_eq!(
        get_metric_broken_out_by_dissolve_delay(&result, "governance_smart_neurons_e8s_buckets",),
        hashmap! { "[24, 30)".to_string() => 40.0 },
    );
    assert_eq!(
        get_metric_broken_out_by_dissolve_delay(
            &result,
            "governance_smart_neurons_staked_maturity_e8s_equivalent_buckets",
        ),
        hashmap! { "[30, 36)".to_string() => 500.0 },
    );
    assert_eq!(
        get_metric_broken_out_by_dissolve_delay(
            &result,
            "governance_smart_neurons_maturity_e8s_equivalent_buckets",
        ),
        hashmap! { "[36, 42)".to_string() => 6_000.0 },
    );

    assert_eq!(
        get_metric_broken_out_by_dissolve_delay(
            &result,
            "governance_smart_neurons_voting_power_buckets",
        ),
        hashmap! {
            "[42, 48)".to_string() =>  70_000.0,
            "[48, 54)".to_string() => 800_000.0,
        },
    );
    assert_eq!(
        get_metric_broken_out_by_dissolve_delay(
            &result,
            "governance_smart_deciding_voting_power_buckets",
        ),
        hashmap! {
            "[54, 60)".to_string() =>  9e6,
            "[60, 66)".to_string() => 11e7,
        },
    );
    assert_eq!(
        get_metric_broken_out_by_dissolve_delay(
            &result,
            "governance_smart_potential_voting_power_buckets",
        ),
        hashmap! {
            "[66, 72)".to_string() => 12e9,
            "[72, 78)".to_string() => 13e11,
        },
    );
}
