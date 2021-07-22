use super::super::test_fixtures::*;
use super::*;
use ic_test_utilities::metrics::MetricVec;
use ic_test_utilities::{
    metrics::{fetch_gauge_vec, fetch_int_counter, metric_vec},
    with_test_replica_logger,
};

/// Asserts that `proximity_map.pick_node()` will pick `expected_node` for all
/// `gen_range()` values in the `[low + numerator_low * (high - low) /
/// denominator, low + numerator_high * (high - low) / denominator)` range (i.e.
/// dividing the range into `denominator` equal chunks, any random value in
/// chunks `nominator_low` through `nominator_high` will result in
/// `expected_node` being selected).
fn assert_pick_node(
    expected_node: NodeId,
    proximity_map: &mut ProximityMap,
    gen_range_numerator_low: u64,
    gen_range_numerator_high: u64,
    gen_range_denominator: u64,
) {
    let mut gen_range = mock_gen_range_low(gen_range_numerator_low, gen_range_denominator);
    // Remember the original `gen_range`.
    std::mem::swap(&mut proximity_map.gen_range, &mut gen_range);
    assert_eq!(
        expected_node,
        proximity_map
            .pick_node(REMOTE_SUBNET, REGISTRY_VERSION)
            .unwrap()
            .0
    );

    proximity_map.gen_range = mock_gen_range_high(gen_range_numerator_high, gen_range_denominator);
    assert_eq!(
        expected_node,
        proximity_map
            .pick_node(REMOTE_SUBNET, REGISTRY_VERSION)
            .unwrap()
            .0
    );

    // Restore `gen_range` to its original value.
    proximity_map.gen_range = gen_range;
}

#[tokio::test]
async fn pick_node_no_roundtrip_times() {
    with_test_replica_logger(|log| {
        let registry = create_xnet_endpoint_url_test_fixture();
        let metrics = MetricsRegistry::new();

        let mut proximity_map = ProximityMap::with_rng(
            mock_gen_range_low(0, 0),
            LOCAL_NODE,
            registry,
            &metrics,
            log,
        );

        assert_pick_node(REMOTE_NODE_1_OPERATOR_1, &mut proximity_map, 0, 1, 3);
        assert_pick_node(REMOTE_NODE_2_OPERATOR_1, &mut proximity_map, 1, 2, 3);
        assert_pick_node(REMOTE_NODE_3_OPERATOR_2, &mut proximity_map, 2, 3, 3);

        assert_eq!(MetricVec::new(), fetch_gauge_vec(&metrics, METRIC_RTT_EMA));
        assert_eq!(Some(0), fetch_int_counter(&&metrics, METRIC_UNKNOWN_DCOP));
    });
}

#[tokio::test]
async fn pick_node_some_roundtrip_times() {
    with_test_replica_logger(|log| {
        let registry = create_xnet_endpoint_url_test_fixture();
        let metrics = MetricsRegistry::new();

        // A proximity map with a recorded roundtrip time to operator 1. Should result
        // in all nodes being selected with the same probability (as operator 2
        // should be assigned the mean priority of all weighted operators, i.e. the same
        // priority as operator 1).
        let mut proximity_map = ProximityMap::with_rng(
            mock_gen_range_low(0, 0),
            LOCAL_NODE,
            registry,
            &metrics,
            log,
        );
        proximity_map.observe_roundtrip_time(REMOTE_NODE_2_OPERATOR_1, Duration::from_millis(125));

        assert_pick_node(REMOTE_NODE_1_OPERATOR_1, &mut proximity_map, 0, 1, 3);
        assert_pick_node(REMOTE_NODE_2_OPERATOR_1, &mut proximity_map, 1, 2, 3);
        assert_pick_node(REMOTE_NODE_3_OPERATOR_2, &mut proximity_map, 2, 3, 3);

        assert_eq!(
            metric_vec(&[(&[(LABEL_FROM, OPERATOR_1), (LABEL_TO, OPERATOR_1)], 0.125)]),
            fetch_gauge_vec(&metrics, METRIC_RTT_EMA)
        );
        assert_eq!(Some(0), fetch_int_counter(&&metrics, METRIC_UNKNOWN_DCOP));
    });
}

#[tokio::test]
async fn pick_node_all_roundtrip_times() {
    with_test_replica_logger(|log| {
        let registry = create_xnet_endpoint_url_test_fixture();
        let metrics = MetricsRegistry::new();

        let mut proximity_map = ProximityMap::with_rng(
            mock_gen_range_low(0, 0),
            LOCAL_NODE,
            registry,
            &metrics,
            log,
        );
        // Operator 1 should end up with a RTT EMA of 50 ms: (9 * 40 + 1 * 140) / 10.
        proximity_map.observe_roundtrip_time(REMOTE_NODE_1_OPERATOR_1, Duration::from_millis(40));
        proximity_map.observe_roundtrip_time(REMOTE_NODE_2_OPERATOR_1, Duration::from_millis(140));
        // Operator 2 has a RTT of 100 ms, 2x that of operator 1, so half the weight.
        proximity_map.observe_roundtrip_time(REMOTE_NODE_3_OPERATOR_2, Duration::from_millis(100));

        assert_pick_node(REMOTE_NODE_1_OPERATOR_1, &mut proximity_map, 0, 2, 5);
        assert_pick_node(REMOTE_NODE_2_OPERATOR_1, &mut proximity_map, 2, 4, 5);
        assert_pick_node(REMOTE_NODE_3_OPERATOR_2, &mut proximity_map, 4, 5, 5);

        assert_eq!(
            metric_vec(&[
                (&[(LABEL_FROM, OPERATOR_1), (LABEL_TO, OPERATOR_1)], 0.05),
                (&[(LABEL_FROM, OPERATOR_1), (LABEL_TO, OPERATOR_2)], 0.1)
            ]),
            fetch_gauge_vec(&metrics, METRIC_RTT_EMA)
        );
        assert_eq!(Some(0), fetch_int_counter(&&metrics, METRIC_UNKNOWN_DCOP));
    });
}

#[tokio::test]
async fn pick_node_extreme_roundtrip_times() {
    with_test_replica_logger(|log| {
        let registry = create_xnet_endpoint_url_test_fixture();
        let metrics = MetricsRegistry::new();

        let mut proximity_map = ProximityMap::with_rng(
            mock_gen_range_low(0, 0),
            LOCAL_NODE,
            registry,
            &metrics,
            log,
        );
        // Operator 1 with an observed RTT of 13ns => recorded RTT EMA of 1µs.
        proximity_map.observe_roundtrip_time(REMOTE_NODE_1_OPERATOR_1, Duration::from_nanos(13));
        // Operator 2 with an observed RTT of 5s => recorded RTT EMA
        // of 1s.
        proximity_map.observe_roundtrip_time(REMOTE_NODE_3_OPERATOR_2, Duration::from_secs(5));

        // Nodes from `OPERATOR_1` should be 1_000_000x more likely to be picked than
        // nodes from `OPERATOR_2`.
        assert_pick_node(
            REMOTE_NODE_1_OPERATOR_1,
            &mut proximity_map,
            0,
            1_000_000,
            2_000_001,
        );
        assert_pick_node(
            REMOTE_NODE_2_OPERATOR_1,
            &mut proximity_map,
            1_000_000,
            2_000_000,
            2_000_001,
        );
        assert_pick_node(
            REMOTE_NODE_3_OPERATOR_2,
            &mut proximity_map,
            2_000_000,
            2_000_001,
            2_000_001,
        );

        assert_eq!(
            metric_vec(&[
                (
                    &[(LABEL_FROM, OPERATOR_1), (LABEL_TO, OPERATOR_1)],
                    1000.0 * 1e-9
                ),
                (&[(LABEL_FROM, OPERATOR_1), (LABEL_TO, OPERATOR_2)], 1.0)
            ]),
            fetch_gauge_vec(&metrics, METRIC_RTT_EMA)
        );
        assert_eq!(Some(0), fetch_int_counter(&&metrics, METRIC_UNKNOWN_DCOP));
    });
}
