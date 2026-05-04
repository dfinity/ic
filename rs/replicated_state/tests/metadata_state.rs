use ic_protobuf::state::{queues::v1 as pb_queues, system_metadata::v1 as pb_metadata};
use ic_replicated_state::{Stream, metadata_state::SubnetMetrics};
use ic_test_utilities_state::{arb_stream, arb_subnet_metrics};
use std::convert::TryInto;

#[test_strategy::proptest]
fn roundtrip_conversion_stream_proptest(#[strategy(arb_stream(0, 10, 0, 100))] stream: Stream) {
    assert_eq!(stream, pb_queues::Stream::from(&stream).try_into().unwrap());
}

#[test_strategy::proptest]
fn roundtrip_conversion_subnet_metrics(
    #[strategy(arb_subnet_metrics())] subnet_metrics: SubnetMetrics,
) {
    assert_eq!(
        subnet_metrics,
        pb_metadata::SubnetMetrics::from(&subnet_metrics)
            .try_into()
            .unwrap()
    );
}
