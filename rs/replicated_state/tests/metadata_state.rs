use ic_protobuf::state::{queues::v1 as pb_queues, system_metadata::v1 as pb_metadata};
use ic_test_utilities_state::{arb_stream, arb_subnet_metrics};
use proptest::prelude::*;
use std::convert::TryInto;

proptest! {
    #[test]
    fn roundtrip_conversion_stream_proptest(stream in arb_stream(0, 10, 0, 100)) {
        assert_eq!(
            stream,
            pb_queues::Stream::from(&stream)
                .try_into()
                .unwrap()
        );
    }

    #[test]
    fn roundtrip_conversion_subnet_metrics(subnet_metrics in arb_subnet_metrics()) {
        assert_eq!(
            subnet_metrics,
            pb_metadata::SubnetMetrics::from(&subnet_metrics)
                .try_into()
                .unwrap()
        );
    }
}
