use ic_protobuf::state::queues::v1 as pb_queues;
use ic_test_utilities::state::arb_stream_with_signals;
use proptest::prelude::*;
use std::convert::TryInto;

proptest! {
    #[test]
    fn roundtrip_conversion_stream_proptest(stream in arb_stream_with_signals(0, 10, 10000, 0, 100)) {
        assert_eq!(
            stream,
            pb_queues::Stream::from(&stream)
                .try_into()
                .unwrap()
        );
    }
}
