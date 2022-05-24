use ic_protobuf::state::queues::v1 as pb_queues;
use ic_test_utilities::state::arb_stream;
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
}
