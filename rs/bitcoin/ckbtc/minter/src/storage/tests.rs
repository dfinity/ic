use super::{decode_event, encode_event};
use crate::{
    state::eventlog::{Event, EventType},
    test_fixtures::arbitrary,
};
use proptest::proptest;

proptest! {
    #[test]
    fn should_decode_encoded_event(event in arbitrary::event()) {
        let encoded = encode_event(&event);
        let decoded = decode_event(&encoded);

        assert_eq!(event, decoded);
    }

    #[test]
    fn should_decode_encoded_legacy_event(legacy_event in arbitrary::event_type()) {
        /// Legacy events just consist of an event type instance. The encoding logic
        /// is the exact same as for new events. Only the type being encoded differs.
        fn encode_legacy_event(event: &EventType) -> Vec<u8> {
            let mut buf = Vec::new();
            ciborium::ser::into_writer(event, &mut buf).expect("failed to encode a minter event");
            buf
        }

        let encoded = encode_legacy_event(&legacy_event);
        let decoded = decode_event(&encoded);

        assert_eq!(
            decoded,
            Event {
                timestamp: None,
                payload: legacy_event,
            }
        );
    }
}
