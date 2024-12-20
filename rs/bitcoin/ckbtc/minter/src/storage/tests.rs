use crate::state::eventlog::{Event, EventType};
use crate::test_fixtures::{ignored_utxo, ledger_account};

#[test]
fn should_decode_encoded_event() {
    let event = Event {
        timestamp: Some(123),
        payload: event_type(),
    };

    let encoded = super::encode_event(&event);
    let decoded = super::decode_event(&encoded);

    assert_eq!(event, decoded);
}

#[test]
fn should_decode_encoded_legacy_event() {
    /// Legacy events simply consisted of an event type instance. The
    /// encoding logic is the exact same as for new events, only the type
    /// being encoded differs.
    fn encode_legacy_event(event: &EventType) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(event, &mut buf).expect("failed to encode a minter event");
        buf
    }

    let legacy_event = event_type();

    let encoded = encode_legacy_event(&legacy_event);
    let decoded = super::decode_event(&encoded);

    assert_eq!(
        decoded,
        Event {
            timestamp: None,
            payload: legacy_event,
        }
    );
}

fn event_type() -> EventType {
    EventType::ReceivedUtxos {
        mint_txid: Some(1),
        to_account: ledger_account(),
        utxos: vec![ignored_utxo()],
    }
}
