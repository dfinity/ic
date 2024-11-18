use crate::messages::{
    MAX_INTER_CANISTER_PAYLOAD_IN_BYTES, MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64,
    MAX_RESPONSE_COUNT_BYTES,
};

use super::*;
use crate::exhaustive::ExhaustiveSet;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_types_test_utils::ids::canister_test_id;
use std::hash::{DefaultHasher, Hash, Hasher};

/// Old version of `Response`, to ensure `Hash` consistency with the "`Request`
/// with `deadline`" type.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct OldResponse {
    pub originator: CanisterId,
    pub respondent: CanisterId,
    pub originator_reply_callback: CallbackId,
    pub refund: Cycles,
    pub response_payload: Payload,
}

#[test]
fn same_hash_with_zero_deadline() {
    let old_response = OldResponse {
        originator: canister_test_id(1),
        respondent: canister_test_id(2),
        originator_reply_callback: CallbackId::new(3),
        refund: Cycles::new(4),
        response_payload: Payload::Data(vec![5]),
    };
    let new_response = Response {
        originator: canister_test_id(1),
        respondent: canister_test_id(2),
        originator_reply_callback: CallbackId::new(3),
        refund: Cycles::new(4),
        response_payload: Payload::Data(vec![5]),
        deadline: NO_DEADLINE,
    };

    assert_eq!(hash(&old_response), hash(&new_response));
}

#[test]
fn different_hash_with_nonzero_deadline() {
    let old_response = OldResponse {
        originator: canister_test_id(1),
        respondent: canister_test_id(2),
        originator_reply_callback: CallbackId::new(3),
        refund: Cycles::new(4),
        response_payload: Payload::Data(vec![5]),
    };
    let new_response = Response {
        originator: canister_test_id(1),
        respondent: canister_test_id(2),
        originator_reply_callback: CallbackId::new(3),
        refund: Cycles::new(4),
        response_payload: Payload::Data(vec![5]),
        deadline: CoarseTime::from_secs_since_unix_epoch(6),
    };

    assert_ne!(hash(&old_response), hash(&new_response));
}

fn hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Checks that a response with a maximum size payload (reply or reject) has
/// exactly `MAX_RESPONSE_COUNT_BYTES`.
#[test]
fn max_response_count_bytes() {
    // Sanity check.
    assert_eq!(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64,
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES.get()
    );

    // A reply with a maximum size payload.
    let response = Response {
        originator: canister_test_id(1),
        respondent: canister_test_id(2),
        originator_reply_callback: CallbackId::new(3),
        refund: Cycles::new(4),
        response_payload: Payload::Data(vec![5; MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize]),
        deadline: NO_DEADLINE,
    };
    // Its payload size must be exactly `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES`.
    assert_eq!(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        response.payload_size_bytes()
    );
    // And its total size must be exactly `MAX_RESPONSE_COUNT_BYTES`.
    assert_eq!(MAX_RESPONSE_COUNT_BYTES, response.count_bytes());

    // A reject response with a maximum size payload.
    let max_reject_payload_size =
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES_U64 as usize - std::mem::size_of::<RejectCode>();
    let reject = Response {
        originator: canister_test_id(1),
        respondent: canister_test_id(2),
        originator_reply_callback: CallbackId::new(3),
        refund: Cycles::new(4),
        response_payload: Payload::Reject(RejectContext {
            code: RejectCode::CanisterError,
            message: (0..max_reject_payload_size)
                .map(|_| 'A')
                .collect::<String>(),
        }),
        deadline: NO_DEADLINE,
    };
    // Its payload size must be exactly `MAX_INTER_CANISTER_PAYLOAD_IN_BYTES`.
    assert_eq!(
        MAX_INTER_CANISTER_PAYLOAD_IN_BYTES,
        reject.payload_size_bytes()
    );
    // And its total size must be exactly `MAX_RESPONSE_COUNT_BYTES`.
    assert_eq!(MAX_RESPONSE_COUNT_BYTES, reject.count_bytes());
}

#[test]
fn response_payload_proto_round_trip() {
    for payload in Payload::exhaustive_set(&mut reproducible_rng()) {
        let encoded = pb_queues::response::ResponsePayload::from(&payload);
        let round_trip = Payload::try_from(encoded).unwrap();

        assert_eq!(payload, round_trip);
    }
}

#[test]
fn request_or_response_proto_round_trip() {
    for r in RequestOrResponse::exhaustive_set(&mut reproducible_rng()) {
        let encoded = pb_queues::RequestOrResponse::from(&r);
        let round_trip = RequestOrResponse::try_from(encoded).unwrap();

        assert_eq!(r, round_trip);
    }
}
