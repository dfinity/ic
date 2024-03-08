use super::*;
use ic_types_test_utils::ids::canister_test_id;
use std::hash::{DefaultHasher, Hash, Hasher};

/// Old version of `Response`, to ensure `Hash` consistency with the "`Request`
/// with `deadline`" type.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
