use crate::ids::{canister_test_id, node_test_id, subnet_test_id, user_test_id};
use ic_protobuf::types::v1::RejectCode as pbRejectCode;
use ic_types::{
    crypto::{AlgorithmId, KeyPurpose, UserPublicKey},
    messages::{
        CallbackId, Payload, RejectContext, Request, RequestMetadata, RequestOrResponse, Response,
        NO_DEADLINE,
    },
    time::{CoarseTime, UNIX_EPOCH},
    xnet::StreamIndex,
    CanisterId, Cycles, Height, NodeId, RegistryVersion, SubnetId, Time, UserId,
};
use proptest::prelude::*;
use std::{convert::TryInto, time::Duration};
use strum::IntoEnumIterator;

prop_compose! {
    /// Returns an arbitrary [`NodeId`].
    pub fn node_id()(id in any::<u64>()) -> NodeId {
        node_test_id(id)
    }
}

prop_compose! {
    /// Returns an arbitrary [`UserId`].
    pub fn user_id()(id in any::<u64>()) -> UserId {
        user_test_id(id)
    }
}

prop_compose! {
    /// Returns an arbitrary [`CanisterId`].
    pub fn canister_id()(id in any::<u64>()) -> CanisterId {
        canister_test_id(id)
    }
}

prop_compose! {
    /// Returns an arbitrary [`KeyPurpose`].
    pub fn key_purpose() (seed in any::<usize>()) -> KeyPurpose {
        let options: Vec<KeyPurpose> = KeyPurpose::iter().collect();
        options[seed % options.len()]
    }
}

prop_compose! {
    /// Returns an arbitrary [`AlgorithmId`].
    pub fn algorithm_id() (seed in any::<usize>()) -> AlgorithmId {
        let options: Vec<AlgorithmId> = AlgorithmId::iter().collect();
        options[seed % options.len()]
    }
}

prop_compose! {
    /// Returns an arbitrary [`RegistryVersion`].
    pub fn registry_version() (seed in any::<u64>()) -> RegistryVersion {
        RegistryVersion::from(seed)
    }
}

prop_compose! {
    /// Returns an arbitrary [`Time`].
    pub fn time() (seed in any::<u64>()) -> Time {
        UNIX_EPOCH + Duration::from_millis(seed)
    }
}

prop_compose! {
    /// Returns an arbitrary [`UserPublicKey`].
    pub fn user_public_key() (
      key in any::<Vec<u8>>(),
      algorithm_id in algorithm_id()
    ) -> UserPublicKey {
        UserPublicKey {
            key,
            algorithm_id,
        }
    }
}

prop_compose! {
    /// Returns an arbitrary [`Height`].
    pub fn height() (
      height in any::<u64>(),
    ) -> Height {
        Height::from(height)
    }
}

prop_compose! {
    /// Returns an arbitrary [`SubnetId`].
    pub fn subnet_id() (
      subnet_id in any::<u64>(),
    ) -> SubnetId {
        subnet_test_id(subnet_id)
    }
}

prop_compose! {
    /// Returns an arbitrary ['RequestMetadata'].
    pub fn request_metadata()(
        call_tree_depth in any::<u64>(),
        call_tree_start_time_nanos in any::<u64>(),
    ) -> RequestMetadata {
        RequestMetadata::new(
            call_tree_depth,
            Time::from_nanos_since_unix_epoch(call_tree_start_time_nanos),
        )
    }
}

prop_compose! {
    /// Returns an arbitrary deadline that is equal to `NO_DEADLINE` half the time.
    pub fn deadline() (
      deadline in any::<u32>(),
    ) -> CoarseTime {
        if deadline % 2 == 1 {
            NO_DEADLINE
        } else {
            CoarseTime::from_secs_since_unix_epoch(deadline)
        }
    }
}

prop_compose! {
    /// Generates an arbitrary [`Request`], with or without populated `metadata` and
    /// `deadline` fields.
    pub fn request_with_config(populate_metadata: bool, populate_deadline: bool)(
        receiver in canister_id(),
        sender in canister_id(),
        cycles_payment in any::<u64>(),
        method_name in "[a-zA-Z]{1,6}",
        callback in any::<u64>(),
        method_payload in prop::collection::vec(any::<u8>(), 0..16),
        metadata in proptest::option::of(request_metadata()),
        deadline in deadline(),
    ) -> Request {
        Request {
            receiver,
            sender,
            sender_reply_callback: CallbackId::from(callback),
            payment: Cycles::from(cycles_payment),
            method_name,
            method_payload,
            metadata: if populate_metadata { metadata } else { None },
            deadline: if populate_deadline { deadline } else { NO_DEADLINE },
        }
    }
}

prop_compose! {
    /// Returns an arbitrary [`Request`].
    ///
    /// This is what should be used for generating arbitrary requests almost everywhere;
    /// the only exception is when specifically testing for a certain certification version,
    /// in which case `request_with_config()` should be used.
    pub fn request()(
        // Always populate all fields, regardless of e.g. current certification version.
        // `ic_canonical_state` should not be using this generator; and all other crates /
        // proptests should be able to deal with all fields being populated.
        request in request_with_config(true, true),
    ) -> Request {
        request
    }
}

/// Produces an arbitrary response [`Payload`].
pub fn response_payload() -> impl Strategy<Value = Payload> {
    prop_oneof![
        // Data payload.
        prop::collection::vec(any::<u8>(), 0..16).prop_flat_map(|data| Just(Payload::Data(data))),
        // Reject payload.
        (1i32..5, "[a-zA-Z]{1,6}").prop_flat_map(|(code, message)| Just(Payload::Reject(
            RejectContext::new(
                pbRejectCode::try_from(code).unwrap().try_into().unwrap(),
                message
            )
        )))
    ]
}

prop_compose! {
    /// Returns an arbitrary [`Response`], with or without a populated `deadline` field.
    pub fn response_with_config(populate_deadline: bool)(
        originator in canister_id(),
        respondent in canister_id(),
        callback in any::<u64>(),
        cycles_refund in any::<u64>(),
        response_payload in response_payload(),
        deadline in deadline(),
    ) -> Response {
        Response {
            originator,
            respondent,
            originator_reply_callback: CallbackId::from(callback),
            refund: Cycles::from(cycles_refund),
            response_payload,
            deadline: if populate_deadline { deadline } else { NO_DEADLINE },
        }
    }
}

prop_compose! {
    /// Returns an arbitrary [`Response`].
    ///
    /// This is what should be used for generating arbitrary requests almost everywhere;
    /// the only exception is when specifically testing for a certain certification version,
    /// in which case `response_with_config()` should be used.
    pub fn response()(
        response in response_with_config(true),
    ) -> Response {
        response
    }
}

/// Produces an arbitrary [`RequestOrResponse`], with the respective fields
/// populated or not.
pub fn request_or_response_with_config(
    populate_request_metadata: bool,
    populate_deadline: bool,
) -> impl Strategy<Value = RequestOrResponse> {
    prop_oneof![
        request_with_config(populate_request_metadata, populate_deadline)
            .prop_flat_map(|req| Just(req.into())),
        response_with_config(populate_deadline).prop_flat_map(|rep| Just(rep.into())),
    ]
}

/// Produces an arbitrary [`RequestOrResponse`].
pub fn request_or_response() -> impl Strategy<Value = RequestOrResponse> {
    prop_oneof![
        request().prop_flat_map(|req| Just(req.into())),
        response().prop_flat_map(|rep| Just(rep.into())),
    ]
}

prop_compose! {
    /// Returns an arbitrary [`StreamIndex`] in the `[0, max)` range.
    pub fn stream_index(max: u64) (
      index in 0..max,
    ) -> StreamIndex {
        StreamIndex::from(index)
    }
}
