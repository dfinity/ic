use crate::ids::{canister_test_id, node_test_id, subnet_test_id, user_test_id};
use ic_canonical_state::encoding::{
    old_types::{RequestV13 as CanonicalRequestV13, RequestV3 as CanonicalRequestV3},
    types::Request as CanonicalRequestV14,
};
use ic_certification_version::{CertificationVersion, CURRENT_CERTIFICATION_VERSION};
use ic_types::{
    crypto::{AlgorithmId, KeyPurpose, UserPublicKey},
    messages::{
        CallbackId, Payload, RejectContext, Request, RequestMetadata, RequestOrResponse, Response,
    },
    time::UNIX_EPOCH,
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
        RequestMetadata {
            call_tree_depth,
            call_tree_start_time: Time::from_nanos_since_unix_epoch(call_tree_start_time_nanos),
        }
    }
}

prop_compose! {
    /// Returns an arbitrary [`Request`].
    ///
    /// All fields should be populated here, including those not yet supported by the current
    /// certification version; this way `request()` below will automatically start producing
    /// requests including such fields once the current certification is bumped.
    fn request_impl()(
        receiver in canister_id(),
        sender in canister_id(),
        cycles_payment in any::<u64>(),
        method_name in "[a-zA-Z]{1,6}",
        callback in any::<u64>(),
        method_payload in prop::collection::vec(any::<u8>(), 0..16),
        metadata in proptest::option::of(request_metadata()),
    ) -> Request {
        Request {
            receiver,
            sender,
            sender_reply_callback: CallbackId::from(callback),
            payment: Cycles::from(cycles_payment),
            method_name,
            method_payload,
            metadata,
        }
    }
}

prop_compose! {
    /// Returns an arbitrary [`Request`] valid for a given certification version.
    ///
    /// A roundtrip to the canonical version and back ensures compatibility for a given
    /// certification version; e.g. by stripping off certain fields like `metadata` for version 13
    /// and below.
    pub fn valid_request_for_certification_version(certification_version: CertificationVersion)(
        request in request_impl(),
    ) -> Request {
        use CertificationVersion::*;
        match certification_version {
            V0 | V1 | V2 | V3 => {
                let req: CanonicalRequestV3 = (&request, certification_version).into();
                req.try_into().unwrap()
            }
            V4 | V5 | V6 | V7 | V8 | V9 | V10 | V11 | V12 | V13 => {
                let req: CanonicalRequestV13 = (&request, certification_version).into();
                req.try_into().unwrap()
            }
            V14 | V15 => {
                let req: CanonicalRequestV14 = (&request, certification_version).into();
                req.try_into().unwrap()
            }
        }
    }
}

prop_compose! {
    /// Returns an arbitrary [`Request`] valid for the current certification version.
    ///
    /// This is what should be used for generating arbitrary requests almost everywhere;
    /// the only exception is when specifically testing for a certain certification version,
    /// in which case `valid_request_for_certification_version()` should be used.
    pub fn request()(
        request in valid_request_for_certification_version(CURRENT_CERTIFICATION_VERSION),
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
        (1u64..5, "[a-zA-Z]{1,6}").prop_flat_map(|(code, message)| Just(Payload::Reject(
            RejectContext::new(code.try_into().unwrap(), message)
        )))
    ]
}

prop_compose! {
    /// Returns an arbitrary [`Response`].
    pub fn response()(
        originator in canister_id(),
        respondent in canister_id(),
        callback in any::<u64>(),
        cycles_refund in any::<u64>(),
        response_payload in response_payload(),
    ) -> Response {
        Response {
            originator,
            respondent,
            originator_reply_callback: CallbackId::from(callback),
            refund: Cycles::from(cycles_refund),
            response_payload
        }
    }
}

/// Produces an arbitrary [`RequestOrResponse`].
pub fn request_or_response() -> impl Strategy<Value = RequestOrResponse> {
    prop_oneof![
        request().prop_flat_map(|req| Just(req.into())),
        response().prop_flat_map(|rep| Just(rep.into())),
    ]
}

/// Returns an arbitrary [`RequestOrResponse`] valid for a given certification version.
pub fn valid_request_or_response_for_certification_version(
    certification_version: CertificationVersion,
) -> impl Strategy<Value = RequestOrResponse> {
    prop_oneof![
        valid_request_for_certification_version(certification_version)
            .prop_flat_map(|req| Just(req.into())),
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
