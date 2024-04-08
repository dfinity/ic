use crate::CertificationVersion;
use ic_error_types::RejectCode;
use ic_test_utilities_types::ids::canister_test_id;
use ic_types::{
    messages::{
        CallbackId, Payload, RejectContext, Request, RequestMetadata, RequestOrResponse, Response,
        NO_DEADLINE,
    },
    time::CoarseTime,
    xnet::{StreamFlags, StreamHeader},
    Cycles, Time,
};
use std::collections::VecDeque;

pub fn stream_header(certification_version: CertificationVersion) -> StreamHeader {
    let reject_signals = if certification_version < CertificationVersion::V8 {
        VecDeque::new()
    } else {
        vec![10.into(), 200.into(), 250.into()].into()
    };
    let flags = StreamFlags {
        deprecated_responses_only: certification_version >= CertificationVersion::V17,
    };

    StreamHeader::new(23.into(), 25.into(), 256.into(), reject_signals, flags)
}

pub fn request(certification_version: CertificationVersion) -> RequestOrResponse {
    let metadata = (certification_version >= CertificationVersion::V14).then_some(
        RequestMetadata::new(1, Time::from_nanos_since_unix_epoch(100_000)),
    );
    let deadline = if certification_version >= CertificationVersion::V18 {
        CoarseTime::from_secs_since_unix_epoch(8)
    } else {
        NO_DEADLINE
    };
    Request {
        receiver: canister_test_id(1),
        sender: canister_test_id(2),
        sender_reply_callback: CallbackId::from(3),
        payment: Cycles::new(4),
        method_name: "test".to_string(),
        method_payload: vec![6],
        metadata,
        deadline,
    }
    .into()
}

pub fn response(certification_version: CertificationVersion) -> RequestOrResponse {
    let deadline = if certification_version >= CertificationVersion::V18 {
        CoarseTime::from_secs_since_unix_epoch(7)
    } else {
        NO_DEADLINE
    };
    Response {
        originator: canister_test_id(6),
        respondent: canister_test_id(5),
        originator_reply_callback: CallbackId::from(4),
        refund: Cycles::new(3),
        response_payload: Payload::Data(vec![1]),
        deadline,
    }
    .into()
}

pub fn reject_response(certification_version: CertificationVersion) -> RequestOrResponse {
    let deadline = if certification_version >= CertificationVersion::V18 {
        CoarseTime::from_secs_since_unix_epoch(7)
    } else {
        NO_DEADLINE
    };
    Response {
        originator: canister_test_id(6),
        respondent: canister_test_id(5),
        originator_reply_callback: CallbackId::from(4),
        refund: Cycles::new(3),
        response_payload: Payload::Reject(RejectContext::new(RejectCode::SysFatal, "Oops")),
        deadline,
    }
    .into()
}
