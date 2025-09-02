use crate::CertificationVersion;
use ic_error_types::RejectCode;
use ic_test_utilities_types::ids::canister_test_id;
use ic_types::{
    messages::{
        CallbackId, Payload, RejectContext, Request, RequestMetadata, RequestOrResponse, Response,
    },
    time::CoarseTime,
    xnet::{RejectReason, RejectSignal, StreamFlags, StreamHeader},
    Cycles, Time,
};

pub fn stream_header(_certification_version: CertificationVersion) -> StreamHeader {
    let reject_signals = vec![
        RejectSignal::new(RejectReason::CanisterMigrating, 10.into()),
        RejectSignal::new(RejectReason::CanisterNotFound, 200.into()),
        RejectSignal::new(RejectReason::OutOfMemory, 250.into()),
        RejectSignal::new(RejectReason::CanisterStopping, 251.into()),
        RejectSignal::new(RejectReason::CanisterStopped, 252.into()),
        RejectSignal::new(RejectReason::QueueFull, 253.into()),
        RejectSignal::new(RejectReason::Unknown, 254.into()),
    ]
    .into();
    let flags = StreamFlags {
        deprecated_responses_only: true,
    };

    StreamHeader::new(23.into(), 25.into(), 256.into(), reject_signals, flags)
}

pub fn request(_certification_version: CertificationVersion) -> RequestOrResponse {
    let metadata = RequestMetadata::new(1, Time::from_nanos_since_unix_epoch(100_000));
    let deadline = CoarseTime::from_secs_since_unix_epoch(8);
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

pub fn response(_certification_version: CertificationVersion) -> RequestOrResponse {
    let deadline = CoarseTime::from_secs_since_unix_epoch(7);
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

pub fn reject_response(_certification_version: CertificationVersion) -> RequestOrResponse {
    let deadline = CoarseTime::from_secs_since_unix_epoch(7);
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
