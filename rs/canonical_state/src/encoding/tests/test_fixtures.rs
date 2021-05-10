use ic_test_utilities::types::{
    ids::canister_test_id,
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{
    funds::icp::{Tap, ICP},
    messages::{CallbackId, Payload, RejectContext, RequestOrResponse},
    user_error::RejectCode,
    xnet::StreamHeader,
    Cycles, Funds,
};

pub fn stream_header() -> StreamHeader {
    StreamHeader {
        begin: 23.into(),
        end: 25.into(),
        signals_end: 256.into(),
    }
}

pub fn request() -> RequestOrResponse {
    RequestOrResponse::Request(
        RequestBuilder::new()
            .receiver(canister_test_id(1))
            .sender(canister_test_id(2))
            .sender_reply_callback(CallbackId::from(3))
            .payment(Funds::new(Cycles::from(4), Tap::mint(5)))
            .method_name("test".to_string())
            .method_payload(vec![6])
            .build(),
    )
}

pub fn response() -> RequestOrResponse {
    RequestOrResponse::Response(
        ResponseBuilder::new()
            .originator(canister_test_id(6))
            .respondent(canister_test_id(5))
            .originator_reply_callback(CallbackId::from(4))
            .refund(Funds::new(Cycles::from(3), ICP::zero()))
            .response_payload(Payload::Data(vec![1]))
            .build(),
    )
}

pub fn reject_response() -> RequestOrResponse {
    RequestOrResponse::Response(
        ResponseBuilder::new()
            .originator(canister_test_id(6))
            .respondent(canister_test_id(5))
            .originator_reply_callback(CallbackId::from(4))
            .refund(Funds::new(Cycles::from(3), Tap::mint(2)))
            .response_payload(Payload::Reject(RejectContext {
                code: RejectCode::SysFatal,
                message: "Oops".into(),
            }))
            .build(),
    )
}
