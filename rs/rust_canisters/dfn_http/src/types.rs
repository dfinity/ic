use candid::{CandidType, Deserialize};
use serde_bytes::ByteBuf;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: ByteBuf,
    pub streaming_strategy: Option<StreamingStrategy>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Token {}

// This is still not quite correct.
// The spec treats Token as polymorphic type, but we have no way to specify polymorphic
// types in Candid. This works only because the service worker has a special CandidType
// implementation that takes any input type and ignores the subtype checking.
candid::define_function!(pub CallbackFunc : (Token) -> (StreamingCallbackHttpResponse) query);

#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum StreamingStrategy {
    Callback {
        callback: CallbackFunc,
        token: Token,
    },
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StreamingCallbackHttpResponse {
    pub body: ByteBuf,
    pub token: Option<Token>,
}
