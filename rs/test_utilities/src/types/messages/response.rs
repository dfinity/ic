use crate::types::ids::canister_test_id;
use ic_types::{
    messages::{CallbackId, Payload, Response},
    CanisterId, Funds,
};

pub struct ResponseBuilder {
    response: Response,
}

impl Default for ResponseBuilder {
    /// Creates a dummy Response message with default values.
    fn default() -> Self {
        let rpb = super::response_payload::ResponsePayloadBuilder::default();
        Self {
            response: Response {
                originator: canister_test_id(0),
                respondent: canister_test_id(1),
                originator_reply_callback: CallbackId::from(0),
                refund: Funds::zero(),
                response_payload: rpb.build(),
            },
        }
    }
}

impl ResponseBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the originator field.
    pub fn originator(mut self, originator: CanisterId) -> Self {
        self.response.originator = originator;
        self
    }

    /// Sets the respondent field.
    pub fn respondent(mut self, respondent: CanisterId) -> Self {
        self.response.respondent = respondent;
        self
    }

    /// Sets the originator_reply_callback field.
    pub fn originator_reply_callback(mut self, originator_reply_callback: CallbackId) -> Self {
        self.response.originator_reply_callback = originator_reply_callback;
        self
    }

    /// Sets the refund field.
    pub fn refund(mut self, refund: Funds) -> Self {
        self.response.refund = refund;
        self
    }

    /// Sets the response_payload_field.
    pub fn response_payload(mut self, response_payload: Payload) -> Self {
        self.response.response_payload = response_payload;
        self
    }

    pub fn build(&self) -> Response {
        self.response.clone()
    }
}
