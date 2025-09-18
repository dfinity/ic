use crate::ids::canister_test_id;
use ic_types::{
    CanisterId, Cycles,
    messages::{CallbackId, NO_DEADLINE, Payload, Response},
    time::CoarseTime,
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
                refund: Cycles::zero(),
                response_payload: rpb.build(),
                deadline: NO_DEADLINE,
            },
        }
    }
}

impl ResponseBuilder {
    /// Creates a new `ResponseBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `originator` field.
    pub fn originator(mut self, originator: CanisterId) -> Self {
        self.response.originator = originator;
        self
    }

    /// Sets the `respondent` field.
    pub fn respondent(mut self, respondent: CanisterId) -> Self {
        self.response.respondent = respondent;
        self
    }

    /// Sets the `originator_reply_callback` field.
    pub fn originator_reply_callback(mut self, originator_reply_callback: CallbackId) -> Self {
        self.response.originator_reply_callback = originator_reply_callback;
        self
    }

    /// Sets the `refund` field.
    pub fn refund(mut self, refund: Cycles) -> Self {
        self.response.refund = refund;
        self
    }

    /// Sets the `response_payload` field.
    pub fn response_payload(mut self, response_payload: Payload) -> Self {
        self.response.response_payload = response_payload;
        self
    }

    /// Sets the `deadline` field.
    pub fn deadline(mut self, deadline: CoarseTime) -> Self {
        self.response.deadline = deadline;
        self
    }

    /// Returns the built `Response`.
    pub fn build(&self) -> Response {
        self.response.clone()
    }
}
