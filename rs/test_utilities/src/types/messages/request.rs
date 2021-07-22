use crate::types::ids::canister_test_id;
use ic_types::{
    messages::{CallbackId, Request},
    CanisterId, Funds,
};

pub struct RequestBuilder {
    request: Request,
}

impl Default for RequestBuilder {
    /// Creates a dummy Request message with default values.
    fn default() -> Self {
        let name = "No-Op";
        Self {
            request: Request {
                receiver: canister_test_id(0),
                sender: canister_test_id(1),
                sender_reply_callback: CallbackId::from(0),
                payment: Funds::zero(),
                method_name: name.to_string(),
                method_payload: Vec::new(),
            },
        }
    }
}

impl RequestBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the receiver attribute.
    pub fn receiver(mut self, receiver: CanisterId) -> Self {
        self.request.receiver = receiver;
        self
    }

    /// Sets the sender attribute.
    pub fn sender(mut self, sender: CanisterId) -> Self {
        self.request.sender = sender;

        self
    }

    /// Sets the sender_reply_callback attribute.
    pub fn sender_reply_callback(mut self, sender_reply_callback: CallbackId) -> Self {
        self.request.sender_reply_callback = sender_reply_callback;
        self
    }

    /// Sets the payment attribute.
    pub fn payment(mut self, payment: Funds) -> Self {
        self.request.payment = payment;
        self
    }

    /// Sets the method_name attribute.
    pub fn method_name<S: ToString>(mut self, method_name: S) -> Self {
        self.request.method_name = method_name.to_string();
        self
    }

    /// Sets the method_payload attribute.
    pub fn method_payload(mut self, method_payload: Vec<u8>) -> Self {
        self.request.method_payload = method_payload;
        self
    }

    pub fn build(self) -> Request {
        self.request
    }
}
