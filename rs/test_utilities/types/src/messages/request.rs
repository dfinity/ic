use crate::ids::canister_test_id;
use ic_types::{
    CanisterId, Cycles,
    messages::{CallbackId, NO_DEADLINE, Request, RequestMetadata},
    time::CoarseTime,
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
                payment: Cycles::zero(),
                method_name: name.to_string(),
                method_payload: Vec::new(),
                metadata: Default::default(),
                deadline: NO_DEADLINE,
            },
        }
    }
}

impl RequestBuilder {
    /// Creates a new `RequestBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `receiver` field.
    pub fn receiver(mut self, receiver: CanisterId) -> Self {
        self.request.receiver = receiver;
        self
    }

    /// Sets the `sender` field.
    pub fn sender(mut self, sender: CanisterId) -> Self {
        self.request.sender = sender;

        self
    }

    /// Sets the `sender_reply_callback` field.
    pub fn sender_reply_callback(mut self, sender_reply_callback: CallbackId) -> Self {
        self.request.sender_reply_callback = sender_reply_callback;
        self
    }

    /// Sets the `payment` field.
    pub fn payment(mut self, payment: Cycles) -> Self {
        self.request.payment = payment;
        self
    }

    /// Sets the `method_name` field.
    pub fn method_name<S: ToString>(mut self, method_name: S) -> Self {
        self.request.method_name = method_name.to_string();
        self
    }

    /// Sets the `method_payload` field.
    pub fn method_payload(mut self, method_payload: Vec<u8>) -> Self {
        self.request.method_payload = method_payload;
        self
    }

    /// Sets the `metadata` field.
    pub fn metadata(mut self, metadata: RequestMetadata) -> Self {
        self.request.metadata = metadata;
        self
    }

    /// Sets the `deadline` field.
    pub fn deadline(mut self, deadline: CoarseTime) -> Self {
        self.request.deadline = deadline;
        self
    }

    /// Returns the built `Request`.
    pub fn build(self) -> Request {
        self.request
    }
}
