use ic_types::messages::Payload;

pub struct ResponsePayloadBuilder {
    response_payload: Payload,
}

impl Default for ResponsePayloadBuilder {
    /// Creates a dummy ResponsePayload  with default values.
    fn default() -> Self {
        Self {
            response_payload: Payload::Data(Vec::new()),
        }
    }
}

impl ResponsePayloadBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the response_payload field.
    pub fn response_payload(mut self, response_payload: Payload) -> Self {
        self.response_payload = response_payload;
        self
    }

    pub fn build(self) -> Payload {
        self.response_payload
    }
}
