use ic_types::{batch::IngressPayload, messages::SignedIngress};

pub struct IngressPayloadBuilder {
    ingress_payload: Vec<SignedIngress>,
}

impl Default for IngressPayloadBuilder {
    /// Create an default, empty, IngressPayloadBuilder.
    fn default() -> Self {
        Self {
            ingress_payload: Vec::new(),
        }
    }
}

impl IngressPayloadBuilder {
    /// Creates a new `IngressPayloadBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `IngressPayload` messages field to the provided messages.
    pub fn msgs(mut self, ingress_msgs: Vec<SignedIngress>) -> Self {
        self.ingress_payload = ingress_msgs;
        self
    }

    /// Appends the provided Ingress message to the end of the `IngressPayload`.
    pub fn add_ingress(mut self, ingress: SignedIngress) -> Self {
        self.ingress_payload.push(ingress);
        self
    }

    /// Returns the built `IngressPayload`.
    pub fn build(self) -> IngressPayload {
        self.ingress_payload.into()
    }
}
