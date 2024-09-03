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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::SignedIngressBuilder;
    use ic_types::time::expiry_time_from_now;
    use std::time::Duration;

    #[test]
    fn test_ingress_payload_deserialization() {
        // serialization/deserialization of empty payload.
        let payload = IngressPayload::default();
        let bytes = bincode::serialize(&payload).unwrap();
        assert_eq!(
            bincode::deserialize::<IngressPayload>(&bytes).unwrap(),
            payload
        );
        let time = expiry_time_from_now();

        // Some test messages.
        let m1 = SignedIngressBuilder::new()
            .method_name("m1".to_string())
            .expiry_time(time + Duration::from_secs(1))
            .build();
        let m2 = SignedIngressBuilder::new()
            .method_name("m2".to_string())
            .expiry_time(time + Duration::from_secs(2))
            .build();
        let m3 = SignedIngressBuilder::new()
            .method_name("m3".to_string())
            .expiry_time(time + Duration::from_secs(3))
            .build();

        let msgs = vec![m1, m2, m3];
        let payload = IngressPayload::from(msgs.clone());
        // Serialization/deserialization works.
        let bytes = bincode::serialize(&payload).unwrap();
        assert_eq!(
            bincode::deserialize::<IngressPayload>(&bytes).unwrap(),
            payload
        );

        assert_eq!(payload.as_ref(), msgs);
        // Converting back to messages should match original
        assert_eq!(msgs, <Vec<SignedIngress>>::from(payload));
    }
}
