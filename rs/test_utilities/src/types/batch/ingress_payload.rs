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
    /// Create a new IngressPayloadBuilder.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the IngressPayload.msgs field to the provided messages.
    pub fn msgs(mut self, ingress_msgs: Vec<SignedIngress>) -> Self {
        self.ingress_payload = ingress_msgs;
        self
    }

    /// Append the provided Ingress message to the end of the IngressPayload.
    pub fn add_ingress(mut self, ingress: SignedIngress) -> Self {
        self.ingress_payload.push(ingress);
        self
    }

    /// Return the built IngressPayload.
    pub fn build(self) -> IngressPayload {
        self.ingress_payload.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::messages::SignedIngressBuilder;
    use assert_matches::assert_matches;
    use ic_types::{batch::IngressPayloadError, time::current_time_and_expiry_time};
    use std::convert::TryFrom;
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
        let (_, time) = current_time_and_expiry_time();

        // Some test messages.
        let m1 = SignedIngressBuilder::new()
            .method_name("m1".to_string())
            .expiry_time(time + Duration::from_secs(1))
            .build();
        let m1_id = m1.id();
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
        let mut bytes = bincode::serialize(&payload).unwrap();
        assert_eq!(
            bincode::deserialize::<IngressPayload>(&bytes).unwrap(),
            payload
        );
        // Individual lookup works.
        assert_matches!(payload.get(0).unwrap(), (_, msg) if msg == msgs[0]);
        assert_matches!(payload.get(1).unwrap(), (_, msg) if msg == msgs[1]);
        assert_matches!(payload.get(2).unwrap(), (_, msg) if msg == msgs[2]);
        // Test IndexOutOfBound.
        assert_matches!(payload.get(3), Err(IngressPayloadError::IndexOutOfBound(3)));
        // Converting back to messages should match original
        assert_eq!(msgs, <Vec<SignedIngress>>::try_from(payload).unwrap());

        // A sub-sequence search function
        fn find(array: &[u8], subseq: &[u8]) -> Option<usize> {
            for i in 0..array.len() - subseq.len() + 1 {
                if array[i..i + subseq.len()] == subseq[..] {
                    return Some(i);
                }
            }
            None
        }

        // Mutate some byte, deserialization works, but casting back to messages fail.
        let pos = find(&bytes, m1_id.as_bytes()).unwrap();
        // `+= 1` may overflow in debug mode.
        bytes[pos] ^= 1;
        let payload = bincode::deserialize::<IngressPayload>(&bytes);
        assert!(payload.is_ok());
        let payload = payload.unwrap();
        // get(0) should return error.
        assert_matches!(
            payload.get(0),
            Err(IngressPayloadError::MismatchedMessageIdAtIndex(0))
        );
        // Conversion should also fail.
        assert!(<Vec<_>>::try_from(payload).is_err());
    }
}
