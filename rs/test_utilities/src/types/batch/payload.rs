use ic_types::batch::{BatchPayload, IngressPayload, XNetPayload};

pub struct PayloadBuilder {
    payload: BatchPayload,
}

impl Default for PayloadBuilder {
    /// Create a default, empty, XNetPayload
    fn default() -> Self {
        Self {
            payload: BatchPayload {
                ingress: super::ingress_payload::IngressPayloadBuilder::default().build(),
                xnet: super::xnet_payload::XNetPayloadBuilder::default().build(),
            },
        }
    }
}

impl PayloadBuilder {
    /// Create a new XNetPayloadBuilder
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the ingress field to ingress_payload
    pub fn ingress(mut self, ingress_payload: IngressPayload) -> Self {
        self.payload.ingress = ingress_payload;
        self
    }

    /// Set the xnet field to xnet_payload.
    pub fn xnet(mut self, xnet_payload: XNetPayload) -> Self {
        self.payload.xnet = xnet_payload;
        self
    }

    /// Return the built Payload.
    pub fn build(&self) -> BatchPayload {
        self.payload.clone()
    }
}

#[test]
fn batch_payload_serialize_then_deserialize() {
    let ingress_0 = crate::types::messages::SignedIngressBuilder::new()
        .nonce(0)
        .build();
    let batch_payload_0 = BatchPayload {
        ingress: IngressPayload::from(vec![ingress_0]),
        xnet: XNetPayload::default(),
    };
    let vec = serde_cbor::ser::to_vec(&batch_payload_0).unwrap();
    let batch_payload_1: BatchPayload = serde_cbor::de::from_slice(&vec).unwrap();
    assert_eq!(batch_payload_0, batch_payload_1);
}

#[test]
fn payload_serialize_then_deserialize() {
    use ic_types::{
        batch::BatchPayload,
        consensus::{dkg, Payload},
        Height,
    };

    // Test default empty payload
    let payload_0 = Payload::new(
        ic_crypto::crypto_hash,
        (
            BatchPayload::default(),
            dkg::Dealings::new_empty(Height::from(0)),
        )
            .into(),
    );
    let vec = serde_cbor::ser::to_vec(&payload_0).unwrap();
    let payload_1: Payload = serde_cbor::de::from_slice(&vec).unwrap();
    // this compares UID according to Eq instance of Payload.
    assert_eq!(payload_0, payload_1);
    // this compares actual payload.
    assert_eq!(
        payload_0.as_ref().as_batch_payload(),
        payload_1.as_ref().as_batch_payload()
    );

    // Test with a ingress message
    let ingress_0 = crate::types::messages::SignedIngressBuilder::new()
        .nonce(0)
        .build();
    let batch_payload_0 = BatchPayload {
        ingress: IngressPayload::from(vec![ingress_0]),
        xnet: XNetPayload::default(),
    };
    let payload_0 = Payload::new(
        ic_crypto::crypto_hash,
        (batch_payload_0, dkg::Dealings::new_empty(Height::from(0))).into(),
    );
    let vec = serde_cbor::ser::to_vec(&payload_0).unwrap();
    let payload_1: Payload = serde_cbor::de::from_slice(&vec).unwrap();
    // this compares UID according to Eq instance of Payload.
    assert_eq!(payload_0, payload_1);
    // this compares actual payload.
    assert_eq!(
        payload_0.as_ref().as_batch_payload(),
        payload_1.as_ref().as_batch_payload()
    );
}
