use ic_types::batch::{BatchPayload, IngressPayload, SelfValidatingPayload, XNetPayload};

pub struct PayloadBuilder {
    payload: BatchPayload,
}

impl Default for PayloadBuilder {
    fn default() -> Self {
        Self {
            payload: BatchPayload {
                ingress: super::ingress_payload::IngressPayloadBuilder::default().build(),
                xnet: super::xnet_payload::XNetPayloadBuilder::default().build(),
                // TODO(MR-70): use payload builder
                self_validating: SelfValidatingPayload::default(),
                canister_http: vec![],
                query_stats: vec![],
                vetkd: vec![],
            },
        }
    }
}

impl PayloadBuilder {
    /// Creates a new `PayloadBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `ingress` field.
    pub fn ingress(mut self, ingress_payload: IngressPayload) -> Self {
        self.payload.ingress = ingress_payload;
        self
    }

    /// Sets the `xnet` field.
    pub fn xnet(mut self, xnet_payload: XNetPayload) -> Self {
        self.payload.xnet = xnet_payload;
        self
    }

    /// Returns the built `BatchPayload`.
    pub fn build(&self) -> BatchPayload {
        self.payload.clone()
    }
}

#[cfg(test)]
mod tests {
    use ic_types::{
        batch::{BatchPayload, IngressPayload},
        consensus::{BlockPayload, DataPayload},
    };

    #[test]
    fn batch_payload_serialize_then_deserialize() {
        let ingress_0 = crate::messages::SignedIngressBuilder::new()
            .nonce(0)
            .build();
        let batch_payload_0 = BatchPayload {
            ingress: IngressPayload::from(vec![ingress_0]),
            ..BatchPayload::default()
        };
        let vec = serde_cbor::ser::to_vec(&batch_payload_0).unwrap();
        let batch_payload_1: BatchPayload = serde_cbor::de::from_slice(&vec).unwrap();
        assert_eq!(batch_payload_0, batch_payload_1);
    }

    #[test]
    fn payload_serialize_then_deserialize() {
        use ic_types::{
            Height,
            batch::BatchPayload,
            consensus::{Payload, dkg::DkgDataPayload},
        };

        // Test default empty payload
        let payload_0 = Payload::new(
            ic_types::crypto::crypto_hash,
            BlockPayload::Data(DataPayload {
                batch: BatchPayload::default(),
                dkg: DkgDataPayload::new_empty(Height::from(0)),
                idkg: None,
            }),
        );
        let vec = serde_cbor::ser::to_vec(&payload_0).unwrap();
        let payload_1: Payload = serde_cbor::de::from_slice(&vec).unwrap();
        // this compares UID according to Eq instance of Payload.
        assert_eq!(payload_0, payload_1);
        // this compares actual payload.
        assert_eq!(
            payload_0.as_ref().as_data().batch,
            payload_1.as_ref().as_data().batch
        );

        // Test with a ingress message
        let ingress_0 = crate::messages::SignedIngressBuilder::new()
            .nonce(0)
            .build();
        let batch_payload_0 = BatchPayload {
            ingress: IngressPayload::from(vec![ingress_0]),
            ..BatchPayload::default()
        };
        let payload_0 = Payload::new(
            ic_types::crypto::crypto_hash,
            BlockPayload::Data(DataPayload {
                batch: batch_payload_0,
                dkg: DkgDataPayload::new_empty(Height::new(0)),
                idkg: None,
            }),
        );
        let vec = serde_cbor::ser::to_vec(&payload_0).unwrap();
        let payload_1: Payload = serde_cbor::de::from_slice(&vec).unwrap();
        // this compares UID according to Eq instance of Payload.
        assert_eq!(payload_0, payload_1);
        // this compares actual payload.
        assert_eq!(
            payload_0.as_ref().as_data().batch,
            payload_1.as_ref().as_data().batch
        );
    }
}
