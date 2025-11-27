use ic_types::{SubnetId, batch::XNetPayload, xnet::CertifiedStreamSlice};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct XNetPayloadBuilder {
    xnet_payload: XNetPayload,
}

impl Default for XNetPayloadBuilder {
    /// Create a default, empty, XNetPayload
    fn default() -> Self {
        Self {
            xnet_payload: XNetPayload {
                stream_slices: Default::default(),
            },
        }
    }
}

impl XNetPayloadBuilder {
    /// Creates a new `XNetPayloadBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Replaces the `stream_slices` field.
    pub fn stream_slices(
        mut self,
        stream_slices: BTreeMap<SubnetId, CertifiedStreamSlice>,
    ) -> Self {
        self.xnet_payload.stream_slices = stream_slices;
        self
    }

    /// Appends the provided `CertifiedStreamSlice` to the `XNetPayload` under
    /// construction.
    pub fn add_stream_slice(
        mut self,
        src_subnet_id: SubnetId,
        stream_slice: CertifiedStreamSlice,
    ) -> Self {
        self.xnet_payload
            .stream_slices
            .insert(src_subnet_id, stream_slice);
        self
    }

    /// Returns the built `XNetPayload`.
    pub fn build(self) -> XNetPayload {
        self.xnet_payload
    }
}
