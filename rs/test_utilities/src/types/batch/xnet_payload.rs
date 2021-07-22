use ic_types::{batch::XNetPayload, xnet::CertifiedStreamSlice, SubnetId};
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
    /// Create a new XNetPayloadBuilder
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `xnet_payload.stream_slices` field to `stream_slices`.
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

    /// Return the built XNetPayload.
    pub fn build(self) -> XNetPayload {
        self.xnet_payload
    }
}
