use ic_interfaces::messaging::{XNetPayloadBuilder, XNetPayloadValidationError};
use ic_types::{
    batch::{ValidationContext, XNetPayload},
    xnet::CertifiedStreamSlice,
    NumBytes, SubnetId,
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

#[derive(Default)]
pub struct FakeXNetPayloadBuilder(Mutex<VecDeque<BTreeMap<SubnetId, CertifiedStreamSlice>>>);

impl FakeXNetPayloadBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn make(provided_streams: VecDeque<BTreeMap<SubnetId, CertifiedStreamSlice>>) -> Self {
        Self(Mutex::new(provided_streams))
    }
}

impl XNetPayloadBuilder for FakeXNetPayloadBuilder {
    fn get_xnet_payload(
        &self,
        _validation_context: &ValidationContext,
        _past_payloads: &[&XNetPayload],
        _byte_limit: NumBytes,
    ) -> XNetPayload {
        XNetPayload {
            stream_slices: self.0.lock().unwrap().pop_front().unwrap_or_default(),
        }
    }

    fn validate_xnet_payload(
        &self,
        payload: &XNetPayload,
        _validation_context: &ValidationContext,
        _past_payloads: &[&XNetPayload],
    ) -> Result<NumBytes, XNetPayloadValidationError> {
        let size: usize = payload
            .stream_slices
            .iter()
            .map(|(_, stream_slice)| stream_slice.payload.len() + stream_slice.merkle_proof.len())
            .sum();

        Ok(NumBytes::from(size as u64))
    }
}
