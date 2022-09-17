use ic_interfaces::messaging::{XNetPayloadBuilder, XNetPayloadValidationError};
use ic_types::{
    batch::{ValidationContext, XNetPayload},
    xnet::CertifiedStreamSlice,
    CountBytes, NumBytes, SubnetId,
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
        byte_limit: NumBytes,
    ) -> XNetPayload {
        let mut streams = self.0.lock().unwrap();

        // Pick a stream that fits the size requirements
        let mut picked_stream = None;
        for (index, stream_slice) in streams.iter().enumerate() {
            let stream = XNetPayload {
                stream_slices: stream_slice.clone(),
            };
            let stream_size = stream.count_bytes();
            if NumBytes::from(stream_size as u64) < byte_limit {
                picked_stream = Some(index);
                continue;
            }
        }

        match picked_stream {
            None => XNetPayload::default(),
            Some(stream_index) => {
                let stream = streams.remove(stream_index).unwrap();
                XNetPayload {
                    stream_slices: stream,
                }
            }
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
