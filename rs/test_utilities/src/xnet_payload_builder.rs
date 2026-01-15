use ic_interfaces::messaging::{XNetPayloadBuilder, XNetPayloadValidationError};
use ic_types::{
    NumBytes, SubnetId,
    batch::{ValidationContext, XNetPayload},
    xnet::CertifiedStreamSlice,
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
    ) -> (XNetPayload, NumBytes) {
        let mut streams = self.0.lock().unwrap();

        // Pick a stream that fits the size requirements
        let mut picked_stream = None;
        let mut size_bytes = 0.into();
        for (index, stream_slices) in streams.iter().enumerate() {
            let stream_size: usize = stream_slices
                .values()
                .map(|stream_slice| stream_slice.payload.len() + stream_slice.merkle_proof.len())
                .sum();

            if NumBytes::from(stream_size as u64) < byte_limit {
                picked_stream = Some(index);
                size_bytes = (stream_size as u64).into();
                break;
            }
        }

        match picked_stream {
            None => (XNetPayload::default(), 0.into()),
            Some(stream_index) => {
                let stream = streams.remove(stream_index).unwrap();
                (
                    XNetPayload {
                        stream_slices: stream,
                    },
                    size_bytes,
                )
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
            .values()
            .map(|stream_slice| stream_slice.payload.len() + stream_slice.merkle_proof.len())
            .sum();

        Ok(NumBytes::from(size as u64))
    }
}
