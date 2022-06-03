use bytes::{Buf, BytesMut};
use serde::de::DeserializeOwned;
use std::marker::PhantomData;

/// Incremental decoder for stream of data. Splits frames preceded by
/// u32 length tag and deserialized them using cbor.
pub struct FrameDecoder<Message: DeserializeOwned + Clone> {
    state: FrameDecoderState,
    phantom: PhantomData<Message>,
}

enum FrameDecoderState {
    NoLength,
    Length(u32),
}

impl<Message: DeserializeOwned + Clone> FrameDecoder<Message> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        FrameDecoder {
            state: FrameDecoderState::NoLength,
            phantom: PhantomData,
        }
    }

    /// Tries to extract one message from buffer given. The buffer is
    /// consumed as far as possible and resized to adequate size
    /// if more data is needed. Returns one frame if it can be parsed
    /// from given buffer.
    /// This is to be called repeatedly, interleaved with filling the
    /// buffer with more data as needed.
    pub fn decode(&mut self, data: &mut BytesMut) -> Option<Message> {
        loop {
            match &self.state {
                FrameDecoderState::NoLength => {
                    if data.len() < 4 {
                        data.reserve(4);
                        return None;
                    } else {
                        let size = data.get_u32();
                        self.state = FrameDecoderState::Length(size);
                    }
                }
                FrameDecoderState::Length(size) => {
                    let size: usize = *size as usize;
                    if data.len() < size {
                        data.reserve(size);
                        return None;
                    } else {
                        let frame = data.split_to(size);
                        self.state = FrameDecoderState::NoLength;
                        let value = bincode::deserialize(&frame).unwrap();
                        return Some(value);
                    }
                }
            }
        }
    }
}
