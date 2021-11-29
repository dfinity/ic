use io::Read;
use mio::unix::pipe;
use serde::{Deserialize, Serialize};
use std::io;
use std::{convert::TryInto, mem::size_of};

pub fn serialize_and_write<W: io::Write, A: Serialize>(
    w: &mut W,
    payload: &A,
) -> io::Result<usize> {
    let payload = bincode::serialize(payload).unwrap();
    let n = w.write(&(payload.len() as usize).to_be_bytes())?;
    let m = w.write(&payload)?;
    Ok(n + m)
}

pub struct StreamDecoder {
    buf: Vec<u8>,
    offset: usize,
}

impl Default for StreamDecoder {
    fn default() -> Self {
        StreamDecoder::new()
    }
}

impl StreamDecoder {
    pub fn new() -> Self {
        StreamDecoder {
            buf: Vec::new(),
            offset: 0,
        }
    }

    pub fn from_pipe(mut pipe: pipe::Receiver) -> Self {
        let mut u8buf = vec![0u8; 4096];
        let mut buf = Vec::new();
        while let Ok(n) = pipe.read(&mut u8buf) {
            if n == 0 {
                break;
            } else {
                buf.extend_from_slice(&u8buf);
            }
        }
        StreamDecoder { buf, offset: 0 }
    }

    pub fn append(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    // Decode a message if there is enough data in the buffer.
    pub fn try_decode<'de, T: Deserialize<'de>>(&'de mut self) -> Option<T> {
        let avail = self.buf.len() - self.offset;

        if avail < size_of::<usize>() {
            return None;
        }

        let payload_size = &self.buf[self.offset..self.offset + size_of::<usize>()];
        let payload_size = usize::from_be_bytes(payload_size.try_into().unwrap());

        if avail < size_of::<usize>() + payload_size {
            return None;
        }

        let payload_offset = self.offset + size_of::<usize>();
        let payload = &self.buf[payload_offset..payload_offset + payload_size];
        let res: T =
            bincode::deserialize(payload).expect("failed to deserialize a bincode message");
        // Update the offset
        self.offset = payload_offset + payload_size;
        Some(res)
    }
}
