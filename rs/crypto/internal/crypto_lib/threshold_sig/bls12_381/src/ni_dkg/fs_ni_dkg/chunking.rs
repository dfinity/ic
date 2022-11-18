use ic_crypto_internal_bls12_381_type::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The size of a chunk in bytes
pub const CHUNK_BYTES: usize = 2;

/// The size of a chunk in bits
pub const CHUNK_BITS: usize = CHUNK_BYTES * 8;

/// The range of a chunk (ie, the cardinality of the set)
pub const CHUNK_SIZE: usize = 1 << CHUNK_BITS;

/// The type of a chunk, which must be able to hold CHUNK_MIN..=CHUNK_MAX
pub type Chunk = isize;

/// The smallest value that a chunk can take
pub const CHUNK_MIN: Chunk = 0;

/// The largest value that a chunk can take
pub const CHUNK_MAX: Chunk = CHUNK_MIN + (CHUNK_SIZE as Chunk) - 1;

/// The ciphertext is an encoded Scalar element
pub(crate) const MESSAGE_BYTES: usize = Scalar::BYTES;

/// NUM_CHUNKS is simply the number of chunks needed to hold a message
pub const NUM_CHUNKS: usize = (MESSAGE_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PlaintextChunks {
    chunks: [Chunk; NUM_CHUNKS],
}

impl PlaintextChunks {
    pub const SIZE: usize = NUM_CHUNKS;

    /// Create PlaintextChunks by chunking a Scalar value
    pub fn from_scalar(s: &Scalar) -> Self {
        let bytes = s.serialize();
        let mut chunks = [0; NUM_CHUNKS];

        for i in 0..NUM_CHUNKS {
            let mut buffer = [0u8; CHUNK_BYTES];
            buffer.copy_from_slice(&bytes[CHUNK_BYTES * i..CHUNK_BYTES * (i + 1)]);
            chunks[i] = u16::from_be_bytes(buffer) as isize;
        }

        Self { chunks }
    }

    /// Create a PlaintextChunks by rechunking dlog results
    pub fn from_dlogs(dlogs: &[Scalar]) -> Self {
        let chunk_size = Scalar::from_usize(CHUNK_SIZE);
        let mut acc = Scalar::zero();
        for dlog in dlogs {
            acc *= &chunk_size;
            acc += dlog;
        }

        Self::from_scalar(&acc)
    }

    /// Create a PlaintextChunks without checking that the chunking is valid
    ///
    /// This should only be used for testing
    pub fn new_unchecked(chunks: [Chunk; NUM_CHUNKS]) -> Self {
        Self { chunks }
    }

    pub fn chunks(&self) -> &[Chunk; NUM_CHUNKS] {
        &self.chunks
    }

    /// Return the chunk elements encoded as Scalars
    pub fn chunks_as_scalars(&self) -> Vec<Scalar> {
        let mut scalars = Vec::with_capacity(NUM_CHUNKS);
        for i in 0..NUM_CHUNKS {
            scalars.push(Scalar::from_isize(self.chunks[i]));
        }
        scalars
    }

    pub fn recombine_to_scalar(&self) -> Scalar {
        let factor = Scalar::from_usize(CHUNK_SIZE);

        let mut acc = Scalar::zero();
        for chunk in self.chunks {
            acc *= &factor;
            acc += Scalar::from_isize(chunk);
        }

        acc
    }
}
