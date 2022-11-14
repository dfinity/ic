//! Type conversion for using the Miracl-based FS library.
use super::crypto;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    Chunk, FsEncryptionPlaintext, NUM_CHUNKS,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use std::convert::TryFrom;

/// Represents a prefix of an epoch.
pub struct Tau(pub Vec<crypto::Bit>);
impl From<Epoch> for Tau {
    /// Gets the leaf node tau for a given epoch
    fn from(epoch: Epoch) -> Tau {
        let epoch = epoch.get();
        let num_bits = ::std::mem::size_of::<Epoch>() * 8;
        Tau((0..num_bits)
            .rev()
            .map(|shift| crypto::Bit::from(((epoch >> shift) & 1) as u8))
            .collect())
    }
}

impl From<&Tau> for Epoch {
    fn from(tau: &Tau) -> Epoch {
        crypto::epoch_from_tau_vec(&tau.0)
    }
}

/// Converts a miracl-compatible plaintext into a standard-sized plaintext
/// chunk.
///
/// Note: This function may be deprecated when we support out-of-range
/// plaintexts.
///
/// # Panics
/// This will panic of any of the plaintexts is too large to fit into a
/// standard-sized chunk.
pub fn plaintext_to_bytes(plaintext: &[isize]) -> FsEncryptionPlaintext {
    let mut chunks = [0; NUM_CHUNKS];
    for (dst, src) in chunks[..].iter_mut().zip(plaintext) {
        *dst = Chunk::try_from(*src).expect("Invalid chunk: Too large to serialise");
    }
    FsEncryptionPlaintext { chunks }
}

/// Converts standard plaintext chunks into the miracl-compatible form.
///
/// # Panics
/// This will panic if a chunk is too large; this should be impossible as the
/// Chunk size should not be larger than the Miracl representation of a chunk.
pub fn plaintext_from_bytes(bytes: &[Chunk; NUM_CHUNKS]) -> Vec<isize> {
    bytes
        .iter()
        .map(|chunk| isize::try_from(*chunk).expect("Invalid chunk: Too large to parse"))
        .collect()
}
