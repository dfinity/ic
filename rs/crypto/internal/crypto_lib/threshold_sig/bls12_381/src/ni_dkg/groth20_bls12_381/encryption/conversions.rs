//! Type conversion for using the Miracl-based FS library.
use super::crypto;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;

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
