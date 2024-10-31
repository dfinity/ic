use crate::crypto::canister_threshold_sig::ExtendedDerivationPath;
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use std::fmt;
use std::hash::Hash;

/// Counterpart of ThresholdSchnorrSigInputs that holds transcript references,
/// instead of the transcripts.
#[derive(Clone, Eq, PartialEq, Hash)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct VetKdInputs {
    pub derivation_path: ExtendedDerivationPath,
    // TODO: Use correct data
    pub data: Vec<u8>,
}

impl fmt::Debug for VetKdInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VetKdInputs")
            .field("derivation_path", &self.derivation_path)
            .field("data_in_bytes", &self.data.len())
            .finish()
    }
}
