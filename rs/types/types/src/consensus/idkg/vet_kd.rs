use crate::crypto::ExtendedDerivationPath;
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
}

impl fmt::Debug for VetKdInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VetKdInputs")
            .field("derivation_path", &self.derivation_path)
            .finish()
    }
}
