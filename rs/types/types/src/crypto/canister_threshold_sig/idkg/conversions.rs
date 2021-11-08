//! Conversions to/from IDkg types

use super::*;
use crate::consensus::MultiSignature;
use crate::crypto::Signed;

impl From<Signed<IDkgDealing, MultiSignature<IDkgDealing>>> for IDkgMultiSignedDealing {
    fn from(signed: Signed<IDkgDealing, MultiSignature<IDkgDealing>>) -> Self {
        // This drops any duplicates in the signers.
        let signers: BTreeSet<NodeId> = signed.signature.signers.into_iter().collect();

        Self {
            signature: signed.signature.signature,
            signers,
            dealing: signed.content,
        }
    }
}
