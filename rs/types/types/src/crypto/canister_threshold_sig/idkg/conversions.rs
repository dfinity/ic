//! Conversions to/from IDkg types

use super::*;
use crate::crypto::Signed;
use crate::signature::MultiSignature;

impl From<Signed<SignedIDkgDealing, MultiSignature<SignedIDkgDealing>>> for IDkgMultiSignedDealing {
    fn from(signed: Signed<SignedIDkgDealing, MultiSignature<SignedIDkgDealing>>) -> Self {
        // This drops any duplicates in the signers.
        let signers: BTreeSet<NodeId> = signed.signature.signers.into_iter().collect();

        Self {
            signature: signed.signature.signature,
            signers,
            signed_dealing: signed.content,
        }
    }
}

impl From<&IDkgTranscriptOperation> for IDkgTranscriptType {
    /// Compute the type of a transcript that would be created from `op_type`
    fn from(op_type: &IDkgTranscriptOperation) -> Self {
        match op_type {
            IDkgTranscriptOperation::Random => {
                IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
            }
            IDkgTranscriptOperation::ReshareOfMasked(transcript) => IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(transcript.transcript_id),
            ),
            IDkgTranscriptOperation::ReshareOfUnmasked(transcript) => IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareUnmasked(transcript.transcript_id),
            ),
            IDkgTranscriptOperation::UnmaskedTimesMasked(transcript_1, transcript_2) => {
                IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                    transcript_1.transcript_id,
                    transcript_2.transcript_id,
                ))
            }
        }
    }
}
