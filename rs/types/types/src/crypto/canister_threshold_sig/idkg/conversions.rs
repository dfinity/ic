//! Conversions to/from IDkg types

use super::*;

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
