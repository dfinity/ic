//! Defines errors that may occur in the context of canister threshold
//! signatures.

// The errors that might occur are still TBD
#[derive(Copy, Clone, Debug)]
pub enum IDkgParamsValidationError {
    TooManyReceivers { receivers_count: usize },
    TooManyDealers { dealers_count: usize },
    ReceiversEmpty,
    DealersEmpty,
}

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptParsingError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptCreationError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptVerificationError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptOpeningError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptLoadError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgDealingError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgDealingVerificationError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgComplaintParsingError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgComplaintVerificationError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgOpeningParsingError {}

#[derive(Copy, Clone, Debug)]
pub enum IDkgOpeningVerificationError {}

#[derive(Copy, Clone, Debug)]
pub enum ThresholdSignatureVerificationError {}

#[derive(Copy, Clone, Debug)]
pub enum ThresholdSignatureGenerationError {}

#[derive(Copy, Clone, Debug)]
pub enum CombineSignatureError {}
