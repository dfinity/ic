//! Defines errors that may occur in the context of canister threshold
//! signatures.

macro_rules! impl_display_using_debug {
    ($t:ty) => {
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{:?}", self)
            }
        }
    };
}

#[derive(Copy, Clone, Debug)]
pub enum PresignatureQuadrupleCreationError {
    WrongTypes,
}
impl_display_using_debug!(PresignatureQuadrupleCreationError);

#[derive(Copy, Clone, Debug)]
pub enum ThresholdSignatureInputsCreationError {
    NonmatchingTranscriptIds,
}
impl_display_using_debug!(ThresholdSignatureInputsCreationError);

// The errors that might occur are still TBD
#[derive(Copy, Clone, Debug)]
pub enum IDkgParamsValidationError {
    TooManyReceivers { receivers_count: usize },
    TooManyDealers { dealers_count: usize },
    ReceiversEmpty,
    DealersEmpty,
}
impl_display_using_debug!(IDkgParamsValidationError);

#[derive(Copy, Clone, Debug)]
pub enum EcdsaPublicKeyError {}
impl_display_using_debug!(EcdsaPublicKeyError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptParsingError {}
impl_display_using_debug!(IDkgTranscriptParsingError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptCreationError {}
impl_display_using_debug!(IDkgTranscriptCreationError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptVerificationError {}
impl_display_using_debug!(IDkgTranscriptVerificationError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptOpeningError {}
impl_display_using_debug!(IDkgTranscriptOpeningError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptLoadError {}
impl_display_using_debug!(IDkgTranscriptLoadError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgDealingError {}
impl_display_using_debug!(IDkgDealingError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgDealingVerificationError {}
impl_display_using_debug!(IDkgDealingVerificationError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgComplaintParsingError {}
impl_display_using_debug!(IDkgComplaintParsingError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgComplaintVerificationError {}
impl_display_using_debug!(IDkgComplaintVerificationError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgOpeningParsingError {}
impl_display_using_debug!(IDkgOpeningParsingError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgOpeningVerificationError {}
impl_display_using_debug!(IDkgOpeningVerificationError);

#[derive(Copy, Clone, Debug)]
pub enum ThresholdSignatureVerificationError {}
impl_display_using_debug!(ThresholdSignatureVerificationError);

#[derive(Copy, Clone, Debug)]
pub enum ThresholdSignatureGenerationError {}
impl_display_using_debug!(ThresholdSignatureGenerationError);

#[derive(Copy, Clone, Debug)]
pub enum CombineSignatureError {}
impl_display_using_debug!(CombineSignatureError);
