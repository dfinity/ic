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
pub enum ThresholdEcdsaSigInputsCreationError {
    NonmatchingTranscriptIds,
}
impl_display_using_debug!(ThresholdEcdsaSigInputsCreationError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgParamsValidationError {
    TooManyReceivers { receivers_count: usize },
    TooManyDealers { dealers_count: usize },
    ReceiversEmpty,
    DealersEmpty,
}
impl_display_using_debug!(IDkgParamsValidationError);

#[derive(Copy, Clone, Debug)]
pub enum ThresholdEcdsaGetPublicKeyError {}
impl_display_using_debug!(ThresholdEcdsaGetPublicKeyError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgTranscriptParsingError {}
impl_display_using_debug!(IDkgTranscriptParsingError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgCreateTranscriptError {}
impl_display_using_debug!(IDkgCreateTranscriptError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgVerifyTranscriptError {}
impl_display_using_debug!(IDkgVerifyTranscriptError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgOpenTranscriptError {}
impl_display_using_debug!(IDkgOpenTranscriptError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgLoadTranscriptError {}
impl_display_using_debug!(IDkgLoadTranscriptError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgLoadTranscriptWithOpeningsError {}
impl_display_using_debug!(IDkgLoadTranscriptWithOpeningsError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgCreateDealingError {}
impl_display_using_debug!(IDkgCreateDealingError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgVerifyDealingPublicError {}
impl_display_using_debug!(IDkgVerifyDealingPublicError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgVerifyDealingPrivateError {
    NotAReceiver,
}
impl_display_using_debug!(IDkgVerifyDealingPrivateError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgComplaintParsingError {}
impl_display_using_debug!(IDkgComplaintParsingError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgVerifyComplaintError {}
impl_display_using_debug!(IDkgVerifyComplaintError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgOpeningParsingError {}
impl_display_using_debug!(IDkgOpeningParsingError);

#[derive(Copy, Clone, Debug)]
pub enum IDkgVerifyOpeningError {}
impl_display_using_debug!(IDkgVerifyOpeningError);

#[derive(Copy, Clone, Debug)]
pub enum ThresholdEcdsaVerifySigShareError {}
impl_display_using_debug!(ThresholdEcdsaVerifySigShareError);

#[derive(Copy, Clone, Debug)]
pub enum ThresholdEcdsaSignShareError {}
impl_display_using_debug!(ThresholdEcdsaSignShareError);

#[derive(Copy, Clone, Debug)]
pub enum ThresholdEcdsaVerifyCombinedSignatureError {}
impl_display_using_debug!(ThresholdEcdsaVerifyCombinedSignatureError);

#[derive(Copy, Clone, Debug)]
pub enum ThresholdEcdsaCombineSigSharesError {}
impl_display_using_debug!(ThresholdEcdsaCombineSigSharesError);
