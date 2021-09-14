//! Defines canister threshold signature types.
use crate::crypto::canister_threshold_sig::idkg::IDkgTranscriptId;
use ic_base_types::PrincipalId;

pub mod error;
pub mod idkg;

use ic_crypto_internal_types::sign::canister_threshold_sig::CspThresholdSignatureMsg;

pub struct PreSignatureTranscript {
    pub kappa: IDkgTranscriptId,
    pub lambda: IDkgTranscriptId,
    pub mu: IDkgTranscriptId,
    pub omega: IDkgTranscriptId,
}

pub struct ThresholdSignatureInputs {
    pub caller: PrincipalId,
    pub index: u32,
    pub message: Vec<u8>,
    pub presig_transcript: PreSignatureTranscript,
    pub key_transcript: IDkgTranscriptId,
}

impl ThresholdSignatureInputs {
    pub fn new(
        caller: PrincipalId,
        index: u32,
        message: Vec<u8>,
        presig_transcript: PreSignatureTranscript,
        key_transcript: IDkgTranscriptId,
    ) -> Self {
        Self {
            caller,
            index,
            message,
            presig_transcript,
            key_transcript,
        }
    }
}

pub struct ThresholdSignatureMsg {
    pub internal_msg: CspThresholdSignatureMsg,
}
