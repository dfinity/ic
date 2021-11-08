use ic_base_types::NodeId;
use ic_base_types::PrincipalId;
use ic_types::crypto::canister_threshold_sig::error::{
    CombineSignatureError, EcdsaPublicKeyError, IDkgComplaintVerificationError, IDkgDealingError,
    IDkgDealingVerificationError, IDkgOpeningVerificationError, IDkgTranscriptCreationError,
    IDkgTranscriptLoadError, IDkgTranscriptOpeningError, IDkgTranscriptVerificationError,
    ThresholdSignatureGenerationError, ThresholdSignatureVerificationError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgComplaint, IDkgDealing, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptParams, VerifiedIDkgDealing,
};
use ic_types::crypto::canister_threshold_sig::{
    EcdsaPublicKey, ThresholdSignatureInputs, ThresholdSignatureMsg,
};
use std::collections::BTreeMap;

pub trait IDkgTranscriptGenerator {
    // Create a dealing of a prescribed type.
    // If the dealing is of type resharing or multiplication we need to check that
    // the referred transcripts have been preloaded. A dealing contains a
    // polynomial commitment and encryption of the polynomial evaluation in the
    // receivers' index.
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<IDkgDealing, IDkgDealingError>;

    //Public Verification of the dealing
    fn verify_dealing_public(
        &self,
        params: &IDkgTranscriptParams,
        dealing: &IDkgDealing,
    ) -> Result<(), IDkgDealingVerificationError>;

    // Note:
    // * For private verification we could also store the decrypted value, but we
    //   need to be smart when purging the SKS, as this dealing may never appear in
    //   a transcript. It seems premature optimization
    fn verify_dealing_private(
        &self,
        params: &IDkgTranscriptParams,
        dealing: &IDkgDealing,
    ) -> Result<(), IDkgDealingVerificationError>;

    // Probably we don't want to repeat all validations. But we can perform
    // consistency checks: e.g. size of ciphertexts and polynomial commitment and
    // that they all have the same transcript ID. VerifiedIDkgDealings include the
    // multisig on the dealing.
    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: &BTreeMap<NodeId, VerifiedIDkgDealing>,
    ) -> Result<IDkgTranscript, IDkgTranscriptCreationError>;

    // Verification all multi-sig on the various dealings in the transcript.
    fn verify_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<(), IDkgTranscriptVerificationError>;

    // Here we have three possible outputs:
    // * Success
    // * A `IDkgComplaint`
    // * Some error that does not result in a complaint.
    // What's the best output for this?
    // Q: Can we assume that required transcripts will be reloaded if the replica
    // restarts?
    fn load_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<Vec<IDkgComplaint>, IDkgTranscriptLoadError>;

    fn verify_complaint(
        &self,
        transcript_id: IDkgTranscriptId,
        complainer: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgComplaintVerificationError>;

    fn open_transcript(
        &self,
        transcript_id: IDkgTranscriptId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgTranscriptOpeningError>;

    fn verify_opening(
        &self,
        transcript_id: IDkgTranscriptId,
        opener: NodeId,
        opening: &IDkgOpening,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgOpeningVerificationError>;

    // The openings should also encode the position of the receiver, e.g. by using a
    // map between receivers and openings. The openings must have previously
    // been verified using verify_opening
    fn load_transcript_with_openings(
        &self,
        transcript: IDkgTranscript,
        opening: BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgTranscriptLoadError>;

    // Retain only the given transcripts in the state
    fn retain_active_transcripts(&self, active_transcripts: &[IDkgTranscriptId]);
}

// No state is kept between the various calls in this API.
pub trait ThresholdEcdsaSignature: IDkgTranscriptGenerator {
    fn sign_threshold(
        &self,
        inputs: &ThresholdSignatureInputs,
    ) -> Result<ThresholdSignatureMsg, ThresholdSignatureGenerationError>;

    fn validate_threshold_sig_share(
        &self,
        // `signer` is used to check that each node open the shares for their prescribed index.
        signer: NodeId,
        inputs: &ThresholdSignatureInputs,
        output: &ThresholdSignatureMsg,
    ) -> Result<(), ThresholdSignatureVerificationError>;

    fn combine_threshold_sig_shares(
        &self,
        inputs: &ThresholdSignatureInputs,
        outputs: &[ThresholdSignatureMsg],
    ) -> Result<Vec<u8>, CombineSignatureError>;

    fn get_ecdsa_public_key(
        &self,
        canister_id: PrincipalId,
        key_transcript: IDkgTranscript,
    ) -> Result<EcdsaPublicKey, EcdsaPublicKeyError>;
}
