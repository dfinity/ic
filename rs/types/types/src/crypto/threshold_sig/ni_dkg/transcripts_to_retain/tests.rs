use super::*;
use crate::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript};
use ic_base_types::RegistryVersion;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    PublicCoefficientsBytes, Transcript,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use std::collections::BTreeMap;

pub const REG_V2: RegistryVersion = RegistryVersion::new(2);
pub const REG_V3: RegistryVersion = RegistryVersion::new(3);
pub const REG_V4: RegistryVersion = RegistryVersion::new(4);
pub const REG_V5: RegistryVersion = RegistryVersion::new(5);

#[test]
fn should_create_minimal_valid_transcripts() {
    let transcripts = maplit::hashset! {low_transcript(REG_V2), high_transcript(REG_V2)};

    let result = TranscriptsToRetain::new(transcripts);

    assert!(result.is_ok());
}

#[test]
fn should_create_valid_transcripts() {
    let transcripts = maplit::hashset! {
        low_transcript(REG_V5),
        high_transcript(REG_V4),
        high_transcript(REG_V2),
        low_transcript(REG_V3),
    };

    let result = TranscriptsToRetain::new(transcripts);

    assert!(result.is_ok());
}

#[test]
fn should_return_error_if_transcripts_empty() {
    let transcripts = maplit::hashset! {};

    let result = TranscriptsToRetain::new(transcripts);

    assert_eq!(
        result.unwrap_err(),
        TranscriptsToRetainValidationError::NoLowTranscripts
    );
}

#[test]
fn should_return_error_if_no_low_transcripts() {
    let transcripts = maplit::hashset! {high_transcript(REG_V2)};

    let result = TranscriptsToRetain::new(transcripts);

    assert_eq!(
        result.unwrap_err(),
        TranscriptsToRetainValidationError::NoLowTranscripts
    );
}

#[test]
fn should_return_error_if_no_high_transcripts() {
    let transcripts = maplit::hashset! {low_transcript(REG_V2)};

    let result = TranscriptsToRetain::new(transcripts);

    assert_eq!(
        result.unwrap_err(),
        TranscriptsToRetainValidationError::NoHighTranscripts
    );
}

#[test]
fn should_return_min_registry_version() {
    let transcripts = maplit::hashset! {
        low_transcript(REG_V5),
        high_transcript(REG_V2),
        low_transcript(REG_V3),
        high_transcript(REG_V4),
    };

    let version = TranscriptsToRetain::new(transcripts)
        .unwrap()
        .min_registry_version();

    assert_eq!(version, REG_V2);
}

#[test]
fn should_return_correct_public_keys() {
    let transcript_1_coeffs = pub_coeffs(1);
    let transcript_2_coeffs = pub_coeffs(2);
    let transcript_3_coeffs = pub_coeffs(3);

    let transcripts = maplit::hashset! {
        low_transcript_with_pub_coeffs(REG_V3, transcript_1_coeffs.clone()),
        high_transcript_with_pub_coeffs(REG_V2, transcript_2_coeffs.clone()),
        high_transcript_with_pub_coeffs(REG_V2, transcript_3_coeffs.clone()),
    };

    let public_keys = TranscriptsToRetain::new(transcripts).unwrap().public_keys();

    assert_eq!(public_keys.len(), 3);
    assert!(public_keys.contains(&CspPublicCoefficients::Bls12_381(transcript_1_coeffs)));
    assert!(public_keys.contains(&CspPublicCoefficients::Bls12_381(transcript_2_coeffs)));
    assert!(public_keys.contains(&CspPublicCoefficients::Bls12_381(transcript_3_coeffs)));
}

#[test]
fn should_display_ids_and_registry_versions() {
    let transcripts = maplit::hashset! {
        high_transcript(REG_V2),
        low_transcript(REG_V3),
        high_transcript(REG_V4),
    };

    let display_msg = TranscriptsToRetain::new(transcripts)
        .unwrap()
        .display_dkg_ids_and_registry_versions();

    assert!(display_msg.contains("[dkg_id NiDkgId { start_block_height: 0, dealer_subnet: fscpm-uiaaa-aaaaa-aaaap-yai, dkg_tag: HighThreshold, target_subnet: Local }, registry version 2]"));
    assert!(display_msg.contains("[dkg_id NiDkgId { start_block_height: 0, dealer_subnet: fscpm-uiaaa-aaaaa-aaaap-yai, dkg_tag: LowThreshold, target_subnet: Local }, registry version 3]"));
    assert!(display_msg.contains("[dkg_id NiDkgId { start_block_height: 0, dealer_subnet: fscpm-uiaaa-aaaaa-aaaap-yai, dkg_tag: HighThreshold, target_subnet: Local }, registry version 4]"));
}

fn low_transcript(registry_version: RegistryVersion) -> NiDkgTranscript {
    low_transcript_with_pub_coeffs(registry_version, pub_coeffs(0))
}

fn low_transcript_with_pub_coeffs(
    registry_version: RegistryVersion,
    pub_coeffs: PublicCoefficientsBytes,
) -> NiDkgTranscript {
    let mut transcript = NiDkgTranscript::dummy_transcript_for_tests();
    transcript.dkg_id.dkg_tag = NiDkgTag::LowThreshold;
    transcript.registry_version = registry_version;
    transcript.internal_csp_transcript = csp_transcript_with_pub_coeffs(pub_coeffs);
    transcript
}

fn high_transcript(registry_version: RegistryVersion) -> NiDkgTranscript {
    high_transcript_with_pub_coeffs(registry_version, pub_coeffs(0))
}

fn high_transcript_with_pub_coeffs(
    registry_version: RegistryVersion,
    pub_coeffs: PublicCoefficientsBytes,
) -> NiDkgTranscript {
    let mut transcript = NiDkgTranscript::dummy_transcript_for_tests();
    transcript.dkg_id.dkg_tag = NiDkgTag::HighThreshold;
    transcript.registry_version = registry_version;
    transcript.internal_csp_transcript = csp_transcript_with_pub_coeffs(pub_coeffs);
    transcript
}

fn csp_transcript_with_pub_coeffs(pub_coeffs: PublicCoefficientsBytes) -> CspNiDkgTranscript {
    CspNiDkgTranscript::Groth20_Bls12_381(Transcript {
        public_coefficients: pub_coeffs,
        receiver_data: BTreeMap::new(),
    })
}

fn pub_coeffs(pub_coeffs: u8) -> PublicCoefficientsBytes {
    PublicCoefficientsBytes {
        coefficients: vec![PublicKeyBytes([pub_coeffs; PublicKeyBytes::SIZE])],
    }
}
