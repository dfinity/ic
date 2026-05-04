use crate::sign::BTreeSet;
use crate::sign::tests::{REG_V1, REG_V2};
use crate::sign::threshold_sig::CspPublicCoefficients;
use crate::sign::threshold_sig::ni_dkg::retain_active_keys::retain_only_active_keys;
use crate::sign::threshold_sig::ni_dkg::utils::epoch;
use assert_matches::assert_matches;
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::InternalError;
use ic_crypto_internal_threshold_sig_bls12381::api::ni_dkg_errors::{
    CspDkgRetainThresholdKeysError, CspDkgUpdateFsEpochError, KeyNotFoundError,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    PublicCoefficientsBytes, Transcript,
};
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_crypto_test_utils_csp::MockAllCryptoServiceProvider;
use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests;
use ic_types::RegistryVersion;
use ic_types::crypto::AlgorithmId;
use ic_types::crypto::error as cryptoerror;
use ic_types::crypto::threshold_sig::ni_dkg::errors::key_removal_error::DkgKeyRemovalError;
use ic_types::crypto::threshold_sig::ni_dkg::transcripts_to_retain::TranscriptsToRetain;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTranscript};
use std::collections::BTreeMap;

#[test]
fn should_succeed_with_correct_parameters() {
    let transcripts = transcripts_to_retain();
    let expected_active_keys = transcripts.public_keys();
    let epoch = epoch(transcripts.min_registry_version());
    let setup = Setup::builder()
        .with_retain_threshold_keys_if_present(expected_active_keys, Ok(()))
        .with_observe_minimum_epoch_in_active_transcripts(epoch)
        .with_update_forward_secure_epoch(epoch, Ok(()))
        .build();

    assert_eq!(retain_only_active_keys(&setup.csp, transcripts), Ok(()));
}

#[test]
fn should_fail_if_retain_threshold_keys_if_present_fails_with_a_transient_error() {
    let transcripts = transcripts_to_retain();
    let expected_active_keys = transcripts.public_keys();
    let transient_error = "uh oh!";
    let setup = Setup::builder()
        .with_retain_threshold_keys_if_present(
            expected_active_keys,
            Err(CspDkgRetainThresholdKeysError::TransientInternalError(
                InternalError {
                    internal_error: transient_error.to_string(),
                },
            )),
        )
        .build();

    assert_matches!(
        retain_only_active_keys(&setup.csp, transcripts),
        Err(DkgKeyRemovalError::TransientInternalError(cryptoerror::InternalError{internal_error}))
        if internal_error == transient_error
    );
}

#[test]
fn should_fail_if_update_forward_secure_epoch_returns_error() {
    let transcripts = transcripts_to_retain();
    let expected_active_keys = transcripts.public_keys();
    let epoch = epoch(transcripts.min_registry_version());
    let key_not_found_err = key_not_found_err();
    let setup = Setup::builder()
        .with_retain_threshold_keys_if_present(expected_active_keys, Ok(()))
        .with_observe_minimum_epoch_in_active_transcripts(epoch)
        .with_update_forward_secure_epoch(
            epoch,
            Err(CspDkgUpdateFsEpochError::FsKeyNotInSecretKeyStoreError(
                key_not_found_err.clone(),
            )),
        )
        .build();

    assert_matches!(
        retain_only_active_keys(&setup.csp, transcripts),
        Err(DkgKeyRemovalError::FsKeyNotInSecretKeyStoreError(err))
        if err == key_not_found_err
    );
}

fn transcripts_to_retain() -> TranscriptsToRetain {
    let transcripts = maplit::hashset! {
        high_transcript(REG_V1),
        high_transcript(REG_V1),
        low_transcript(REG_V2),
    };
    TranscriptsToRetain::new(transcripts).unwrap()
}

fn key_not_found_err() -> KeyNotFoundError {
    KeyNotFoundError {
        internal_error: "some error".to_string(),
        key_id: "KeyId(0x0000000000000000000000000000000000000000000000000000000000000000)"
            .to_string(),
    }
}

fn high_transcript(registry_version: RegistryVersion) -> NiDkgTranscript {
    high_transcript_with_pub_coeffs(registry_version, pub_coeffs(0))
}

fn high_transcript_with_pub_coeffs(
    registry_version: RegistryVersion,
    pub_coeffs: PublicCoefficientsBytes,
) -> NiDkgTranscript {
    let mut transcript = dummy_transcript_for_tests();
    transcript.dkg_id.dkg_tag = NiDkgTag::HighThreshold;
    transcript.registry_version = registry_version;
    transcript.internal_csp_transcript = csp_transcript_with_pub_coeffs(pub_coeffs);
    transcript
}

fn low_transcript(registry_version: RegistryVersion) -> NiDkgTranscript {
    low_transcript_with_pub_coeffs(registry_version, pub_coeffs(0))
}

fn low_transcript_with_pub_coeffs(
    registry_version: RegistryVersion,
    pub_coeffs: PublicCoefficientsBytes,
) -> NiDkgTranscript {
    let mut transcript = dummy_transcript_for_tests();
    transcript.dkg_id.dkg_tag = NiDkgTag::LowThreshold;
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

struct Setup {
    csp: MockAllCryptoServiceProvider,
}

impl Setup {
    fn builder() -> SetupBuilder {
        SetupBuilder {
            csp: MockAllCryptoServiceProvider::new(),
        }
    }
}

struct SetupBuilder {
    csp: MockAllCryptoServiceProvider,
}

impl SetupBuilder {
    fn with_retain_threshold_keys_if_present(
        mut self,
        active_keys: BTreeSet<CspPublicCoefficients>,
        result: Result<(), CspDkgRetainThresholdKeysError>,
    ) -> Self {
        self.csp
            .expect_retain_threshold_keys_if_present()
            .withf(move |active_keys_| *active_keys_ == active_keys)
            .times(1)
            .return_const(result);
        self
    }

    fn with_update_forward_secure_epoch(
        mut self,
        epoch: Epoch,
        result: Result<(), CspDkgUpdateFsEpochError>,
    ) -> Self {
        self.csp
            .expect_update_forward_secure_epoch()
            .withf(move |algorithm_id, epoch_| {
                *algorithm_id == AlgorithmId::NiDkg_Groth20_Bls12_381 && *epoch_ == epoch
            })
            .times(1)
            .return_const(result);
        self
    }

    fn with_observe_minimum_epoch_in_active_transcripts(mut self, epoch: Epoch) -> Self {
        self.csp
            .expect_observe_minimum_epoch_in_active_transcripts()
            .withf(move |epoch_| *epoch_ == epoch)
            .times(1)
            .return_const(());
        self
    }

    fn build(self) -> Setup {
        Setup { csp: self.csp }
    }
}
