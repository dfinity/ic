use super::*;
use crate::sign::threshold_sig::dkg::dealings_to_csp_dealings::{
    CspDealings, DealingsToCspDealings, DealingsToCspDealingsError,
};
use crate::sign::threshold_sig::tests::mock_csp_public_coefficients_from_bytes;
use ic_crypto_internal_csp::types::{CspDealing, CspDkgTranscript, CspEncryptedSecretKey, CspPop};
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::{
    CLibTranscriptBytes, EncryptedShareBytes, EphemeralPopBytes,
};
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::secp256k1::EphemeralPublicKeyBytes;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::{
    CspEncryptionPublicKey, InternalCspEncryptionPublicKey,
};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_types::crypto::dkg::{EncryptionPublicKey, EncryptionPublicKeyPop};
use mockall::*;

mock! {
    pub DealingsToCspDealings {}

    pub trait DealingsToCspDealings {
    fn convert(
        &self,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealings: &BTreeMap<NodeId, Dealing>,
    ) -> Result<CspDealings, DealingsToCspDealingsError>;
    }

}

pub fn keys_with(
    node_id: NodeId,
    enc_pk: CspEncryptionPublicKey,
    pop: CspPop,
) -> BTreeMap<NodeId, EncryptionPublicKeyWithPop> {
    let mut keys = BTreeMap::new();
    keys.insert(node_id, enc_pk_with_pop(enc_pk, pop));
    keys
}

pub fn dealings_with(node_id: NodeId, dealing: Dealing) -> BTreeMap<NodeId, Dealing> {
    let mut dealings = BTreeMap::new();
    dealings.insert(node_id, dealing);
    dealings
}

pub fn csp_pk_pop_dealing() -> (CspEncryptionPublicKey, CspPop, CspDealing) {
    (csp_enc_pk(42), csp_pop(43), csp_dealing(44))
}

pub fn csp_pk_pop_dealing_2() -> (CspEncryptionPublicKey, CspPop, CspDealing) {
    (csp_enc_pk(45), csp_pop(46), csp_dealing(47))
}

pub fn csp_enc_pk(content: u8) -> CspEncryptionPublicKey {
    CspEncryptionPublicKey {
        internal: InternalCspEncryptionPublicKey::Secp256k1(EphemeralPublicKeyBytes(
            [content; EphemeralPublicKeyBytes::SIZE],
        )),
    }
}

pub fn csp_pop(content: u8) -> CspPop {
    CspPop::Secp256k1(EphemeralPopBytes([content; EphemeralPopBytes::SIZE]))
}

pub fn enc_pk_with_pop(
    csp_enc_pk: CspEncryptionPublicKey,
    csp_pop: CspPop,
) -> EncryptionPublicKeyWithPop {
    EncryptionPublicKeyWithPop {
        key: EncryptionPublicKey::from(&csp_enc_pk),
        proof_of_possession: EncryptionPublicKeyPop::from(&csp_pop),
    }
}

pub fn pub_coeffs(content: u8) -> CspPublicCoefficients {
    mock_csp_public_coefficients_from_bytes(content)
}

pub fn csp_dealing(content: u8) -> CspDealing {
    CspDealing {
        common_data: pub_coeffs(content),
        receiver_data: vec![
            Some(CspEncryptedSecretKey::ThresBls12_381(EncryptedShareBytes(
                [9; EncryptedShareBytes::SIZE],
            ))),
            None,
            Some(CspEncryptedSecretKey::ThresBls12_381(EncryptedShareBytes(
                [11; EncryptedShareBytes::SIZE],
            ))),
        ],
    }
}

// TODO (CRP-381): Use this method in response/tests.rs: code copied from there.
pub fn dealings_mapper_expecting(
    expected_keys: BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
    expected_dealings: BTreeMap<NodeId, Dealing>,
) -> impl DealingsToCspDealings {
    let mut dealings_mapper = MockDealingsToCspDealings::new();
    dealings_mapper
        .expect_convert()
        .withf(move |verified_keys, verified_dealings| {
            verified_keys == &expected_keys && verified_dealings == &expected_dealings
        })
        .times(1)
        .return_const(Ok(vec![]));
    dealings_mapper
}

// TODO (CRP-381): Use this method in response/tests.rs: code copied from there.
pub fn dealings_mapper_returning(
    result: Result<CspDealings, DealingsToCspDealingsError>,
) -> impl DealingsToCspDealings {
    let mut dealings_mapper = MockDealingsToCspDealings::new();
    dealings_mapper
        .expect_convert()
        .times(1)
        .return_const(result);
    dealings_mapper
}

// TODO (CRP-381): Use this method in response/tests.rs: code copied from there.
pub fn any_dealings_to_pass_to_mapper_mock() -> BTreeMap<NodeId, Dealing> {
    BTreeMap::new()
}

pub fn csp_transcript() -> CspDkgTranscript {
    CspDkgTranscript::Secp256k1(CLibTranscriptBytes {
        dealer_public_keys: vec![],
        dealer_reshare_indices: None,
        public_coefficients: PublicCoefficientsBytes::from(pub_coeffs(42)),
        receiver_data: vec![],
    })
}
