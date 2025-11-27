use std::sync::Arc;

use super::*;
use crate::common::test_utils::{CryptoRegistryKey, CryptoRegistryRecord};
use crate::sign::canister_threshold_sig::test_utils::batch_signed_dealing_with;
use crate::sign::canister_threshold_sig::test_utils::node_set;
use crate::sign::canister_threshold_sig::test_utils::valid_internal_dealing_raw;
use crate::sign::tests::{
    REG_V1, mega_encryption_pk_record_with, registry_returning, registry_returning_none,
    registry_with,
};
use assert_matches::assert_matches;
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{EccCurveType, MEGaPublicKey};
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::canister_threshold_sig::idkg::BatchSignedIDkgDealing;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgDealing;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscriptId, IDkgTranscriptType,
    SignedIDkgDealing,
};
use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, KeyPurpose};
use ic_types::signature::{BasicSignature, BasicSignatureBatch};
use ic_types::{Height, RegistryVersion, registry::RegistryClientError};
use ic_types_test_utils::ids::{NODE_1, NODE_2, SUBNET_42};
use rand::{CryptoRng, Rng};

#[test]
fn should_fail_on_transcript_id_mismatch() {
    let rng = &mut reproducible_rng();
    let transcript_id_1 = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let transcript_id_2 = transcript_id_1.increment();
    assert_ne!(transcript_id_1, transcript_id_2);

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let transcript = IDkgTranscript {
            transcript_id: transcript_id_1,
            receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            verified_dealings: Arc::new(BTreeMap::new()),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id: transcript_id_2,
            dealer_id: NODE_1,
            internal_complaint_raw: valid_internal_complaint_raw(),
        };
        let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1, rng));

        let result = verify_complaint(registry.as_ref(), &transcript, &complaint, NODE_1);

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::InvalidArgumentMismatchingTranscriptIDs)
        );
    }
}

#[test]
fn should_fail_if_dealing_missing_in_transcript() {
    const COMPLAINT_DEALER_ID: NodeId = NODE_2;
    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let verified_dealings_missing_complaint_dealer_id = Arc::new(BTreeMap::new());

        let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
        let transcript = IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            verified_dealings: verified_dealings_missing_complaint_dealer_id,
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id,
            dealer_id: COMPLAINT_DEALER_ID,
            internal_complaint_raw: valid_internal_complaint_raw(),
        };
        let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1, rng));

        let result = verify_complaint(registry.as_ref(), &transcript, &complaint, NODE_1);

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::InvalidArgumentMissingDealingInTranscript { dealer_id })
                if dealer_id == COMPLAINT_DEALER_ID
        );
    }
}

#[test]
fn should_fail_if_complainer_missing_in_transcript() {
    const COMPLAINER_ID: NodeId = NODE_2;

    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let receivers_missing_complainer_id = IDkgReceivers::new(node_set(&[NODE_1])).unwrap();
        assert!(
            !receivers_missing_complainer_id
                .get()
                .contains(&COMPLAINER_ID)
        );

        let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
        let mut verified_dealings = BTreeMap::new();
        verified_dealings.insert(0, batch_signed_dealing_with_invalid_internal(NODE_1));
        let transcript = IDkgTranscript {
            transcript_id,
            receivers: receivers_missing_complainer_id,
            registry_version: REG_V1,
            verified_dealings: Arc::new(verified_dealings),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id,
            dealer_id: NODE_1,
            internal_complaint_raw: valid_internal_complaint_raw(),
        };
        let registry = registry_with(mega_encryption_pk_record(COMPLAINER_ID, REG_V1, rng));

        let result = verify_complaint(registry.as_ref(), &transcript, &complaint, COMPLAINER_ID);

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::InvalidArgumentMissingComplainerInTranscript { complainer_id })
                if complainer_id == COMPLAINER_ID
        );
    }
}

#[test]
fn should_fail_if_deserializing_complaint_fails() {
    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let invalid_internal_complaint_raw = b"invalid complaint".to_vec();

        let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
        let mut verified_dealings = BTreeMap::new();
        verified_dealings.insert(0, batch_signed_dealing(NODE_1));
        let transcript = IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            verified_dealings: Arc::new(verified_dealings),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id,
            dealer_id: NODE_1,
            internal_complaint_raw: invalid_internal_complaint_raw,
        };
        let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1, rng));

        let result = verify_complaint(registry.as_ref(), &transcript, &complaint, NODE_1);

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::SerializationError { internal_error })
                if internal_error.contains("failed to deserialize complaint")
        );
    }
}

#[test]
fn should_fail_if_deserializing_dealing_fails() {
    let rng = &mut reproducible_rng();

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let mut verified_dealings = BTreeMap::new();
        verified_dealings.insert(0, batch_signed_dealing_with_invalid_internal(NODE_1));

        let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
        let transcript = IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            verified_dealings: Arc::new(verified_dealings),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id,
            dealer_id: NODE_1,
            internal_complaint_raw: valid_internal_complaint_raw(),
        };
        let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1, rng));

        let result = verify_complaint(registry.as_ref(), &transcript, &complaint, NODE_1);

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::SerializationError { internal_error })
                if internal_error.contains("Error deserializing a signed dealing")
        );
    }
}

#[test]
fn should_fail_if_complainer_mega_pubkey_not_in_registry() {
    let registry_missing_complainer_pubkey = registry_returning_none();

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let mut verified_dealings = BTreeMap::new();
        verified_dealings.insert(0, batch_signed_dealing(NODE_1));
        let transcript = IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            verified_dealings: Arc::new(verified_dealings),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id,
            dealer_id: NODE_1,
            internal_complaint_raw: valid_internal_complaint_raw(),
        };

        let result = verify_complaint(
            registry_missing_complainer_pubkey.as_ref(),
            &transcript,
            &complaint,
            NODE_1,
        );

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::ComplainerPublicKeyNotInRegistry { node_id, registry_version })
                if node_id == NODE_1 && registry_version == REG_V1
        );
    }
}

#[test]
fn should_fail_if_complainer_mega_pubkey_is_malformed() {
    let registry_with_malformed_complainer_pubkey =
        registry_with(malformed_mega_encryption_pk_record(NODE_1, REG_V1));

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let mut verified_dealings = BTreeMap::new();
        verified_dealings.insert(0, batch_signed_dealing(NODE_1));
        let transcript = IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            verified_dealings: Arc::new(verified_dealings),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id,
            dealer_id: NODE_1,
            internal_complaint_raw: valid_internal_complaint_raw(),
        };

        let result = verify_complaint(
            registry_with_malformed_complainer_pubkey.as_ref(),
            &transcript,
            &complaint,
            NODE_1,
        );

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::MalformedComplainerPublicKey { node_id, .. })
                if node_id == NODE_1
        );
    }
}

#[test]
fn should_fail_if_complainer_mega_pubkey_algorithm_is_unsupported() {
    let registry_with_unsupported_complainer_pubkey_algorithm = registry_with(
        mega_encryption_pk_record_with_unsupported_algorithm(NODE_1, REG_V1),
    );

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let mut verified_dealings = BTreeMap::new();
        verified_dealings.insert(0, batch_signed_dealing(NODE_1));
        let transcript = IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            verified_dealings: Arc::new(verified_dealings),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id,
            dealer_id: NODE_1,
            internal_complaint_raw: valid_internal_complaint_raw(),
        };

        let result = verify_complaint(
            registry_with_unsupported_complainer_pubkey_algorithm.as_ref(),
            &transcript,
            &complaint,
            NODE_1,
        );

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::UnsupportedComplainerPublicKeyAlgorithm { .. })
        );
    }
}

#[test]
fn should_fail_if_registry_client_returns_error() {
    let registry_error = RegistryClientError::PollingLatestVersionFailed { retries: 3 };
    let registry_returning_error = registry_returning(registry_error.clone());

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));

    for alg in AlgorithmId::all_threshold_ecdsa_algorithms() {
        let mut verified_dealings = BTreeMap::new();
        verified_dealings.insert(0, batch_signed_dealing(NODE_1));
        let transcript = IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
            registry_version: REG_V1,
            verified_dealings: Arc::new(verified_dealings),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: alg,
            internal_transcript_raw: vec![],
        };
        let complaint = IDkgComplaint {
            transcript_id,
            dealer_id: NODE_1,
            internal_complaint_raw: valid_internal_complaint_raw(),
        };

        let result = verify_complaint(
            registry_returning_error.as_ref(),
            &transcript,
            &complaint,
            NODE_1,
        );

        assert_matches!(
            result,
            Err(IDkgVerifyComplaintError::Registry(e)) if e == registry_error
        );
    }
}

fn batch_signed_dealing(dealer_id: NodeId) -> BatchSignedIDkgDealing {
    batch_signed_dealing_with(valid_internal_dealing_raw(), dealer_id)
}

fn batch_signed_dealing_with_invalid_internal(dealer_id: NodeId) -> BatchSignedIDkgDealing {
    let dealing = IDkgDealing {
        transcript_id: IDkgTranscriptId::new(SUBNET_42, 1234, Height::new(123)),
        internal_dealing_raw: vec![],
    };
    let signed_dealing = SignedIDkgDealing {
        content: dealing,
        signature: BasicSignature {
            signature: BasicSigOf::new(BasicSig(vec![1, 2, 3])),
            signer: dealer_id,
        },
    };
    BatchSignedIDkgDealing {
        content: signed_dealing,
        signature: BasicSignatureBatch {
            signatures_map: BTreeMap::new(),
        },
    }
}

/// Generated by running an integration test that produces a valid complaint
/// `c` using `println!("{:?}", hex::encode(&c.internal_complaint_raw));`
const VALID_INTERNAL_COMPLAINT_HEX: &str = "a26570726f6f66a2696368616c6c656e6765582101abbbb1c6c68cf646aa3cb27cebb\
     cd735fc8bf7ae040378f0bb7bfd38c75bdd9768726573706f6e7365582101c5fedaef\
     e3bd8442a1b6272cb3f5e5f9e7e657487b10cf4705d241a8a7214e076d73686172656\
     45f736563726574582201032d3c8e27962bccdca0efbf30ee91a56c8b1100c3a0d749\
     a4a2273e8349f5e00f";

fn valid_internal_complaint_raw() -> Vec<u8> {
    hex::decode(VALID_INTERNAL_COMPLAINT_HEX).expect("failed to hex-decode")
}

fn mega_encryption_pk_record<R: Rng + CryptoRng>(
    node_id: NodeId,
    registry_version: RegistryVersion,
    rng: &mut R,
) -> CryptoRegistryRecord {
    let mega_pk = generate_mega_public_key(rng);
    let key_value = mega_pk.serialize();

    mega_encryption_pk_record_with(node_id, key_value, registry_version)
}

fn generate_mega_public_key<R: Rng + CryptoRng>(rng: &mut R) -> MEGaPublicKey {
    let (mega_pk, _mega_sk) = ic_crypto_internal_threshold_sig_canister_threshold_sig::gen_keypair(
        EccCurveType::K256,
        Seed::from_rng(rng),
    );
    mega_pk
}

fn malformed_mega_encryption_pk_record(
    node_id: NodeId,
    registry_version: RegistryVersion,
) -> CryptoRegistryRecord {
    mega_encryption_pk_record_with(node_id, [42, 43, 44].to_vec(), registry_version)
}

fn mega_encryption_pk_record_with_unsupported_algorithm(
    node_id: NodeId,
    registry_version: RegistryVersion,
) -> CryptoRegistryRecord {
    CryptoRegistryRecord {
        key: CryptoRegistryKey {
            node_id,
            key_purpose: KeyPurpose::IDkgMEGaEncryption,
        },
        value: PublicKeyProto {
            algorithm: AlgorithmIdProto::Unspecified as i32,
            key_value: vec![],
            version: 0,
            proof_data: None,
            timestamp: None,
        },
        registry_version,
    }
}
