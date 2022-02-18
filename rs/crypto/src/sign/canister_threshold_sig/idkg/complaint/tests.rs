#![allow(clippy::unwrap_used)]
use super::*;
use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::common::test_utils::{CryptoRegistryKey, CryptoRegistryRecord};
use crate::sign::tests::{
    mega_encryption_pk_record_with, registry_returning, registry_returning_none, registry_with,
    REG_V1,
};
use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, MEGaPublicKey};
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_registry_client::client::RegistryClientError;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4, SUBNET_42};
use ic_types::consensus::ecdsa::EcdsaDealing;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscriptId, IDkgTranscriptType,
};
use ic_types::crypto::{AlgorithmId, CombinedMultiSig, CombinedMultiSigOf, KeyPurpose};
use ic_types::{Height, Randomness, RegistryVersion};
use rand::{thread_rng, Rng};
use std::collections::BTreeSet;

#[test]
fn should_call_csp_with_correct_arguments() {
    const COMPLAINER: NodeId = NODE_4;
    const DEALER: NodeId = NODE_2;
    let complainer_key = generate_mega_public_key();
    let internal_complaint_raw = valid_internal_complaint_raw();
    let internal_dealing_raw = valid_internal_dealing_raw();
    let dealer_index = 2;
    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(
        dealer_index,
        multi_signed_dealing_with(internal_dealing_raw.clone(), DEALER),
    );
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1, NODE_2, NODE_3, NODE_4])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complainer_index = 3; // index of COMPLAINER in transcript.receivers
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: DEALER,
        internal_complaint_raw: internal_complaint_raw.clone(),
    };
    let registry = registry_with(mega_encryption_pk_record_with_key(
        &complainer_key,
        COMPLAINER,
        REG_V1,
    ));
    let internal_complaint = IDkgComplaintInternal::deserialize(&internal_complaint_raw).unwrap();
    let internal_dealing = IDkgDealingInternal::deserialize(&internal_dealing_raw).unwrap();
    let context_data = transcript.context_data();

    let mut csp = MockAllCryptoServiceProvider::new();
    csp.expect_idkg_verify_complaint()
        .withf(
            move |internal_complaint_,
                  complainer_index_,
                  complainer_key_,
                  internal_dealing_,
                  dealer_index_,
                  context_data_| {
                *internal_complaint_ == internal_complaint
                    && *complainer_index_ == complainer_index
                    && *complainer_key_ == complainer_key
                    && *internal_dealing_ == internal_dealing
                    && *dealer_index_ == dealer_index
                    && *context_data_ == context_data
            },
        )
        .times(1)
        .return_const(Ok(()));

    let _ = verify_complaint(&csp, &registry, &transcript, &complaint, COMPLAINER);
}

#[test]
fn should_fail_on_transcript_id_mismatch() {
    let transcript_id_1 = IDkgTranscriptId::new(SUBNET_42, 27);
    let transcript_id_2 = IDkgTranscriptId::new(SUBNET_42, 28);
    assert_ne!(transcript_id_1, transcript_id_2);

    let transcript = IDkgTranscript {
        transcript_id: transcript_id_1,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings: BTreeMap::new(),
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id: transcript_id_2,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };
    let csp = MockAllCryptoServiceProvider::new();
    let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1));

    let result = verify_complaint(&csp, &registry, &transcript, &complaint, NODE_1);

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::InvalidArgumentMismatchingTranscriptIDs)
    ));
}

#[test]
fn should_fail_if_dealing_missing_in_transcript() {
    const COMPLAINT_DEALER_ID: NodeId = NODE_2;
    let verified_dealings_missing_complaint_dealer_id = BTreeMap::new();

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings: verified_dealings_missing_complaint_dealer_id,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: COMPLAINT_DEALER_ID,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };
    let csp = MockAllCryptoServiceProvider::new();
    let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1));

    let result = verify_complaint(&csp, &registry, &transcript, &complaint, NODE_1);

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::InvalidArgumentMissingDealingInTranscript { dealer_id })
          if dealer_id == COMPLAINT_DEALER_ID
    ));
}

#[test]
fn should_fail_if_complainer_missing_in_transcript() {
    const COMPLAINER_ID: NodeId = NODE_2;

    let receivers_missing_complainer_id = IDkgReceivers::new(node_set(&[NODE_1])).unwrap();
    assert!(!receivers_missing_complainer_id
        .get()
        .contains(&COMPLAINER_ID));

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing_with_invalid_internal(NODE_1));
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: receivers_missing_complainer_id,
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };
    let csp = MockAllCryptoServiceProvider::new();
    let registry = registry_with(mega_encryption_pk_record(COMPLAINER_ID, REG_V1));

    let result = verify_complaint(&csp, &registry, &transcript, &complaint, COMPLAINER_ID);

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::InvalidArgumentMissingComplainerInTranscript { complainer_id })
          if complainer_id == COMPLAINER_ID
    ));
}

#[test]
fn should_fail_if_deserializing_complaint_fails() {
    let invalid_internal_complaint_raw = b"invalid complaint".to_vec();

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing(NODE_1));
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: invalid_internal_complaint_raw,
    };
    let csp = MockAllCryptoServiceProvider::new();
    let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1));

    let result = verify_complaint(&csp, &registry, &transcript, &complaint, NODE_1);

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::SerializationError { internal_error })
          if internal_error.contains("failed to deserialize complaint")
    ));
}

#[test]
fn should_fail_if_deserializing_dealing_fails() {
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing_with_invalid_internal(NODE_1));

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };
    let csp = MockAllCryptoServiceProvider::new();
    let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1));

    let result = verify_complaint(&csp, &registry, &transcript, &complaint, NODE_1);

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::SerializationError { internal_error })
          if internal_error.contains("failed to deserialize dealing")
    ));
}

#[test]
fn should_fail_if_complainer_mega_pubkey_not_in_registry() {
    let registry_missing_complainer_pubkey = registry_returning_none();

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing(NODE_1));
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };

    let result = verify_complaint(
        &MockAllCryptoServiceProvider::new(),
        &registry_missing_complainer_pubkey,
        &transcript,
        &complaint,
        NODE_1,
    );

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::ComplainerPublicKeyNotInRegistry { node_id, registry_version })
          if node_id == NODE_1 && registry_version == REG_V1
    ));
}

#[test]
fn should_fail_if_complainer_mega_pubkey_is_malformed() {
    let registry_with_malformed_complainer_pubkey =
        registry_with(malformed_mega_encryption_pk_record(NODE_1, REG_V1));

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing(NODE_1));
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };

    let result = verify_complaint(
        &MockAllCryptoServiceProvider::new(),
        &registry_with_malformed_complainer_pubkey,
        &transcript,
        &complaint,
        NODE_1,
    );

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::MalformedComplainerPublicKey { node_id, .. })
          if node_id == NODE_1
    ));
}

#[test]
fn should_fail_if_complainer_mega_pubkey_algorithm_is_unsupported() {
    let registry_with_unsupported_complainer_pubkey_algorithm = registry_with(
        mega_encryption_pk_record_with_unsupported_algorithm(NODE_1, REG_V1),
    );

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing(NODE_1));
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };

    let result = verify_complaint(
        &MockAllCryptoServiceProvider::new(),
        &registry_with_unsupported_complainer_pubkey_algorithm,
        &transcript,
        &complaint,
        NODE_1,
    );

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::UnsupportedComplainerPublicKeyAlgorithm { .. })
    ));
}

#[test]
fn should_fail_if_registry_client_returns_error() {
    let registry_error = RegistryClientError::PollingLatestVersionFailed { retries: 3 };
    let registry_returning_error = registry_returning(registry_error.clone());

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing(NODE_1));
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };

    let result = verify_complaint(
        &MockAllCryptoServiceProvider::new(),
        &registry_returning_error,
        &transcript,
        &complaint,
        NODE_1,
    );

    assert!(matches!(
        result,
        Err(IDkgVerifyComplaintError::Registry(e)) if e == registry_error
    ));
}

#[test]
fn should_return_ok_if_csp_returns_ok() {
    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing(NODE_1));
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };
    let csp = csp_with_verify_complaint_returning(Ok(()));
    let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1));

    let result = verify_complaint(&csp, &registry, &transcript, &complaint, NODE_1);

    assert!(result.is_ok());
}

#[test]
fn should_return_error_if_csp_returns_error() {
    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27);
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, multi_signed_dealing(NODE_1));
    let transcript = IDkgTranscript {
        transcript_id,
        receivers: IDkgReceivers::new(node_set(&[NODE_1])).unwrap(),
        registry_version: REG_V1,
        verified_dealings,
        transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    };
    let complaint = IDkgComplaint {
        transcript_id,
        dealer_id: NODE_1,
        internal_complaint_raw: valid_internal_complaint_raw(),
    };

    let csp_error = IDkgVerifyComplaintError::InvalidComplaint;
    let csp = csp_with_verify_complaint_returning(Err(csp_error.clone()));
    let registry = registry_with(mega_encryption_pk_record(NODE_1, REG_V1));

    let result = verify_complaint(&csp, &registry, &transcript, &complaint, NODE_1);

    assert!(matches!(result, Err(e) if e == csp_error));
}

fn node_set(nodes: &[NodeId]) -> BTreeSet<NodeId> {
    nodes.iter().copied().collect()
}

fn multi_signed_dealing(dealer_id: NodeId) -> IDkgMultiSignedDealing {
    multi_signed_dealing_with(valid_internal_dealing_raw(), dealer_id)
}

fn multi_signed_dealing_with(
    internal_dealing_raw: Vec<u8>,
    dealer_id: NodeId,
) -> IDkgMultiSignedDealing {
    let ecdsa_dealing = EcdsaDealing {
        requested_height: Height::new(123),
        idkg_dealing: IDkgDealing {
            transcript_id: IDkgTranscriptId::new(SUBNET_42, 1234),
            dealer_id,
            internal_dealing_raw,
        },
    };

    IDkgMultiSignedDealing {
        signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![])),
        signers: BTreeSet::new(),
        dealing: ecdsa_dealing,
    }
}

fn multi_signed_dealing_with_invalid_internal(dealer_id: NodeId) -> IDkgMultiSignedDealing {
    let ecdsa_dealing = EcdsaDealing {
        requested_height: Height::new(123),
        idkg_dealing: IDkgDealing {
            transcript_id: IDkgTranscriptId::new(SUBNET_42, 1234),
            dealer_id,
            internal_dealing_raw: vec![],
        },
    };

    IDkgMultiSignedDealing {
        signature: CombinedMultiSigOf::new(CombinedMultiSig(vec![])),
        signers: BTreeSet::new(),
        dealing: ecdsa_dealing,
    }
}

/// Generated by running an integration test that produces a valid complaint
/// `c` using `println!("{:?}", hex::encode(&c.internal_complaint_raw));`
const VALID_INTERNAL_COMPLAINT_HEX: &str =
    "a26570726f6f66a2696368616c6c656e6765a26a63757276655f74797065644b32353\
    663726177982018ab188b18d21893182a183c181a182118fe183718c1187b1869110f1\
    841181918a91872187d021864183e18a5186618fa18d818d518eb185f1832187768726\
    573706f6e7365a26a63757276655f74797065644b3235366372617798201891182a18f\
    d18ad183c186c185118af18e918de18da18ad1828188e182118fe0e181d0a0a18cd101\
    8dc186818261863181a183118b11118b418b46d7368617265645f736563726574a26a6\
    3757276655f74797065644b323536637261779821021829186718241821183e188c0d1\
    85e1838185d18fa18fe186e186d188718fb18d01896187818860b18d4181e18c503188\
    4185d18c51881183418771833";

/// Generated by running an integration test that produces a valid dealing
/// in a transcript `t` using
/// `println!("{:?}", hex::encode(&t. ... .internal_dealing_raw));`
const VALID_INTERNAL_DEALING_HEX: &str =
    "a36a63697068657274657874a1655061697273a26d657068656d6572616c5f6b6579a\
    26a63757276655f74797065644b323536637261779821021894186018e81843185518a\
    018bf188918471866185118d718a918951872185718ab1888091876189f186218b2182\
    1187718e5184518d11859189818ec1893666374657874738182a26a63757276655f747\
    97065644b323536637261779820182018dd187d16187218ae189318fc18a8185c184e1\
    8d70f18cd188b1618e61896189718a618ec188018e018de181c185418f815182016182\
    518a6a26a63757276655f74797065644b323536637261779820011718b81878189018c\
    c1859189618a218e9183818c418db18e31896188618ba188b186f187106189518b5181\
    b18fc186e1868185c17189d18fd18966a636f6d6d69746d656e74a1685065646572736\
    56ea166706f696e747381a26a63757276655f74797065644b323536637261779821021\
    86b18ba18211885182718ac1618b9183418a7186118611885184518e9186e18e8181f1\
    8a4182d18c2182f18fe1887184118701877183c188b183d189e18f96570726f6f66f6";

fn valid_internal_complaint_raw() -> Vec<u8> {
    hex::decode(VALID_INTERNAL_COMPLAINT_HEX).expect("failed to hex-decode")
}

fn valid_internal_dealing_raw() -> Vec<u8> {
    hex::decode(VALID_INTERNAL_DEALING_HEX).expect("failed to hex-decode")
}

fn mega_encryption_pk_record(
    node_id: NodeId,
    registry_version: RegistryVersion,
) -> CryptoRegistryRecord {
    let mega_pk = generate_mega_public_key();
    let key_value = mega_pk.serialize();

    mega_encryption_pk_record_with(node_id, key_value, registry_version)
}

fn mega_encryption_pk_record_with_key(
    key: &MEGaPublicKey,
    node_id: NodeId,
    registry_version: RegistryVersion,
) -> CryptoRegistryRecord {
    mega_encryption_pk_record_with(node_id, key.serialize(), registry_version)
}

fn generate_mega_public_key() -> MEGaPublicKey {
    let rng = &mut thread_rng();
    let (mega_pk, _mega_sk) = ic_crypto_internal_threshold_sig_ecdsa::gen_keypair(
        EccCurveType::K256,
        Randomness::new(rng.gen()),
    )
    .expect("failed to generate keypair");
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
        },
        registry_version,
    }
}

fn csp_with_verify_complaint_returning(
    result: Result<(), IDkgVerifyComplaintError>,
) -> impl CryptoServiceProvider {
    let mut csp = MockAllCryptoServiceProvider::new();
    csp.expect_idkg_verify_complaint()
        .times(1)
        .return_const(result);
    csp
}
