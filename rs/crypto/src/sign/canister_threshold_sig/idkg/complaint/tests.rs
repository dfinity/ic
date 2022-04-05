#![allow(clippy::unwrap_used)]
use super::*;
use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::common::test_utils::{CryptoRegistryKey, CryptoRegistryRecord};
use crate::sign::tests::{
    mega_encryption_pk_record_with, registry_returning, registry_returning_none, registry_with,
    REG_V1,
};
use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, IDkgDealingInternal, MEGaPublicKey};
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4, SUBNET_42};
use ic_types::consensus::ecdsa::EcdsaDealing;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscriptId, IDkgTranscriptType,
};
use ic_types::crypto::{AlgorithmId, CombinedMultiSig, CombinedMultiSigOf, KeyPurpose};
use ic_types::{registry::RegistryClientError, Height, Randomness, RegistryVersion};
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
          if internal_error.contains("Error deserializing a signed dealing")
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
    6637261779820188718ab18920318bf184b184b18190d18ed18f8184c188a184418c41\
    857181a18fb18741862186618350818ae18cf18f1186918f818cf187118ab18e368726\
    573706f6e7365a26a63757276655f74797065644b323536637261779820187f182118e\
    0184e18dc18de1867183f18251318df18cd1865189e186718f80f08185918c71879186\
    4182518f6189118de185a1882183a18e1187418b66d7368617265645f736563726574a\
    26a63757276655f74797065644b3235366372617798210318c918e2188818ed1897189\
    018f218c518c60d1854184f183d1893186a18791897187918b718d9184418ba189618c\
    e185d18eb185118ef1862185418ec18d7";

/// Generated by running an integration test that produces a valid dealing
/// in a transcript `t` using
/// `println!("{:?}", hex::encode(&t. ... .internal_dealing_raw));`
const VALID_INTERNAL_DEALING_HEX: &str =
    "a36a63697068657274657874a1655061697273a46d657068656d6572616c5f6b6579a\
     26a63757276655f74797065644b32353663726177982102186f181f185518aa18d218f\
     318b218fd1897186518f218b21880181a182e18cf182918cb18dd18ae18f018ea18b01\
     84a18bf0c18c518f6184d1820186418a26e706f705f7075626c69635f6b6579a26a637\
     57276655f74797065644b32353663726177982102189f184518cb1898184a0218f5182\
     e18b5188918cb1867188f189c18951864181d185418671883185b18ac18ed1834187b1\
     8ea183c18261844188318df1369706f705f70726f6f66a2696368616c6c656e6765a26\
     a63757276655f74797065644b323536637261779820187518870e18c418bf184f18691\
     8a018bb18dd010c18c5185b18bb18bb18c318c918ed05185a188c185c18781618f818d\
     318cc17181c188318d468726573706f6e7365a26a63757276655f74797065644b32353\
     6637261779820182418bd18f518901897188f0a18481848182a18b118de188e184b189\
     a17187e18f60c18b81831185018b311186218cd18881845184b187d183018c76663746\
     57874738282a26a63757276655f74797065644b32353663726177982018bf182018431\
     8cb18d8189718d3184f18d518a6182c18b80f185b182b0618a7189418d1184d18ce051\
     829185d1881186e188618fc1884183d182818fda26a63757276655f74797065644b323\
     53663726177982018ba1858183a1518db185d18ae189f18ef1888182e18b718d318df1\
     86218cb18ac183518db1861189018d5183c18a2189e03189e18e9187e1828183018b18\
     2a26a63757276655f74797065644b323536637261779820187518f718ab189418190d1\
     85e18e418b718761827182a18481876186f186118ea18271824183818ca18be187e186\
     8183f18fc18cd1868186318b5183c185aa26a63757276655f74797065644b323536637\
     261779820181f1895187518421879184b1882189818a6188918b618d818dd18b418fe1\
     8f418491873185a0d181b18a21877187318c402182318a318401879184818276a636f6\
     d6d69746d656e74a168506564657273656ea166706f696e747381a26a63757276655f7\
     4797065644b32353663726177982102184218271854182a18b1186604186a187518a11\
     218cf18bb18a4181d189b186518370b186118d918491846187918ba1819188318f5182\
     8185f183218c16570726f6f66f6";

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
