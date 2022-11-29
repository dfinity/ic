#![allow(clippy::unwrap_used)]
use super::*;
use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;
use crate::common::test_utils::{CryptoRegistryKey, CryptoRegistryRecord};
use crate::sign::tests::{
    mega_encryption_pk_record_with, registry_returning, registry_returning_none, registry_with,
    REG_V1,
};
use ic_crypto_internal_seed::Seed;
use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, IDkgDealingInternal, MEGaPublicKey};
use ic_protobuf::registry::crypto::v1::AlgorithmId as AlgorithmIdProto;
use ic_protobuf::registry::crypto::v1::PublicKey as PublicKeyProto;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgDealing;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscriptId, IDkgTranscriptType,
    SignedIDkgDealing,
};
use ic_types::crypto::{AlgorithmId, BasicSig, BasicSigOf, KeyPurpose};
use ic_types::signature::{BasicSignature, BasicSignatureBatch};
use ic_types::{registry::RegistryClientError, Height, RegistryVersion};
use ic_types_test_utils::ids::{NODE_1, NODE_2, NODE_3, NODE_4, SUBNET_42};
use rand::thread_rng;
use std::collections::BTreeSet;

#[test]
fn should_call_csp_with_correct_arguments() {
    const COMPLAINER: NodeId = NODE_4;
    const DEALER: NodeId = NODE_2;
    let complainer_key = generate_mega_public_key();
    let internal_complaint_raw = valid_internal_complaint_raw();
    let internal_dealing_raw = valid_internal_dealing_raw();
    let dealer_index = 2;
    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(
        dealer_index,
        batch_signed_dealing_with(internal_dealing_raw.clone(), DEALER),
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
    let transcript_id_1 = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let transcript_id_2 = transcript_id_1.increment();
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

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
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

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, batch_signed_dealing_with_invalid_internal(NODE_1));
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

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, batch_signed_dealing(NODE_1));
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
    verified_dealings.insert(0, batch_signed_dealing_with_invalid_internal(NODE_1));

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
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

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, batch_signed_dealing(NODE_1));
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

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, batch_signed_dealing(NODE_1));
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

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, batch_signed_dealing(NODE_1));
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

    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, batch_signed_dealing(NODE_1));
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
    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, batch_signed_dealing(NODE_1));
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
    let transcript_id = IDkgTranscriptId::new(SUBNET_42, 27, Height::new(12));
    let mut verified_dealings = BTreeMap::new();
    verified_dealings.insert(0, batch_signed_dealing(NODE_1));
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

fn batch_signed_dealing(dealer_id: NodeId) -> BatchSignedIDkgDealing {
    batch_signed_dealing_with(valid_internal_dealing_raw(), dealer_id)
}

fn batch_signed_dealing_with(
    internal_dealing_raw: Vec<u8>,
    dealer_id: NodeId,
) -> BatchSignedIDkgDealing {
    let dealing = IDkgDealing {
        transcript_id: IDkgTranscriptId::new(SUBNET_42, 1234, Height::new(123)),
        internal_dealing_raw,
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
const VALID_INTERNAL_COMPLAINT_HEX: &str =
    "a26570726f6f66a2696368616c6c656e6765582101abbbb1c6c68cf646aa3cb27cebb\
     cd735fc8bf7ae040378f0bb7bfd38c75bdd9768726573706f6e7365582101c5fedaef\
     e3bd8442a1b6272cb3f5e5f9e7e657487b10cf4705d241a8a7214e076d73686172656\
     45f736563726574582201032d3c8e27962bccdca0efbf30ee91a56c8b1100c3a0d749\
     a4a2273e8349f5e00f";

/// Generated by running an integration test that produces a valid dealing
/// in a transcript `t` using
/// `println!("{:?}", hex::encode(&t. ... .internal_dealing_raw));`
const VALID_INTERNAL_DEALING_HEX: &str =
    "a36a63697068657274657874a1655061697273a46d657068656d6572616c5f6b657958\
     220102337d807963a57619ae7d1137f0f5938cca8e2a3047b28201c81b152508e33be2\
     6e706f705f7075626c69635f6b6579582201029739379e980a267ada615a5c5fed62ff\
     60d9cd0832a46a8738695e9f4e7d232269706f705f70726f6f66a2696368616c6c656e\
     6765582101e2c7c262a759796ecbfb3141dd4e5734de5b683e8100dbc6f8b1d226016a\
     20e168726573706f6e73655821016f45f744b83594bbbd0f883066ae6fa624ccf0d9a5\
     f37e24fe912c1cea0acdfa666374657874738a82582101c7879cfcb44557d933d649d1\
     d4a03d1281a72a44d36a4c8dee8309be8ad28c10582101822f40b19676052447a809aa\
     924d5bb7ad5850cd3999ef9ca9e4595adfc7bdfe82582101ec473c4aa28d12b91fa601\
     37a23331a05d6b6d5c8bebb73d1f1fb276f626bee85821014f44ecebebeaeee6593f8e\
     98bdfb5d49483e1d22e60f408412b7309fb75dcc7682582101e285561b28f8972ae8d6\
     244d50bb601dc2316421071ddb5b5a89ec6e296aff2e582101e37de40b83826d03fe7b\
     7575ec6b06545295043c9bc75a51c7b3f280dcbe3bfd825821017f7899cc8de5f627d0\
     fe468e4f7ea380957c21a809d421ed803c585d1ae550c8582101a68a5e0fedc0504e1b\
     0f8a344420295d1eff750a73808e5cfedb9685c762866d825821013ede272aa74b169f\
     6ed7ef2f470c8adf73c9942d6bb9bdacfe753f7f65bcdad0582101780de821e2679401\
     540a334a6133b3fc93550a93c5131eb5d7a6ba7941122a1f825821015e69f240987dfe\
     ed8064328f43fbdd4e7b03703fb331bcb10c7721543ad028d258210173fbb6b0fc7928\
     198c7df5343d2096c1a6c0f9ed68fb2a8d9d927e9d872f552d82582101a6a699a8c609\
     f8842425caea0fd78dad64306669ac1e1fbcab1d36898cd1c0b55821014a4ab6907d11\
     a9f32d5cbdb466646e139aba1427b34025683464b133cfdf249e825821011ccc7ed54e\
     3619913710b0c8233f741a86a420abbed431ea9da915d55c5d5973582101e7b3f19bbc\
     ad6f8febd6c59cd1b4e7d67169d2a966922b13035f6c781fbb3a8e825821013a6dc6e0\
     754647d6565feafa21443576053cb76bb8404c6b5e11187f3fa3a6ae58210130a70215\
     209438f8fc3178f4594810565d49335073b6cf6de1ee803cf579aa5682582101a5564e\
     ce831f10c08fea839822c0bc774bd1cf92df1d5dae1dc36fbb9aaec6065821015b7c53\
     edb993e701cb7776f166be25057bdfe53e5787002f7a5dc4abb3148f866a636f6d6d69\
     746d656e74a168506564657273656ea166706f696e747383582201027ddf9bb3320a0c\
     5d0513c2aa2a032757443ea81b27d1a6617bf8d18bd3d2bde4582201023e4b0cf646d0\
     bc988209a81c1757a4a7343275ce8d31e112a0feb415c761eb1758220102580d79438d\
     0fc38a249dc14a918f94fbe1756b8bfaad2a5f77314f97c3059c6a6570726f6f66f6";

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
        Seed::from_rng(rng),
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
            timestamp: None,
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
