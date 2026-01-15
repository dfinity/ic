use ic_base_types::NodeId;
use ic_config::crypto::CryptoConfig;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::{
    CspNiDkgTranscript, ni_dkg_groth20_bls12_381,
};
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_test_utils_ni_dkg::InitialNiDkgConfig;
use ic_crypto_test_utils_ni_dkg::initial_dkg_transcript_and_master_key;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use ic_crypto_utils_ni_dkg::extract_subnet_threshold_sig_public_key;
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
use ic_types::RegistryVersion;
use ic_types::crypto::CurrentNodePublicKeys;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetId, NiDkgTranscript};
use ic_types_test_utils::ids::SUBNET_1;
use std::collections::{BTreeMap, BTreeSet};

mod extract_subnet_threshold_sig_public_key {
    use super::*;
    use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
    use ic_crypto_utils_ni_dkg::SubnetPubKeyExtractionError;
    use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;

    #[test]
    fn should_successfully_parse_valid_initial_ni_dkg_transcript_record() {
        let transcript = ni_dkg_transcript();
        let expected = match transcript.internal_csp_transcript.public_coefficients() {
            CspPublicCoefficients::Bls12_381(public_coefficient_bytes) => {
                ThresholdSigPublicKey::from(
                    *public_coefficient_bytes
                        .coefficients
                        .first()
                        .expect("should have at least one coefficient"),
                )
            }
        };
        let initial_ni_dkg_transcript_record = InitialNiDkgTranscriptRecord::from(transcript);

        let extracted = extract_subnet_threshold_sig_public_key(&initial_ni_dkg_transcript_record);
        assert_eq!(Ok(expected), extracted);
    }

    #[test]
    fn should_return_deserialization_error_if_internal_csp_transcript_cannot_be_deserialized() {
        let transcript = ni_dkg_transcript();
        let mut initial_ni_dkg_transcript_record = InitialNiDkgTranscriptRecord::from(transcript);
        initial_ni_dkg_transcript_record.internal_csp_transcript = vec![0; 10];

        let result = extract_subnet_threshold_sig_public_key(&initial_ni_dkg_transcript_record);
        assert_eq!(Err(SubnetPubKeyExtractionError::Deserialization), result);
    }

    #[test]
    fn should_return_coefficients_empty_error_if_public_key_is_corrupt() {
        let mut transcript = ni_dkg_transcript();
        let receiver_data = match transcript.internal_csp_transcript {
            CspNiDkgTranscript::Groth20_Bls12_381(transcript) => transcript.receiver_data,
        };
        transcript.internal_csp_transcript =
            CspNiDkgTranscript::Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript {
                public_coefficients: PublicCoefficientsBytes {
                    coefficients: vec![],
                },
                receiver_data,
            });
        let initial_ni_dkg_transcript_record = InitialNiDkgTranscriptRecord::from(transcript);

        let result = extract_subnet_threshold_sig_public_key(&initial_ni_dkg_transcript_record);
        assert_eq!(Err(SubnetPubKeyExtractionError::CoefficientsEmpty), result);
    }
}

mod extract_threshold_sig_public_key {
    use super::*;
    use ic_crypto_utils_ni_dkg::{
        ThresholdPubKeyExtractionError, extract_threshold_sig_public_key,
    };
    use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;

    #[test]
    fn should_succeed_for_valid_transcript() {
        let transcript = ni_dkg_transcript();
        let expected_threshold_signing_public_key =
            ThresholdSigPublicKey::from(match &transcript.internal_csp_transcript {
                CspNiDkgTranscript::Groth20_Bls12_381(transcript) => transcript
                    .public_coefficients
                    .coefficients
                    .first()
                    .copied()
                    .expect("should contain at least one coefficient"),
            });

        let result = extract_threshold_sig_public_key(&transcript.internal_csp_transcript);
        assert_eq!(Ok(expected_threshold_signing_public_key), result);
    }

    #[test]
    fn should_return_coefficients_empty_error_if_public_key_is_corrupt() {
        let mut transcript = ni_dkg_transcript();
        let receiver_data = match transcript.internal_csp_transcript {
            CspNiDkgTranscript::Groth20_Bls12_381(transcript) => transcript.receiver_data,
        };
        transcript.internal_csp_transcript =
            CspNiDkgTranscript::Groth20_Bls12_381(ni_dkg_groth20_bls12_381::Transcript {
                public_coefficients: PublicCoefficientsBytes {
                    coefficients: vec![],
                },
                receiver_data,
            });

        let result = extract_threshold_sig_public_key(&transcript.internal_csp_transcript);
        assert_eq!(
            Err(ThresholdPubKeyExtractionError::CoefficientsEmpty),
            result
        );
    }
}

fn generate_node_keys(num_nodes: usize) -> BTreeMap<NodeId, PublicKey> {
    let mut node_keys = BTreeMap::new();
    for _ in 0..num_nodes {
        let (node_pks, node_id) = valid_node_keys_and_node_id();
        let dkg_dealing_encryption_public_key = node_pks
            .dkg_dealing_encryption_public_key
            .as_ref()
            .expect("should have a dkg dealing encryption pk")
            .clone();

        node_keys.insert(node_id, dkg_dealing_encryption_public_key);
    }
    node_keys
}

fn valid_node_keys_and_node_id() -> (CurrentNodePublicKeys, NodeId) {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let node_pks =
        generate_node_keys_once(&config, None).expect("error generating node public keys");
    let node_id = node_pks.node_id();
    (map_to_current_node_public_keys(node_pks), node_id)
}

fn map_to_current_node_public_keys(value: ValidNodePublicKeys) -> CurrentNodePublicKeys {
    CurrentNodePublicKeys {
        node_signing_public_key: Some(value.node_signing_key().clone()),
        committee_signing_public_key: Some(value.committee_signing_key().clone()),
        tls_certificate: Some(value.tls_certificate().clone()),
        dkg_dealing_encryption_public_key: Some(value.dkg_dealing_encryption_key().clone()),
        idkg_dealing_encryption_public_key: Some(value.idkg_dealing_encryption_key().clone()),
    }
}

fn ni_dkg_transcript() -> NiDkgTranscript {
    let registry_version = RegistryVersion::new(1);
    let dealer_subnet = SUBNET_1;
    let dkg_tag = NiDkgTag::LowThreshold;
    let target_id = NiDkgTargetId::new([42u8; 32]);
    let rng = &mut reproducible_rng();
    let receiver_keys = generate_node_keys(2);
    let nodes_set: BTreeSet<NodeId> = receiver_keys.keys().cloned().collect();
    let initial_ni_dkg_config = InitialNiDkgConfig::new(
        &nodes_set,
        dealer_subnet,
        dkg_tag,
        target_id,
        registry_version,
    );
    let (transcript, _secret) =
        initial_dkg_transcript_and_master_key(initial_ni_dkg_config, &receiver_keys, rng);
    transcript
}
