use ic_management_canister_types_private::{EcdsaCurve, EcdsaKeyId, VetKdCurve, VetKdKeyId};

use super::*;
use std::str::FromStr;

#[test]
fn test_none_is_accepted() {
    let result = SubnetFeatures::from_str("None").unwrap();
    assert_eq!(result, SubnetFeatures::default());
}

#[test]
fn test_double_entries_are_handled() {
    let result = SubnetFeatures::from_str("canister_sandboxing,canister_sandboxing").unwrap();
    assert_eq!(
        result,
        SubnetFeatures {
            canister_sandboxing: true,
            ..SubnetFeatures::default()
        }
    );
}

#[test]
fn test_chain_key_config_round_trip() {
    // Run code under test.
    let chain_key_config = ChainKeyConfig {
        key_configs: vec![
            KeyConfig {
                key_id: MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: "test_key1".to_string(),
                }),
                pre_signatures_to_create_in_advance: 77,
                max_queue_size: 30,
            },
            KeyConfig {
                key_id: MasterPublicKeyId::VetKd(VetKdKeyId {
                    curve: VetKdCurve::Bls12_381_G2,
                    name: "test_key2".to_string(),
                }),
                pre_signatures_to_create_in_advance: 0,
                max_queue_size: 30,
            },
        ],
        signature_request_timeout_ns: Some(123_456),
        idkg_key_rotation_period_ms: Some(321_654),
        max_parallel_pre_signature_transcripts_in_creation: Some(123_654),
    };

    let chain_key_config_pb = pb::ChainKeyConfig::from(chain_key_config.clone());

    // Assert expected result value.
    let expected_chain_key_config_pb = pb::ChainKeyConfig {
        key_configs: vec![
            pb::KeyConfig {
                key_id: Some(pb_types::MasterPublicKeyId {
                    key_id: Some(pb_types::master_public_key_id::KeyId::Ecdsa(
                        pb_types::EcdsaKeyId {
                            curve: 1,
                            name: "test_key1".to_string(),
                        },
                    )),
                }),
                pre_signatures_to_create_in_advance: Some(77),
                max_queue_size: Some(30),
            },
            pb::KeyConfig {
                key_id: Some(pb_types::MasterPublicKeyId {
                    key_id: Some(pb_types::master_public_key_id::KeyId::Vetkd(
                        pb_types::VetKdKeyId {
                            curve: 1,
                            name: "test_key2".to_string(),
                        },
                    )),
                }),
                pre_signatures_to_create_in_advance: Some(0),
                max_queue_size: Some(30),
            },
        ],
        signature_request_timeout_ns: Some(123_456),
        idkg_key_rotation_period_ms: Some(321_654),
        max_parallel_pre_signature_transcripts_in_creation: Some(123_654),
    };

    assert_eq!(chain_key_config_pb, expected_chain_key_config_pb,);

    let chain_key_config_after_deser =
        ChainKeyConfig::try_from(chain_key_config_pb).expect("Deserialization should succeed.");

    assert_eq!(chain_key_config, chain_key_config_after_deser,);
}
