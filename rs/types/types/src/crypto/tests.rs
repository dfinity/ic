use super::*;
use crate::NodeId;
use strum::IntoEnumIterator;

#[test]
fn should_correctly_convert_i32_to_algorithm_id() {
    // ensure _all_ algorithm IDs are compared (i.e., no algorithm was forgotten)
    assert_eq!(AlgorithmId::iter().count(), 21);

    assert_eq!(AlgorithmId::from(0), AlgorithmId::Unspecified);
    assert_eq!(AlgorithmId::from(1), AlgorithmId::MultiBls12_381);
    assert_eq!(AlgorithmId::from(2), AlgorithmId::ThresBls12_381);
    assert_eq!(AlgorithmId::from(3), AlgorithmId::SchnorrSecp256k1);
    assert_eq!(AlgorithmId::from(4), AlgorithmId::StaticDhSecp256k1);
    assert_eq!(AlgorithmId::from(5), AlgorithmId::HashSha256);
    assert_eq!(AlgorithmId::from(6), AlgorithmId::Tls);
    assert_eq!(AlgorithmId::from(7), AlgorithmId::Ed25519);
    assert_eq!(AlgorithmId::from(8), AlgorithmId::Secp256k1);
    assert_eq!(AlgorithmId::from(9), AlgorithmId::Groth20_Bls12_381);
    assert_eq!(AlgorithmId::from(10), AlgorithmId::NiDkg_Groth20_Bls12_381);
    assert_eq!(AlgorithmId::from(11), AlgorithmId::EcdsaP256);
    assert_eq!(AlgorithmId::from(12), AlgorithmId::EcdsaSecp256k1);
    assert_eq!(AlgorithmId::from(13), AlgorithmId::IcCanisterSignature);
    assert_eq!(AlgorithmId::from(14), AlgorithmId::RsaSha256);
    assert_eq!(AlgorithmId::from(15), AlgorithmId::ThresholdEcdsaSecp256k1);
    assert_eq!(AlgorithmId::from(16), AlgorithmId::MegaSecp256k1);
    assert_eq!(AlgorithmId::from(17), AlgorithmId::ThresholdEcdsaSecp256r1);
    assert_eq!(AlgorithmId::from(18), AlgorithmId::ThresholdSchnorrBip340);
    assert_eq!(AlgorithmId::from(19), AlgorithmId::ThresholdEd25519);
    assert_eq!(AlgorithmId::from(20), AlgorithmId::VetKD);

    // Verify that an unknown i32 maps onto Placeholder
    assert_eq!(AlgorithmId::from(42), AlgorithmId::Unspecified);

    // Verify that an i32 that doesn't fit into a u8 maps onto Placeholder
    assert_eq!(AlgorithmId::from(420), AlgorithmId::Unspecified);
}

#[test]
fn should_correctly_convert_algorithm_id_to_i32() {
    // ensure _all_ algorithm IDs are compared (i.e., no algorithm was forgotten)
    assert_eq!(AlgorithmId::iter().count(), 21);

    assert_eq!(AlgorithmId::Unspecified as i32, 0);
    assert_eq!(AlgorithmId::MultiBls12_381 as i32, 1);
    assert_eq!(AlgorithmId::ThresBls12_381 as i32, 2);
    assert_eq!(AlgorithmId::SchnorrSecp256k1 as i32, 3);
    assert_eq!(AlgorithmId::StaticDhSecp256k1 as i32, 4);
    assert_eq!(AlgorithmId::HashSha256 as i32, 5);
    assert_eq!(AlgorithmId::Tls as i32, 6);
    assert_eq!(AlgorithmId::Ed25519 as i32, 7);
    assert_eq!(AlgorithmId::Secp256k1 as i32, 8);
    assert_eq!(AlgorithmId::Groth20_Bls12_381 as i32, 9);
    assert_eq!(AlgorithmId::NiDkg_Groth20_Bls12_381 as i32, 10);
    assert_eq!(AlgorithmId::EcdsaP256 as i32, 11);
    assert_eq!(AlgorithmId::EcdsaSecp256k1 as i32, 12);
    assert_eq!(AlgorithmId::IcCanisterSignature as i32, 13);
    assert_eq!(AlgorithmId::RsaSha256 as i32, 14);
    assert_eq!(AlgorithmId::ThresholdEcdsaSecp256k1 as i32, 15);
    assert_eq!(AlgorithmId::MegaSecp256k1 as i32, 16);
    assert_eq!(AlgorithmId::ThresholdEcdsaSecp256r1 as i32, 17);
    assert_eq!(AlgorithmId::ThresholdSchnorrBip340 as i32, 18);
    assert_eq!(AlgorithmId::ThresholdEd25519 as i32, 19);
    assert_eq!(AlgorithmId::VetKD as i32, 20);
}

#[test]
fn should_correctly_convert_algorithm_id_to_u8() {
    // ensure _all_ algorithm IDs are compared (i.e., no algorithm was forgotten)
    assert_eq!(AlgorithmId::iter().count(), 21);

    let tests: Vec<(AlgorithmId, u8)> = vec![
        (AlgorithmId::Unspecified, 0),
        (AlgorithmId::MultiBls12_381, 1),
        (AlgorithmId::ThresBls12_381, 2),
        (AlgorithmId::SchnorrSecp256k1, 3),
        (AlgorithmId::StaticDhSecp256k1, 4),
        (AlgorithmId::HashSha256, 5),
        (AlgorithmId::Tls, 6),
        (AlgorithmId::Ed25519, 7),
        (AlgorithmId::Secp256k1, 8),
        (AlgorithmId::Groth20_Bls12_381, 9),
        (AlgorithmId::NiDkg_Groth20_Bls12_381, 10),
        (AlgorithmId::EcdsaP256, 11),
        (AlgorithmId::EcdsaSecp256k1, 12),
        (AlgorithmId::IcCanisterSignature, 13),
        (AlgorithmId::RsaSha256, 14),
        (AlgorithmId::ThresholdEcdsaSecp256k1, 15),
        (AlgorithmId::MegaSecp256k1, 16),
        (AlgorithmId::ThresholdEcdsaSecp256r1, 17),
        (AlgorithmId::ThresholdSchnorrBip340, 18),
        (AlgorithmId::ThresholdEd25519, 19),
        (AlgorithmId::VetKD, 20),
    ];

    for (algorithm_id, expected_discriminant) in tests {
        assert_eq!(u8::from(algorithm_id), expected_discriminant);
    }
}

#[test]
fn should_correctly_convert_usize_to_key_purpose() {
    // ensure _all_ key purposes are compared (i.e., no key purpose was forgotten)
    assert_eq!(KeyPurpose::iter().count(), 6);

    assert_eq!(KeyPurpose::from(0), KeyPurpose::Placeholder);
    assert_eq!(KeyPurpose::from(1), KeyPurpose::NodeSigning);
    assert_eq!(KeyPurpose::from(2), KeyPurpose::QueryResponseSigning);
    assert_eq!(KeyPurpose::from(3), KeyPurpose::DkgDealingEncryption);
    assert_eq!(KeyPurpose::from(4), KeyPurpose::CommitteeSigning);
    assert_eq!(KeyPurpose::from(5), KeyPurpose::IDkgMEGaEncryption);

    // Verify that an unknown usize maps onto Placeholder
    assert_eq!(AlgorithmId::from(42), AlgorithmId::Unspecified);
}

#[test]
fn should_not_have_any_algorithm_id_that_does_not_fit_into_u8() {
    for algorithm_id in AlgorithmId::iter() {
        assert!(algorithm_id as isize >= (u8::MIN as isize));
        assert!(algorithm_id as isize <= (u8::MAX as isize));
    }
}

#[test]
fn should_have_consistent_logic_for_tecdsa_algorithm_identification() {
    let tecdsa_algos = AlgorithmId::all_threshold_ecdsa_algorithms();

    for algorithm_id in AlgorithmId::iter() {
        let is_tecdsa = algorithm_id.is_threshold_ecdsa();

        assert_eq!(is_tecdsa, tecdsa_algos.contains(&algorithm_id));
    }
}

#[cfg(test)]
impl KeyPurpose {
    fn as_str(&self) -> &'static str {
        match self {
            KeyPurpose::Placeholder => "",
            KeyPurpose::NodeSigning => "node_signing",
            KeyPurpose::QueryResponseSigning => "query_response_signing",
            KeyPurpose::DkgDealingEncryption => "dkg_dealing_encryption",
            KeyPurpose::CommitteeSigning => "committee_signing",
            KeyPurpose::IDkgMEGaEncryption => "idkg_mega_encryption",
        }
    }
}

#[test]
fn should_correctly_convert_between_enum_and_string() {
    for i in 0..KeyPurpose::iter().count() {
        if i == 0 {
            continue;
        }
        let key_purpose = KeyPurpose::from(i);
        let converted_key_purpose = key_purpose.as_str();
        assert_eq!(
            KeyPurpose::from_str(converted_key_purpose).unwrap(),
            key_purpose
        );
    }
}

pub fn set_of(node_ids: &[NodeId]) -> BTreeSet<NodeId> {
    let mut dealers = BTreeSet::new();
    node_ids.iter().for_each(|node_id| {
        dealers.insert(*node_id);
    });
    dealers
}

mod current_node_public_keys {
    use super::*;
    use ic_crypto_internal_types::curves::bls12_381;
    use ic_crypto_internal_types::sign::eddsa::ed25519::PublicKey as ed25519PublicKey;

    #[test]
    fn should_count_correctly_empty_node_public_keys() {
        let node_public_keys = CurrentNodePublicKeys {
            node_signing_public_key: None,
            committee_signing_public_key: None,
            tls_certificate: None,
            dkg_dealing_encryption_public_key: None,
            idkg_dealing_encryption_public_key: None,
        };
        assert_eq!(0, node_public_keys.get_pub_keys_and_cert_count());
    }

    #[test]
    fn should_count_correctly_full_node_public_keys() {
        let node_public_keys = all_current_node_public_keys();
        assert_eq!(5, node_public_keys.get_pub_keys_and_cert_count());
    }

    #[test]
    fn should_count_correctly_partial_node_public_keys() {
        let node_public_keys = CurrentNodePublicKeys {
            committee_signing_public_key: None,
            dkg_dealing_encryption_public_key: None,
            ..all_current_node_public_keys()
        };
        assert_eq!(3, node_public_keys.get_pub_keys_and_cert_count());
    }

    fn all_current_node_public_keys() -> CurrentNodePublicKeys {
        CurrentNodePublicKeys {
            node_signing_public_key: Some(valid_node_signing_key()),
            committee_signing_public_key: Some(valid_committee_signing_public_key()),
            tls_certificate: Some(valid_tls_certificate()),
            dkg_dealing_encryption_public_key: Some(valid_dkg_dealing_encryption_public_key()),
            idkg_dealing_encryption_public_key: Some(valid_idkg_dealing_encryption_public_key()),
        }
    }

    fn valid_node_signing_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::Ed25519 as i32,
            key_value: [0; ed25519PublicKey::SIZE].to_vec(),
            proof_data: None,
            timestamp: None,
        }
    }

    fn valid_committee_signing_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MultiBls12_381 as i32,
            key_value: [0u8; bls12_381::G2Bytes::SIZE].to_vec(),
            proof_data: Some([0u8; bls12_381::G1Bytes::SIZE].to_vec()),
            timestamp: None,
        }
    }

    fn valid_tls_certificate() -> X509PublicKeyCert {
        X509PublicKeyCert {
            certificate_der: vec![],
        }
    }

    fn valid_dkg_dealing_encryption_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::Groth20_Bls12_381 as i32,
            key_value: [0u8; bls12_381::G1Bytes::SIZE].to_vec(),
            proof_data: None,
            timestamp: None,
        }
    }

    fn valid_idkg_dealing_encryption_public_key() -> PublicKey {
        PublicKey {
            version: 0,
            algorithm: AlgorithmId::MegaSecp256k1 as i32,
            key_value: vec![],
            proof_data: None,
            timestamp: None,
        }
    }
}
