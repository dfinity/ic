use super::*;
use crate::NodeId;
use strum::IntoEnumIterator;

#[test]
fn should_correctly_convert_i32_to_algorithm_id() {
    // ensure _all_ algorithm IDs are compared (i.e., no algorithm was forgotten)
    assert_eq!(AlgorithmId::iter().count(), 17);

    assert_eq!(AlgorithmId::from(0), AlgorithmId::Placeholder);
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

    // Verify that an unknown i32 maps onto Placeholder
    assert_eq!(AlgorithmId::from(42), AlgorithmId::Placeholder);
}

#[test]
fn should_correctly_convert_algorithm_id_to_i32() {
    // ensure _all_ algorithm IDs are compared (i.e., no algorithm was forgotten)
    assert_eq!(AlgorithmId::iter().count(), 17);

    assert_eq!(AlgorithmId::Placeholder as i32, 0);
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
    assert_eq!(AlgorithmId::MegaSecp256k1 as i32, 16)
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
    assert_eq!(AlgorithmId::from(42), AlgorithmId::Placeholder);
}

pub fn set_of(node_ids: &[NodeId]) -> BTreeSet<NodeId> {
    let mut dealers = BTreeSet::new();
    node_ids.iter().for_each(|node_id| {
        dealers.insert(*node_id);
    });
    dealers
}
