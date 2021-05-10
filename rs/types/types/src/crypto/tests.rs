use super::*;
use crate::NodeId;

#[test]
fn should_correctly_convert_i32_to_algorithm_id() {
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
    assert_eq!(AlgorithmId::from(42), AlgorithmId::Placeholder);
}

#[test]
fn should_correctly_convert_algorithm_id_to_i32() {
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
}

pub fn set_of(node_ids: &[NodeId]) -> BTreeSet<NodeId> {
    let mut dealers = BTreeSet::new();
    node_ids.iter().for_each(|node_id| {
        dealers.insert(*node_id);
    });
    dealers
}
