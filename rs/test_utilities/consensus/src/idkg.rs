use std::str::FromStr;

use ic_management_canister_types_private::{
    EcdsaKeyId, MasterPublicKeyId, SchnorrAlgorithm, SchnorrKeyId, VetKdKeyId,
};
use ic_test_utilities_types::ids::subnet_test_id;
use ic_types::{
    consensus::idkg::{
        IDkgMasterPublicKeyId, IDkgPayload, KeyTranscriptCreation, MasterKeyTranscript,
    },
    crypto::{
        threshold_sig::ni_dkg::{NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetSubnet},
        AlgorithmId,
    },
    Height, SubnetId,
};
use strum::IntoEnumIterator;

pub fn empty_idkg_payload(subnet_id: SubnetId) -> IDkgPayload {
    empty_idkg_payload_with_key_ids(subnet_id, vec![fake_ecdsa_idkg_master_public_key_id()])
}

pub fn empty_idkg_payload_with_key_ids(
    subnet_id: SubnetId,
    key_ids: Vec<IDkgMasterPublicKeyId>,
) -> IDkgPayload {
    IDkgPayload::empty(
        Height::new(0),
        subnet_id,
        key_ids
            .into_iter()
            .map(|key_id| MasterKeyTranscript::new(key_id.clone(), KeyTranscriptCreation::Begin))
            .collect(),
    )
}

pub fn key_id_with_name(key_id: &MasterPublicKeyId, name: &str) -> MasterPublicKeyId {
    let mut key_id = key_id.clone();
    match key_id {
        MasterPublicKeyId::Ecdsa(ref mut key_id) => key_id.name = name.into(),
        MasterPublicKeyId::Schnorr(ref mut key_id) => key_id.name = name.into(),
        MasterPublicKeyId::VetKd(ref mut key_id) => key_id.name = name.into(),
    }
    key_id
}

pub fn fake_ecdsa_key_id() -> EcdsaKeyId {
    EcdsaKeyId::from_str("Secp256k1:some_key").unwrap()
}

pub fn fake_ecdsa_idkg_master_public_key_id() -> IDkgMasterPublicKeyId {
    MasterPublicKeyId::Ecdsa(fake_ecdsa_key_id())
        .try_into()
        .unwrap()
}

pub fn fake_schnorr_key_id(algorithm: SchnorrAlgorithm) -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm,
        name: String::from("some_schnorr_key"),
    }
}

pub fn fake_schnorr_idkg_master_public_key_id(
    algorithm: SchnorrAlgorithm,
) -> IDkgMasterPublicKeyId {
    MasterPublicKeyId::Schnorr(fake_schnorr_key_id(algorithm))
        .try_into()
        .unwrap()
}

pub fn schnorr_algorithm(algorithm: AlgorithmId) -> SchnorrAlgorithm {
    match algorithm {
        AlgorithmId::ThresholdSchnorrBip340 => SchnorrAlgorithm::Bip340Secp256k1,
        AlgorithmId::ThresholdEd25519 => SchnorrAlgorithm::Ed25519,
        other => panic!("Unexpected algorithm: {other:?}"),
    }
}

pub fn fake_vetkd_key_id() -> VetKdKeyId {
    VetKdKeyId::from_str("bls12_381_g2:some_key").unwrap()
}

pub fn fake_vetkd_master_public_key_id() -> MasterPublicKeyId {
    MasterPublicKeyId::VetKd(fake_vetkd_key_id())
}

pub fn fake_dkg_id(key_id: VetKdKeyId) -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(0),
        dealer_subnet: subnet_test_id(0),
        dkg_tag: NiDkgTag::HighThresholdForKey(NiDkgMasterPublicKeyId::VetKd(key_id)),
        target_subnet: NiDkgTargetSubnet::Local,
    }
}

pub fn fake_master_public_key_ids_for_all_idkg_algorithms() -> Vec<IDkgMasterPublicKeyId> {
    AlgorithmId::iter()
        .flat_map(|alg| match alg {
            AlgorithmId::ThresholdEcdsaSecp256k1 => Some(fake_ecdsa_idkg_master_public_key_id()),
            AlgorithmId::ThresholdSchnorrBip340 => Some(fake_schnorr_idkg_master_public_key_id(
                SchnorrAlgorithm::Bip340Secp256k1,
            )),
            AlgorithmId::ThresholdEd25519 => Some(fake_schnorr_idkg_master_public_key_id(
                SchnorrAlgorithm::Ed25519,
            )),
            _ => None,
        })
        .collect()
}

pub fn fake_master_public_key_ids_for_all_algorithms() -> Vec<MasterPublicKeyId> {
    std::iter::once(fake_vetkd_master_public_key_id())
        .chain(
            fake_master_public_key_ids_for_all_idkg_algorithms()
                .into_iter()
                .map(MasterPublicKeyId::from),
        )
        .collect()
}
