use candid::CandidType;
use ic_cdk::api::management_canister::{ecdsa::EcdsaKeyId, schnorr::SchnorrKeyId};
use ic_management_canister_types::VetKDKeyId;
use serde::Deserialize;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GenEcdsaParams {
    pub derivation_path_length: usize,
    pub derivation_path_element_size: usize,
    pub key_id: EcdsaKeyId,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GenSchnorrParams {
    pub message_size: usize,
    pub derivation_path_length: usize,
    pub derivation_path_element_size: usize,
    pub key_id: SchnorrKeyId,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GenVetkdParams {
    pub context_size: usize,
    pub input_size: usize,
    pub key_id: VetKDKeyId,
}
