use candid::CandidType;
use ic_cdk::management_canister::{EcdsaKeyId, SchnorrAux, SchnorrKeyId, VetKDKeyId};
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
    pub aux: Option<SchnorrAux>,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GenVetkdParams {
    pub context_size: usize,
    pub input_size: usize,
    pub key_id: VetKDKeyId,
}
