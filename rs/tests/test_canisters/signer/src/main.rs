use std::marker::PhantomData;

use candid::Encode;
use ic_cdk::{
    api::{msg_reject, msg_reply},
    management_canister::{
        SignWithEcdsaArgs, SignWithEcdsaResult, SignWithSchnorrArgs, SignWithSchnorrResult,
        VetKDDeriveKeyArgs, VetKDDeriveKeyResult, sign_with_ecdsa, sign_with_schnorr,
        vetkd_derive_key,
    },
    update,
};
use ic_signer::{GenEcdsaParams, GenSchnorrParams, GenVetkdParams};

/// Generates a dummy ECDSA signature of given size parameters.
/// The call does not verify the signature, it only generates it.
#[update(manual_reply = true)]
pub async fn gen_ecdsa_sig(
    GenEcdsaParams {
        derivation_path_length,
        derivation_path_element_size,
        key_id,
    }: GenEcdsaParams,
) -> PhantomData<SignWithEcdsaResult> {
    let signature_request = SignWithEcdsaArgs {
        message_hash: vec![1; 32],
        derivation_path: vec![vec![2; derivation_path_element_size]; derivation_path_length],
        key_id,
    };

    match sign_with_ecdsa(&signature_request).await {
        Ok(sig) => msg_reply(Encode!(&sig).unwrap()),
        Err(err) => msg_reject(err.to_string()),
    }
    PhantomData
}

/// Generates a dummy Schnorr signature of given size parameters.
/// The call does not verify the signature, it only generates it.
#[update(manual_reply = true)]
pub async fn gen_schnorr_sig(
    GenSchnorrParams {
        message_size,
        derivation_path_length,
        derivation_path_element_size,
        key_id,
        aux,
    }: GenSchnorrParams,
) -> PhantomData<SignWithSchnorrResult> {
    let signature_request = SignWithSchnorrArgs {
        message: vec![1; message_size],
        derivation_path: vec![vec![2; derivation_path_element_size]; derivation_path_length],
        key_id,
        aux,
    };

    match sign_with_schnorr(&signature_request).await {
        Ok(sig) => msg_reply(Encode!(&sig).unwrap()),
        Err(err) => msg_reject(err.to_string()),
    }
    PhantomData
}

/// Generates a dummy VetKD key of given size parameters.
/// The call does not verify the encrypted key, it only generates it.
#[update(manual_reply = true)]
pub async fn gen_vetkd_key(
    GenVetkdParams {
        context_size,
        input_size,
        key_id,
    }: GenVetkdParams,
) -> PhantomData<VetKDDeriveKeyResult> {
    let key_request = VetKDDeriveKeyArgs {
        context: vec![1; context_size],
        input: vec![2; input_size],
        key_id,
        transport_public_key: ic_bls12_381::G1Affine::generator().to_compressed().to_vec(),
    };

    match vetkd_derive_key(&key_request).await {
        Ok(sig) => msg_reply(Encode!(&sig).unwrap()),
        Err(err) => msg_reject(err.to_string()),
    }
    PhantomData
}

fn main() {}
