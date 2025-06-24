use candid::Principal;
use ic_cdk::{
    api::{
        call::{call_with_payment128, CallResult},
        management_canister::{
            ecdsa::{sign_with_ecdsa, SignWithEcdsaArgument, SignWithEcdsaResponse},
            schnorr::{sign_with_schnorr, SignWithSchnorrArgument, SignWithSchnorrResponse},
        },
    },
    update,
};
use ic_management_canister_types::{VetKDDeriveKeyArgs, VetKDDeriveKeyResult};
use ic_signer::{GenEcdsaParams, GenSchnorrParams, GenVetkdParams};

/// Generates a dummy ECDSA signature of given size parameters.
/// The call does not verify the signature, it only generates it.
#[update]
pub async fn gen_ecdsa_sig(
    GenEcdsaParams {
        derivation_path_length,
        derivation_path_element_size,
        key_id,
    }: GenEcdsaParams,
) -> Result<SignWithEcdsaResponse, String> {
    let signature_request = SignWithEcdsaArgument {
        message_hash: vec![1; 32],
        derivation_path: vec![vec![2; derivation_path_element_size]; derivation_path_length],
        key_id,
    };

    sign_with_ecdsa(signature_request)
        .await
        .map(|(res,)| res)
        .map_err(|err| err.1)
}

/// Generates a dummy Schnorr signature of given size parameters.
/// The call does not verify the signature, it only generates it.
#[update]
pub async fn gen_schnorr_sig(
    GenSchnorrParams {
        message_size,
        derivation_path_length,
        derivation_path_element_size,
        key_id,
    }: GenSchnorrParams,
) -> Result<SignWithSchnorrResponse, String> {
    let signature_request = SignWithSchnorrArgument {
        message: vec![1; message_size],
        derivation_path: vec![vec![2; derivation_path_element_size]; derivation_path_length],
        key_id,
    };

    sign_with_schnorr(signature_request)
        .await
        .map(|(res,)| res)
        .map_err(|err| err.1)
}

/// Generates a dummy VetKD key of given size parameters.
/// The call does not verify the encrypted key, it only generates it.
#[update]
pub async fn gen_vetkd_key(
    GenVetkdParams {
        context_size,
        input_size,
        key_id,
    }: GenVetkdParams,
) -> Result<VetKDDeriveKeyResult, String> {
    let key_request = VetKDDeriveKeyArgs {
        context: vec![1; context_size],
        input: vec![2; input_size],
        key_id,
        transport_public_key: ic_bls12_381::G1Affine::generator().to_compressed().to_vec(),
    };

    vetkd_derive_key(&key_request).await.map_err(|err| err.1)
}

pub async fn vetkd_derive_key(arg: &VetKDDeriveKeyArgs) -> CallResult<VetKDDeriveKeyResult> {
    let (result,) = call_with_payment128(
        Principal::management_canister(),
        "vetkd_derive_key",
        (arg,),
        26_153_846_153,
    )
    .await?;

    result
}

fn main() {}
