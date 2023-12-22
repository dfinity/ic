use crate::miscellaneous::Error;
use crate::models::RosettaSupportedKeyPair;
use crate::objects::{CurveType, PublicKey};
use ic_canister_client_sender::Ed25519KeyPair as EdKeypair;
use ic_canister_client_sender::Secp256k1KeyPair;
use ic_types::PrincipalId;

pub fn principal_id_from_public_key(pk: &PublicKey) -> Result<PrincipalId, Error> {
    match pk.curve_type {
        CurveType::Edwards25519 => EdKeypair::get_principal_id(&pk.hex_bytes),
        CurveType::Secp256K1 => Secp256k1KeyPair::get_principal_id(&pk.hex_bytes),
        _ => Err(Error {
            code: 713,
            message: format!("Curve Type {} is not supported", pk.curve_type),
            description: None,
            retriable: false,
            details: None,
        }),
    }
}
