use crate::models::{Ed25519KeyPair, RosettaSupportedKeyPair, Secp256k1KeyPair};
use crate::objects::{CurveType, PublicKey};
use anyhow::{self, bail};
use ic_types::PrincipalId;

pub fn principal_id_from_public_key(pk: &PublicKey) -> anyhow::Result<PrincipalId> {
    match pk.curve_type {
        CurveType::Edwards25519 => Ed25519KeyPair::get_principal_id(&pk.hex_bytes),
        CurveType::Secp256K1 => Secp256k1KeyPair::get_principal_id(&pk.hex_bytes),
        _ => bail!("Curve Type {:?} is not supported", pk.curve_type),
    }
}
