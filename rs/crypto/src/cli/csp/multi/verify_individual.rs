use crate::cli::csp;
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_csp::types::{CspPublicKey, CspSignature, MultiBls12_381_Signature};
use ic_crypto_internal_multi_sig_bls12381::types::{IndividualSignatureBytes, PublicKeyBytes};
use ic_types::crypto::AlgorithmId;
use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [signature, message, public_key] => core(signature, message, public_key),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <signature> <message> <public_key>".to_string(), 1))
}

fn core(signature: &str, message: &str, public_key: &str) -> Result<(), (String, i32)> {
    let signature =
        IndividualSignatureBytes::try_from(signature).map_err(|e| (format!("{:?}", e), 2))?;
    let signature = CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(signature));

    let algorithm_id = AlgorithmId::MultiBls12_381;

    let public_key = PublicKeyBytes::try_from(public_key).map_err(|e| (format!("{:?}", e), 2))?;
    let public_key = CspPublicKey::MultiBls12_381(public_key);

    csp()
        .verify(&signature, message.as_bytes(), algorithm_id, public_key)
        .map_err(|e| (format!("Verification failed: {:?}", e), 2))?;
    println!("Signature checks out.");
    Ok(())
}
