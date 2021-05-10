//! Command line interface for verifying a combined threshold signature
use ic_crypto_internal_threshold_sig_bls12381::api;
use ic_crypto_internal_threshold_sig_bls12381::types::CombinedSignatureBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [message, signature, public_key] => core(message, signature, public_key),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <message> <signature> <public_key>".to_string(), 1))
}

fn core(message: &str, signature: &str, public_key: &str) -> Result<(), (String, i32)> {
    let signature =
        CombinedSignatureBytes::try_from(signature).map_err(|e| (format!("{:?}", e), 2))?;
    let public_key = PublicKeyBytes::try_from(public_key).map_err(|e| (format!("{:?}", e), 2))?;
    api::verify_combined_signature(message.as_bytes(), signature, public_key)
        .map_err(|e| (format!("Verification failed: {:?}", e), 2))?;
    println!("Signature checks out.");
    Ok(())
}
