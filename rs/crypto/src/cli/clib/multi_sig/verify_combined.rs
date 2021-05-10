use ic_crypto_internal_multi_sig_bls12381::types::{CombinedSignatureBytes, PublicKeyBytes};
use ic_crypto_internal_multi_sig_bls12381::verify_combined;
use ic_types::crypto::CryptoResult;
use std::convert::{TryFrom, TryInto};

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    if args.len() >= 2 {
        core(&args[0], &args[1], &args[2..])
    } else {
        usage()
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err((
        "Args: <message> <signature> [public_key1] [public_key2] ...".to_string(),
        1,
    ))
}

fn core(message: &str, signature: &str, public_keys: &[String]) -> Result<(), (String, i32)> {
    let message = message.as_bytes();
    let signature: CombinedSignatureBytes =
        signature.try_into().map_err(|e| (format!("{:?}", e), 2))?;
    let public_keys: CryptoResult<Vec<PublicKeyBytes>> =
        public_keys.iter().map(PublicKeyBytes::try_from).collect();
    let public_keys = public_keys.map_err(|e| (format!("{:?}", e), 2))?;

    verify_combined(message, signature, &public_keys)
        .map_err(|_| ("Combined signature verification failed".to_string(), 2))?;

    println!("Signature checks out.");
    Ok(())
}
