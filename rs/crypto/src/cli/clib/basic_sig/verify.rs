use ed25519::types::{PublicKeyBytes, SignatureBytes};
use ed25519::verify;
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
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
    let signature = SignatureBytes::try_from(signature).map_err(|e| (format!("{:?}", e), 2))?;
    let public_key = PublicKeyBytes::try_from(public_key).map_err(|e| (format!("{:?}", e), 2))?;
    verify(&signature, message.as_bytes(), &public_key)
        .map_err(|e| (format!("Verification failed: {:?}", e), 2))?;
    println!("Signature checks out.");
    Ok(())
}
