//! Command line interface for threshold signing a message
use ic_crypto_internal_threshold_sig_bls12381::api;
use ic_crypto_internal_threshold_sig_bls12381::types::SecretKeyBytes;

use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [message, secret_key] => core(message, secret_key),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <public_coefficients> <index>".to_string(), 1))
}

fn core(message: &str, secret_key: &str) -> Result<(), (String, i32)> {
    let secret_key = SecretKeyBytes::try_from(secret_key).expect("Could not parse secret key");
    let signature = api::sign_message(message.as_bytes(), &secret_key).expect("Could not sign");
    println!("IndividualSignature: {}", Into::<String>::into(signature));
    Ok(())
}
