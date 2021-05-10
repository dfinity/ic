use ic_crypto_internal_multi_sig_bls12381::sign;
use ic_crypto_internal_multi_sig_bls12381::types::SecretKeyBytes;
use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [message, secret_key] => core(message, secret_key),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <message> <secret_key>".to_string(), 1))
}

fn core(message: &str, secret_key: &str) -> Result<(), (String, i32)> {
    let secret_key = SecretKeyBytes::try_from(secret_key).map_err(|e| (format!("{:?}", e), 2))?;
    let signature = sign(message.as_bytes(), secret_key).map_err(|e| (format!("{:?}", e), 2))?;
    println!("Signature: {}", Into::<String>::into(signature));
    Ok(())
}
