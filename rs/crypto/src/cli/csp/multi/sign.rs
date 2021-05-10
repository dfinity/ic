use crate::cli::csp;
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_csp::types::{CspSignature, MultiBls12_381_Signature};
use ic_types::crypto::{AlgorithmId, KeyId};

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [message, key_id] => core(message, key_id),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <message> <key_id>".to_string(), 1))
}

fn core(message: &str, key_id: &str) -> Result<(), (String, i32)> {
    let csp = csp();
    let algorithm_id = AlgorithmId::MultiBls12_381;
    let key_id: KeyId = {
        let bytes = base64::decode(key_id).expect("Invalid key id format");
        if bytes.len() != std::mem::size_of::<KeyId>() {
            panic!("Malformed key ID");
        }
        let mut buffer = [0u8; std::mem::size_of::<KeyId>()];
        buffer.copy_from_slice(&bytes);
        KeyId::from(buffer)
    };
    let signature = csp
        .sign(algorithm_id, message.as_bytes(), key_id)
        .map_err(|e| (format!("{:?}", e), 2))?;
    match signature {
        CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(signature)) => {
            println!("Signature: {}", Into::<String>::into(signature))
        }
        _ => panic!("Unexpected signature type"),
    }
    Ok(())
}
