use ic_crypto_internal_multi_sig_bls12381::combine;
use ic_crypto_internal_multi_sig_bls12381::types::IndividualSignatureBytes;
use ic_types::crypto::CryptoResult;
use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [flag] if flag == "--help" => usage(),
        _ => core(args),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <signature1> [signature2] ...".to_string(), 1))
}

fn core(signatures: &[String]) -> Result<(), (String, i32)> {
    let signatures: CryptoResult<Vec<IndividualSignatureBytes>> = signatures
        .iter()
        .map(IndividualSignatureBytes::try_from)
        .collect();
    let signatures = signatures.map_err(|e| (format!("{:?}", e), 2))?;
    let signature = combine(&signatures).map_err(|e| (format!("Error combining: {:?}", e), 2))?;
    println!("Combined signature: {}", Into::<String>::into(signature));
    Ok(())
}
