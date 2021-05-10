use crate::cli::csp;
use ic_crypto_internal_csp::api::CspSigner;
use ic_crypto_internal_csp::types::{CspPublicKey, CspSignature, MultiBls12_381_Signature};
use ic_crypto_internal_multi_sig_bls12381::types::{IndividualSignatureBytes, PublicKeyBytes};
use ic_types::crypto::{AlgorithmId, CryptoResult};
use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [flag] if flag == "--help" => usage(),
        _ => core(args),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err((
        "Args: <pubkey;signature1> [pubkey;signature2] ...".to_string(),
        1,
    ))
}

fn core(signatures: &[String]) -> Result<(), (String, i32)> {
    let algorithm_id = AlgorithmId::MultiBls12_381;

    let signatures: Result<Vec<(CspPublicKey, CspSignature)>, (String, i32)> = signatures
        .iter()
        .map(|tuple| {
            let parts: Vec<&str> = tuple.split(';').collect();
            match parts[..] {
                [public_key, signature] => to_csp_key_signature_pair(public_key, signature)
                    .map_err(|e| (format!("Parsing key;signature pairs failed: {:?}", e), 2)),

                _ => Err((
                    format!("Malformed <public_key>;<signature> pair: {:?}", tuple),
                    2,
                )),
            }
        })
        .collect();
    let signatures = signatures?;

    let signature = csp()
        .combine_sigs(signatures, algorithm_id)
        .map_err(|e| (format!("Error combining: {:?}", e), 2))?;
    match signature {
        CspSignature::MultiBls12_381(MultiBls12_381_Signature::Combined(signature)) => {
            println!("Combined Signature: {}", Into::<String>::into(signature))
        }
        _ => panic!("Unexpected signature type"),
    }
    Ok(())
}

fn to_csp_key_signature_pair(
    public_key: &str,
    signature: &str,
) -> CryptoResult<(CspPublicKey, CspSignature)> {
    let signature =
        IndividualSignatureBytes::try_from(&String::from(signature)).map(|signature| {
            CspSignature::MultiBls12_381(MultiBls12_381_Signature::Individual(signature))
        })?;

    let public_key = PublicKeyBytes::try_from(&String::from(public_key))?;
    let public_key = CspPublicKey::MultiBls12_381(public_key);
    Ok((public_key, signature))
}
