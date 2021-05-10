//! Command line interface to combine threshold signatures
use ic_crypto_internal_threshold_sig_bls12381::api;
use ic_crypto_internal_threshold_sig_bls12381::types::IndividualSignatureBytes;
use ic_types::crypto::CryptoResult;
use ic_types::{NodeIndex, NumberOfNodes};
use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [flag] if flag == "--help" => usage(),
        args if !args.is_empty() => core(&args[0], &args[1..]),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err((
        "Args: <threshold> [signature1 or '-'] [signature2 or '-'] ...".to_string(),
        1,
    ))
}

fn core(threshold: &str, signatures: &[String]) -> Result<(), (String, i32)> {
    let threshold = NumberOfNodes::from(
        threshold
            .parse::<NodeIndex>()
            .expect("Could not parse threshold"),
    );
    let signatures: CryptoResult<Vec<Option<IndividualSignatureBytes>>> = signatures
        .iter()
        .map(|signature| {
            if signature == "-" {
                Ok(None)
            } else {
                IndividualSignatureBytes::try_from(signature).map(Some)
            }
        })
        .collect();
    let signatures = signatures.map_err(|e| (format!("{:?}", e), 2))?;
    let signature = api::combine_signatures(&signatures, threshold)
        .map_err(|e| (format!("Error combining: {:?}", e), 2))?;
    println!("Combined signature: {}", Into::<String>::into(signature));
    Ok(())
}
