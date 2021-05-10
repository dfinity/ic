//! Command line interface for computing an individual threshold public key
use ic_crypto_internal_threshold_sig_bls12381::api;
use ic_types::NodeIndex;

use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [public_coefficients, index] => core(public_coefficients, index),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <public_coefficients> <index>".to_string(), 1))
}

fn core(public_coefficients: &str, index: &str) -> Result<(), (String, i32)> {
    let index = index
        .parse::<NodeIndex>()
        .expect("Could not parse threshold");
    let public_coefficients = PublicCoefficientsBytes::try_from(public_coefficients)
        .expect("Could not parse public coefficients");
    let public_key_bytes = api::individual_public_key(&public_coefficients, index)
        .map_err(|e| (format!("{:?}", e), 2))?;
    println!("PublicKey: {}", Into::<String>::into(public_key_bytes));
    Ok(())
}
