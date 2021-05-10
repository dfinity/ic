//! Command line interface to get a combined threshold public key
use ic_crypto_internal_threshold_sig_bls12381::api;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::PublicCoefficients;
use std::convert::TryFrom;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [flag] if flag == "--help" => usage(),
        [public_coefficients] => core(public_coefficients),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: <public_coefficients> <index>".to_string(), 1))
}

fn core(public_coefficients: &str) -> Result<(), (String, i32)> {
    let public_coefficients = PublicCoefficients::try_from(public_coefficients)
        .expect("Could not parse public coefficients");
    let PublicCoefficients::Bls12_381(bytes) = public_coefficients;
    let public_key_bytes =
        api::combined_public_key(&bytes).expect("Could not compute combined public key");
    println!("PublicKey: {}", Into::<String>::into(public_key_bytes));
    Ok(())
}
