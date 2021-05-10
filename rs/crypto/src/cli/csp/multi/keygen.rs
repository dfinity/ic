use crate::cli::csp;
use ic_crypto_internal_csp::api::CspKeyGenerator;
use ic_crypto_internal_csp::types::{CspPop, CspPublicKey};
use ic_types::crypto::AlgorithmId;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [] => core(),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("This function takes no args.".to_string(), 1))
}

fn core() -> Result<(), (String, i32)> {
    let csp = csp();
    let generated = csp
        .gen_key_pair_with_pop(AlgorithmId::MultiBls12_381)
        .expect("Failed to generate key pair with PoP");
    match generated {
        (key_id, CspPublicKey::MultiBls12_381(public_key), CspPop::MultiBls12_381(pop)) => {
            println!("KeyId:     {}", base64::encode(&key_id.get()));
            println!("PublicKey: {}", Into::<String>::into(public_key));
            println!("Pop:       {}", Into::<String>::into(pop));
        }
        _ => panic!("Unexpected types"),
    }
    Ok(())
}
