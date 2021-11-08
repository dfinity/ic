//! Command line interface for generating threshold keys
use ic_crypto_internal_threshold_sig_bls12381::api::keygen;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use openssl::sha::sha256;
use rand::rngs::StdRng;
use rand::Rng;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [threshold, eligibility, seed] => core(threshold, eligibility, Some(seed)),
        [threshold, eligibility] => core(threshold, eligibility, None),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err((
        "Args: <threshold> <receiver_eligibility as string of 0s and 1s> [seed]".to_string(),
        1,
    ))
}

fn core(threshold: &str, eligibility: &str, seed: Option<&str>) -> Result<(), (String, i32)> {
    let mut rng = {
        let seed = if let Some(seed) = seed {
            sha256(seed.as_bytes())
        } else {
            let mut rng = StdRng::from_entropy();
            rng.gen::<[u8; 32]>()
        };
        ChaChaRng::from_seed(seed)
    };
    let threshold = NumberOfNodes::from(
        threshold
            .parse::<NodeIndex>()
            .expect("Could not parse threshold"),
    );
    let eligibility: Result<Vec<bool>, (String, i32)> = eligibility
        .chars()
        .map(|character| match character {
            '0' => Ok(false),
            '1' => Ok(true),
            character => Err((
                format!("Invalid eligibility '{}' should be '0' or '1'", character),
                1,
            )),
        })
        .collect();
    let eligibility = eligibility?;
    let (public_coefficients, secret_keys) = keygen(
        Randomness::from(rng.gen::<[u8; 32]>()),
        threshold,
        &eligibility,
    )
    .map_err(|error| (format!("Error: {:?}", error), 1))?;
    println!(
        "PublicCoefficients: {}",
        Into::<String>::into(public_coefficients)
    );
    for (index, secret_key) in secret_keys.into_iter().enumerate() {
        let secret_key = if let Some(secret_key) = secret_key {
            Into::<String>::into(secret_key)
        } else {
            "".to_string()
        };
        println!("SecretKey for {}: {}", index, secret_key);
    }
    Ok(())
}
