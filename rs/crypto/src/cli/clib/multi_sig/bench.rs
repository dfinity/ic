use ic_crypto_internal_multi_sig_bls12381 as multi;
use ic_crypto_internal_multi_sig_bls12381::types::{
    CombinedSignatureBytes, IndividualSignatureBytes, PublicKeyBytes, SecretKeyBytes,
};
use ic_types::crypto::CryptoResult;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::Instant;

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [flag] if flag == "--help" => usage(),
        [num_signers] => core(num_signers),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err((
        "Args: .. bench <num_signers:u32>
          \nE.g.:
          \n   cargo run --release lib multi bench 64"
            .to_string(),
        1,
    ))
}

fn keygen(num_signers: usize, mut rng: &mut StdRng) -> Vec<(SecretKeyBytes, PublicKeyBytes)> {
    (0..num_signers)
        .map(|_| multi::keypair_from_rng(&mut rng))
        .collect()
}
fn sign(
    message: &[u8],
    key_pairs: &[(SecretKeyBytes, PublicKeyBytes)],
) -> CryptoResult<Vec<IndividualSignatureBytes>> {
    key_pairs
        .iter()
        .map(|(secret_key_bytes, _public_key_bytes)| multi::sign(message, *secret_key_bytes))
        .collect()
}
fn verify_individual(
    message: &[u8],
    signatures: &[IndividualSignatureBytes],
    key_pairs: &[(SecretKeyBytes, PublicKeyBytes)],
) -> CryptoResult<Vec<()>> {
    key_pairs
        .iter()
        .zip(signatures)
        .map(|((_, public_key), signature)| {
            multi::verify_individual(message, *signature, *public_key)
        })
        .collect()
}
fn verify_combined(
    message: &[u8],
    signature: &CombinedSignatureBytes,
    key_pairs: &[(SecretKeyBytes, PublicKeyBytes)],
) -> CryptoResult<()> {
    let public_keys: Vec<PublicKeyBytes> = key_pairs
        .iter()
        .cloned()
        .map(|(_secret_key, public_key)| public_key)
        .collect();
    multi::verify_combined(message, *signature, &public_keys)
}
fn print_time(title: &str, interval_nanos: f64, num_signers: usize) {
    let interval = interval_nanos / 1_000_000f64;
    println!(
        "{:30}: {}/{} = {} ms",
        title,
        interval,
        num_signers,
        interval / (num_signers as f64)
    );
}

fn core(num_signers: &str) -> Result<(), (String, i32)> {
    let mut keygen_time = 0;
    let mut signing_time = 0;
    let mut individual_verification_time = 0;
    let mut combining_time = 0;
    let mut combined_verification_time = 0;

    let num_signers = num_signers
        .parse::<usize>()
        .map_err(|_| (format!("Invalid num_signers {}", num_signers), 2))?;
    let mut rng = StdRng::from_entropy();

    let iterations = 10_000 / num_signers + 1;

    for _ in 0..iterations {
        let time_start = Instant::now();
        let key_pairs: Vec<(SecretKeyBytes, PublicKeyBytes)> = keygen(num_signers, &mut rng);
        let after_keygen = Instant::now();
        let message =
            "Twas brillig, and the slithy toves, did gyre and gimble in the wabe".as_bytes();
        let signatures = sign(message, &key_pairs).map_err(|e| (format!("{:?}", e), 2))?;
        let after_signing = Instant::now();
        verify_individual(message, &signatures, &key_pairs)
            .map_err(|_| ("Individual signature verification failed".to_string(), 2))?;
        let after_individual_verification = Instant::now();
        let combined_signature =
            multi::combine(&signatures).map_err(|e| (format!("Error combining: {:?}", e), 2))?;
        let after_combining = Instant::now();
        verify_combined(message, &combined_signature, &key_pairs)
            .map_err(|_| ("Combined signature verification failed".to_string(), 2))?;
        let after_combined_verification = Instant::now();

        keygen_time += after_keygen.duration_since(time_start).as_nanos();
        signing_time += after_signing.duration_since(after_keygen).as_nanos();
        individual_verification_time += after_individual_verification
            .duration_since(after_signing)
            .as_nanos();
        combining_time += after_combining
            .duration_since(after_individual_verification)
            .as_nanos();
        combined_verification_time += after_combined_verification
            .duration_since(after_combining)
            .as_nanos();
    }

    println!("Times: ({} iterations)", iterations);
    print_time(
        "keygen",
        keygen_time as f64 / iterations as f64,
        num_signers,
    );
    print_time(
        "signing",
        signing_time as f64 / iterations as f64,
        num_signers,
    );
    print_time(
        "individual_verification",
        individual_verification_time as f64 / iterations as f64,
        num_signers,
    );
    print_time(
        "combining",
        combining_time as f64 / iterations as f64,
        num_signers,
    );
    print_time(
        "combined_verification",
        combined_verification_time as f64 / iterations as f64,
        num_signers,
    );
    Ok(())
}
