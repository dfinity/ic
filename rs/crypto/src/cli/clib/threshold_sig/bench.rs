//! Benchmark the performance of threshold signatures
use ic_crypto_internal_threshold_sig_bls12381::api;
use ic_crypto_internal_threshold_sig_bls12381::types::public_coefficients::conversions::pub_key_bytes_from_pub_coeff_bytes;
use ic_crypto_internal_threshold_sig_bls12381::types::{IndividualSignatureBytes, SecretKeyBytes};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::{NodeIndex, NumberOfNodes, Randomness};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::time::{Duration, Instant};

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
          \n   cargo run --release lib threshold bench 64"
            .to_string(),
        1,
    ))
}

fn generate_public_keys(
    public_coefficients: &PublicCoefficientsBytes,
    secret_keys: &[Option<SecretKeyBytes>],
) -> Result<Vec<Option<PublicKeyBytes>>, (String, i32)> {
    (0..)
        .zip(secret_keys)
        .map(|(index, maybe)| {
            maybe
                .map(|_| api::individual_public_key(public_coefficients, index))
                .transpose()
                .map_err(|e| {
                    (
                        format!("Error computing individual public key:\n{:?}", e),
                        2,
                    )
                })
        })
        .collect()
}
fn sign(
    message: &[u8],
    secret_keys: &[Option<SecretKeyBytes>],
) -> Result<Vec<Option<IndividualSignatureBytes>>, (String, i32)> {
    secret_keys
        .iter()
        .map(|secret_key_bytes_maybe| {
            secret_key_bytes_maybe
                .as_ref()
                .map(|secret_key_bytes| api::sign_message(message, secret_key_bytes))
                .transpose()
                .map_err(|e| (format!("Error signing:\n{:?}", e), 2))
        })
        .collect()
}
fn verify_individual(
    message: &[u8],
    signatures: &[Option<IndividualSignatureBytes>],
    public_keys: &[Option<PublicKeyBytes>],
) -> Result<Vec<Option<()>>, (String, i32)> {
    signatures
        .iter()
        .zip(public_keys)
        .map(|(signature_maybe, public_key_maybe)| {
            signature_maybe
                .map(|signature| {
                    api::verify_individual_signature(
                        message,
                        signature,
                        public_key_maybe
                            .expect("Benchmark error:  Missing public key for signature"),
                    )
                })
                .transpose()
                .map_err(|e| (format!("Error verifying individual:\n{:?}", e), 2))
        })
        .collect()
}

/// Print the time spent on an operation.
///
/// Note: Benchmark results always need to be treated with caution in many ways.
/// The division by the number of nodes in the printout reflects the
/// fact that most of the operations we are timing have fixed runtime but are
/// performed once per signatory, e.g. signature verification, or are performed
/// once but have a linear component in the number of nodes.  Where this is not
/// the case, as with combined signature verification, num_signers should be set
/// to 1.  The division yields a more useful number than the raw time, however
/// there are often other nonlinear terms that influence the runtime.  We
/// explicitly do not claim that the relationship is always precisely linear.
fn print_time(title: &str, interval: Duration, num_signers: usize) {
    let interval_ms = interval.as_nanos() as f64 / 1_000_000f64;
    println!(
        "{:30}: {} ms/{} = {} ms per signer",
        title,
        interval_ms,
        num_signers,
        interval_ms / (num_signers as f64)
    );
}

fn core(num_signers: &str) -> Result<(), (String, i32)> {
    let mut keygen_time = Duration::new(0, 0);
    let mut public_key_derivation_time = Duration::new(0, 0);
    let mut signing_time = Duration::new(0, 0);
    let mut individual_verification_time = Duration::new(0, 0);
    let mut combining_time = Duration::new(0, 0);
    let mut combined_verification_time = Duration::new(0, 0);

    let mut rng = StdRng::from_entropy();
    let num_signers = num_signers
        .parse::<usize>()
        .map_err(|_| (format!("Invalid num_signers {}", num_signers), 2))?;
    let seed = Randomness::from(rng.gen::<[u8; 32]>());
    let threshold = NumberOfNodes::from(num_signers as NodeIndex);
    let eligibility = vec![true; num_signers];
    let message = "Twas brillig, and the slithy toves, did gyre and gimble in the wabe".as_bytes();
    let iterations = 1000 / num_signers + 1;

    for _ in 0..iterations {
        let time_start = Instant::now();

        let (public_coefficients, secret_keys) = api::keygen(seed, threshold, &eligibility)
            .map_err(|e| (format!("Keygen failed: {:?}", e), 2))?;
        let after_keygen = Instant::now();

        let public_keys = generate_public_keys(&public_coefficients, &secret_keys)?;
        let after_public_key_derivation = Instant::now();

        let signatures = sign(message, &secret_keys)?;
        let after_signing = Instant::now();

        verify_individual(message, &signatures, &public_keys)?;
        let after_individual_verification = Instant::now();

        let combined_signature = api::combine_signatures(&signatures, threshold)
            .map_err(|e| (format!("Error combining: {:?}", e), 2))?;
        let after_combining = Instant::now();

        api::verify_combined_signature(
            message,
            combined_signature,
            pub_key_bytes_from_pub_coeff_bytes(&public_coefficients),
        )
        .map_err(|_| ("Combined signature verification failed".to_string(), 2))?;
        let after_combined_verification = Instant::now();

        keygen_time += after_keygen.duration_since(time_start);
        public_key_derivation_time += after_public_key_derivation.duration_since(after_keygen);
        signing_time += after_signing.duration_since(after_public_key_derivation);
        individual_verification_time += after_individual_verification.duration_since(after_signing);
        combining_time += after_combining.duration_since(after_individual_verification);
        combined_verification_time += after_combined_verification.duration_since(after_combining);
    }

    println!("Times: ({} iterations)", iterations);
    print_time("keygen", keygen_time / iterations as u32, num_signers);
    print_time(
        "public_key_derivation",
        public_key_derivation_time / iterations as u32,
        num_signers,
    );
    print_time("signing", signing_time / iterations as u32, num_signers);
    print_time(
        "individual_verification",
        individual_verification_time / iterations as u32,
        num_signers,
    );
    print_time("combining", combining_time / iterations as u32, num_signers);
    print_time(
        "combined_verification",
        combined_verification_time / iterations as u32,
        1,
    );
    Ok(())
}
