use ed25519::types::{PublicKeyBytes, SecretKeyBytes};
use ed25519::{keypair_from_rng, sign, verify};
use ic_crypto_internal_basic_sig_ed25519 as ed25519;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::{Duration, Instant};

pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [flag] if flag == "--help" => usage(),
        [] => core(),
        _ => usage(),
    }
}

fn usage() -> Result<(), (String, i32)> {
    Err(("Args: This function taks no arguments".to_string(), 1))
}

fn print_time(title: &str, interval: Duration) {
    let interval = interval.as_nanos() as f64 / 1_000_000f64;
    println!("{:30}: {} ms", title, interval,);
}

fn core() -> Result<(), (String, i32)> {
    let mut keygen_time = Duration::new(0, 0);
    let mut signing_time = Duration::new(0, 0);
    let mut verification_time = Duration::new(0, 0);

    let mut rng = StdRng::from_entropy();

    let iterations = 10_000;

    for _ in 0..iterations {
        let time_start = Instant::now();
        let (secret_key, public_key): (SecretKeyBytes, PublicKeyBytes) = keypair_from_rng(&mut rng);
        let after_keygen = Instant::now();
        let message =
            "Twas brillig, and the slithy toves, did gyre and gimble in the wabe".as_bytes();
        let signature = sign(message, &secret_key).map_err(|e| (format!("{:?}", e), 2))?;
        let after_signing = Instant::now();
        verify(&signature, message, &public_key)
            .map_err(|_| ("Signature verification failed".to_string(), 2))?;
        let after_verification = Instant::now();

        keygen_time += after_keygen.duration_since(time_start);
        signing_time += after_signing.duration_since(after_keygen);
        verification_time += after_verification.duration_since(after_signing);
    }

    println!("Times: ({} iterations)", iterations);
    print_time("keygen", keygen_time / iterations);
    print_time("signing", signing_time / iterations);
    print_time("verification", verification_time / iterations);
    Ok(())
}
