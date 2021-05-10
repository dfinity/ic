use ic_crypto_internal_basic_sig_ed25519::keypair_from_rng;
use rand::rngs::StdRng;
use rand::SeedableRng;

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
    let mut rng = StdRng::from_entropy();
    let (secret_key, public_key) = keypair_from_rng(&mut rng);
    println!("SecretKey: {}", Into::<String>::into(secret_key));
    println!("PublicKey: {}", Into::<String>::into(public_key));
    Ok(())
}
