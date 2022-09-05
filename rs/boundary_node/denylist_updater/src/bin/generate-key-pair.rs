use std::path::PathBuf;

use anyhow::{Context, Error};
use clap::Parser;
use rand_core::OsRng;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};

#[derive(Parser)]
#[clap(name = "generate-key-pair")]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    #[clap(long, default_value = "key.pem")]
    private_key_path: PathBuf,

    #[clap(long, default_value = "pkey.pem")]
    public_key_path: PathBuf,

    #[clap(long, default_value = "2048")]
    bit_size: usize,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Private Key
    let private_key =
        RsaPrivateKey::new(&mut OsRng, cli.bit_size).context("failed to create new privat key")?;

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::default())
        .context("failed to serialize private key")?;

    std::fs::write(cli.private_key_path, private_key_pem)?;

    // Public Key
    let public_key = RsaPublicKey::from(&private_key);

    let public_key_pem = public_key
        .to_public_key_pem(LineEnding::default())
        .context("failed to serialize public key")?;

    std::fs::write(cli.public_key_path, public_key_pem)?;

    Ok(())
}
