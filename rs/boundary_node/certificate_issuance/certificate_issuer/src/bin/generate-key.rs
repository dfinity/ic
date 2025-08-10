use std::path::PathBuf;

use anyhow::Error;
use chacha20poly1305::{aead::OsRng as ChaChaOsRng, KeyInit, XChaCha20Poly1305};
use clap::Parser;
use pem::Pem;

#[derive(Parser)]
#[clap(name = "generate-key")]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    #[clap(long, default_value = "key.pem")]
    key_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Symmetric Key
    let sym_key = XChaCha20Poly1305::generate_key(&mut ChaChaOsRng);

    let sym_key_pem = pem::encode(&Pem {
        tag: "SYMMETRIC_KEY".into(),
        contents: sym_key.to_vec(),
    });

    std::fs::write(cli.key_path, sym_key_pem)?;

    Ok(())
}
