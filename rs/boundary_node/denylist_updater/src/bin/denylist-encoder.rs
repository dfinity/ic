use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::{anyhow, Context, Error};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use clap::Parser;
use flate2::{write::GzEncoder, Compression};
use rand_core::{OsRng, RngCore};
use rsa::{pkcs8::DecodePublicKey, PaddingScheme, PublicKey, RsaPublicKey};
use sha2::Sha256;
use tar::{Builder, Header};

#[derive(Parser)]
#[clap(name = "denylist-encoder")]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    #[clap(long, default_value = "pkey.pem")]
    public_key_path: PathBuf,

    #[clap(long, default_value = "denylist.json")]
    denylist_path: PathBuf,

    #[clap(long, default_value = "denylist.tar.gz")]
    payload_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Compress data
    let data = std::fs::read(cli.denylist_path).context("failed to read denylist")?;

    let mut v = Vec::new();
    let mut enc = GzEncoder::new(&mut v, Compression::default());
    enc.write_all(&data).context("failed to write data")?;
    enc.finish()?;

    let data = v;

    // Generate symmetric key
    let sym_key = XChaCha20Poly1305::generate_key(&mut OsRng);

    // Encrypt data
    let cipher = XChaCha20Poly1305::new(&sym_key);

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let nonce = XNonce::from_slice(&nonce);

    let data_enc = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|err| anyhow!("failed to encrypt data: {err}"))?;

    // Encrypt symmetric key
    let public_key_pem = std::fs::read_to_string(cli.public_key_path)?;
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem)?;

    let padding = PaddingScheme::new_oaep::<Sha256>();
    let sym_key_enc = public_key.encrypt(&mut OsRng, padding, &sym_key)?;

    // Generate payload
    let payload = Vec::new();
    let mut ar = Builder::new(payload);

    let nonce: Result<Vec<_>, _> = nonce.bytes().collect();
    let nonce = nonce.context("failed to collect nonce")?;

    [
        (&sym_key_enc, "sym.key.enc"),
        (&data_enc, "denylist.json.enc"),
        (&nonce, "denylist.json.nonce"),
    ]
    .iter()
    .try_for_each(|(v, name)| {
        let mut header = Header::new_gnu();

        header.set_path(name).context("failed to set path")?;
        header.set_size(v.len() as u64);
        header.set_cksum();

        ar.append(&header, v.as_slice())
            .context("failed to append to tar archive")?;

        let out: Result<(), Error> = Ok(());
        out
    })?;

    let payload = ar.into_inner().context("failed to finalize tar archive")?;

    let f_payload = File::create(cli.payload_path).context("failed to create payload file")?;
    let mut enc = GzEncoder::new(f_payload, Compression::default());
    enc.write_all(&payload).context("failed to write payload")?;
    enc.finish()?;

    Ok(())
}
