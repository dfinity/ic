use std::io::Read;

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use flate2::read::GzDecoder;
use rsa::{PaddingScheme, RsaPrivateKey};
use sha2::Sha256;
use tar::Archive;

#[async_trait]
pub trait Decode: Send + Sync {
    async fn decode(&self, data: Vec<u8>) -> Result<Vec<u8>, Error>;
}

pub struct NopDecoder;

#[async_trait]
impl Decode for NopDecoder {
    async fn decode(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(data)
    }
}

pub struct Decoder {
    key: RsaPrivateKey,
}

impl Decoder {
    pub fn new(key: RsaPrivateKey) -> Self {
        Self { key }
    }
}

#[async_trait]
impl Decode for Decoder {
    async fn decode(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut dec = GzDecoder::new(data.as_slice());

        let mut data = Vec::new();
        dec.read_to_end(&mut data)
            .context("failed to decode gzip")?;

        let extract = |data: &[u8], name| {
            let mut ar = Archive::new(data);

            let f = ar
                .entries()?
                .find(|e| e.as_ref().unwrap().path().unwrap().as_os_str() == name);

            let mut f = match f {
                Some(Ok(f)) => f,
                _ => return Err(anyhow!("archive missing {name}")),
            };

            let mut v = Vec::new();
            f.read_to_end(&mut v)
                .context(format!("failed to read {name}"))?;

            Ok(v)
        };

        // Retrieve files from archive
        let [sym_key_enc, data_enc, data_nonce] = [
            extract(&data, "sym.key.enc")?,
            extract(&data, "denylist.json.enc")?,
            extract(&data, "denylist.json.nonce")?,
        ];

        // Decrypt symmetric key
        let padding = PaddingScheme::new_oaep::<Sha256>();
        let sym_key = self
            .key
            .decrypt(padding, &sym_key_enc)
            .context("failed to decrypt symmetric key")?;

        // Decrypt data
        let cipher =
            XChaCha20Poly1305::new_from_slice(&sym_key).context("failed to init symmetric key")?;

        let nonce = XNonce::from_slice(&data_nonce);

        let data = cipher
            .decrypt(nonce, data_enc.as_ref())
            .map_err(|err| anyhow!("failed to decrypt data: {err}"))?;

        // Decompress data
        let mut dec = GzDecoder::new(data.as_slice());

        let mut data = Vec::new();
        dec.read_to_end(&mut data)
            .context("failed to decode gzip")?;

        Ok(data)
    }
}
