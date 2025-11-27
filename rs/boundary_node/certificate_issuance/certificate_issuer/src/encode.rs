use std::{sync::Arc, time::Instant};

use anyhow::{Error, anyhow};
use async_trait::async_trait;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use tracing::info;

use crate::metrics::{MetricParams, WithMetrics};

const NONCE_LEN: usize = 24;

#[async_trait]
pub trait Encode: Sync + Send {
    async fn encode(&self, v: &[u8]) -> Result<Vec<u8>, Error>;
}

#[async_trait]
pub trait Decode: Sync + Send {
    async fn decode(&self, v: &[u8]) -> Result<Vec<u8>, Error>;
}

pub struct Encoder {
    cipher: Arc<XChaCha20Poly1305>,
}

impl Encoder {
    pub fn new(cipher: Arc<XChaCha20Poly1305>) -> Self {
        Self { cipher }
    }
}

#[async_trait]
impl Encode for Encoder {
    async fn encode(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let nonce = XNonce::from_slice(&nonce).to_owned();

        if nonce.len() != NONCE_LEN {
            return Err(anyhow!("wrong nonce length"));
        }

        let data_enc = self
            .cipher
            .encrypt(&nonce, data)
            .map_err(|err| anyhow!("failed to encrypt data: {err}"))?;

        Ok([
            nonce.to_vec(), // non-encrypted nonce
            data_enc,       // encrypted data
        ]
        .concat())
    }
}

#[async_trait]
impl<T: Encode> Encode for WithMetrics<T> {
    async fn encode(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let start_time = Instant::now();

        let out = self.0.encode(data).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.with_label_values(&[status]).inc();
        recorder.with_label_values(&[status]).observe(duration);

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}

pub struct Decoder {
    cipher: Arc<XChaCha20Poly1305>,
}

impl Decoder {
    pub fn new(cipher: Arc<XChaCha20Poly1305>) -> Self {
        Self { cipher }
    }
}

#[async_trait]
impl Decode for Decoder {
    async fn decode(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let (nonce, data_enc) = data.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce);

        let data = self
            .cipher
            .decrypt(nonce, data_enc)
            .map_err(|err| anyhow!("failed to decrypt data: {err}"))?;

        Ok(data)
    }
}

#[async_trait]
impl<T: Decode> Decode for WithMetrics<T> {
    async fn decode(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let start_time = Instant::now();

        let out = self.0.decode(data).await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.with_label_values(&[status]).inc();
        recorder.with_label_values(&[status]).observe(duration);

        info!(action = action.as_str(), status, duration, error = ?out.as_ref().err());

        out
    }
}
