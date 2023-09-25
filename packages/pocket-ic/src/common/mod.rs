use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod rest;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct BlobId(pub [u8; 32]);

#[derive(Clone, Debug)]
pub struct BinaryBlob {
    pub data: Vec<u8>,
    pub compression: BlobCompression,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobCompression {
    Gzip,
    NoCompression,
}

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn store(&self, blob: BinaryBlob) -> BlobId;
    async fn fetch(&self, blob_id: BlobId) -> Option<BinaryBlob>;
}
