use serde::{Deserialize, Serialize};

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
