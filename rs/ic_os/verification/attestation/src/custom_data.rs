use der::Encode;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("EncodingError({0})")]
pub struct EncodingError(pub String);

pub trait EncodeSevCustomData: Debug + PartialEq {
    fn encode_for_sev(&self) -> Result<[u8; 64], EncodingError>;
}

impl<T: Encode + Debug + PartialEq> EncodeSevCustomData for T {
    fn encode_for_sev(&self) -> Result<[u8; 64], EncodingError> {
        let mut encoded = vec![];
        self.encode(&mut encoded)
            .map_err(|e| EncodingError(e.to_string()))?;

        let hash = ring::digest::digest(&ring::digest::SHA512, &encoded);
        Ok(hash.as_ref().try_into().unwrap())
    }
}
