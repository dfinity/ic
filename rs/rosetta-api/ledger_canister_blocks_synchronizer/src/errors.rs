use crate::store::BlockStoreError;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidBlockId(String),
    InternalError(String),
}

impl From<BlockStoreError> for Error {
    fn from(e: BlockStoreError) -> Self {
        match e {
            BlockStoreError::NotFound(idx) => {
                Error::InvalidBlockId(format!("Block not found: {}", idx))
            }
            BlockStoreError::NotAvailable(idx) => {
                Error::InvalidBlockId(format!("Block not available for query: {}", idx))
            }
            BlockStoreError::Other(msg) => Error::InternalError(msg),
        }
    }
}
