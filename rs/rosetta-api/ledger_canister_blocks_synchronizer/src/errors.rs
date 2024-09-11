use icp_ledger::{Block, BlockIndex};

use crate::blocks::BlockStoreError;

#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    InvalidBlockId(String),
    InvalidTipOfChain(String),
    InternalError(String),
}

impl Error {
    pub fn invalid_tip_of_chain(index: BlockIndex, expected: Block, found: Block) -> Error {
        let msg = format!("The tip of the chain at index {} is different from the expected one. Expected: {:?}, found: {:?}",
                        index, expected, found);
        Error::InvalidTipOfChain(msg)
    }
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
