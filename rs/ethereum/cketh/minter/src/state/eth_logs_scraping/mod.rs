use crate::numeric::BlockNumber;
use ic_ethereum_types::Address;
use std::fmt::Debug;

#[derive(Clone, PartialEq, Debug)]
pub enum LogScrapingStateError {
    InvalidContractAddress(String),
}

#[derive(Clone, PartialEq, Debug)]
pub struct LogScrapingState {
    contract_address: Option<Address>,
    last_scraped_block_number: BlockNumber,
}

impl LogScrapingState {
    pub fn new(last_scraped_block_number: BlockNumber) -> Self {
        Self {
            contract_address: None,
            last_scraped_block_number,
        }
    }

    pub fn set_contract_address(
        &mut self,
        contract_address: Address,
    ) -> Result<(), LogScrapingStateError> {
        if contract_address == Address::ZERO {
            return Err(LogScrapingStateError::InvalidContractAddress(
                "contract address must not be zero".to_string(),
            ));
        }
        self.contract_address = Some(contract_address);
        Ok(())
    }

    pub fn set_last_scraped_block_number(&mut self, block_number: BlockNumber) {
        self.last_scraped_block_number = block_number;
    }

    pub fn last_scraped_block_number(&self) -> BlockNumber {
        self.last_scraped_block_number
    }

    pub fn contract_address(&self) -> Option<&Address> {
        self.contract_address.as_ref()
    }
}
