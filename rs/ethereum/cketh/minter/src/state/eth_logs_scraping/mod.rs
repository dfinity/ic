use crate::numeric::BlockNumber;
use ic_ethereum_types::Address;
use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

/// A container to aggregate all log scrapings.
#[derive(Clone, PartialEq, Debug)]
pub struct LogScrapings {
    scrapings: BTreeMap<LogScrapingId, LogScrapingState>,
}

impl LogScrapings {
    pub fn new(last_scraped_block_number: BlockNumber) -> Self {
        let mut scrapings = BTreeMap::new();
        for id in LogScrapingId::iter() {
            scrapings.insert(id, LogScrapingState::new(last_scraped_block_number));
        }
        Self { scrapings }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&LogScrapingId, &LogScrapingState)> {
        self.scrapings.iter()
    }

    pub fn set_contract_address(
        &mut self,
        id: LogScrapingId,
        contract_address: Address,
    ) -> Result<(), LogScrapingStateError> {
        self.get_mut(id).set_contract_address(contract_address)
    }

    pub fn set_last_scraped_block_number(&mut self, id: LogScrapingId, block_number: BlockNumber) {
        self.get_mut(id).set_last_scraped_block_number(block_number)
    }

    fn get_mut(&mut self, id: LogScrapingId) -> &mut LogScrapingState {
        self.scrapings
            .get_mut(&id)
            .expect("BUG: LogScrapings should contain all LogScrapingId")
    }

    pub fn last_scraped_block_number(&self, id: LogScrapingId) -> BlockNumber {
        self.get(id).last_scraped_block_number()
    }

    pub fn contract_address(&self, id: LogScrapingId) -> Option<&Address> {
        self.get(id).contract_address()
    }

    fn get(&self, id: LogScrapingId) -> &LogScrapingState {
        self.scrapings
            .get(&id)
            .expect("BUG: LogScrapings should contain all LogScrapingId")
    }
}

#[derive(Clone, PartialEq, Copy, Debug, PartialOrd, Ord, Eq, EnumIter)]
#[repr(u8)]
pub enum LogScrapingId {
    EthDepositWithoutSubaccount,
    Erc20DepositWithoutSubaccount,
    EthOrErc20DepositWithSubaccount,
}

impl Display for LogScrapingId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LogScrapingId::EthDepositWithoutSubaccount => write!(f, "ETH"),
            LogScrapingId::Erc20DepositWithoutSubaccount => write!(f, "ERC-20"),
            LogScrapingId::EthOrErc20DepositWithSubaccount => {
                write!(f, "ETH or ERC-20 (with subaccount)")
            }
        }
    }
}

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
