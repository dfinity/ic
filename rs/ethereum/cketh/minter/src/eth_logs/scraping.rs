use crate::eth_logs::{
    LogParser, ReceivedErc20LogParser, ReceivedEthLogParser, ReceivedEthOrErc20LogParser,
    RECEIVED_ERC20_EVENT_TOPIC, RECEIVED_ETH_EVENT_TOPIC,
    RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC,
};
use crate::eth_rpc::{FixedSizeData, Topic};
use crate::numeric::BlockNumber;
use crate::state::eth_logs_scraping::LogScrapingId;
use crate::state::State;
use ic_ethereum_types::Address;
use std::iter::once;

/// Trait for managing log scraping.
pub trait LogScraping {
    /// The unique identifier for this log scraping.
    const ID: LogScrapingId;

    /// The parser type that defines how to parse logs found by this log scraping.
    type Parser: LogParser;

    fn next_scrape(state: &State) -> Option<Scrape>;

    fn contract_address(state: &State) -> Option<&Address> {
        state.log_scrapings.contract_address(Self::ID)
    }

    fn last_scraped_block_number(state: &State) -> BlockNumber {
        state.log_scrapings.last_scraped_block_number(Self::ID)
    }

    fn update_last_scraped_block_number(state: &mut State, block_number: BlockNumber) {
        state
            .log_scrapings
            .set_last_scraped_block_number(Self::ID, block_number);
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Scrape {
    pub contract_address: Address,
    pub last_scraped_block_number: BlockNumber,
    pub topics: Vec<Topic>,
}

pub enum ReceivedEthLogScraping {}

impl LogScraping for ReceivedEthLogScraping {
    const ID: LogScrapingId = LogScrapingId::EthDepositWithoutSubaccount;
    type Parser = ReceivedEthLogParser;

    fn next_scrape(state: &State) -> Option<Scrape> {
        let contract_address = *Self::contract_address(state)?;
        let last_scraped_block_number = Self::last_scraped_block_number(state);
        let topics = vec![Topic::from(FixedSizeData(RECEIVED_ETH_EVENT_TOPIC))];
        Some(Scrape {
            contract_address,
            last_scraped_block_number,
            topics,
        })
    }
}

pub enum ReceivedErc20LogScraping {}

impl LogScraping for ReceivedErc20LogScraping {
    const ID: LogScrapingId = LogScrapingId::Erc20DepositWithoutSubaccount;
    type Parser = ReceivedErc20LogParser;

    fn next_scrape(state: &State) -> Option<Scrape> {
        if state.ckerc20_tokens.is_empty() {
            return None;
        }
        let contract_address = *Self::contract_address(state)?;
        let last_scraped_block_number = Self::last_scraped_block_number(state);

        let mut topics: Vec<_> = vec![Topic::from(FixedSizeData(RECEIVED_ERC20_EVENT_TOPIC))];
        // We add token contract addresses as additional topics to match.
        // It has a disjunction semantics, so it will match if event matches any one of these addresses.
        topics.push(
            erc20_smart_contracts_addresses_as_topics(state)
                .collect::<Vec<_>>()
                .into(),
        );

        Some(Scrape {
            contract_address,
            last_scraped_block_number,
            topics,
        })
    }
}

pub enum ReceivedEthOrErc20LogScraping {}

impl LogScraping for ReceivedEthOrErc20LogScraping {
    const ID: LogScrapingId = LogScrapingId::EthOrErc20DepositWithSubaccount;
    type Parser = ReceivedEthOrErc20LogParser;

    fn next_scrape(state: &State) -> Option<Scrape> {
        let contract_address = *Self::contract_address(state)?;
        let last_scraped_block_number = Self::last_scraped_block_number(state);

        let mut topics: Vec<_> = vec![Topic::from(FixedSizeData(
            RECEIVED_ETH_OR_ERC20_WITH_SUBACCOUNT_EVENT_TOPIC,
        ))];
        // We add token contract addresses as additional topics to match.
        // It has a disjunction semantics, so it will match if event matches any one of these addresses.
        topics.push(
            once(FixedSizeData::ZERO)
                .chain(erc20_smart_contracts_addresses_as_topics(state))
                .collect::<Vec<_>>()
                .into(),
        );

        Some(Scrape {
            contract_address,
            last_scraped_block_number,
            topics,
        })
    }
}

fn erc20_smart_contracts_addresses_as_topics(
    state: &State,
) -> impl Iterator<Item = FixedSizeData> + '_ {
    state
        .ckerc20_tokens
        .alt_keys()
        .map(|address| FixedSizeData(address.into()))
}
