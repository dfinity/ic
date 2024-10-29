use crate::eth_logs::{RECEIVED_ERC20_EVENT_TOPIC, RECEIVED_ETH_EVENT_TOPIC};
use crate::eth_rpc::{FixedSizeData, Topic};
use crate::numeric::BlockNumber;
use crate::state::State;
use ic_ethereum_types::Address;

/// Trait for managing the state of a log scraping.
pub trait LogScraping {
    fn next_scrape(state: &State) -> Option<Scrape>;
    fn update_last_scraped_block_number(state: &mut State, block_number: BlockNumber);
    fn event_topics(state: &State) -> Vec<Topic>;
    fn display_id() -> &'static str;
}

pub struct Scrape {
    pub contract_address: Address,
    pub last_scraped_block_number: BlockNumber,
    pub topics: Vec<Topic>,
}

pub struct ReceivedEthLogScraping {}

impl LogScraping for ReceivedEthLogScraping {
    fn next_scrape(state: &State) -> Option<Scrape> {
        let contract_address = *state.eth_log_scraping.contract_address()?;
        let last_scraped_block_number = state.eth_log_scraping.last_scraped_block_number();
        let topics = vec![Topic::from(FixedSizeData(RECEIVED_ETH_EVENT_TOPIC))];
        Some(Scrape {
            contract_address,
            last_scraped_block_number,
            topics,
        })
    }

    fn update_last_scraped_block_number(state: &mut State, block_number: BlockNumber) {
        state
            .eth_log_scraping
            .set_last_scraped_block_number(block_number);
    }

    fn event_topics(_state: &State) -> Vec<Topic> {
        vec![Topic::from(FixedSizeData(RECEIVED_ETH_EVENT_TOPIC))]
    }

    fn display_id() -> &'static str {
        "ETH"
    }
}

pub struct ReceivedErc20LogScraping {}

impl LogScraping for ReceivedErc20LogScraping {
    fn next_scrape(state: &State) -> Option<Scrape> {
        if state.ckerc20_tokens.is_empty() {
            return None;
        }
        let contract_address = *state.erc20_log_scraping.contract_address()?;
        let last_scraped_block_number = state.erc20_log_scraping.last_scraped_block_number();

        let token_contract_addresses = state.ckerc20_tokens.alt_keys().cloned().collect::<Vec<_>>();
        let mut topics: Vec<_> = vec![Topic::from(FixedSizeData(RECEIVED_ERC20_EVENT_TOPIC))];
        // We add token contract addresses as additional topics to match.
        // It has a disjunction semantics, so it will match if event matches any one of these addresses.
        topics.push(
            token_contract_addresses
                .iter()
                .map(|address| FixedSizeData(address.into()))
                .collect::<Vec<_>>()
                .into(),
        );

        Some(Scrape {
            contract_address,
            last_scraped_block_number,
            topics,
        })
    }

    fn update_last_scraped_block_number(state: &mut State, block_number: BlockNumber) {
        state
            .erc20_log_scraping
            .set_last_scraped_block_number(block_number);
    }

    fn event_topics(state: &State) -> Vec<Topic> {
        let token_contract_addresses = state.ckerc20_tokens.alt_keys().cloned().collect::<Vec<_>>();
        let mut topics: Vec<_> = vec![Topic::from(FixedSizeData(RECEIVED_ERC20_EVENT_TOPIC))];
        // We add token contract addresses as additional topics to match.
        // It has a disjunction semantics, so it will match if event matches any one of these addresses.
        if !token_contract_addresses.is_empty() {
            topics.push(
                token_contract_addresses
                    .iter()
                    .map(|address| FixedSizeData(address.into()))
                    .collect::<Vec<_>>()
                    .into(),
            )
        }
        topics
    }

    fn display_id() -> &'static str {
        "ERC-20"
    }
}
