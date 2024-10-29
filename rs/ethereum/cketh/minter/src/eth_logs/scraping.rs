use crate::eth_logs::{RECEIVED_ERC20_EVENT_TOPIC, RECEIVED_ETH_EVENT_TOPIC};
use crate::eth_rpc::{FixedSizeData, Topic};
use crate::numeric::BlockNumber;
use crate::state::eth_logs_scraping::ActiveLogScrapingState;
use crate::state::State;

/// Trait for managing the state of a log scraping.
pub trait LogScraping {
    fn check_active(state: &State) -> Option<ActiveLogScrapingState>;
    fn update_last_scraped_block_number(state: &mut State, block_number: BlockNumber);
    fn event_topics(state: &State) -> Vec<Topic>;
    fn display_id() -> &'static str;
}

pub struct ReceivedEthLogScraping {}

impl LogScraping for ReceivedEthLogScraping {
    fn check_active(state: &State) -> Option<ActiveLogScrapingState> {
        state.eth_log_scraping.clone().into_active()
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
    fn check_active(state: &State) -> Option<ActiveLogScrapingState> {
        if state.ckerc20_tokens.is_empty() {
            return None;
        }
        state.erc20_log_scraping.clone().into_active()
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
