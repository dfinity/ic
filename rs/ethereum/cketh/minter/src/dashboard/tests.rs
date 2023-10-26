use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::DashboardTemplate;
use candid::Principal;
use ic_cketh_minter::eth_logs::{EventSource, ReceivedEthEvent};
use ic_cketh_minter::lifecycle::EthereumNetwork;
use ic_cketh_minter::numeric::{BlockNumber, LedgerMintIndex, LogIndex, TransactionNonce};
use ic_cketh_minter::state::audit::{apply_state_transition, EventType};
use ic_cketh_minter::state::State;

#[test]
fn should_display_metadata() {
    let dashboard = DashboardTemplate {
        minter_address: "0x1789F79e95324A47c5Fd6693071188e82E9a3558".to_string(),
        contract_address: "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
        ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
            .expect("BUG: invalid principal"),
        ecdsa_key_name: "key_1".to_string(),
        next_transaction_nonce: TransactionNonce::from(42_u8),
        ..initial_dashboard()
    };

    DashboardAssert::assert_that(dashboard)
        .has_ethereum_network("Ethereum Testnet Sepolia")
        .has_minter_address("0x1789F79e95324A47c5Fd6693071188e82E9a3558")
        .has_contract_address("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34")
        .has_ledger_canister_id("apia6-jaaaa-aaaar-qabma-cai")
        .has_tecdsa_key_name("key_1")
        .has_next_transaction_nonce("42");
}

#[test]
fn should_display_block_sync() {
    let dashboard = DashboardTemplate {
        last_observed_block: None,
        last_synced_block: BlockNumber::from(4552270_u32),
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(dashboard)
        .has_no_elements_matching("#last-observed-block-number")
        .has_last_synced_block_href("https://sepolia.etherscan.io/block/4552270");

    let dashboard = DashboardTemplate {
        last_observed_block: Some(BlockNumber::from(4552271_u32)),
        last_synced_block: BlockNumber::from(4552270_u32),
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(dashboard)
        .has_last_observed_block_href("https://sepolia.etherscan.io/block/4552271")
        .has_last_synced_block_href("https://sepolia.etherscan.io/block/4552270");
}

#[test]
fn should_display_events_to_mint_sorted_by_decreasing_block_number() {
    DashboardAssert::assert_that(initial_dashboard()).has_no_elements_matching("#events-to-mint");

    let dashboard = {
        let mut state = initial_state();
        let event_1 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960623_u32),
            ..received_eth_event()
        };
        let event_2 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960624_u32),
            transaction_hash: "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796"
                .parse()
                .unwrap(),
            ..received_eth_event()
        };
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_1));
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_2));
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_events_to_mint(
            1,
            &vec![
                "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "3960624",
            ],
        )
        .has_events_to_mint(
            2,
            &vec![
                "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "3960623",
            ],
        );
}

#[test]
fn should_display_minted_events_sorted_by_decreasing_mint_block_index() {
    DashboardAssert::assert_that(initial_dashboard()).has_no_elements_matching("#minted-events");

    let dashboard = {
        let mut state = initial_state();
        let event_1 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960623_u32),
            ..received_eth_event()
        };
        let event_2 = ReceivedEthEvent {
            block_number: BlockNumber::from(3960624_u32),
            transaction_hash: "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796"
                .parse()
                .unwrap(),
            ..received_eth_event()
        };
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_1.clone()));
        apply_state_transition(&mut state, &EventType::AcceptedDeposit(event_2.clone()));
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: event_1.source(),
                mint_block_index: LedgerMintIndex::new(42),
            },
        );
        apply_state_transition(
            &mut state,
            &EventType::MintedCkEth {
                event_source: event_2.source(),
                mint_block_index: LedgerMintIndex::new(43),
            },
        );
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_minted_events(
            1,
            &vec![
                "0x5e5a5954e0a6fe5e61067330ea6f1398425a5e01a1dc1ef895b5dde00994e796",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "43",
            ],
        )
        .has_minted_events(
            2,
            &vec![
                "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2",
                "29",
                "0xdd2851Cdd40aE6536831558DD46db62fAc7A844d",
                "10_000_000_000_000_000",
                "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
                "42",
            ],
        );
}

#[test]
fn should_display_rejected_deposits() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#rejected-deposits");

    let dashboard = {
        let mut state = initial_state();
        let event_source_1 = EventSource {
            transaction_hash: "0x05c6ec45699c9a6a4b1a4ea2058b0cee852ea2f19b18fb8313c04bf8156efde4"
                .parse()
                .unwrap(),
            log_index: LogIndex::from(11_u8),
        };
        let event_source_2 = EventSource {
            transaction_hash: "0x09a5ee10c942f99b79cabcfb9647fc06e79489c6a8e96d39faed4f3ac6bc83d3"
                .parse()
                .unwrap(),
            log_index: LogIndex::from(0_u8),
        };
        apply_state_transition(
            &mut state,
            &EventType::InvalidDeposit {
                event_source: event_source_1,
                reason: "failed to decode principal".to_string(),
            },
        );
        apply_state_transition(
            &mut state,
            &EventType::InvalidDeposit {
                event_source: event_source_2,
                reason: "failed to decode principal".to_string(),
            },
        );
        DashboardTemplate::from_state(&state)
    };

    DashboardAssert::assert_that(dashboard)
        .has_rejected_deposits(
            1,
            &vec![
                "0x05c6ec45699c9a6a4b1a4ea2058b0cee852ea2f19b18fb8313c04bf8156efde4",
                "11",
                "failed to decode principal",
            ],
        )
        .has_rejected_deposits(
            2,
            &vec![
                "0x09a5ee10c942f99b79cabcfb9647fc06e79489c6a8e96d39faed4f3ac6bc83d3",
                "0",
                "failed to decode principal",
            ],
        );
}

#[test]
fn should_display_etherscan_links_according_to_chosen_network() {
    let sepolia_dashboard = DashboardTemplate {
        ethereum_network: EthereumNetwork::Sepolia,
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(sepolia_dashboard).has_links_satisfying(
        |link| link.contains("etherscan.io/"),
        |link| link.starts_with("https://sepolia.etherscan.io"),
    );

    let mainnet_dashboard = DashboardTemplate {
        ethereum_network: EthereumNetwork::Mainnet,
        ..initial_dashboard()
    };
    DashboardAssert::assert_that(mainnet_dashboard).has_links_satisfying(
        |link| link.contains("etherscan.io/"),
        |link| link.starts_with("https://etherscan.io"),
    );
}

fn initial_dashboard() -> DashboardTemplate {
    DashboardTemplate::from_state(&initial_state())
}

fn initial_state() -> State {
    use ic_cketh_minter::lifecycle::init::InitArg;
    use ic_cketh_minter::numeric::Wei;
    State::try_from(InitArg {
        ethereum_network: Default::default(),
        ecdsa_key_name: "test_key_1".to_string(),
        ethereum_contract_address: None,
        ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
            .expect("BUG: invalid principal"),
        ethereum_block_height: Default::default(),
        minimum_withdrawal_amount: Wei::TWO.into(),
        next_transaction_nonce: TransactionNonce::ZERO.into(),
    })
    .expect("valid init args")
}

fn received_eth_event() -> ReceivedEthEvent {
    use ic_cketh_minter::numeric::Wei;
    ReceivedEthEvent {
        transaction_hash: "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2"
            .parse()
            .unwrap(),
        block_number: BlockNumber::new(3960623u128),
        log_index: LogIndex::from(29u8),
        from_address: "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
            .parse()
            .unwrap(),
        value: Wei::from(10_000_000_000_000_000_u128),
        principal: "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
            .parse()
            .unwrap(),
    }
}

mod assertions {
    use crate::dashboard::DashboardTemplate;
    use askama::Template;
    use scraper::Html;
    use scraper::Selector;

    pub struct DashboardAssert {
        rendered_html: String,
        actual: Html,
    }

    impl DashboardAssert {
        pub fn assert_that(actual: DashboardTemplate) -> Self {
            let rendered_html = actual.render().unwrap();
            Self {
                actual: Html::parse_document(&rendered_html),
                rendered_html,
            }
        }

        pub fn has_no_elements_matching(&self, selector: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            assert!(
                self.actual.select(&selector).next().is_none(),
                "expected no elements matching '{:?}', but found some",
                selector
            );
            self
        }

        pub fn has_last_observed_block_href(&self, expected_href: &str) -> &Self {
            self.has_href_value(
                "#last-observed-block-number > td > a",
                expected_href,
                "wrong last observed block href",
            )
        }

        pub fn has_last_synced_block_href(&self, expected_href: &str) -> &Self {
            self.has_href_value(
                "#last-synced-block-number > td > a",
                expected_href,
                "wrong last synced block href",
            )
        }

        pub fn has_links_satisfying<F: Fn(&str) -> bool, P: Fn(&str) -> bool>(
            &self,
            filter: F,
            predicate: P,
        ) -> &Self {
            let selector = Selector::parse("a").unwrap();
            for link in self.actual.select(&selector) {
                let href = link.value().attr("href").expect("href not found");
                if filter(href) {
                    assert!(
                        predicate(href),
                        "Link '{}' does not satisfy predicate",
                        href
                    );
                }
            }
            self
        }

        pub fn has_ethereum_network(&self, expected_network: &str) -> &Self {
            self.has_string_value(
                "#ethereum-network > td > a",
                expected_network,
                "wrong ethereum network",
            )
        }

        pub fn has_minter_address(&self, expected_address: &str) -> &Self {
            self.has_string_value(
                "#minter-address > td",
                expected_address,
                "wrong minter address",
            )
        }

        pub fn has_contract_address(&self, expected_address: &str) -> &Self {
            self.has_string_value(
                "#contract-address > td",
                expected_address,
                "wrong contract address",
            )
        }

        pub fn has_ledger_canister_id(&self, expected_id: &str) -> &Self {
            self.has_string_value(
                "#ledger-canister-id > td",
                expected_id,
                "wrong ledger canister ID",
            )
        }

        pub fn has_tecdsa_key_name(&self, expected_name: &str) -> &Self {
            self.has_string_value(
                "#tecdsa-key-name > td",
                expected_name,
                "wrong tECDSA key name",
            )
        }

        pub fn has_next_transaction_nonce(&self, expected_value: &str) -> &Self {
            self.has_string_value(
                "#next-transaction-nonce > td",
                expected_value,
                "wrong next transaction nonce",
            )
        }

        pub fn has_events_to_mint(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#events-to-mint + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "events-to-mint",
            )
        }

        pub fn has_minted_events(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#minted-events + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "events-to-mint",
            )
        }

        pub fn has_rejected_deposits(&self, row_index: u8, expected_value: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#rejected-deposits + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "rejected-deposits",
            )
        }

        fn has_table_row_string_value(
            &self,
            selector: &str,
            expected_value: &Vec<&str>,
            error_msg: &str,
        ) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_value = only_one(&mut self.actual.select(&selector));
            let string_value = actual_value
                .text()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(
                &string_value, expected_value,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }

        fn has_string_value(&self, selector: &str, expected_value: &str, error_msg: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_value = only_one(&mut self.actual.select(&selector));
            let string_value = actual_value.text().collect::<String>();
            assert_eq!(
                string_value, expected_value,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }

        fn has_href_value(&self, selector: &str, expected_href: &str, error_msg: &str) -> &Self {
            let selector = Selector::parse(selector).unwrap();
            let actual_href = only_one(&mut self.actual.select(&selector))
                .value()
                .attr("href")
                .expect("href not found");
            assert_eq!(
                actual_href, expected_href,
                "{}. Rendered html: {}",
                error_msg, self.rendered_html
            );
            self
        }
    }

    fn only_one<I, T>(iter: &mut I) -> T
    where
        I: Iterator<Item = T>,
    {
        let value = iter.next().expect("expected one element, got zero");
        assert!(iter.next().is_none(), "expected one element, got more");
        value
    }
}
