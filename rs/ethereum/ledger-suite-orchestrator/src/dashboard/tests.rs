use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::DashboardTemplate;
use candid::Principal;
use fixtures::{usdc, usdt, USDC_ADDRESS, USDT_ADDRESS};
use ic_ledger_suite_orchestrator::candid::InitArg;
use ic_ledger_suite_orchestrator::state::{Index, Ledger, State, WasmHash};
use std::str::FromStr;

#[test]
fn should_display_managed_canisters() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#managed-canisters");

    const USDC_LEDGER_ID: &str = "apia6-jaaaa-aaaar-qabma-cai";
    const USDC_INDEX_ID: &str = "s3zol-vqaaa-aaaar-qacpa-cai";
    const USDT_LEDGER_ID: &str = "mxzaz-hqaaa-aaaar-qaada-cai";
    const USDT_INDEX_ID: &str = "n5wcd-faaaa-aaaar-qaaea-cai";
    const LEDGER_WASM_HASH: &str =
        "3148f7a9f1b0ee39262c8abe3b08813480cf78551eee5a60ab1cf38433b5d9b0";
    const INDEX_WASM_HASH: &str =
        "3a6d39b5e94cdef5203bca62720e75a28cd071ff434d22b9746403ac7ae59614";

    let mut state = initial_state();
    state.record_created_canister::<Ledger>(&usdc(), Principal::from_str(USDC_LEDGER_ID).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state).has_managed_canister(
        1,
        USDC_ADDRESS,
        1,
        &vec![USDC_LEDGER_ID, "Ledger", "not installed"],
    );

    state.record_installed_canister::<Ledger>(
        &usdc(),
        WasmHash::from_str(LEDGER_WASM_HASH).unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state).has_managed_canister(
        1,
        USDC_ADDRESS,
        1,
        &vec![USDC_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
    );

    state.record_created_canister::<Index>(&usdc(), Principal::from_str(USDC_INDEX_ID).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            1,
            &vec![USDC_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            2,
            &vec![USDC_INDEX_ID, "Index", "not installed"],
        );

    state.record_installed_canister::<Index>(&usdc(), WasmHash::from_str(INDEX_WASM_HASH).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            1,
            &vec![USDC_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            2,
            &vec![USDC_INDEX_ID, "Index", INDEX_WASM_HASH],
        );

    state.record_created_canister::<Ledger>(&usdt(), Principal::from_str(USDT_LEDGER_ID).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            1,
            &vec![USDC_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            2,
            &vec![USDC_INDEX_ID, "Index", INDEX_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDT_ADDRESS,
            1,
            &vec![USDT_LEDGER_ID, "Ledger", "not installed"],
        );

    state.record_installed_canister::<Ledger>(
        &usdt(),
        WasmHash::from_str(LEDGER_WASM_HASH).unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            1,
            &vec![USDC_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            2,
            &vec![USDC_INDEX_ID, "Index", INDEX_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDT_ADDRESS,
            1,
            &vec![USDT_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        );

    state.record_created_canister::<Index>(&usdt(), Principal::from_str(USDT_INDEX_ID).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            1,
            &vec![USDC_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            2,
            &vec![USDC_INDEX_ID, "Index", INDEX_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDT_ADDRESS,
            1,
            &vec![USDT_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDT_ADDRESS,
            2,
            &vec![USDT_INDEX_ID, "Index", "not installed"],
        );

    state.record_installed_canister::<Index>(&usdt(), WasmHash::from_str(INDEX_WASM_HASH).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            1,
            &vec![USDC_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDC_ADDRESS,
            2,
            &vec![USDC_INDEX_ID, "Index", INDEX_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDT_ADDRESS,
            1,
            &vec![USDT_LEDGER_ID, "Ledger", LEDGER_WASM_HASH],
        )
        .has_managed_canister(
            1,
            USDT_ADDRESS,
            2,
            &vec![USDT_INDEX_ID, "Index", INDEX_WASM_HASH],
        );
}

#[test]
fn should_display_etherscan_links_according_to_chain_id() {
    let mut state = initial_state();
    state.record_created_canister::<Ledger>(
        &usdc(),
        Principal::from_str("apia6-jaaaa-aaaar-qabma-cai").unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state).has_links_satisfying(
        |link| link.contains("etherscan.io/"),
        |link| link.starts_with("https://etherscan.io"),
    );

    let mut state = initial_state();
    state.record_created_canister::<Ledger>(
        &ic_ledger_suite_orchestrator::candid::Erc20Contract {
            chain_id: 11155111_u64.into(),
            address: "0x7439E9Bb6D8a84dd3A23fe621A30F95403F87fB9".to_string(),
        }
        .try_into()
        .unwrap(),
        Principal::from_str("apia6-jaaaa-aaaar-qabma-cai").unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state).has_links_satisfying(
        |link| link.contains("etherscan.io/"),
        |link| link.starts_with("https://sepolia.etherscan.io"),
    );

    let mut state = initial_state();
    state.record_created_canister::<Ledger>(
        &ic_ledger_suite_orchestrator::candid::Erc20Contract {
            chain_id: 5_u8.into(),
            address: "0x7439E9Bb6D8a84dd3A23fe621A30F95403F87fB9".to_string(),
        }
        .try_into()
        .unwrap(),
        Principal::from_str("apia6-jaaaa-aaaar-qabma-cai").unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state).has_no_elements_matching("a");
}

fn initial_dashboard() -> DashboardTemplate {
    DashboardTemplate::from_state(&initial_state())
}

fn initial_state() -> State {
    State::from(InitArg {})
}
mod assertions {
    use crate::dashboard::DashboardTemplate;
    use ic_ledger_suite_orchestrator::state::State;
    use scraper::{Html, Selector};

    pub struct DashboardAssert {
        rendered_html: String,
        actual: Html,
    }

    impl DashboardAssert {
        pub fn assert_that_dashboard_from_state(state: &State) -> Self {
            Self::assert_that(DashboardTemplate::from_state(state))
        }

        pub fn assert_that(actual: DashboardTemplate) -> Self {
            use crate::dashboard::Template;
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
                "expected no elements matching '{:?}', but found some. Rendered html: {}",
                selector,
                self.rendered_html
            );
            self
        }

        pub fn has_managed_canister(
            &self,
            chain_id: u64,
            erc20_address: &str,
            row_index: u8,
            expected_value: &Vec<&str>,
        ) -> &Self {
            self.has_table_row_string_value(
                &format!("#managed-canisters-{chain_id}-{erc20_address} + table > tbody > tr:nth-child({row_index})"),
                expected_value,
                "managed-canisters",
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

mod fixtures {
    use ic_ledger_suite_orchestrator::scheduler::Erc20Contract;

    pub const USDC_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    pub const USDT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    pub fn usdc() -> Erc20Contract {
        ic_ledger_suite_orchestrator::candid::Erc20Contract {
            chain_id: 1_u8.into(),
            address: USDC_ADDRESS.to_string(),
        }
        .try_into()
        .unwrap()
    }

    pub fn usdt() -> Erc20Contract {
        ic_ledger_suite_orchestrator::candid::Erc20Contract {
            chain_id: 1_u8.into(),
            address: USDT_ADDRESS.to_string(),
        }
        .try_into()
        .unwrap()
    }
}
