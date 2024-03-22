use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::tests::fixtures::usdc_metadata;
use crate::dashboard::DashboardTemplate;
use candid::Principal;
use fixtures::{usdc, usdt, USDC_ADDRESS, USDT_ADDRESS};
use ic_ledger_suite_orchestrator::candid::InitArg;
use ic_ledger_suite_orchestrator::scheduler::Erc20Token;
use ic_ledger_suite_orchestrator::state::{CanistersMetadata, Index, Ledger, State, WasmHash};
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
    state.record_new_erc20_token(
        usdc(),
        CanistersMetadata {
            ckerc20_token_symbol: "ckUSDC".to_string(),
        },
    );
    state.record_created_canister::<Ledger>(&usdc(), Principal::from_str(USDC_LEDGER_ID).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, "not installed");

    state.record_installed_canister::<Ledger>(
        &usdc(),
        WasmHash::from_str(LEDGER_WASM_HASH).unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, LEDGER_WASM_HASH);

    state.record_created_canister::<Index>(&usdc(), Principal::from_str(USDC_INDEX_ID).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDC_INDEX_ID, "not installed");

    state.record_installed_canister::<Index>(&usdc(), WasmHash::from_str(INDEX_WASM_HASH).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDC_INDEX_ID, INDEX_WASM_HASH);

    state.record_new_erc20_token(
        usdt(),
        CanistersMetadata {
            ckerc20_token_symbol: "ckUSDT".to_string(),
        },
    );
    state.record_created_canister::<Ledger>(&usdt(), Principal::from_str(USDT_LEDGER_ID).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDC_INDEX_ID, INDEX_WASM_HASH)
        .has_erc20("ckUSDT", 1, USDT_ADDRESS)
        .has_ledger(USDT_LEDGER_ID, "not installed");

    state.record_installed_canister::<Ledger>(
        &usdt(),
        WasmHash::from_str(LEDGER_WASM_HASH).unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDC_INDEX_ID, INDEX_WASM_HASH)
        .has_erc20("ckUSDT", 1, USDT_ADDRESS)
        .has_ledger(USDT_LEDGER_ID, LEDGER_WASM_HASH);

    state.record_created_canister::<Index>(&usdt(), Principal::from_str(USDT_INDEX_ID).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDC_INDEX_ID, INDEX_WASM_HASH)
        .has_erc20("ckUSDT", 1, USDT_ADDRESS)
        .has_ledger(USDT_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDT_INDEX_ID, "not installed");

    state.record_installed_canister::<Index>(&usdt(), WasmHash::from_str(INDEX_WASM_HASH).unwrap());
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDC_INDEX_ID, INDEX_WASM_HASH)
        .has_erc20("ckUSDT", 1, USDT_ADDRESS)
        .has_ledger(USDT_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDT_INDEX_ID, INDEX_WASM_HASH);
}

#[test]
fn should_display_etherscan_links_according_to_chain_id() {
    let mut state = initial_state();
    state.record_new_erc20_token(usdc(), usdc_metadata());
    state.record_created_canister::<Ledger>(
        &usdc(),
        Principal::from_str("apia6-jaaaa-aaaar-qabma-cai").unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state).has_links_satisfying(
        |link| link.contains("etherscan.io/"),
        |link| link.starts_with("https://etherscan.io"),
    );

    let mut state = initial_state();
    let erc20: Erc20Token = ic_ledger_suite_orchestrator::candid::Erc20Contract {
        chain_id: 11155111_u64.into(),
        address: "0x7439E9Bb6D8a84dd3A23fe621A30F95403F87fB9".to_string(),
    }
    .try_into()
    .unwrap();
    state.record_new_erc20_token(erc20.clone(), usdc_metadata());
    state.record_created_canister::<Ledger>(
        &erc20,
        Principal::from_str("apia6-jaaaa-aaaar-qabma-cai").unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state).has_links_satisfying(
        |link| link.contains("etherscan.io/"),
        |link| link.starts_with("https://sepolia.etherscan.io"),
    );

    let mut state = initial_state();
    let erc20: Erc20Token = ic_ledger_suite_orchestrator::candid::Erc20Contract {
        chain_id: 5_u8.into(),
        address: "0x7439E9Bb6D8a84dd3A23fe621A30F95403F87fB9".to_string(),
    }
    .try_into()
    .unwrap();
    state.record_new_erc20_token(erc20.clone(), usdc_metadata());
    state.record_created_canister::<Ledger>(
        &erc20,
        Principal::from_str("apia6-jaaaa-aaaar-qabma-cai").unwrap(),
    );
    DashboardAssert::assert_that_dashboard_from_state(&state).has_no_elements_matching("a");
}

fn initial_dashboard() -> DashboardTemplate {
    DashboardTemplate::from_state(&initial_state())
}

fn initial_state() -> State {
    State::try_from(InitArg {
        more_controller_ids: vec![],
        minter_id: None,
        cycles_management: None,
    })
    .unwrap()
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

        pub fn has_erc20(
            self,
            ckerc20_token_symbol: &str,
            chain_id: u64,
            erc20_address: &str,
        ) -> DashboardErc20Assert {
            self.has_string_value(
                &format!("#managed-canisters-{chain_id}-{erc20_address}"),
                &format!("{ckerc20_token_symbol}({erc20_address})"),
                "wrong erc20 token",
            );
            DashboardErc20Assert {
                assert: self,
                chain_id,
                erc20_address: erc20_address.to_string(),
            }
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

    pub struct DashboardErc20Assert {
        assert: DashboardAssert,
        chain_id: u64,
        erc20_address: String,
    }

    impl DashboardErc20Assert {
        pub fn has_erc20(
            self,
            ckerc20_token_symbol: &str,
            chain_id: u64,
            erc20_address: &str,
        ) -> DashboardErc20Assert {
            self.assert
                .has_erc20(ckerc20_token_symbol, chain_id, erc20_address)
        }

        pub fn has_ledger(self, expected_canister_id: &str, expected_version: &str) -> Self {
            self.has_erc20_table_row_string_value("Ledger", expected_canister_id, expected_version)
        }

        pub fn has_index(self, expected_canister_id: &str, expected_version: &str) -> Self {
            self.has_erc20_table_row_string_value("Index", expected_canister_id, expected_version)
        }

        fn has_erc20_table_row_string_value(
            self,
            canister_type: &str,
            expected_canister_id: &str,
            expected_version: &str,
        ) -> Self {
            let row_selector = Selector::parse(&format!(
                "#managed-canisters-{}-{} + table > tbody > tr",
                self.chain_id, self.erc20_address
            ))
            .unwrap();
            let cell_selector = Selector::parse("td").unwrap();
            for row in self.assert.actual.select(&row_selector) {
                let cells: Vec<_> = row
                    .select(&cell_selector)
                    .map(|c| c.text().collect::<String>())
                    .collect();
                assert_eq!(
                    cells.len(),
                    3,
                    "expected 3 cells in a row of an ERC-20 table, but got {:?}. Rendered html: {}",
                    cells,
                    self.assert.rendered_html
                );
                if cells[1] == canister_type {
                    assert_eq!(
                        cells[0], expected_canister_id,
                        "Unexpected canister ID. Rendered html: {}",
                        self.assert.rendered_html
                    );
                    assert_eq!(
                        cells[2], expected_version,
                        "Unexpected version. Rendered html: {}",
                        self.assert.rendered_html
                    );
                    return self;
                }
            }
            panic!(
                "BUG: row matching canister type {} not found!",
                canister_type
            );
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
    use ic_ledger_suite_orchestrator::scheduler::Erc20Token;
    use ic_ledger_suite_orchestrator::state::CanistersMetadata;

    pub const USDC_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    pub const USDT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

    pub fn usdc() -> Erc20Token {
        ic_ledger_suite_orchestrator::candid::Erc20Contract {
            chain_id: 1_u8.into(),
            address: USDC_ADDRESS.to_string(),
        }
        .try_into()
        .unwrap()
    }

    pub fn usdc_metadata() -> CanistersMetadata {
        CanistersMetadata {
            ckerc20_token_symbol: "ckUSDC".to_string(),
        }
    }

    pub fn usdt() -> Erc20Token {
        ic_ledger_suite_orchestrator::candid::Erc20Contract {
            chain_id: 1_u8.into(),
            address: USDT_ADDRESS.to_string(),
        }
        .try_into()
        .unwrap()
    }
}
