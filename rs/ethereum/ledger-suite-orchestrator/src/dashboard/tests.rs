use crate::dashboard::tests::assertions::DashboardAssert;
use crate::dashboard::tests::fixtures::{usdc_metadata, usdc_token_id, usdt_token_id};
use crate::dashboard::DashboardTemplate;
use candid::Principal;
use fixtures::{usdc, usdt, USDC_ADDRESS, USDT_ADDRESS};
use ic_ledger_suite_orchestrator::candid::InitArg;
use ic_ledger_suite_orchestrator::scheduler::Erc20Token;
use ic_ledger_suite_orchestrator::state::{
    ArchiveWasm, CanistersMetadata, GitCommitHash, Index, IndexWasm, Ledger, LedgerWasm, State,
    WasmHash,
};
use ic_ledger_suite_orchestrator::storage::{wasm_store_try_insert, WasmStore};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};
use ic_stable_structures::DefaultMemoryImpl;
use std::str::FromStr;

#[test]
fn should_display_managed_canisters() {
    DashboardAssert::assert_that(initial_dashboard())
        .has_no_elements_matching("#managed-canisters")
        .has_no_elements_matching("#wasm-store");

    const USDC_LEDGER_ID: &str = "apia6-jaaaa-aaaar-qabma-cai";
    const USDC_INDEX_ID: &str = "s3zol-vqaaa-aaaar-qacpa-cai";
    const USDC_ARCHIVE_ID: &str = "t4dy3-uiaaa-aaaar-qafua-cai";
    const USDT_LEDGER_ID: &str = "mxzaz-hqaaa-aaaar-qaada-cai";
    const USDT_INDEX_ID: &str = "n5wcd-faaaa-aaaar-qaaea-cai";
    const USDT_ARCHIVE_ID: &str = "xrs4b-hiaaa-aaaar-qafoa-cai";
    const LEDGER_WASM_HASH: &str =
        "3148f7a9f1b0ee39262c8abe3b08813480cf78551eee5a60ab1cf38433b5d9b0";
    const INDEX_WASM_HASH: &str =
        "3a6d39b5e94cdef5203bca62720e75a28cd071ff434d22b9746403ac7ae59614";

    let mut state = initial_state();
    state.record_new_erc20_token(
        usdc(),
        CanistersMetadata {
            token_symbol: "ckUSDC".to_string(),
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
            token_symbol: "ckUSDT".to_string(),
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

    state.record_archives(
        &usdc_token_id(),
        vec![Principal::from_str(USDC_ARCHIVE_ID).unwrap()],
    );
    state.record_archives(
        &usdt_token_id(),
        vec![Principal::from_str(USDT_ARCHIVE_ID).unwrap()],
    );
    DashboardAssert::assert_that_dashboard_from_state(&state)
        .has_erc20("ckUSDC", 1, USDC_ADDRESS)
        .has_ledger(USDC_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDC_INDEX_ID, INDEX_WASM_HASH)
        .has_archive(USDC_ARCHIVE_ID)
        .has_erc20("ckUSDT", 1, USDT_ADDRESS)
        .has_ledger(USDT_LEDGER_ID, LEDGER_WASM_HASH)
        .has_index(USDT_INDEX_ID, INDEX_WASM_HASH)
        .has_archive(USDT_ARCHIVE_ID);
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

#[test]
fn should_display_stored_wasms() {
    let mut store = empty_wasm_store();
    let git_commit_hash: GitCommitHash =
        "3f9cf5e990a99c3b27af97b3bfbc8a0ace776cab".parse().unwrap();
    let ledger_wasm = LedgerWasm::new("ledger".as_bytes().to_vec());
    let index_wasm = IndexWasm::new("index".as_bytes().to_vec());
    let archive_wasm = ArchiveWasm::new("archive".as_bytes().to_vec());

    wasm_store_try_insert(&mut store, 0, git_commit_hash.clone(), ledger_wasm).unwrap();
    wasm_store_try_insert(&mut store, 0, git_commit_hash.clone(), index_wasm).unwrap();
    wasm_store_try_insert(&mut store, 0, git_commit_hash, archive_wasm).unwrap();

    DashboardAssert::assert_that_dashboard_from_wasm_store(&store)
        .has_stored_wasm(
            1,
            &vec![
                "1970-01-01T00:00:00+00:00",
                "Ledger",
                "3f9cf5e990a99c3b27af97b3bfbc8a0ace776cab",
                "fe14010b4fe83303852f0467c919ef9a7ca089b91e96e3aad7d426dd87079297",
            ],
        )
        .has_stored_wasm(
            2,
            &vec![
                "1970-01-01T00:00:00+00:00",
                "Index",
                "3f9cf5e990a99c3b27af97b3bfbc8a0ace776cab",
                "1bc04b5291c26a46d918139138b992d2de976d6851d0893b0476b85bfbdfc6e6",
            ],
        )
        .has_stored_wasm(
            3,
            &vec![
                "1970-01-01T00:00:00+00:00",
                "Archive",
                "3f9cf5e990a99c3b27af97b3bfbc8a0ace776cab",
                "0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3",
            ],
        );
}

fn initial_dashboard() -> DashboardTemplate {
    DashboardTemplate::from_state(&initial_state(), &empty_wasm_store())
}

fn initial_state() -> State {
    State::try_from(InitArg {
        more_controller_ids: vec![],
        minter_id: None,
        cycles_management: None,
    })
    .unwrap()
}

pub fn empty_wasm_store() -> WasmStore {
    WasmStore::init(MemoryManager::init(DefaultMemoryImpl::default()).get(MemoryId::new(0)))
}

mod assertions {
    use crate::dashboard::tests::{empty_wasm_store, initial_state};
    use crate::dashboard::DashboardTemplate;
    use ic_ledger_suite_orchestrator::state::State;
    use ic_ledger_suite_orchestrator::storage::WasmStore;
    use scraper::{Html, Selector};

    pub struct DashboardAssert {
        rendered_html: String,
        actual: Html,
    }

    impl DashboardAssert {
        pub fn assert_that_dashboard_from_state(state: &State) -> Self {
            Self::assert_that(DashboardTemplate::from_state(state, &empty_wasm_store()))
        }

        pub fn assert_that_dashboard_from_wasm_store(wasm_store: &WasmStore) -> Self {
            Self::assert_that(DashboardTemplate::from_state(&initial_state(), wasm_store))
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

        pub fn has_stored_wasm(&self, row_index: u8, expected_wasm: &Vec<&str>) -> &Self {
            self.has_table_row_string_value(
                &format!("#wasm-store + table > tbody > tr:nth-child({row_index})"),
                expected_wasm,
                "wrong stored wasm",
            )
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

        pub fn has_archive(self, expected_canister_id: &str) -> Self {
            self.has_erc20_table_row_string_value("Archive", expected_canister_id, "N/A")
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
    use ic_ledger_suite_orchestrator::state::{CanistersMetadata, TokenId};

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
            token_symbol: "ckUSDC".to_string(),
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

    pub fn usdc_token_id() -> TokenId {
        TokenId::from(usdc())
    }

    pub fn usdt_token_id() -> TokenId {
        TokenId::from(usdt())
    }
}
