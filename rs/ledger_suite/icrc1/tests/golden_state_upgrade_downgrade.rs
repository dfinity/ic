use crate::common::{ledger_wasm, load_wasm_using_env_var};
use candid::Encode;
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger_sm_tests::in_memory_ledger::{
    ApprovalKey, BurnsWithoutSpender, InMemoryLedger,
};
use ic_icrc1_ledger_sm_tests::{
    generate_transactions, get_all_ledger_and_archive_blocks, TransactionGenerationParameters,
};
use ic_nns_test_utils::governance::bump_gzip_timestamp;
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_fiduciary_state_or_panic;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use std::str::FromStr;

mod common;

const NUM_TRANSACTIONS_PER_TYPE: usize = 20;
const MINT_MULTIPLIER: u64 = 10_000;
const TRANSFER_MULTIPLIER: u64 = 1000;
const APPROVE_MULTIPLIER: u64 = 100;
const TRANSFER_FROM_MULTIPLIER: u64 = 10;
const BURN_MULTIPLIER: u64 = 1;

#[cfg(not(feature = "u256-tokens"))]
type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
type Tokens = ic_icrc1_tokens_u256::U256;

#[cfg(not(feature = "u256-tokens"))]
lazy_static! {
    pub static ref MAINNET_WASM: Wasm = Wasm::from_bytes(load_wasm_using_env_var(
        "CKBTC_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));
    pub static ref MASTER_WASM: Wasm = Wasm::from_bytes(ledger_wasm());
}

#[cfg(feature = "u256-tokens")]
lazy_static! {
    pub static ref MAINNET_U256_WASM: Wasm = Wasm::from_bytes(load_wasm_using_env_var(
        "CKETH_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));
    pub static ref MAINNET_U64_WASM: Wasm = Wasm::from_bytes(load_wasm_using_env_var(
        "IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));
    pub static ref MASTER_WASM: Wasm = Wasm::from_bytes(ledger_wasm());
}

struct LedgerSuiteConfig {
    ledger_id: &'static str,
    canister_name: &'static str,
    burns_without_spender: Option<BurnsWithoutSpender<Account>>,
    extended_testing: bool,
    mainnet_wasm: &'static Wasm,
    master_wasm: &'static Wasm,
}

impl LedgerSuiteConfig {
    fn new(
        canister_id_and_name: (&'static str, &'static str),
        mainnet_wasm: &'static Wasm,
        master_wasm: &'static Wasm,
    ) -> Self {
        let (canister_id, canister_name) = canister_id_and_name;
        Self {
            ledger_id: canister_id,
            canister_name,
            burns_without_spender: None,
            extended_testing: false,
            mainnet_wasm,
            master_wasm,
        }
    }

    fn new_with_params(
        canister_id_and_name: (&'static str, &'static str),
        mainnet_wasm: &'static Wasm,
        master_wasm: &'static Wasm,
        burns_without_spender: Option<BurnsWithoutSpender<Account>>,
        extended_testing: bool,
    ) -> Self {
        Self {
            burns_without_spender,
            extended_testing,
            ..Self::new(canister_id_and_name, mainnet_wasm, master_wasm)
        }
    }

    fn perform_upgrade_downgrade_testing(&self, state_machine: &StateMachine) {
        println!(
            "Processing {} ledger, id {}",
            self.ledger_id, self.canister_name
        );
        let ledger_canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.ledger_id).unwrap());
        let mut previous_ledger_state = None;
        if self.extended_testing {
            previous_ledger_state = Some(LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_canister_id,
                self.burns_without_spender.clone(),
                None,
            ));
        }
        self.upgrade_canister(state_machine, self.master_wasm.clone());
        // Upgrade again with bumped wasm timestamp to test pre_upgrade
        self.upgrade_canister(state_machine, bump_gzip_timestamp(self.master_wasm));
        if self.extended_testing {
            previous_ledger_state = Some(LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_canister_id,
                self.burns_without_spender.clone(),
                previous_ledger_state,
            ));
        }
        // Downgrade back to the mainnet ledger version
        self.upgrade_canister(state_machine, self.mainnet_wasm.clone());
        if self.extended_testing {
            let _ = LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_canister_id,
                self.burns_without_spender.clone(),
                previous_ledger_state,
            );
        }
    }

    fn upgrade_canister(&self, state_machine: &StateMachine, wasm: Wasm) {
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.ledger_id).unwrap());
        let args = ic_icrc1_ledger::LedgerArgument::Upgrade(None);
        let args = Encode!(&args).unwrap();
        state_machine
            .upgrade_canister(canister_id, wasm.bytes(), args)
            .expect("should successfully upgrade ledger canister");
        println!("Upgraded {} '{}'", self.canister_name, self.ledger_id);
    }
}

struct LedgerState {
    in_memory_ledger: InMemoryLedger<ApprovalKey, Account, Tokens>,
    num_blocks: u64,
}

impl LedgerState {
    fn assert_eq(&self, other: &Self) {
        assert_eq!(
            other.num_blocks, self.num_blocks,
            "Number of blocks ({}) does not match number of blocks in previous state ({})",
            self.num_blocks, other.num_blocks,
        );
        assert!(
            other.in_memory_ledger == self.in_memory_ledger,
            "In-memory ledger state does not match previous state"
        );
    }

    /// Fetch the next blocks from the ledger canister and ingest them into the in-memory ledger.
    /// If `total_num_blocks` is `None`, fetch all blocks from the ledger canister, otherwise fetch
    /// `total_num_blocks - self.num_blocks` blocks (some amount of latest blocks that the in-memory
    /// ledger does not hold yet).
    fn fetch_next_blocks(
        &mut self,
        state_machine: &StateMachine,
        canister_id: CanisterId,
        total_num_blocks: Option<u64>,
    ) {
        let num_blocks = total_num_blocks
            .unwrap_or(u64::MAX)
            .saturating_sub(self.num_blocks);
        let blocks = get_all_ledger_and_archive_blocks(
            state_machine,
            canister_id,
            Some(self.num_blocks),
            Some(num_blocks),
        );
        self.num_blocks = self
            .num_blocks
            .checked_add(blocks.len() as u64)
            .expect("number of blocks should fit in u64");
        self.in_memory_ledger.ingest_icrc1_ledger_blocks(&blocks);
    }

    fn new(burns_without_spender: Option<BurnsWithoutSpender<Account>>) -> Self {
        let in_memory_ledger = InMemoryLedger::new(burns_without_spender);
        Self {
            in_memory_ledger,
            num_blocks: 0,
        }
    }

    fn verify_balances_and_allowances(
        &self,
        state_machine: &StateMachine,
        canister_id: CanisterId,
    ) {
        self.in_memory_ledger
            .verify_balances_and_allowances(state_machine, canister_id);
    }

    /// Verify the ledger state and generate new transactions. In particular:
    /// - Create a new instance of an in-memory ledger by fetching blocks from the ledger
    ///   - If a previous ledger state is provided, only fetch the blocks that were present when
    ///     the previous state was generated.
    /// - Verify that the balances and allowances in the in-memory ledger match the ledger
    ///   canister state
    /// - If a previous ledger state is provided, assert that the state of the newly-generated
    ///   in-memory ledger state matches that of the previous state
    /// - Generate transactions on the ledger canister
    /// - Fetch all blocks from the ledger canister into the new `ledger_state`
    /// - Return the new `ledger_state`
    fn verify_state_and_generate_transactions(
        state_machine: &StateMachine,
        canister_id: CanisterId,
        burns_without_spender: Option<BurnsWithoutSpender<Account>>,
        previous_ledger_state: Option<LedgerState>,
    ) -> Self {
        let num_blocks_to_fetch = previous_ledger_state
            .as_ref()
            .map(|previous_ledger_state| previous_ledger_state.num_blocks);

        let mut ledger_state = LedgerState::new(burns_without_spender);
        // Only fetch the blocks that were present when the previous state was generated. This is
        // necessary since there may have been in-transit messages for the ledger in the backup,
        // or new transactions triggered e.g., by timers running in other canisters on the subnet,
        // that get applied after the `StateMachine` is initialized, and are not part of the
        // transactions in `generate_transactions`.
        ledger_state.fetch_next_blocks(state_machine, canister_id, num_blocks_to_fetch);
        ledger_state.verify_balances_and_allowances(state_machine, canister_id);
        // Verify the reconstructed ledger state matches the previous state
        if let Some(previous_ledger_state) = &previous_ledger_state {
            ledger_state.assert_eq(previous_ledger_state);
        }
        generate_transactions(
            state_machine,
            canister_id,
            TransactionGenerationParameters {
                mint_multiplier: MINT_MULTIPLIER,
                transfer_multiplier: TRANSFER_MULTIPLIER,
                approve_multiplier: APPROVE_MULTIPLIER,
                transfer_from_multiplier: TRANSFER_FROM_MULTIPLIER,
                burn_multiplier: BURN_MULTIPLIER,
                num_transactions_per_type: NUM_TRANSACTIONS_PER_TYPE,
            },
        );
        // Fetch all blocks into the new `ledger_state`. This call only retrieves blocks that were
        // not fetched in the previous call to `fetch_next_blocks`.
        ledger_state.fetch_next_blocks(state_machine, canister_id, None);
        ledger_state
    }
}

#[cfg(not(feature = "u256-tokens"))]
#[test]
fn should_upgrade_icrc_ck_btc_canister_with_golden_state() {
    const CK_BTC_LEDGER_CANISTER_ID: &str = "mxzaz-hqaaa-aaaar-qaada-cai";
    const CK_BTC_LEDGER_CANISTER_NAME: &str = "ckBTC";

    let ck_btc_minter = icrc_ledger_types::icrc1::account::Account {
        owner: PrincipalId::from_str("mqygn-kiaaa-aaaar-qaadq-cai")
            .unwrap()
            .0,
        subaccount: None,
    };
    let burns_without_spender = ic_icrc1_ledger_sm_tests::in_memory_ledger::BurnsWithoutSpender {
        minter: ck_btc_minter,
        burn_indexes: vec![
            100785, 101298, 104447, 116240, 454395, 455558, 458776, 460251,
        ],
    };

    let state_machine = new_state_machine_with_golden_fiduciary_state_or_panic();

    LedgerSuiteConfig::new_with_params(
        (CK_BTC_LEDGER_CANISTER_ID, CK_BTC_LEDGER_CANISTER_NAME),
        &MAINNET_WASM,
        &MASTER_WASM,
        Some(burns_without_spender),
        true,
    )
    .perform_upgrade_downgrade_testing(&state_machine);
}

#[cfg(feature = "u256-tokens")]
#[test]
fn should_upgrade_icrc_ck_u256_canisters_with_golden_state() {
    // u256 testnet ledgers
    const CK_SEPOLIA_LINK_LEDGER: (&str, &str) = ("r52mc-qaaaa-aaaar-qafzq-cai", "ckSepoliaLINK");
    const CK_SEPOLIA_PEPE_LEDGER: (&str, &str) = ("hw4ru-taaaa-aaaar-qagdq-cai", "ckSepoliaPEPE");
    const CK_SEPOLIA_USDC_LEDGER: (&str, &str) = ("yfumr-cyaaa-aaaar-qaela-cai", "ckSepoliaUSDC");
    // u256 production ledgers
    const CK_ETH_LEDGER: (&str, &str) = ("ss2fx-dyaaa-aaaar-qacoq-cai", "ckETH");
    const CK_EURC_LEDGER: (&str, &str) = ("pe5t5-diaaa-aaaar-qahwa-cai", "ckEURC");
    const CK_USDC_LEDGER: (&str, &str) = ("xevnm-gaaaa-aaaar-qafnq-cai", "ckUSDC");
    const CK_LINK_LEDGER: (&str, &str) = ("g4tto-rqaaa-aaaar-qageq-cai", "ckLINK");
    const CK_OCT_LEDGER: (&str, &str) = ("ebo5g-cyaaa-aaaar-qagla-cai", "ckOCT");
    const CK_PEPE_LEDGER: (&str, &str) = ("etik7-oiaaa-aaaar-qagia-cai", "ckPEPE");
    const CK_SHIB_LEDGER: (&str, &str) = ("fxffn-xiaaa-aaaar-qagoa-cai", "ckSHIB");
    const CK_UNI_LEDGER: (&str, &str) = ("ilzky-ayaaa-aaaar-qahha-cai", "ckUNI");
    const CK_USDT_LEDGER: (&str, &str) = ("cngnf-vqaaa-aaaar-qag4q-cai", "ckUSDT");
    const CK_WBTC_LEDGER: (&str, &str) = ("bptq2-faaaa-aaaar-qagxq-cai", "ckWBTC");
    const CK_WSTETH_LEDGER: (&str, &str) = ("j2tuh-yqaaa-aaaar-qahcq-cai", "ckWSTETH");
    const CK_XAUT_LEDGER: (&str, &str) = ("nza5v-qaaaa-aaaar-qahzq-cai", "ckXAUT");

    let ck_eth_minter = icrc_ledger_types::icrc1::account::Account {
        owner: PrincipalId::from_str("sv3dd-oaaaa-aaaar-qacoa-cai")
            .unwrap()
            .0,
        subaccount: None,
    };
    let ck_eth_burns_without_spender = BurnsWithoutSpender {
        minter: ck_eth_minter,
        burn_indexes: vec![
            1051, 1094, 1276, 1759, 1803, 1929, 2449, 2574, 2218, 2219, 2231, 1777, 4, 9, 31, 1540,
            1576, 1579, 1595, 1607, 1617, 1626, 1752, 1869, 1894, 2013, 2555,
        ],
    };

    let mut canister_configs = vec![LedgerSuiteConfig::new_with_params(
        CK_ETH_LEDGER,
        &MAINNET_U256_WASM,
        &MASTER_WASM,
        Some(ck_eth_burns_without_spender),
        true,
    )];
    for canister_id_and_name in vec![
        CK_SEPOLIA_LINK_LEDGER,
        CK_SEPOLIA_LINK_LEDGER,
        CK_SEPOLIA_PEPE_LEDGER,
        CK_SEPOLIA_USDC_LEDGER,
        CK_EURC_LEDGER,
        CK_USDC_LEDGER,
        CK_LINK_LEDGER,
        CK_OCT_LEDGER,
        CK_PEPE_LEDGER,
        CK_SHIB_LEDGER,
        CK_UNI_LEDGER,
        CK_USDT_LEDGER,
        CK_WBTC_LEDGER,
        CK_WSTETH_LEDGER,
        CK_XAUT_LEDGER,
    ] {
        canister_configs.push(LedgerSuiteConfig::new(
            canister_id_and_name,
            &MAINNET_U256_WASM,
            &MASTER_WASM,
        ));
    }

    let state_machine = new_state_machine_with_golden_fiduciary_state_or_panic();

    for canister_config in canister_configs {
        canister_config.perform_upgrade_downgrade_testing(&state_machine);
    }
}

#[cfg(feature = "u256-tokens")]
#[test]
fn should_upgrade_icrc_sns_canisters_with_golden_state() {
    // SNS canisters
    const BOOMDAO: (&str, &str) = ("vtrom-gqaaa-aaaaq-aabia-cai", "BoomDAO");
    const CATALYZE: (&str, &str) = ("uf2wh-taaaa-aaaaq-aabna-cai", "Catalyze");
    const CYCLES_TRANSFER_STATION: (&str, &str) =
        ("itgqj-7qaaa-aaaaq-aadoa-cai", "CyclesTransferStation");
    const DECIDEAI: (&str, &str) = ("xsi2v-cyaaa-aaaaq-aabfq-cai", "DecideAI");
    const DOGMI: (&str, &str) = ("np5km-uyaaa-aaaaq-aadrq-cai", "DOGMI");
    const DRAGGINZ: (&str, &str) = ("zfcdd-tqaaa-aaaaq-aaaga-cai", "DRAGGINZ");
    const ELNAAI: (&str, &str) = ("gemj7-oyaaa-aaaaq-aacnq-cai", "ELNA AI");
    const ESTATEDAO: (&str, &str) = ("bliq2-niaaa-aaaaq-aac4q-cai", "EstateDAO");
    const GOLDDAO: (&str, &str) = ("tyyy3-4aaaa-aaaaq-aab7a-cai", "GoldDAO");
    const ICGHOST: (&str, &str) = ("4c4fd-caaaa-aaaaq-aaa3a-cai", "ICGhost");
    const ICLIGHTHOUSE: (&str, &str) = ("hhaaz-2aaaa-aaaaq-aacla-cai", "ICLighthouse DAO");
    const ICPANDA: (&str, &str) = ("druyg-tyaaa-aaaaq-aactq-cai", "ICPanda DAO");
    const ICPCC: (&str, &str) = ("lrtnw-paaaa-aaaaq-aadfa-cai", "ICPCC DAO LLC");
    const ICPSWAP: (&str, &str) = ("ca6gz-lqaaa-aaaaq-aacwa-cai", "ICPSwap");
    const ICVC: (&str, &str) = ("m6xut-mqaaa-aaaaq-aadua-cai", "ICVC");
    const KINIC: (&str, &str) = ("73mez-iiaaa-aaaaq-aaasq-cai", "Kinic");
    const MOTOKO: (&str, &str) = ("k45jy-aiaaa-aaaaq-aadcq-cai", "Motoko");
    const NEUTRINITE: (&str, &str) = ("f54if-eqaaa-aaaaq-aacea-cai", "Neutrinite");
    const NUANCE: (&str, &str) = ("rxdbk-dyaaa-aaaaq-aabtq-cai", "Nuance");
    const OPENCHAT: (&str, &str) = ("2ouva-viaaa-aaaaq-aaamq-cai", "OpenChat");
    const OPENFPL: (&str, &str) = ("ddsp7-7iaaa-aaaaq-aacqq-cai", "OpenFPL");
    const ORIGYN: (&str, &str) = ("lkwrt-vyaaa-aaaaq-aadhq-cai", "Origyn");
    const SEERS: (&str, &str) = ("rffwt-piaaa-aaaaq-aabqq-cai", "Seers");
    const SNEED: (&str, &str) = ("hvgxa-wqaaa-aaaaq-aacia-cai", "Sneed");
    const SONIC: (&str, &str) = ("qbizb-wiaaa-aaaaq-aabwq-cai", "Sonic");
    const TRAX: (&str, &str) = ("emww2-4yaaa-aaaaq-aacbq-cai", "Trax");
    const WATERNEURON: (&str, &str) = ("jcmow-hyaaa-aaaaq-aadlq-cai", "WaterNeuron");
    const YRAL: (&str, &str) = ("6rdgd-kyaaa-aaaaq-aaavq-cai", "YRAL");
    const YUKU: (&str, &str) = ("atbfz-diaaa-aaaaq-aacyq-cai", "Yuku DAO");

    let mut canister_configs = vec![LedgerSuiteConfig::new_with_params(
        OPENCHAT,
        &MAINNET_U64_WASM,
        &MASTER_WASM,
        None,
        true,
    )];
    for canister_id_and_name in vec![
        BOOMDAO,
        CATALYZE,
        CYCLES_TRANSFER_STATION,
        DECIDEAI,
        DOGMI,
        DRAGGINZ,
        ELNAAI,
        ESTATEDAO,
        GOLDDAO,
        ICGHOST,
        ICLIGHTHOUSE,
        ICPANDA,
        ICPCC,
        ICPSWAP,
        ICVC,
        KINIC,
        MOTOKO,
        NEUTRINITE,
        NUANCE,
        OPENFPL,
        ORIGYN,
        SEERS,
        SNEED,
        SONIC,
        TRAX,
        WATERNEURON,
        YRAL,
        YUKU,
    ] {
        canister_configs.push(LedgerSuiteConfig::new(
            canister_id_and_name,
            &MAINNET_U64_WASM,
            &MASTER_WASM,
        ));
    }

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic();

    for canister_config in canister_configs {
        canister_config.perform_upgrade_downgrade_testing(&state_machine);
    }
}
