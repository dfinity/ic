use crate::common::{index_ng_wasm, ledger_wasm, load_wasm_using_env_var};
use candid::Encode;
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index_ng::{IndexArg, UpgradeArg as IndexUpgradeArg};
use ic_icrc1_ledger_sm_tests::in_memory_ledger::{
    ApprovalKey, BurnsWithoutSpender, InMemoryLedger,
};
use ic_icrc1_ledger_sm_tests::{
    generate_transactions, get_all_ledger_and_archive_blocks, TransactionGenerationParameters,
};
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
    pub static ref MAINNET_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKBTC_IC_ICRC1_INDEX_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKBTC_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
        ))
    );
    pub static ref MASTER_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(index_ng_wasm()),
        Wasm::from_bytes(ledger_wasm())
    );
}

#[cfg(feature = "u256-tokens")]
lazy_static! {
    pub static ref MAINNET_U256_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKETH_IC_ICRC1_INDEX_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "CKETH_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
        ))
    );
    pub static ref MAINNET_U64_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(load_wasm_using_env_var(
            "IC_ICRC1_INDEX_DEPLOYED_VERSION_WASM_PATH",
        )),
        Wasm::from_bytes(load_wasm_using_env_var(
            "IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
        ))
    );
    pub static ref MASTER_WASMS: Wasms = Wasms::new(
        Wasm::from_bytes(index_ng_wasm()),
        Wasm::from_bytes(ledger_wasm())
    );
}

pub struct Wasms {
    index_wasm: Wasm,
    ledger_wasm: Wasm,
}

impl Wasms {
    fn new(index_wasm: Wasm, ledger_wasm: Wasm) -> Self {
        Self {
            index_wasm,
            ledger_wasm,
        }
    }
}

struct LedgerSuiteConfig {
    ledger_id: &'static str,
    index_id: &'static str,
    canister_name: &'static str,
    burns_without_spender: Option<BurnsWithoutSpender<Account>>,
    extended_testing: bool,
    mainnet_wasms: &'static Wasms,
    master_wasms: &'static Wasms,
}

impl LedgerSuiteConfig {
    fn new(
        canister_ids_and_name: (&'static str, &'static str, &'static str),
        mainnet_wasms: &'static Wasms,
        master_wasms: &'static Wasms,
    ) -> Self {
        let (ledger_id, index_id, canister_name) = canister_ids_and_name;
        Self {
            ledger_id,
            index_id,
            canister_name,
            burns_without_spender: None,
            extended_testing: false,
            mainnet_wasms,
            master_wasms,
        }
    }

    fn new_with_params(
        canister_ids_and_name: (&'static str, &'static str, &'static str),
        mainnet_wasms: &'static Wasms,
        master_wasms: &'static Wasms,
        burns_without_spender: Option<BurnsWithoutSpender<Account>>,
        extended_testing: bool,
    ) -> Self {
        Self {
            burns_without_spender,
            extended_testing,
            ..Self::new(canister_ids_and_name, mainnet_wasms, master_wasms)
        }
    }

    fn perform_upgrade_downgrade_testing(&self, state_machine: &StateMachine) {
        println!(
            "Processing {}, ledger id: {}, index id: {}",
            self.canister_name, self.ledger_id, self.index_id
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
        // Upgrade to the new canister versions
        self.upgrade_to_master(state_machine);
        if self.extended_testing {
            previous_ledger_state = Some(LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_canister_id,
                self.burns_without_spender.clone(),
                previous_ledger_state,
            ));
        }
        // Downgrade back to the mainnet canister versions
        self.upgrade_to_mainnet(state_machine);
        if self.extended_testing {
            let _ = LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_canister_id,
                self.burns_without_spender.clone(),
                previous_ledger_state,
            );
        }
    }

    fn upgrade_index(&self, state_machine: &StateMachine, wasm: &Wasm) {
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.index_id).unwrap());
        let index_upgrade_arg = IndexArg::Upgrade(IndexUpgradeArg {
            ledger_id: None,
            retrieve_blocks_from_ledger_interval_seconds: None,
        });
        let args = Encode!(&index_upgrade_arg).unwrap();
        state_machine
            .upgrade_canister(canister_id, wasm.clone().bytes(), args.clone())
            .expect("should successfully upgrade index canister");
        println!("Upgraded {} index '{}'", self.canister_name, self.index_id);
    }

    fn upgrade_ledger(&self, state_machine: &StateMachine, wasm: &Wasm) {
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(self.ledger_id).unwrap());
        let args = ic_icrc1_ledger::LedgerArgument::Upgrade(None);
        let args = Encode!(&args).unwrap();
        state_machine
            .upgrade_canister(canister_id, wasm.clone().bytes(), args.clone())
            .expect("should successfully upgrade ledger canister");
        println!(
            "Upgraded {} ledger '{}'",
            self.canister_name, self.ledger_id
        );
    }

    fn upgrade_to_mainnet(&self, state_machine: &StateMachine) {
        // Upgrade each canister twice to exercise pre-upgrade
        self.upgrade_index(state_machine, &self.mainnet_wasms.index_wasm);
        self.upgrade_index(state_machine, &self.mainnet_wasms.index_wasm);
        self.upgrade_ledger(state_machine, &self.mainnet_wasms.ledger_wasm);
        self.upgrade_ledger(state_machine, &self.mainnet_wasms.ledger_wasm);
    }

    fn upgrade_to_master(&self, state_machine: &StateMachine) {
        // Upgrade each canister twice to exercise pre-upgrade
        self.upgrade_index(state_machine, &self.master_wasms.index_wasm);
        self.upgrade_index(state_machine, &self.master_wasms.index_wasm);
        self.upgrade_ledger(state_machine, &self.master_wasms.ledger_wasm);
        self.upgrade_ledger(state_machine, &self.master_wasms.ledger_wasm);
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
    const CK_BTC_INDEX_CANISTER_ID: &str = "n5wcd-faaaa-aaaar-qaaea-cai";
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
        (
            CK_BTC_LEDGER_CANISTER_ID,
            CK_BTC_INDEX_CANISTER_ID,
            CK_BTC_LEDGER_CANISTER_NAME,
        ),
        &MAINNET_WASMS,
        &MASTER_WASMS,
        Some(burns_without_spender),
        true,
    )
    .perform_upgrade_downgrade_testing(&state_machine);
}

#[cfg(feature = "u256-tokens")]
#[test]
fn should_upgrade_icrc_ck_u256_canisters_with_golden_state() {
    // u256 testnet ledgers
    const CK_SEPOLIA_LINK_LEDGER_SUITE: (&str, &str, &str) = (
        "r52mc-qaaaa-aaaar-qafzq-cai",
        "ri55p-riaaa-aaaar-qaf2a-cai",
        "ckSepoliaLINK",
    );
    const CK_SEPOLIA_PEPE_LEDGER_SUITE: (&str, &str, &str) = (
        "hw4ru-taaaa-aaaar-qagdq-cai",
        "g3sv2-4iaaa-aaaar-qagea-cai",
        "ckSepoliaPEPE",
    );
    const CK_SEPOLIA_USDC_LEDGER_SUITE: (&str, &str, &str) = (
        "yfumr-cyaaa-aaaar-qaela-cai",
        "ycvkf-paaaa-aaaar-qaelq-cai",
        "ckSepoliaUSDC",
    );
    // u256 production ledgers
    const CK_ETH_LEDGER_SUITE: (&str, &str, &str) = (
        "ss2fx-dyaaa-aaaar-qacoq-cai",
        "s3zol-vqaaa-aaaar-qacpa-cai",
        "ckETH",
    );
    const CK_EURC_LEDGER_SUITE: (&str, &str, &str) = (
        "pe5t5-diaaa-aaaar-qahwa-cai",
        "pd4vj-oqaaa-aaaar-qahwq-cai",
        "ckEURC",
    );
    const CK_LINK_LEDGER_SUITE: (&str, &str, &str) = (
        "g4tto-rqaaa-aaaar-qageq-cai",
        "gvqys-hyaaa-aaaar-qagfa-cai",
        "ckLINK",
    );
    const CK_OCT_LEDGER_SUITE: (&str, &str, &str) = (
        "ebo5g-cyaaa-aaaar-qagla-cai",
        "egp3s-paaaa-aaaar-qaglq-cai",
        "ckOCT",
    );
    const CK_PEPE_LEDGER_SUITE: (&str, &str, &str) = (
        "etik7-oiaaa-aaaar-qagia-cai",
        "eujml-dqaaa-aaaar-qagiq-cai",
        "ckPEPE",
    );
    const CK_SHIB_LEDGER_SUITE: (&str, &str, &str) = (
        "fxffn-xiaaa-aaaar-qagoa-cai",
        "fqedz-2qaaa-aaaar-qagoq-cai",
        "ckSHIB",
    );
    const CK_UNI_LEDGER_SUITE: (&str, &str, &str) = (
        "ilzky-ayaaa-aaaar-qahha-cai",
        "imymm-naaaa-aaaar-qahhq-cai",
        "ckUNI",
    );
    const CK_USDC_LEDGER_SUITE: (&str, &str, &str) = (
        "xevnm-gaaaa-aaaar-qafnq-cai",
        "xrs4b-hiaaa-aaaar-qafoa-cai",
        "ckUSDC",
    );
    const CK_USDT_LEDGER_SUITE: (&str, &str, &str) = (
        "cngnf-vqaaa-aaaar-qag4q-cai",
        "cefgz-dyaaa-aaaar-qag5a-cai",
        "ckUSDT",
    );
    const CK_WBTC_LEDGER_SUITE: (&str, &str, &str) = (
        "bptq2-faaaa-aaaar-qagxq-cai",
        "dso6s-wiaaa-aaaar-qagya-cai",
        "ckWBTC",
    );
    const CK_WSTETH_LEDGER_SUITE: (&str, &str, &str) = (
        "j2tuh-yqaaa-aaaar-qahcq-cai",
        "jtq73-oyaaa-aaaar-qahda-cai",
        "ckWSTETH",
    );
    const CK_XAUT_LEDGER_SUITE: (&str, &str, &str) = (
        "nza5v-qaaaa-aaaar-qahzq-cai",
        "nmhmy-riaaa-aaaar-qah2a-cai",
        "ckXAUT",
    );

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
        CK_ETH_LEDGER_SUITE,
        &MAINNET_U256_WASMS,
        &MASTER_WASMS,
        Some(ck_eth_burns_without_spender),
        true,
    )];
    for canister_id_and_name in vec![
        CK_SEPOLIA_LINK_LEDGER_SUITE,
        CK_SEPOLIA_LINK_LEDGER_SUITE,
        CK_SEPOLIA_PEPE_LEDGER_SUITE,
        CK_SEPOLIA_USDC_LEDGER_SUITE,
        CK_EURC_LEDGER_SUITE,
        CK_USDC_LEDGER_SUITE,
        CK_LINK_LEDGER_SUITE,
        CK_OCT_LEDGER_SUITE,
        CK_PEPE_LEDGER_SUITE,
        CK_SHIB_LEDGER_SUITE,
        CK_UNI_LEDGER_SUITE,
        CK_USDT_LEDGER_SUITE,
        CK_WBTC_LEDGER_SUITE,
        CK_WSTETH_LEDGER_SUITE,
        CK_XAUT_LEDGER_SUITE,
    ] {
        canister_configs.push(LedgerSuiteConfig::new(
            canister_id_and_name,
            &MAINNET_U256_WASMS,
            &MASTER_WASMS,
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
    const BOOMDAO_LEDGER_SUITE: (&str, &str, &str) = (
        "vtrom-gqaaa-aaaaq-aabia-cai",
        "v5tde-5aaaa-aaaaq-aabja-cai",
        "BoomDAO",
    );
    const CATALYZE_LEDGER_SUITE: (&str, &str, &str) = (
        "uf2wh-taaaa-aaaaq-aabna-cai",
        "ux4b6-7qaaa-aaaaq-aaboa-cai",
        "Catalyze",
    );
    const CYCLES_TRANSFER_STATION_LEDGER_SUITE: (&str, &str, &str) = (
        "itgqj-7qaaa-aaaaq-aadoa-cai",
        "i5e5b-eaaaa-aaaaq-aadpa-cai",
        "CyclesTransferStation",
    );
    const DECIDEAI_LEDGER_SUITE: (&str, &str, &str) = (
        "xsi2v-cyaaa-aaaaq-aabfq-cai",
        "xaonm-oiaaa-aaaaq-aabgq-cai",
        "DecideAI",
    );
    const DOGMI_LEDGER_SUITE: (&str, &str, &str) = (
        "np5km-uyaaa-aaaaq-aadrq-cai",
        "n535v-yiaaa-aaaaq-aadsq-cai",
        "DOGMI",
    );
    const DRAGGINZ_LEDGER_SUITE: (&str, &str, &str) = (
        "zfcdd-tqaaa-aaaaq-aaaga-cai",
        "zlaol-iaaaa-aaaaq-aaaha-cai",
        "DRAGGINZ",
    );
    const ELNAAI_LEDGER_SUITE: (&str, &str, &str) = (
        "gemj7-oyaaa-aaaaq-aacnq-cai",
        "gwk6g-ciaaa-aaaaq-aacoq-cai",
        "ELNA AI",
    );
    const ESTATEDAO_LEDGER_SUITE: (&str, &str, &str) = (
        "bliq2-niaaa-aaaaq-aac4q-cai",
        "bfk5s-wyaaa-aaaaq-aac5q-cai",
        "EstateDAO",
    );
    const GOLDDAO_LEDGER_SUITE: (&str, &str, &str) = (
        "tyyy3-4aaaa-aaaaq-aab7a-cai",
        "efv5g-kqaaa-aaaaq-aacaa-cai",
        "GoldDAO",
    );
    const ICGHOST_LEDGER_SUITE: (&str, &str, &str) = (
        "4c4fd-caaaa-aaaaq-aaa3a-cai",
        "5ithz-aqaaa-aaaaq-aaa4a-cai",
        "ICGhost",
    );
    const ICLIGHTHOUSE_LEDGER_SUITE: (&str, &str, &str) = (
        "hhaaz-2aaaa-aaaaq-aacla-cai",
        "gnpcd-yqaaa-aaaaq-aacma-cai",
        "ICLighthouse DAO",
    );
    const ICPANDA_LEDGER_SUITE: (&str, &str, &str) = (
        "druyg-tyaaa-aaaaq-aactq-cai",
        "c3324-riaaa-aaaaq-aacuq-cai",
        "ICPanda DAO",
    );
    const ICPCC_LEDGER_SUITE: (&str, &str, &str) = (
        "lrtnw-paaaa-aaaaq-aadfa-cai",
        "ldv2p-dqaaa-aaaaq-aadga-cai",
        "ICPCC DAO LLC",
    );
    const ICPSWAP_LEDGER_SUITE: (&str, &str, &str) = (
        "ca6gz-lqaaa-aaaaq-aacwa-cai",
        "co4lr-qaaaa-aaaaq-aacxa-cai",
        "ICPSwap",
    );
    const ICVC_LEDGER_SUITE: (&str, &str, &str) = (
        "m6xut-mqaaa-aaaaq-aadua-cai",
        "mqvz3-xaaaa-aaaaq-aadva-cai",
        "ICVC",
    );
    const KINIC_LEDGER_SUITE: (&str, &str, &str) = (
        "73mez-iiaaa-aaaaq-aaasq-cai",
        "7vojr-tyaaa-aaaaq-aaatq-cai",
        "Kinic",
    );
    const MOTOKO_LEDGER_SUITE: (&str, &str, &str) = (
        "k45jy-aiaaa-aaaaq-aadcq-cai",
        "ks7eq-3yaaa-aaaaq-aaddq-cai",
        "Motoko",
    );
    const NEUTRINITE_LEDGER_SUITE: (&str, &str, &str) = (
        "f54if-eqaaa-aaaaq-aacea-cai",
        "ft6fn-7aaaa-aaaaq-aacfa-cai",
        "Neutrinite",
    );
    const NUANCE_LEDGER_SUITE: (&str, &str, &str) = (
        "rxdbk-dyaaa-aaaaq-aabtq-cai",
        "q5mdq-biaaa-aaaaq-aabuq-cai",
        "Nuance",
    );
    const OPENCHAT_LEDGER_SUITE: (&str, &str, &str) = (
        "2ouva-viaaa-aaaaq-aaamq-cai",
        "2awyi-oyaaa-aaaaq-aaanq-cai",
        "OpenChat",
    );
    const OPENFPL_LEDGER_SUITE: (&str, &str, &str) = (
        "ddsp7-7iaaa-aaaaq-aacqq-cai",
        "dnqcx-eyaaa-aaaaq-aacrq-cai",
        "OpenFPL",
    );
    const ORIGYN_LEDGER_SUITE: (&str, &str, &str) = (
        "lkwrt-vyaaa-aaaaq-aadhq-cai",
        "jqkzp-liaaa-aaaaq-aadiq-cai",
        "Origyn",
    );
    const SEERS_LEDGER_SUITE: (&str, &str, &str) = (
        "rffwt-piaaa-aaaaq-aabqq-cai",
        "rlh33-uyaaa-aaaaq-aabrq-cai",
        "Seers",
    );
    const SNEED_LEDGER_SUITE: (&str, &str, &str) = (
        "hvgxa-wqaaa-aaaaq-aacia-cai",
        "h3e2i-naaaa-aaaaq-aacja-cai",
        "Sneed",
    );
    const SONIC_LEDGER_SUITE: (&str, &str, &str) = (
        "qbizb-wiaaa-aaaaq-aabwq-cai",
        "qpkuj-nyaaa-aaaaq-aabxq-cai",
        "Sonic",
    );
    const TRAX_LEDGER_SUITE: (&str, &str, &str) = (
        "emww2-4yaaa-aaaaq-aacbq-cai",
        "e6qbd-qiaaa-aaaaq-aaccq-cai",
        "Trax",
    );
    const WATERNEURON_LEDGER_SUITE: (&str, &str, &str) = (
        "jcmow-hyaaa-aaaaq-aadlq-cai",
        "iidmm-fiaaa-aaaaq-aadmq-cai",
        "WaterNeuron",
    );
    const YRAL_LEDGER_SUITE: (&str, &str, &str) = (
        "6rdgd-kyaaa-aaaaq-aaavq-cai",
        "6dfr2-giaaa-aaaaq-aaawq-cai",
        "YRAL",
    );
    const YUKU_LEDGER_SUITE: (&str, &str, &str) = (
        "atbfz-diaaa-aaaaq-aacyq-cai",
        "a5dir-yyaaa-aaaaq-aaczq-cai",
        "Yuku DAO",
    );

    let mut canister_configs = vec![LedgerSuiteConfig::new_with_params(
        OPENCHAT_LEDGER_SUITE,
        &MAINNET_U64_WASMS,
        &MASTER_WASMS,
        None,
        true,
    )];
    for canister_id_and_name in vec![
        BOOMDAO_LEDGER_SUITE,
        CATALYZE_LEDGER_SUITE,
        CYCLES_TRANSFER_STATION_LEDGER_SUITE,
        DECIDEAI_LEDGER_SUITE,
        DOGMI_LEDGER_SUITE,
        DRAGGINZ_LEDGER_SUITE,
        ELNAAI_LEDGER_SUITE,
        ESTATEDAO_LEDGER_SUITE,
        GOLDDAO_LEDGER_SUITE,
        ICGHOST_LEDGER_SUITE,
        ICLIGHTHOUSE_LEDGER_SUITE,
        ICPANDA_LEDGER_SUITE,
        ICPCC_LEDGER_SUITE,
        ICPSWAP_LEDGER_SUITE,
        ICVC_LEDGER_SUITE,
        KINIC_LEDGER_SUITE,
        MOTOKO_LEDGER_SUITE,
        NEUTRINITE_LEDGER_SUITE,
        NUANCE_LEDGER_SUITE,
        OPENFPL_LEDGER_SUITE,
        ORIGYN_LEDGER_SUITE,
        SEERS_LEDGER_SUITE,
        SNEED_LEDGER_SUITE,
        SONIC_LEDGER_SUITE,
        TRAX_LEDGER_SUITE,
        WATERNEURON_LEDGER_SUITE,
        YRAL_LEDGER_SUITE,
        YUKU_LEDGER_SUITE,
    ] {
        canister_configs.push(LedgerSuiteConfig::new(
            canister_id_and_name,
            &MAINNET_U64_WASMS,
            &MASTER_WASMS,
        ));
    }

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic();

    for canister_config in canister_configs {
        canister_config.perform_upgrade_downgrade_testing(&state_machine);
    }
}
