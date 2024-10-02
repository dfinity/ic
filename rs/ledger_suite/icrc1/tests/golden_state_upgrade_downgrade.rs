use crate::common::{ledger_wasm, load_wasm_using_env_var};
use crate::index::{get_all_index_blocks, wait_until_index_sync_is_completed};
use candid::{Decode, Encode, Nat};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::Block;
use ic_icrc1_ledger_sm_tests::in_memory_ledger::{
    ApprovalKey, BurnsWithoutSpender, InMemoryLedger,
};
use ic_icrc1_ledger_sm_tests::{
    get_all_ledger_and_archive_blocks, get_allowance, send_approval, send_transfer,
    send_transfer_from,
};
use ic_nns_test_utils::governance::bump_gzip_timestamp;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg};
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use std::str::FromStr;
use std::time::{Duration, Instant, UNIX_EPOCH};

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

struct CanisterConfig {
    index_id: &'static str,
    ledger_id: &'static str,
    canister_name: &'static str,
    burns_without_spender: Option<BurnsWithoutSpender<Account>>,
    extended_testing: bool,
}

impl CanisterConfig {
    #[cfg(feature = "u256-tokens")]
    fn new(canister_ids_and_name: (&'static str, &'static str, &'static str)) -> Self {
        let (ledger_id, index_id, canister_name) = canister_ids_and_name;
        Self {
            index_id,
            ledger_id,
            canister_name,
            burns_without_spender: None,
            extended_testing: false,
        }
    }

    fn new_with_params(
        canister_ids_and_name: (&'static str, &'static str, &'static str),
        burns_without_spender: Option<BurnsWithoutSpender<Account>>,
        extended_testing: bool,
    ) -> Self {
        let (ledger_id, index_id, canister_name) = canister_ids_and_name;
        Self {
            index_id,
            ledger_id,
            canister_name,
            burns_without_spender,
            extended_testing,
        }
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
    fn fetch_next_blocks_and_verify_ledger_index_parity(
        &mut self,
        state_machine: &StateMachine,
        ledger_id: CanisterId,
        index_id: CanisterId,
        total_num_blocks: Option<u64>,
    ) {
        let num_blocks = total_num_blocks
            .unwrap_or(u64::MAX)
            .saturating_sub(self.num_blocks);
        let blocks = get_all_ledger_and_archive_blocks(
            state_machine,
            ledger_id,
            Some(self.num_blocks),
            Some(num_blocks),
        );
        wait_until_index_sync_is_completed(state_machine, index_id, ledger_id);
        let index_blocks = get_all_index_blocks(
            state_machine,
            index_id,
            Some(self.num_blocks),
            Some(num_blocks),
        );
        assert_eq!(
            blocks.len(),
            index_blocks.len(),
            "Number of blocks fetched from the ledger and index do not match: {} vs {}",
            blocks.len(),
            index_blocks.len()
        );
        assert_eq!(blocks, index_blocks);
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
        ledger_id: CanisterId,
        index_id: CanisterId,
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
        ledger_state.fetch_next_blocks_and_verify_ledger_index_parity(
            state_machine,
            ledger_id,
            index_id,
            num_blocks_to_fetch,
        );
        ledger_state.verify_balances_and_allowances(state_machine, ledger_id);
        // Verify the reconstructed ledger state matches the previous state
        if let Some(previous_ledger_state) = &previous_ledger_state {
            ledger_state.assert_eq(previous_ledger_state);
        }
        generate_transactions(state_machine, ledger_id);
        // Fetch all blocks into the new `ledger_state`. This call only retrieves blocks that were
        // not fetched in the previous call to `fetch_next_blocks`.
        ledger_state.fetch_next_blocks_and_verify_ledger_index_parity(
            state_machine,
            ledger_id,
            index_id,
            None,
        );
        ledger_state
    }
}

#[cfg(not(feature = "u256-tokens"))]
#[test]
fn should_upgrade_icrc_ck_btc_canister_with_golden_state() {
    const CK_BTC_LEDGER_CANISTER_ID: &str = "mxzaz-hqaaa-aaaar-qaada-cai";
    const CK_BTC_INDEX_CANISTER_ID: &str = "n5wcd-faaaa-aaaar-qaaea-cai";
    const CK_BTC_LEDGER_CANISTER_NAME: &str = "ckBTC";

    let ledger_wasm = Wasm::from_bytes(ledger_wasm());
    let mainnet_ledger_wasm = Wasm::from_bytes(load_wasm_using_env_var(
        "CKBTC_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_fiduciary_state_or_panic(
        );

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

    perform_upgrade_downgrade_testing(
        &state_machine,
        vec![CanisterConfig::new_with_params(
            (
                CK_BTC_LEDGER_CANISTER_ID,
                CK_BTC_INDEX_CANISTER_ID,
                CK_BTC_LEDGER_CANISTER_NAME,
            ),
            Some(burns_without_spender),
            true,
        )],
        ledger_wasm,
        mainnet_ledger_wasm,
    );
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

    let mainnet_ledger_wasm_u256 = Wasm::from_bytes(load_wasm_using_env_var(
        "CKETH_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));
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

    let ledger_wasm_u256 = Wasm::from_bytes(ledger_wasm());

    let canister_configs = vec![
        CanisterConfig::new_with_params(
            CK_ETH_LEDGER_SUITE,
            Some(ck_eth_burns_without_spender),
            true,
        ),
        CanisterConfig::new(CK_SEPOLIA_LINK_LEDGER_SUITE),
        CanisterConfig::new(CK_SEPOLIA_LINK_LEDGER_SUITE),
        CanisterConfig::new(CK_SEPOLIA_PEPE_LEDGER_SUITE),
        CanisterConfig::new(CK_SEPOLIA_USDC_LEDGER_SUITE),
        CanisterConfig::new(CK_EURC_LEDGER_SUITE),
        CanisterConfig::new(CK_USDC_LEDGER_SUITE),
        CanisterConfig::new(CK_LINK_LEDGER_SUITE),
        CanisterConfig::new(CK_OCT_LEDGER_SUITE),
        CanisterConfig::new(CK_PEPE_LEDGER_SUITE),
        CanisterConfig::new(CK_SHIB_LEDGER_SUITE),
        CanisterConfig::new(CK_UNI_LEDGER_SUITE),
        CanisterConfig::new(CK_USDT_LEDGER_SUITE),
        CanisterConfig::new(CK_WBTC_LEDGER_SUITE),
        CanisterConfig::new(CK_WSTETH_LEDGER_SUITE),
        CanisterConfig::new(CK_XAUT_LEDGER_SUITE),
    ];

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_fiduciary_state_or_panic(
        );

    perform_upgrade_downgrade_testing(
        &state_machine,
        canister_configs,
        ledger_wasm_u256,
        mainnet_ledger_wasm_u256,
    );
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

    let ledger_wasm = Wasm::from_bytes(ledger_wasm());
    let mainnet_ledger_wasm = Wasm::from_bytes(load_wasm_using_env_var(
        "IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));

    let canister_configs = vec![
        CanisterConfig::new_with_params(OPENCHAT_LEDGER_SUITE, None, true),
        CanisterConfig::new(BOOMDAO_LEDGER_SUITE),
        CanisterConfig::new(CATALYZE_LEDGER_SUITE),
        CanisterConfig::new(CYCLES_TRANSFER_STATION_LEDGER_SUITE),
        CanisterConfig::new(DECIDEAI_LEDGER_SUITE),
        CanisterConfig::new(DOGMI_LEDGER_SUITE),
        CanisterConfig::new(DRAGGINZ_LEDGER_SUITE),
        CanisterConfig::new(ELNAAI_LEDGER_SUITE),
        CanisterConfig::new(ESTATEDAO_LEDGER_SUITE),
        CanisterConfig::new(GOLDDAO_LEDGER_SUITE),
        CanisterConfig::new(ICGHOST_LEDGER_SUITE),
        CanisterConfig::new(ICLIGHTHOUSE_LEDGER_SUITE),
        CanisterConfig::new(ICPANDA_LEDGER_SUITE),
        CanisterConfig::new(ICPCC_LEDGER_SUITE),
        CanisterConfig::new(ICPSWAP_LEDGER_SUITE),
        CanisterConfig::new(ICVC_LEDGER_SUITE),
        CanisterConfig::new(KINIC_LEDGER_SUITE),
        CanisterConfig::new(MOTOKO_LEDGER_SUITE),
        CanisterConfig::new(NEUTRINITE_LEDGER_SUITE),
        CanisterConfig::new(NUANCE_LEDGER_SUITE),
        CanisterConfig::new(OPENFPL_LEDGER_SUITE),
        CanisterConfig::new(ORIGYN_LEDGER_SUITE),
        CanisterConfig::new(SEERS_LEDGER_SUITE),
        CanisterConfig::new(SNEED_LEDGER_SUITE),
        CanisterConfig::new(SONIC_LEDGER_SUITE),
        CanisterConfig::new(TRAX_LEDGER_SUITE),
        CanisterConfig::new(WATERNEURON_LEDGER_SUITE),
        CanisterConfig::new(YRAL_LEDGER_SUITE),
        CanisterConfig::new(YUKU_LEDGER_SUITE),
    ];

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic();

    perform_upgrade_downgrade_testing(
        &state_machine,
        canister_configs,
        ledger_wasm,
        mainnet_ledger_wasm,
    );
}

fn generate_transactions(state_machine: &StateMachine, canister_id: CanisterId) {
    let start = Instant::now();
    let minter_account = ic_icrc1_ledger_sm_tests::minting_account(state_machine, canister_id)
        .unwrap_or_else(|| panic!("minter account should be set for {:?}", canister_id));
    let u64_fee = ic_icrc1_ledger_sm_tests::fee(state_machine, canister_id);
    let fee = Tokens::from(u64_fee);
    let burn_amount = Tokens::from(
        u64_fee
            .checked_mul(BURN_MULTIPLIER)
            .unwrap_or_else(|| panic!("burn amount overflowed for canister {:?}", canister_id)),
    );
    let transfer_amount =
        Tokens::from(u64_fee.checked_mul(TRANSFER_MULTIPLIER).unwrap_or_else(|| {
            panic!("transfer amount overflowed for canister {:?}", canister_id)
        }));
    let mint_amount = Tokens::from(
        u64_fee
            .checked_mul(MINT_MULTIPLIER)
            .unwrap_or_else(|| panic!("mint amount overflowed for canister {:?}", canister_id)),
    );
    let transfer_from_amount = Tokens::from(
        u64_fee
            .checked_mul(TRANSFER_FROM_MULTIPLIER)
            .unwrap_or_else(|| {
                panic!(
                    "transfer_from amount overflowed for canister {:?}",
                    canister_id
                )
            }),
    );
    let approve_amount = Tokens::from(
        u64_fee
            .checked_mul(APPROVE_MULTIPLIER)
            .unwrap_or_else(|| panic!("approve amount overflowed for canister {:?}", canister_id)),
    );
    let mut accounts = vec![];
    for i in 0..NUM_TRANSACTIONS_PER_TYPE {
        let subaccount = match i {
            0 => None,
            _ => Some([i as u8; 32]),
        };
        accounts.push(Account {
            owner: PrincipalId::new_user_test_id(i as u64).0,
            subaccount,
        });
    }
    // Mint
    let mut minted = 0usize;
    println!("minting");
    for to in &accounts {
        send_transfer(
            state_machine,
            canister_id,
            minter_account.owner,
            &TransferArg {
                from_subaccount: minter_account.subaccount,
                to: *to,
                fee: None,
                created_at_time: Some(
                    state_machine
                        .time()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                ),
                memo: Some(Memo::from(minted as u64)),
                amount: Nat::from(mint_amount),
            },
        )
        .expect("should be able to mint");
        minted += 1;
        if minted >= NUM_TRANSACTIONS_PER_TYPE {
            break;
        }
    }
    // Transfer
    println!("transferring");
    for i in 0..NUM_TRANSACTIONS_PER_TYPE {
        let from = accounts[i];
        let to = accounts[(i + 1) % NUM_TRANSACTIONS_PER_TYPE];
        send_transfer(
            state_machine,
            canister_id,
            from.owner,
            &TransferArg {
                from_subaccount: from.subaccount,
                to,
                fee: Some(Nat::from(fee)),
                created_at_time: Some(
                    state_machine
                        .time()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                ),
                memo: Some(Memo::from(i as u64)),
                amount: Nat::from(transfer_amount),
            },
        )
        .expect("should be able to transfer");
    }
    // Approve
    println!("approving");
    for i in 0..NUM_TRANSACTIONS_PER_TYPE {
        let from = accounts[i];
        let spender = accounts[(i + 1) % NUM_TRANSACTIONS_PER_TYPE];
        let current_allowance = get_allowance(state_machine, canister_id, from, spender);
        let expires_at = state_machine
            .time()
            .checked_add(std::time::Duration::from_secs(3600))
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        send_approval(
            state_machine,
            canister_id,
            from.owner,
            &ApproveArgs {
                from_subaccount: from.subaccount,
                spender,
                amount: Nat::from(approve_amount),
                expected_allowance: Some(current_allowance.allowance.clone()),
                expires_at: Some(expires_at),
                fee: Some(Nat::from(fee)),
                memo: Some(Memo::from(i as u64)),
                created_at_time: Some(
                    state_machine
                        .time()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                ),
            },
        )
        .expect("should be able to transfer");
    }
    // Transfer From
    println!("transferring from");
    for i in 0..NUM_TRANSACTIONS_PER_TYPE {
        let from = accounts[i];
        let spender = accounts[(i + 1) % NUM_TRANSACTIONS_PER_TYPE];
        let to = accounts[(i + 2) % NUM_TRANSACTIONS_PER_TYPE];
        send_transfer_from(
            state_machine,
            canister_id,
            spender.owner,
            &TransferFromArgs {
                spender_subaccount: spender.subaccount,
                from,
                to,
                amount: Nat::from(transfer_from_amount),
                fee: Some(Nat::from(fee)),
                memo: Some(Memo::from(i as u64)),
                created_at_time: Some(
                    state_machine
                        .time()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                ),
            },
        )
        .expect("should be able to transfer from");
    }
    // Burn
    println!("burning");
    for (i, from) in accounts.iter().enumerate().take(NUM_TRANSACTIONS_PER_TYPE) {
        send_transfer(
            state_machine,
            canister_id,
            from.owner,
            &TransferArg {
                from_subaccount: from.subaccount,
                to: minter_account,
                fee: None,
                created_at_time: Some(
                    state_machine
                        .time()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                ),
                memo: Some(Memo::from(i as u64)),
                amount: Nat::from(burn_amount),
            },
        )
        .expect("should be able to transfer");
    }
    println!(
        "generated {} transactions in {:?}",
        NUM_TRANSACTIONS_PER_TYPE * 5,
        start.elapsed()
    );
}

fn perform_upgrade_downgrade_testing(
    state_machine: &StateMachine,
    canister_configs: Vec<CanisterConfig>,
    master_canister_wasm: Wasm,
    mainnet_canister_wasm: Wasm,
) {
    for canister_config in canister_configs {
        let CanisterConfig {
            index_id: index_id_str,
            ledger_id: ledger_id_str,
            canister_name,
            burns_without_spender,
            extended_testing,
        } = canister_config;
        println!(
            "Processing {} ledger, {} index, id {}",
            ledger_id_str, index_id_str, canister_name
        );
        assert_ne!(ledger_id_str, index_id_str);
        let ledger_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(ledger_id_str).unwrap());
        let index_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(index_id_str).unwrap());
        let mut previous_ledger_state = None;
        if extended_testing {
            previous_ledger_state = Some(LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_id,
                index_id,
                burns_without_spender.clone(),
                None,
            ));
        }
        // Upgrade ledger
        upgrade_canister(
            state_machine,
            (ledger_id_str, canister_name),
            master_canister_wasm.clone(),
        );
        // Upgrade ledger again with bumped wasm timestamp to test pre_upgrade
        upgrade_canister(
            state_machine,
            (ledger_id_str, canister_name),
            bump_gzip_timestamp(&master_canister_wasm),
        );
        if extended_testing {
            previous_ledger_state = Some(LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_id,
                index_id,
                burns_without_spender.clone(),
                previous_ledger_state,
            ));
        }
        // Downgrade back to the mainnet ledger version
        upgrade_canister(
            state_machine,
            (ledger_id_str, canister_name),
            mainnet_canister_wasm.clone(),
        );
        if extended_testing {
            let _ = LedgerState::verify_state_and_generate_transactions(
                state_machine,
                ledger_id,
                index_id,
                burns_without_spender.clone(),
                previous_ledger_state,
            );
        }
    }
}

fn upgrade_canister(
    state_machine: &StateMachine,
    (canister_id_str, canister_name): (&str, &str),
    ledger_wasm: Wasm,
) {
    let canister_id =
        CanisterId::unchecked_from_principal(PrincipalId::from_str(canister_id_str).unwrap());
    upgrade_ledger(state_machine, ledger_wasm, canister_id);
    println!("Upgraded {} '{}'", canister_name, canister_id_str);
}

fn upgrade_ledger(state_machine: &StateMachine, wasm: Wasm, canister_id: CanisterId) {
    let args = ic_icrc1_ledger::LedgerArgument::Upgrade(None);
    let args = Encode!(&args).unwrap();
    state_machine
        .upgrade_canister(canister_id, wasm.bytes(), args)
        .expect("should successfully upgrade ledger canister");
}

mod index {
    use super::*;
    use ic_icrc1_index_ng::Status;
    use ic_state_machine_tests::WasmResult;

    pub fn get_all_index_blocks(
        state_machine: &StateMachine,
        index_id: CanisterId,
        start_index: Option<u64>,
        num_blocks: Option<u64>,
    ) -> Vec<Block<Tokens>> {
        let start_index = start_index.unwrap_or(0);
        let num_blocks = num_blocks.unwrap_or(u32::MAX as u64);

        let res = get_index_blocks(state_machine, index_id, 0_u64, 0_u64);
        let length = num_blocks.min(res.chain_length.saturating_sub(start_index));
        let mut blocks: Vec<_> = vec![];
        let mut curr_start = start_index;
        while length > blocks.len() as u64 {
            let new_blocks = get_index_blocks(
                state_machine,
                index_id,
                curr_start,
                length - (curr_start - start_index),
            )
            .blocks;
            assert!(!new_blocks.is_empty());
            curr_start += new_blocks.len() as u64;
            blocks.extend(new_blocks);
        }
        blocks
            .into_iter()
            .map(ic_icrc1::Block::try_from)
            .collect::<Result<Vec<Block<Tokens>>, String>>()
            .expect("should convert generic blocks to ICRC1 blocks")
    }

    pub fn wait_until_index_sync_is_completed(
        env: &StateMachine,
        index_id: CanisterId,
        ledger_id: CanisterId,
    ) {
        const MAX_ATTEMPTS: u8 = 100;
        const SYNC_STEP_SECONDS: Duration = Duration::from_secs(1);

        let mut num_blocks_synced = u64::MAX;
        let mut chain_length = u64::MAX;
        for _i in 0..MAX_ATTEMPTS {
            env.advance_time(SYNC_STEP_SECONDS);
            env.tick();
            num_blocks_synced = u64::try_from(status(env, index_id).num_blocks_synced.0)
                .expect("num_blocks_synced should fit in u64");
            chain_length = get_index_blocks(env, ledger_id, 0u64, 0u64).chain_length;
            if num_blocks_synced == chain_length {
                return;
            }
        }
        panic!("The index canister was unable to sync all the blocks with the ledger. Number of blocks synced {} but the Ledger chain length is {}", num_blocks_synced, chain_length);
    }

    fn get_index_blocks<I>(
        state_machine: &StateMachine,
        index_id: CanisterId,
        start_index: I,
        num_blocks: I,
    ) -> ic_icrc1_index_ng::GetBlocksResponse
    where
        I: Into<Nat>,
    {
        let req = GetBlocksRequest {
            start: start_index.into(),
            length: num_blocks.into(),
        };
        let req = Encode!(&req).expect("Failed to encode GetBlocksRequest");
        let res = state_machine
            .query(index_id, "get_blocks", req)
            .expect("Failed to send get_blocks request")
            .bytes();
        Decode!(&res, ic_icrc1_index_ng::GetBlocksResponse)
            .expect("Failed to decode GetBlocksResponse")
    }

    fn status(state_machine: &StateMachine, canister_id: CanisterId) -> Status {
        let arg = Encode!(&()).unwrap();
        match state_machine.query(canister_id, "status", arg) {
            Err(err) => {
                panic!("{canister_id}.status query failed with error {err}");
            }
            Ok(WasmResult::Reject(err)) => {
                panic!("{canister_id}.status query rejected with error {err}");
            }
            Ok(WasmResult::Reply(res)) => {
                Decode!(&res, Status).expect("error decoding response to status query")
            }
        }
    }
}
