use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger_sm_tests::metrics::retrieve_metrics;
use ic_nns_test_utils_golden_nns_state::{
    new_state_machine_with_golden_fiduciary_state_or_panic,
    new_state_machine_with_golden_sns_state_or_panic,
};
use ic_state_machine_tests::StateMachine;
use std::path::PathBuf;
use std::str::FromStr;

// u64 ledgers
const CK_BTC_LEDGER: (&str, &str) = ("mxzaz-hqaaa-aaaar-qaada-cai", "ckBTC");
// u256 ledgers
const CK_ETH_LEDGER: (&str, &str) = ("ss2fx-dyaaa-aaaar-qacoq-cai", "ckETH");
const CK_USDC_LEDGER: (&str, &str) = ("xevnm-gaaaa-aaaar-qafnq-cai", "ckUSDC");
const CK_LINK_LEDGER: (&str, &str) = ("g4tto-rqaaa-aaaar-qageq-cai", "ckLINK");
// SNS canisters
const DRAGGINZ: (&str, &str) = ("zfcdd-tqaaa-aaaaq-aaaga-cai", "DRAGGINZ");
const OPENCHAT: (&str, &str) = ("2ouva-viaaa-aaaaq-aaamq-cai", "OpenChat");
const ICPSWAP: (&str, &str) = ("ca6gz-lqaaa-aaaaq-aacwa-cai", "ICPSwap");
const BOOMDAO: (&str, &str) = ("vtrom-gqaaa-aaaaq-aabia-cai", "BoomDAO");
const CATALYZE: (&str, &str) = ("uf2wh-taaaa-aaaaq-aabna-cai", "Catalyze");
const ELNAAI: (&str, &str) = ("gemj7-oyaaa-aaaaq-aacnq-cai", "Elna AI");
const ESTATEDAO: (&str, &str) = ("bliq2-niaaa-aaaaq-aac4q-cai", "EstateDAO");
const GOLDDAO: (&str, &str) = ("tyyy3-4aaaa-aaaaq-aab7a-cai", "GoldDAO");
const HOTORNOT: (&str, &str) = ("6rdgd-kyaaa-aaaaq-aaavq-cai", "HotOrNot");
const ICGHOST: (&str, &str) = ("4c4fd-caaaa-aaaaq-aaa3a-cai", "ICGhost");
const ICLIGHTHOUSE: (&str, &str) = ("hhaaz-2aaaa-aaaaq-aacla-cai", "ICLighthouse");
const ICPANDA: (&str, &str) = ("druyg-tyaaa-aaaaq-aactq-cai", "ICPanda");
const ICPCC: (&str, &str) = ("lrtnw-paaaa-aaaaq-aadfa-cai", "ICPCC");
const ICX: (&str, &str) = ("rffwt-piaaa-aaaaq-aabqq-cai", "ICX");
const KINIC: (&str, &str) = ("73mez-iiaaa-aaaaq-aaasq-cai", "Kinic");
const MODCLUB: (&str, &str) = ("xsi2v-cyaaa-aaaaq-aabfq-cai", "ModClub");
const MOTOKO: (&str, &str) = ("k45jy-aiaaa-aaaaq-aadcq-cai", "Motoko");
const NEUTRINITE: (&str, &str) = ("f54if-eqaaa-aaaaq-aacea-cai", "Neutrinite");
const NUANCE: (&str, &str) = ("rxdbk-dyaaa-aaaaq-aabtq-cai", "Nuance");
const OPENFPL: (&str, &str) = ("ddsp7-7iaaa-aaaaq-aacqq-cai", "OpenFPL");
const ORIGYN: (&str, &str) = ("lkwrt-vyaaa-aaaaq-aadhq-cai", "Origyn");
const SNEED: (&str, &str) = ("hvgxa-wqaaa-aaaaq-aacia-cai", "Sneed");
const SONIC: (&str, &str) = ("qbizb-wiaaa-aaaaq-aabwq-cai", "Sonic");
const TRAX: (&str, &str) = ("emww2-4yaaa-aaaaq-aacbq-cai", "Trax");
const YUKU: (&str, &str) = ("atbfz-diaaa-aaaaq-aacyq-cai", "Yuku");

#[test]
fn should_upgrade_icrc_ck_canisters_with_golden_state_and_print_metrics() {
    let ledger_wasm = ledger_wasm();
    let ledger_wasm_u256 = ledger_wasm_u256();

    let canisters = vec![CK_BTC_LEDGER];
    let canisters_u256 = vec![CK_ETH_LEDGER, CK_USDC_LEDGER, CK_LINK_LEDGER];

    let state_machine = new_state_machine_with_golden_fiduciary_state_or_panic();

    for canister in canisters {
        upgrade_canister_and_print_balances_and_approvals(
            &state_machine,
            canister,
            ledger_wasm.clone(),
        );
    }
    for canister_u256 in canisters_u256 {
        upgrade_canister_and_print_balances_and_approvals(
            &state_machine,
            canister_u256,
            ledger_wasm_u256.clone(),
        );
    }
}

#[test]
fn should_upgrade_icrc_sns_canisters_with_golden_state_and_print_metrics() {
    let ledger_wasm = ledger_wasm();

    let canisters = vec![
        DRAGGINZ,
        OPENCHAT,
        ICPSWAP,
        BOOMDAO,
        CATALYZE,
        ELNAAI,
        ESTATEDAO,
        GOLDDAO,
        HOTORNOT,
        ICGHOST,
        ICLIGHTHOUSE,
        ICPANDA,
        ICPCC,
        ICX,
        KINIC,
        MODCLUB,
        MOTOKO,
        NEUTRINITE,
        NUANCE,
        OPENFPL,
        ORIGYN,
        SNEED,
        SONIC,
        TRAX,
        YUKU,
    ];

    let state_machine = new_state_machine_with_golden_sns_state_or_panic();

    for canister in canisters {
        upgrade_canister_and_print_balances_and_approvals(
            &state_machine,
            canister,
            ledger_wasm.clone(),
        );
    }
}

fn upgrade_canister_and_print_balances_and_approvals(
    state_machine: &StateMachine,
    (canister_id_str, canister_name): (&str, &str),
    ledger_wasm: Vec<u8>,
) {
    let canister_id =
        CanisterId::unchecked_from_principal(PrincipalId::from_str(canister_id_str).unwrap());
    upgrade_ledger(state_machine, ledger_wasm, canister_id);
    let metrics = retrieve_metrics(state_machine, canister_id);
    println!("{} '{}':", canister_name, canister_id_str);
    for metric in &metrics {
        if metric.starts_with("ledger_num_approvals")
            || metric.starts_with("ledger_balance_store_entries")
        {
            println!("{}", metric);
        }
    }
}

fn ledger_wasm() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ledger"),
        "ic-icrc1-ledger",
        &[],
    )
}

fn ledger_wasm_u256() -> Vec<u8> {
    ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ledger"),
        "ic-icrc1-ledger",
        &["u256"],
    )
}

fn upgrade_ledger(state_machine: &StateMachine, wasm_bytes: Vec<u8>, canister_id: CanisterId) {
    let args = ic_icrc1_ledger::LedgerArgument::Upgrade(None);
    let args = Encode!(&args).unwrap();
    state_machine
        .upgrade_canister(canister_id, wasm_bytes, args)
        .expect("should successfully upgrade ledger canister");
}
