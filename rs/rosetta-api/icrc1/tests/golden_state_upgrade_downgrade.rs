use candid::Encode;
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_test_utils::governance::bump_gzip_timestamp;
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
const CK_OCT_LEDGER: (&str, &str) = ("ebo5g-cyaaa-aaaar-qagla-cai", "ckOCT");
const CK_PEPE_LEDGER: (&str, &str) = ("etik7-oiaaa-aaaar-qagia-cai", "ckPEPE");
const CK_SHIB_LEDGER: (&str, &str) = ("fxffn-xiaaa-aaaar-qagoa-cai", "ckSHIB");
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
const DECIDEAI: (&str, &str) = ("xsi2v-cyaaa-aaaaq-aabfq-cai", "DecideAI");
const MOTOKO: (&str, &str) = ("k45jy-aiaaa-aaaaq-aadcq-cai", "Motoko");
const NEUTRINITE: (&str, &str) = ("f54if-eqaaa-aaaaq-aacea-cai", "Neutrinite");
const NUANCE: (&str, &str) = ("rxdbk-dyaaa-aaaaq-aabtq-cai", "Nuance");
const OPENFPL: (&str, &str) = ("ddsp7-7iaaa-aaaaq-aacqq-cai", "OpenFPL");
const ORIGYN: (&str, &str) = ("lkwrt-vyaaa-aaaaq-aadhq-cai", "Origyn");
const SNEED: (&str, &str) = ("hvgxa-wqaaa-aaaaq-aacia-cai", "Sneed");
const SONIC: (&str, &str) = ("qbizb-wiaaa-aaaaq-aabwq-cai", "Sonic");
const TRAX: (&str, &str) = ("emww2-4yaaa-aaaaq-aacbq-cai", "Trax");
const WATERNEURON: (&str, &str) = ("jcmow-hyaaa-aaaaq-aadlq-cai", "WaterNeuron");
const YUKU: (&str, &str) = ("atbfz-diaaa-aaaaq-aacyq-cai", "Yuku");

#[test]
fn should_upgrade_icrc_ck_canisters_with_golden_state() {
    let ledger_wasm = ledger_wasm();
    let ledger_wasm_u256 = ledger_wasm_u256();

    let canister_ids_and_names = vec![CK_BTC_LEDGER];
    let canister_ids_and_names_u256 = vec![
        CK_ETH_LEDGER,
        CK_USDC_LEDGER,
        CK_LINK_LEDGER,
        CK_OCT_LEDGER,
        CK_PEPE_LEDGER,
        CK_SHIB_LEDGER,
    ];

    let state_machine = new_state_machine_with_golden_fiduciary_state_or_panic();

    for canister_id_and_name in canister_ids_and_names {
        upgrade_canister(&state_machine, canister_id_and_name, ledger_wasm.clone());
        // Upgrade again with bumped wasm timestamp to test pre_upgrade
        upgrade_canister(
            &state_machine,
            canister_id_and_name,
            bump_gzip_timestamp(&ledger_wasm),
        );
    }
    for canister_id_and_name_u256 in canister_ids_and_names_u256 {
        upgrade_canister(
            &state_machine,
            canister_id_and_name_u256,
            ledger_wasm_u256.clone(),
        );
        // Upgrade again with bumped wasm timestamp to test pre_upgrade
        upgrade_canister(
            &state_machine,
            canister_id_and_name_u256,
            bump_gzip_timestamp(&ledger_wasm_u256),
        );
    }
}

#[test]
fn should_upgrade_icrc_sns_canisters_with_golden_state() {
    let ledger_wasm = ledger_wasm();

    let canister_id_and_names = vec![
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
        DECIDEAI,
        MOTOKO,
        NEUTRINITE,
        NUANCE,
        OPENFPL,
        ORIGYN,
        SNEED,
        SONIC,
        TRAX,
        WATERNEURON,
        YUKU,
    ];

    let state_machine = new_state_machine_with_golden_sns_state_or_panic();

    for canister_id_and_name in canister_id_and_names {
        upgrade_canister(&state_machine, canister_id_and_name, ledger_wasm.clone());
        // Upgrade again with bumped wasm timestamp to test pre_upgrade
        upgrade_canister(
            &state_machine,
            canister_id_and_name,
            bump_gzip_timestamp(&ledger_wasm),
        );
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

fn ledger_wasm() -> Wasm {
    Wasm::from_bytes(ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ledger"),
        "ic-icrc1-ledger",
        &[],
    ))
}

fn ledger_wasm_u256() -> Wasm {
    Wasm::from_bytes(ic_test_utilities_load_wasm::load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ledger"),
        "ic-icrc1-ledger",
        &["u256"],
    ))
}

fn upgrade_ledger(state_machine: &StateMachine, wasm: Wasm, canister_id: CanisterId) {
    let args = ic_icrc1_ledger::LedgerArgument::Upgrade(None);
    let args = Encode!(&args).unwrap();
    state_machine
        .upgrade_canister(canister_id, wasm.bytes(), args)
        .expect("should successfully upgrade ledger canister");
}
