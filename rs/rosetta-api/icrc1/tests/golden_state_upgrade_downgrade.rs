use crate::common::{ledger_wasm, load_wasm_using_env_var};
use candid::Encode;
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger_sm_tests::in_memory_ledger::verify_ledger_state;
use ic_nns_test_utils::governance::bump_gzip_timestamp;
use ic_state_machine_tests::StateMachine;
use std::str::FromStr;

mod common;

#[cfg(not(feature = "u256-tokens"))]
#[test]
fn should_upgrade_icrc_ck_btc_canisters_with_golden_state() {
    const CK_TEST_BTC_LEDGER: (&str, &str) = ("mc6ru-gyaaa-aaaar-qaaaq-cai", "ckTestBTC");
    const CK_BTC_LEDGER: (&str, &str) = ("mxzaz-hqaaa-aaaar-qaada-cai", "ckBTC");

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
    let ck_btc_burns_without_spender = ic_icrc1_ledger_sm_tests::in_memory_ledger::BurnsWithoutSpender {
        minter: ck_btc_minter,
        burn_indexes: vec![
            100785, 101298, 104447, 116240, 454395, 455558, 458776, 460251,
        ],
    };

    let canister_ids_names_and_burns_without_spender = vec![
        // (CK_TEST_BTC_LEDGER, None), // TODO: FI-1471: Needs workaround similar to the CK_BTC_LEDGER
        (CK_BTC_LEDGER, Some(ck_btc_burns_without_spender)),
    ];

    for ((canister_id_str, canister_name), burns_without_spender) in
        canister_ids_names_and_burns_without_spender
    {
        println!(
            "Processing {} ledger, id {}",
            canister_id_str, canister_name
        );
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(canister_id_str).unwrap());
        verify_ledger_state(
            &state_machine,
            canister_id,
            burns_without_spender.clone(),
        );
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            ledger_wasm.clone(),
        );
        // Upgrade again with bumped wasm timestamp to test pre_upgrade
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            bump_gzip_timestamp(&ledger_wasm),
        );
        verify_ledger_state(&state_machine, canister_id, burns_without_spender);
        // Downgrade back to the mainnet ledger version
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            mainnet_ledger_wasm.clone(),
        );
    }
}

#[cfg(feature = "u256-tokens")]
#[test]
fn should_upgrade_icrc_ck_u256_canisters_with_golden_state() {
    // u256 testnet ledgers
    const CK_SEPOLIA_ETH_LEDGER: (&str, &str) = ("apia6-jaaaa-aaaar-qabma-cai", "ckSepoliaETH");
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

    let mainnet_ledger_wasm_u256 = Wasm::from_bytes(load_wasm_using_env_var(
        "CKETH_IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));
    let ck_eth_minter = icrc_ledger_types::icrc1::account::Account {
        owner: PrincipalId::from_str("sv3dd-oaaaa-aaaar-qacoa-cai")
            .unwrap()
            .0,
        subaccount: None,
    };
    let ck_eth_burns_without_spender =
        ic_icrc1_ledger_sm_tests::in_memory_ledger::BurnsWithoutSpender {
            minter: ck_eth_minter,
            burn_indexes: vec![
                1051, 1094, 1276, 1759, 1803, 1929, 2449, 2574, 2218, 2219, 2231, 1777, 4, 9, 31,
                1540, 1576, 1579, 1595, 1607, 1617, 1626, 1752, 1869, 1894, 2013, 2555,
            ],
        };

    let ledger_wasm_u256 = Wasm::from_bytes(ledger_wasm());

    let canister_ids_names_and_burns_without_spender = vec![
        // (CK_SEPOLIA_ETH_LEDGER, None), // TODO: FI-1471: Needs workaround similar to the CK_ETH_LEDGER
        (CK_SEPOLIA_LINK_LEDGER, None),
        (CK_SEPOLIA_PEPE_LEDGER, None),
        (CK_SEPOLIA_USDC_LEDGER, None),
        (CK_ETH_LEDGER, Some(ck_eth_burns_without_spender)),
        (CK_EURC_LEDGER, None),
        (CK_USDC_LEDGER, None),
        (CK_LINK_LEDGER, None),
        (CK_OCT_LEDGER, None),
        (CK_PEPE_LEDGER, None),
        (CK_SHIB_LEDGER, None),
        (CK_UNI_LEDGER, None),
        (CK_USDT_LEDGER, None),
        (CK_WBTC_LEDGER, None),
        (CK_WSTETH_LEDGER, None),
        (CK_XAUT_LEDGER, None),
    ];

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_fiduciary_state_or_panic(
        );

    for ((canister_id_str, canister_name), burns_without_spender) in
        canister_ids_names_and_burns_without_spender
    {
        println!(
            "Processing {} ledger, id {}",
            canister_id_str, canister_name
        );
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(canister_id_str).unwrap());
        verify_ledger_state(&state_machine, canister_id, burns_without_spender.clone());
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            ledger_wasm_u256.clone(),
        );
        // Upgrade again with bumped wasm timestamp to test pre_upgrade
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            bump_gzip_timestamp(&ledger_wasm_u256),
        );
        // Downgrade back to the mainnet ledger version
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            mainnet_ledger_wasm_u256.clone(),
        );
        verify_ledger_state(&state_machine, canister_id, burns_without_spender);
    }
}

#[cfg(feature = "u256-tokens")]
#[test]
fn should_upgrade_icrc_sns_canisters_with_golden_state() {
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

    let ledger_wasm = Wasm::from_bytes(ledger_wasm());
    let mainnet_ledger_wasm = Wasm::from_bytes(load_wasm_using_env_var(
        "IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));

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

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic();

    for (canister_id_str, canister_name) in canister_id_and_names {
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(canister_id_str).unwrap());
        // TODO: Uncomment once mainnet ledgers have been upgraded to include `ledger_num_approvals` metric
        // verify_ledger_state(&state_machine, canister_id, None);
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            ledger_wasm.clone(),
        );
        // Upgrade again with bumped wasm timestamp to test pre_upgrade
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            bump_gzip_timestamp(&ledger_wasm),
        );
        verify_ledger_state(&state_machine, canister_id, None);
        // Downgrade back to the mainnet ledger version
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            mainnet_ledger_wasm.clone(),
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

fn upgrade_ledger(state_machine: &StateMachine, wasm: Wasm, canister_id: CanisterId) {
    let args = ic_icrc1_ledger::LedgerArgument::Upgrade(None);
    let args = Encode!(&args).unwrap();
    state_machine
        .upgrade_canister(canister_id, wasm.bytes(), args)
        .expect("should successfully upgrade ledger canister");
}
