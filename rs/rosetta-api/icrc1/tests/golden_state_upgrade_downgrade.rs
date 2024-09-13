use crate::common::{ledger_wasm, load_wasm_using_env_var};
use candid::{Encode, Nat};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_ledger_sm_tests::in_memory_ledger::{
    verify_ledger_state, ApprovalKey, InMemoryLedger, InMemoryLedgerState,
};
use ic_icrc1_ledger_sm_tests::{
    get_all_ledger_and_archive_blocks, send_approval, send_transfer, send_transfer_from,
};
use ic_ledger_core::approvals::Allowance;
use ic_ledger_core::timestamp::TimeStamp;
use ic_nns_test_utils::governance::bump_gzip_timestamp;
use ic_state_machine_tests::StateMachine;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg};
use icrc_ledger_types::icrc2::approve::ApproveArgs;
use icrc_ledger_types::icrc2::transfer_from::TransferFromArgs;
use std::str::FromStr;
use std::time::{Instant, UNIX_EPOCH};

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
#[test]
fn should_upgrade_icrc_ck_btc_canister_with_golden_state() {
    const CK_BTC_LEDGER_CANISTER_ID: &str = "mxzaz-hqaaa-aaaar-qaada-cai";
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

    let canister_id = CanisterId::unchecked_from_principal(
        PrincipalId::from_str(CK_BTC_LEDGER_CANISTER_ID).unwrap(),
    );
    verify_ledger_state(
        &state_machine,
        canister_id,
        Some(burns_without_spender.clone()),
    );
    upgrade_canister(
        &state_machine,
        (CK_BTC_LEDGER_CANISTER_ID, CK_BTC_LEDGER_CANISTER_NAME),
        ledger_wasm.clone(),
    );
    // Upgrade again with bumped wasm timestamp to test pre_upgrade
    upgrade_canister(
        &state_machine,
        (CK_BTC_LEDGER_CANISTER_ID, CK_BTC_LEDGER_CANISTER_NAME),
        bump_gzip_timestamp(&ledger_wasm),
    );
    let blocks = get_all_ledger_and_archive_blocks(&state_machine, canister_id);
    let mut expected_ledger_state =
        ic_icrc1_ledger_sm_tests::in_memory_ledger::InMemoryLedger::new(None);
    expected_ledger_state.ingest_icrc1_ledger_blocks(&blocks);
    generate_transactions(&state_machine, canister_id, &mut expected_ledger_state);
    verify_ledger_state(&state_machine, canister_id, Some(burns_without_spender));
    // Downgrade back to the mainnet ledger version
    upgrade_canister(
        &state_machine,
        (CK_BTC_LEDGER_CANISTER_ID, CK_BTC_LEDGER_CANISTER_NAME),
        mainnet_ledger_wasm,
    );
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
        let blocks = get_all_ledger_and_archive_blocks(&state_machine, canister_id);
        let mut expected_ledger_state =
            ic_icrc1_ledger_sm_tests::in_memory_ledger::InMemoryLedger::new(None);
        expected_ledger_state.ingest_icrc1_ledger_blocks(&blocks);
        generate_transactions(&state_machine, canister_id, &mut expected_ledger_state);
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

    let ledger_wasm = Wasm::from_bytes(ledger_wasm());
    let mainnet_ledger_wasm = Wasm::from_bytes(load_wasm_using_env_var(
        "IC_ICRC1_LEDGER_DEPLOYED_VERSION_WASM_PATH",
    ));

    let canister_id_and_names = vec![
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
        OPENCHAT,
        OPENFPL,
        ORIGYN,
        SEERS,
        SNEED,
        SONIC,
        TRAX,
        WATERNEURON,
        YRAL,
        YUKU,
    ];

    let state_machine =
        ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_sns_state_or_panic();

    for (canister_id_str, canister_name) in canister_id_and_names {
        let canister_id =
            CanisterId::unchecked_from_principal(PrincipalId::from_str(canister_id_str).unwrap());
        // TODO: Verify the ledger state here already once mainnet ledgers have been upgraded to include `ledger_num_approvals` metric
        let blocks = get_all_ledger_and_archive_blocks(&state_machine, canister_id);
        let mut expected_ledger_state =
            ic_icrc1_ledger_sm_tests::in_memory_ledger::InMemoryLedger::new(None);
        expected_ledger_state.ingest_icrc1_ledger_blocks(&blocks);
        generate_transactions(&state_machine, canister_id, &mut expected_ledger_state);
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
        let blocks = get_all_ledger_and_archive_blocks(&state_machine, canister_id);
        let mut expected_ledger_state =
            ic_icrc1_ledger_sm_tests::in_memory_ledger::InMemoryLedger::new(None);
        expected_ledger_state.ingest_icrc1_ledger_blocks(&blocks);
        generate_transactions(&state_machine, canister_id, &mut expected_ledger_state);
        verify_ledger_state(&state_machine, canister_id, None);
        // Downgrade back to the mainnet ledger version
        upgrade_canister(
            &state_machine,
            (canister_id_str, canister_name),
            mainnet_ledger_wasm.clone(),
        );
    }
}

fn generate_transactions(
    state_machine: &StateMachine,
    canister_id: CanisterId,
    in_memory_ledger: &mut InMemoryLedger<ApprovalKey, Account, Tokens>,
) {
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
        in_memory_ledger.process_mint(to, &Tokens::from(mint_amount));
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
        in_memory_ledger.process_transfer(
            &from,
            &to,
            &None,
            &Tokens::from(transfer_amount),
            &Some(fee),
        );
    }
    // Approve
    println!("approving");
    for i in 0..NUM_TRANSACTIONS_PER_TYPE {
        let from = accounts[i];
        let spender = accounts[(i + 1) % NUM_TRANSACTIONS_PER_TYPE];
        let current_allowance = in_memory_ledger
            .get_allowance_if_set(&from, &spender)
            .unwrap_or(Allowance::default());
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
                expected_allowance: Some(Nat::from(current_allowance.amount)),
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
        in_memory_ledger.process_approve(
            &from,
            &spender,
            &Tokens::from(approve_amount),
            &Some(current_allowance.amount),
            &Some(expires_at),
            &Some(fee),
            TimeStamp::from_nanos_since_unix_epoch(
                state_machine
                    .time()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64,
            ),
        );
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
        in_memory_ledger.process_transfer(
            &from,
            &to,
            &Some(spender),
            &Tokens::from(transfer_from_amount),
            &Some(fee),
        );
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
        in_memory_ledger.process_transfer(
            from,
            &minter_account,
            &None,
            &Tokens::from(burn_amount),
            &None,
        );
    }
    println!(
        "generated {} transactions in {:?}",
        NUM_TRANSACTIONS_PER_TYPE * 5,
        start.elapsed()
    );
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
