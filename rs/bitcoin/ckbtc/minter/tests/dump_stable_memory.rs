use candid::{CandidType, Deserialize, Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ckbtc_minter::Network;
use ic_ckbtc_minter::lifecycle::init::{InitArgs as CkbtcMinterInitArgs, MinterArg};
use ic_ckbtc_minter::state::Mode;
use ic_ckbtc_minter::state::eventlog::CkBtcMinterEvent;
use ic_test_utilities_load_wasm::load_wasm;
use pocket_ic::{PocketIc, PocketIcBuilder};

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetEventsResult {
    pub events: Vec<CkBtcMinterEvent>,
    pub total_event_count: u64,
}

fn read_events_file(file_name: &str) -> GetEventsResult {
    use candid::Decode;
    use flate2::read::GzDecoder;
    use std::fs::File;
    use std::io::Read;

    let file = File::open(file_name).unwrap();
    let mut gz = GzDecoder::new(file);
    let mut decompressed_buffer = Vec::new();
    gz.read_to_end(&mut decompressed_buffer)
        .expect("BUG: failed to decompress events");
    Decode!(&decompressed_buffer, GetEventsResult).expect("Failed to decode events")
}

struct Setup {
    minter_id: Principal,
    env: PocketIc,
}

impl Setup {
    pub fn new(btc_network: Network) -> Self {
        let env = PocketIcBuilder::new().with_application_subnet().build();

        // install bitcoin canister
        let bitcoin_id = bitcoin_canister_id(btc_network);
        env.create_canister_with_id(None, None, bitcoin_id).unwrap();
        let ledger_id = env.create_canister();
        let minter_id = env.create_canister();
        let btc_checker_id = env.create_canister();
        env.add_cycles(minter_id, 100_000_000_000_000);

        let init_args = Encode!(&MinterArg::Init(CkbtcMinterInitArgs {
            btc_network,
            retrieve_btc_min_amount: 100_000,
            ledger_id: CanisterId::try_from(PrincipalId::from(ledger_id)).unwrap(),
            max_time_in_queue_nanos: 100,
            check_fee: Some(100),
            btc_checker_principal: Some(
                CanisterId::try_from(PrincipalId::from(btc_checker_id)).unwrap()
            ),
            ..default_init_args()
        }))
        .unwrap();
        env.install_canister(minter_id, minter_wasm(), init_args, None);
        Self { env, minter_id }
    }
}

fn bitcoin_canister_id(btc_network: Network) -> Principal {
    Principal::from_text(match btc_network {
        Network::Testnet | Network::Regtest => {
            ic_config::execution_environment::BITCOIN_TESTNET_CANISTER_ID
        }
        Network::Mainnet => ic_config::execution_environment::BITCOIN_MAINNET_CANISTER_ID,
    })
    .unwrap()
}

fn minter_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-ckbtc-minter",
        &[],
    )
}

#[allow(deprecated)]
fn default_init_args() -> CkbtcMinterInitArgs {
    CkbtcMinterInitArgs {
        btc_network: Network::Regtest,
        ecdsa_key_name: "master_ecdsa_public_key".into(),
        retrieve_btc_min_amount: 2000,
        ledger_id: CanisterId::from(0),
        max_time_in_queue_nanos: 10_000_000_000,
        min_confirmations: Some(6),
        mode: Mode::GeneralAvailability,
        check_fee: None,
        btc_checker_principal: Some(CanisterId::from(0)),
        kyt_principal: None,
        kyt_fee: None,
        get_utxos_cache_expiration_seconds: None,
        utxo_consolidation_threshold: None,
        max_num_inputs_in_transaction: None,
    }
}

fn upload_events(setup: &Setup, file_name: &str) {
    let events = read_events_file(file_name);
    let total = events.events.len();
    let mut start = 0;
    while start < total {
        let mut end = start + 2000;
        if end > total {
            end = total;
        };
        setup
            .env
            .update_call(
                setup.minter_id,
                Principal::anonymous(),
                "upload_events",
                Encode!(&events.events[start..end].to_vec()).unwrap(),
            )
            .unwrap();
        start = end;
    }
}

fn upload_events_and_dump_stable_memory(input_file: &str, output_file: &str) {
    use flate2::Compression;
    use flate2::bufread::GzEncoder;
    use std::fs::File;
    use std::io::{BufReader, BufWriter, Read, Write};

    let setup = Setup::new(Network::Mainnet);
    upload_events(&setup, input_file);
    let mem = setup.env.get_stable_memory(setup.minter_id);
    let mut gz = GzEncoder::new(BufReader::new(mem.as_slice()), Compression::best());
    let mut compressed_buffer = Vec::new();
    gz.read_to_end(&mut compressed_buffer)
        .expect("BUG: failed to compress events");
    let mut compressed_file = BufWriter::new(File::create(output_file).unwrap());
    compressed_file
        .write_all(&compressed_buffer)
        .expect("BUG: failed to write events");
}

// This is used by Bazel to build an executable.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        panic!("USAGE: {} mainnet_events.gz memory_dump.gz", args[0]);
    }
    upload_events_and_dump_stable_memory(&args[1], &args[2]);
}

#[test]
fn test_minter_dump_stable_mem_mainnet() {
    fn path_to_events_file(file_name: &str) -> String {
        let mut path = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push("test_resources");
        path.push(file_name);
        path.display().to_string()
    }
    let input_file = path_to_events_file("mainnet_events.gz");
    let output_file = path_to_events_file("mainnet_events.mem.gz");
    upload_events_and_dump_stable_memory(&input_file, &output_file);
}
