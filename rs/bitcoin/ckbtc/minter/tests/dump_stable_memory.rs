use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_btc_interface::Network;
use ic_ckbtc_minter::lifecycle::init::{InitArgs as CkbtcMinterInitArgs, MinterArg};
use ic_ckbtc_minter::state::eventlog::Event;
use ic_ckbtc_minter::state::Mode;
use ic_test_utilities_load_wasm::load_wasm;
use pocket_ic::{PocketIc, PocketIcBuilder};
use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetEventsResult {
    pub events: Vec<Event>,
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
        env.install_canister(
            bitcoin_id,
            bitcoin_mock_wasm(),
            Encode!(&btc_network).unwrap(),
            None,
        );

        let ledger_id = env.create_canister();
        let minter_id = env.create_canister();
        let btc_checker_id = env.create_canister();
        env.add_cycles(minter_id, 100_000_000_000_000);

        let init_args = Encode!(&MinterArg::Init(CkbtcMinterInitArgs {
            btc_network: btc_network.into(),
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

        // println!("{:02x?}", init_args);

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

fn bitcoin_mock_wasm() -> Vec<u8> {
    load_wasm(
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("mock"),
        "ic-bitcoin-canister-mock",
        &[],
    )
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
        btc_network: Network::Regtest.into(),
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

fn upload_events_and_dump_stable_memory<Out: Write>(input_file: &str, mut output: Out) {
    let setup = Setup::new(Network::Mainnet);
    upload_events(&setup, input_file);

    let mem = setup.env.get_stable_memory(setup.minter_id);
    output.write_all(&mem).unwrap();
}

// This is used by Bazel to build an executable.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        panic!("Expecting path to events.gz file as argument");
    }
    upload_events_and_dump_stable_memory(&args[1], std::io::stdout());
}

#[test]
fn test_minter_dump_stable_mem_mainnet() {
    fn path_to_events_file(file_name: &str) -> PathBuf {
        let mut path = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        path.push(format!("test_resources/{}", file_name));
        path
    }
    let input_file = path_to_events_file("mainnet_events.gz");
    let mem_path = path_to_events_file("mainnet_events.mem");
    let file = std::fs::File::create(mem_path).unwrap();
    upload_events_and_dump_stable_memory(input_file.to_str().unwrap(), file);
}
