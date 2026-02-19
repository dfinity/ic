use candid::{IDLArgs, Principal};
use candid_parser::parse_idl_args;
use cargo_metadata::MetadataCommand;
use ic_cdk::bitcoin_canister::Network;
use std::path::PathBuf;

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn test_bitcoin_canister() {
    // Mainnet
    let mainnet_id = Principal::from_slice(&[0, 0, 0, 0, 1, 160, 0, 4, 1, 1]);
    let mainnet_init_args = r#"(
  record {
    api_access = variant { enabled };
    lazily_evaluate_fee_percentiles = variant { enabled };
    blocks_source = principal "aaaaa-aa";
    fees = record {
      get_current_fee_percentiles = 10_000_000 : nat;
      get_utxos_maximum = 10_000_000_000 : nat;
      get_block_headers_cycles_per_ten_instructions = 10 : nat;
      get_current_fee_percentiles_maximum = 100_000_000 : nat;
      send_transaction_per_byte = 20_000_000 : nat;
      get_balance = 10_000_000 : nat;
      get_utxos_cycles_per_ten_instructions = 10 : nat;
      get_block_headers_base = 50_000_000 : nat;
      get_utxos_base = 50_000_000 : nat;
      get_balance_maximum = 100_000_000 : nat;
      send_transaction_base = 5_000_000_000 : nat;
      get_block_headers_maximum = 10_000_000_000 : nat;
    };
    network = variant { mainnet };
    stability_threshold = 100 : nat;
    syncing = variant { enabled };
    burn_cycles = variant { enabled };
    disable_api_if_not_fully_synced = variant { enabled };
  },
)"#;
    test_network(Network::Mainnet, mainnet_id, mainnet_init_args);
    // Testnet
    let testnet_id = Principal::from_slice(&[0, 0, 0, 0, 1, 160, 0, 1, 1, 1]);
    let testnet_init_args = r#"(
  record {
    api_access = variant { enabled };
    lazily_evaluate_fee_percentiles = variant { enabled };
    blocks_source = principal "aaaaa-aa";
    fees = record {
      get_current_fee_percentiles = 4_000_000 : nat;
      get_utxos_maximum = 4_000_000_000 : nat;
      get_block_headers_cycles_per_ten_instructions = 10 : nat;
      get_current_fee_percentiles_maximum = 40_000_000 : nat;
      send_transaction_per_byte = 8_000_000 : nat;
      get_balance = 4_000_000 : nat;
      get_utxos_cycles_per_ten_instructions = 10 : nat;
      get_block_headers_base = 20_000_000 : nat;
      get_utxos_base = 20_000_000 : nat;
      get_balance_maximum = 40_000_000 : nat;
      send_transaction_base = 2_000_000_000 : nat;
      get_block_headers_maximum = 4_000_000_000 : nat;
    };
    network = variant { testnet };
    stability_threshold = 144 : nat;
    syncing = variant { enabled };
    burn_cycles = variant { enabled };
    disable_api_if_not_fully_synced = variant { enabled };
  },
)"#;
    test_network(Network::Testnet, testnet_id, testnet_init_args);
    // Regtest
    let regtest_id = testnet_id;
    let regtest_init_args = r#"(
  record {
    api_access = variant { enabled };
    lazily_evaluate_fee_percentiles = variant { enabled };
    blocks_source = principal "aaaaa-aa";
    fees = record {
      get_current_fee_percentiles = 0 : nat;
      get_utxos_maximum = 0 : nat;
      get_block_headers_cycles_per_ten_instructions = 0 : nat;
      get_current_fee_percentiles_maximum = 0 : nat;
      send_transaction_per_byte = 0 : nat;
      get_balance = 0 : nat;
      get_utxos_cycles_per_ten_instructions = 0 : nat;
      get_block_headers_base = 0 : nat;
      get_utxos_base = 0 : nat;
      get_balance_maximum = 0 : nat;
      send_transaction_base = 0 : nat;
      get_block_headers_maximum = 0 : nat;
    };
    network = variant { regtest };
    stability_threshold = 144 : nat;
    syncing = variant { enabled };
    burn_cycles = variant { enabled };
    disable_api_if_not_fully_synced = variant { enabled };
  },
)"#;
    test_network(Network::Regtest, regtest_id, regtest_init_args);
}

fn test_network(network: Network, btc_id: Principal, init_args: &str) {
    let wasm = cargo_build_canister("bitcoin_canister");
    // The Bitcoin canisters can still function without connecting to a `bitcoind` node.
    // The interface check and the cycles cost logic are still valid.
    let pic = pic_base().with_bitcoin_subnet().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 10_000_000_000_000u128); // 10 T
    pic.install_canister(canister_id, wasm, vec![], None);

    let btc_canister_wasm = std::fs::read(cache_btc_canister_wasm()).unwrap();
    let _ = pic.create_canister_with_id(None, None, btc_id).unwrap();
    pic.add_cycles(btc_id, 10_000_000_000_000u128);
    let args: IDLArgs = parse_idl_args(init_args).expect("failed to parse IDL args");
    let encoded_args = args.to_bytes().expect("failed to encode IDL args");
    pic.install_canister(btc_id, btc_canister_wasm.clone(), encoded_args, None);
    let () = update(&pic, canister_id, "execute_non_query_methods", (network,)).unwrap();
}

fn cache_btc_canister_wasm() -> PathBuf {
    const EXPECTED_TAG: &str = "release%2F2024-08-30"; // The slash is encoded as %2F in the URL
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let cargo_toml_path = dir.join("Cargo.toml");
    let target_dir = MetadataCommand::new()
        .manifest_path(&cargo_toml_path)
        .exec()
        .expect("failed to run cargo metadata")
        .target_directory;
    let artifact_dir = target_dir.join("e2e-tests-artifacts");
    std::fs::create_dir_all(&artifact_dir).expect("failed to create artifact directory");
    let tag_file = artifact_dir.join("ic-btc-canister-tag");
    let binary_file = artifact_dir.join("ic-btc-canister.wasm.gz");
    if let Ok(tag) = std::fs::read_to_string(&tag_file) {
        if tag == EXPECTED_TAG && binary_file.exists() {
            return binary_file.into();
        }
    }
    let url = format!(
        " https://github.com/dfinity/bitcoin-canister/releases/download/{EXPECTED_TAG}/ic-btc-canister.wasm.gz");
    let gz_bytes = reqwest::blocking::get(url)
        .expect("failed to download ic-btc-canister.wasm.gz")
        .bytes()
        .expect("failed to get bytes of ic-btc-canister.wasm.gz")
        .to_vec();
    std::fs::write(&binary_file, gz_bytes).expect("failed to write binary file");
    std::fs::write(tag_file, EXPECTED_TAG).expect("failed to write tag file");
    binary_file.into()
}
