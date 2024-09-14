use bitcoincore_rpc::{bitcoin::Address, Auth, Client, RpcApi};
use candid::{CandidType, Encode, Principal};
use ic_btc_interface::{Config, Fees, Flag, Network};
use ic_config::execution_environment::BITCOIN_TESTNET_CANISTER_ID;
use ic_nns_constants::ROOT_CANISTER_ID;
use pocket_ic::{update_candid, PocketIc, PocketIcBuilder};
use std::fs::{copy, create_dir, File};
use std::io::Write;
use std::process::Command;
use std::str::FromStr;
use tempfile::tempdir;

#[derive(CandidType, serde::Deserialize)]
pub struct SendRequest {
    pub destination_address: String,
    pub amount_in_satoshi: u64,
}

fn deploy_btc_canister(pic: &PocketIc) {
    let root_canister_id: Principal = ROOT_CANISTER_ID.into();
    let btc_canister_id = Principal::from_text(BITCOIN_TESTNET_CANISTER_ID).unwrap();
    let actual_canister_id = pic
        .create_canister_with_id(Some(root_canister_id), None, btc_canister_id)
        .unwrap();
    assert_eq!(actual_canister_id, btc_canister_id);

    let btc_path =
        std::env::var_os("BTC_WASM").expect("Missing BTC_WASM (path to BTC canister wasm) in env.");
    let btc_wasm = std::fs::read(btc_path).expect("Could not read BTC canister wasm file.");
    // default values: https://github.com/dfinity/bitcoin-canister/blob/52c160168c478d5bce34b7dc5bacb78243c9d8aa/interface/src/lib.rs#L651
    let args = Config {
        stability_threshold: 0,
        network: Network::Regtest,
        blocks_source: Principal::management_canister(),
        syncing: Flag::Enabled,
        fees: Fees::default(),
        api_access: Flag::Enabled,
        disable_api_if_not_fully_synced: Flag::Enabled,
        watchdog_canister: None,
        burn_cycles: Flag::Disabled,
        lazily_evaluate_fee_percentiles: Flag::Disabled,
    };
    pic.install_canister(
        btc_canister_id,
        btc_wasm,
        Encode!(&args).unwrap(),
        Some(root_canister_id),
    );
}

fn deploy_basic_bitcoin_canister(pic: &PocketIc) -> Principal {
    const T: u128 = 1_000_000_000_000;
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100 * T);
    let basic_bitcoin_path = std::env::var_os("BASIC_BITCOIN_WASM")
        .expect("Missing BASIC_BITCOIN_WASM (path to basic_bitcoin canister wasm) in env.");
    let basic_bitcoin_wasm = std::fs::read(basic_bitcoin_path)
        .expect("Could not read basic_bitcoin canister wasm file.");
    pic.install_canister(
        canister_id,
        basic_bitcoin_wasm.to_vec(),
        Encode!(&Network::Regtest).unwrap(),
        None,
    );
    canister_id
}

#[test]
fn bitcoin_integration_test() {
    let tmp_dir = tempdir().unwrap();

    let bitcoind_path = tmp_dir.path().join("bitcoind");
    let bitcoind_env = std::env::var_os("BITCOIND_BIN")
        .expect("Missing BITCOIND_BIN (path to bitcoind executable) in env.");
    copy(bitcoind_env, bitcoind_path.clone()).unwrap();

    let conf_path = tmp_dir.path().join("bitcoin.conf");
    let mut conf = File::create(conf_path.clone()).unwrap();
    conf.write_all(r#"regtest=1
# Dummy credentials for bitcoin RPC.
rpcuser=ic-btc-integration
rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E=
rpcauth=ic-btc-integration:cdf2741387f3a12438f69092f0fdad8e$62081498c98bee09a0dce2b30671123fa561932992ce377585e8e08bb0c11dfa"#.as_bytes()).unwrap();
    drop(conf);

    let data_dir_path = tmp_dir.path().join("data");
    create_dir(data_dir_path.clone()).unwrap();

    Command::new(bitcoind_path)
        .arg(format!("-conf={}", conf_path.display()))
        .arg(format!("-datadir={}", data_dir_path.display()))
        .spawn()
        .unwrap();

    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_bitcoin_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build();
    pic.auto_progress(); // bitcoind uses real time
    deploy_btc_canister(&pic);

    let basic_bitcoin_canister_id = deploy_basic_bitcoin_canister(&pic);
    let bitcoin_address =
        update_candid::<_, (String,)>(&pic, basic_bitcoin_canister_id, "get_p2pkh_address", ((),))
            .unwrap()
            .0;

    let another_basic_bitcoin_canister_id = deploy_basic_bitcoin_canister(&pic);
    let another_bitcoin_address = update_candid::<_, (String,)>(
        &pic,
        another_basic_bitcoin_canister_id,
        "get_p2pkh_address",
        ((),),
    )
    .unwrap()
    .0;

    let btc_rpc = Client::new(
        "http://127.0.0.1:18443",
        Auth::UserPass(
            "ic-btc-integration".to_string(),
            "QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E=".to_string(),
        ),
    )
    .unwrap();

    let mut n = 101; // must be more than 100 (Coinbase maturity rule)
    btc_rpc
        .generate_to_address(n, &Address::from_str(&bitcoin_address).unwrap())
        .unwrap();

    let reward = 50 * 100_000_000; // 50 BTC

    loop {
        if let Ok((balance,)) = update_candid::<_, (u64,)>(
            &pic,
            basic_bitcoin_canister_id,
            "get_balance",
            (bitcoin_address.clone(),),
        ) {
            if balance == n * reward {
                break;
            }
        }
    }

    let send_amount = 100000000; // 1 BTC
    let send_request = SendRequest {
        destination_address: another_bitcoin_address.clone(),
        amount_in_satoshi: send_amount,
    };
    update_candid::<_, (String,)>(
        &pic,
        basic_bitcoin_canister_id,
        "send_from_p2pkh",
        (send_request,),
    )
    .unwrap();

    loop {
        if let Ok((balance,)) = update_candid::<_, (u64,)>(
            &pic,
            basic_bitcoin_canister_id,
            "get_balance",
            (another_bitcoin_address.clone(),),
        ) {
            if balance == send_amount {
                break;
            } else {
                btc_rpc
                    .generate_to_address(1, &Address::from_str(&bitcoin_address).unwrap())
                    .unwrap();
                n += 1;
            }
        }
    }

    loop {
        if let Ok((balance,)) = update_candid::<_, (u64,)>(
            &pic,
            basic_bitcoin_canister_id,
            "get_balance",
            (bitcoin_address.clone(),),
        ) {
            if balance == n * reward - send_amount {
                break;
            }
        }
    }
}
