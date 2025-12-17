use candid::{CandidType, Encode, Principal};
use ic_btc_adapter_test_utils::{
    bitcoin::{Address, Network as BtcNetwork},
    bitcoind::{Conf, Daemon},
    rpc_client::RpcError,
};
use ic_btc_interface::Network;
use pocket_ic::common::rest::{IcpFeatures, IcpFeaturesConfig};
use pocket_ic::{PocketIc, PocketIcBuilder, update_candid};
use std::str::FromStr;
use std::time::SystemTime;

#[derive(CandidType, serde::Deserialize)]
pub struct SendRequest {
    pub destination_address: String,
    pub amount_in_satoshi: u64,
}

fn deploy_bitcoin_example_canister(pic: &PocketIc) -> Principal {
    const T: u128 = 1_000_000_000_000;
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100 * T);
    let bitcoin_example_canister_path = std::env::var_os("BITCOIN_EXAMPLE_CANISTER_WASM")
        .expect("Missing BITCOIN_EXAMPLE_CANISTER_WASM environment variable (path to bitcoin example canister WASM file).");
    let bitcoin_example_canister_wasm = std::fs::read(bitcoin_example_canister_path)
        .expect("Could not read bitcoin example canister WASM file.");
    pic.install_canister(
        canister_id,
        bitcoin_example_canister_wasm.to_vec(),
        Encode!(&Network::Regtest).unwrap(),
        None,
    );
    canister_id
}

fn get_balance(
    pic: &PocketIc,
    bitcoin_example_canister_id: Principal,
    bitcoin_address: String,
) -> u64 {
    loop {
        if let Ok((balance,)) = update_candid::<_, (u64,)>(
            pic,
            bitcoin_example_canister_id,
            "get_balance",
            (bitcoin_address.clone(),),
        ) {
            break balance;
        }
    }
}

#[test]
fn bitcoin_integration_test() {
    let bitcoind_path = std::env::var("BITCOIND_BIN")
        .expect("Missing BITCOIND_BIN (path to bitcoind executable) in env.");
    let conf = Conf {
        p2p: true,
        ..Conf::default()
    };
    let bitcoind = Daemon::new(&bitcoind_path, BtcNetwork::Regtest, conf);

    let icp_features = IcpFeatures {
        bitcoin: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet() // to have tECDSA keys available
        .with_bitcoin_subnet()
        .with_application_subnet() // to deploy the test dapp
        .with_bitcoind_addr(bitcoind.p2p_socket().unwrap().into())
        .with_icp_features(icp_features)
        .build();

    pic.set_time(SystemTime::now().into());

    let bitcoin_example_canister_id = deploy_bitcoin_example_canister(&pic);
    let bitcoin_address = update_candid::<_, (String,)>(
        &pic,
        bitcoin_example_canister_id,
        "get_p2pkh_address",
        ((),),
    )
    .unwrap()
    .0;

    let another_bitcoin_example_canister_id = deploy_bitcoin_example_canister(&pic);
    let another_bitcoin_address = update_candid::<_, (String,)>(
        &pic,
        another_bitcoin_example_canister_id,
        "get_p2pkh_address",
        ((),),
    )
    .unwrap()
    .0;

    let btc_rpc = &bitcoind.rpc_client;

    // `n` must be more than 100 (Coinbase maturity rule) so that the reward for the first block can be sent out
    let n = 101;
    // retry generating blocks until the bitcoind is up and running
    let start = std::time::Instant::now();
    loop {
        match btc_rpc.generate_to_address(
            n,
            &Address::from_str(&bitcoin_address)
                .unwrap()
                .assume_checked(),
        ) {
            Ok(_) => break,
            Err(RpcError::JsonRpc(err)) => {
                if start.elapsed() > std::time::Duration::from_secs(30) {
                    panic!("Timed out when waiting for bitcoind; last error: {err}");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err) => panic!("Unexpected error when talking to bitcoind: {err:?}"),
        }
    }

    let reward = 50 * 100_000_000; // 50 BTC

    loop {
        if get_balance(&pic, bitcoin_example_canister_id, bitcoin_address.clone()) == n * reward {
            break;
        }
    }

    let send_amount = 100_000_000; // 1 BTC
    let send_request = SendRequest {
        destination_address: another_bitcoin_address.clone(),
        amount_in_satoshi: send_amount,
    };
    update_candid::<_, (String,)>(
        &pic,
        bitcoin_example_canister_id,
        "send_from_p2pkh_address",
        (send_request,),
    )
    .unwrap();

    loop {
        if get_balance(
            &pic,
            bitcoin_example_canister_id,
            another_bitcoin_address.clone(),
        ) == send_amount
        {
            break;
        } else {
            btc_rpc
                .generate_to_address(
                    1,
                    &Address::from_str(&bitcoin_address)
                        .unwrap()
                        .assume_checked(),
                )
                .unwrap();
        }
    }
}
