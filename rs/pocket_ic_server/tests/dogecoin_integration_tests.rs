use bitcoin::dogecoin::{Address, Network as DogeNetwork};
use candid::{CandidType, Encode, Nat, Principal};
use ic_btc_adapter_test_utils::{
    bitcoind::{Conf, Daemon},
    rpc_client::RpcError,
};
use ic_doge_interface::Network;
use pocket_ic::common::rest::{IcpFeatures, IcpFeaturesConfig};
use pocket_ic::{PocketIc, PocketIcBuilder, update_candid};
use std::str::FromStr;
use std::time::SystemTime;

#[derive(CandidType, serde::Deserialize)]
pub struct SendRequest {
    pub destination_address: String,
    pub amount_in_koinu: u64,
}

fn deploy_dogecoin_example_canister(pic: &PocketIc) -> Principal {
    const T: u128 = 1_000_000_000_000;
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100 * T);
    let dogecoin_example_canister_path = std::env::var_os("DOGECOIN_EXAMPLE_CANISTER_WASM")
        .expect("Missing DOGECOIN_EXAMPLE_CANISTER_WASM environment variable (path to dogecoin example canister WASM file).");
    let dogecoin_example_canister_wasm = std::fs::read(dogecoin_example_canister_path)
        .expect("Could not read dogecoin example canister WASM file.");
    pic.install_canister(
        canister_id,
        dogecoin_example_canister_wasm.to_vec(),
        Encode!(&Network::Regtest).unwrap(),
        None,
    );
    canister_id
}

fn get_balance(
    pic: &PocketIc,
    dogecoin_example_canister_id: Principal,
    dogecoin_address: String,
) -> u64 {
    loop {
        if let Ok((balance,)) = update_candid::<_, (Nat,)>(
            pic,
            dogecoin_example_canister_id,
            "get_balance",
            (dogecoin_address.clone(),),
        ) {
            break balance.0.try_into().unwrap();
        }
    }
}

#[test]
fn dogecoin_integration_test() {
    let dogecoind_path = std::env::var("DOGECOIND_BIN")
        .expect("Missing DOGECOIND_BIN (path to dogecoind executable) in env.");
    let conf = Conf {
        p2p: true,
        ..Conf::default()
    };
    let dogecoind = Daemon::new(&dogecoind_path, DogeNetwork::Regtest, conf);

    let icp_features = IcpFeatures {
        dogecoin: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet() // to have tECDSA keys available
        .with_bitcoin_subnet()
        .with_application_subnet() // to deploy the test dapp
        .with_dogecoind_addrs(vec![dogecoind.p2p_socket().unwrap().into()])
        .with_icp_features(icp_features)
        .build();

    pic.set_time(SystemTime::now().into());

    let dogecoin_example_canister_id = deploy_dogecoin_example_canister(&pic);
    let dogecoin_address = update_candid::<_, (String,)>(
        &pic,
        dogecoin_example_canister_id,
        "get_p2pkh_address",
        ((),),
    )
    .unwrap()
    .0;

    let another_dogecoin_example_canister_id = deploy_dogecoin_example_canister(&pic);
    let another_dogecoin_address = update_candid::<_, (String,)>(
        &pic,
        another_dogecoin_example_canister_id,
        "get_p2pkh_address",
        ((),),
    )
    .unwrap()
    .0;

    let doge_rpc = &dogecoind.rpc_client;

    // `n` must be more than 60 (Coinbase maturity rule) so that the reward for the first block can be sent out
    let n = 61;
    // retry generating blocks until the dogecoind is up and running
    let start = std::time::Instant::now();
    loop {
        match doge_rpc.generate_to_address(
            n,
            &Address::from_str(&dogecoin_address)
                .unwrap()
                .assume_checked(),
        ) {
            Ok(_) => break,
            Err(RpcError::JsonRpc(err)) => {
                if start.elapsed() > std::time::Duration::from_secs(30) {
                    panic!("Timed out when waiting for dogecoind; last error: {err}");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(err) => panic!("Unexpected error when talking to dogecoind: {err:?}"),
        }
    }

    let reward = 500_000 * 100_000_000; // 500,000 DOGE

    loop {
        if get_balance(&pic, dogecoin_example_canister_id, dogecoin_address.clone()) == n * reward {
            break;
        }
    }

    let send_amount = 100_000_000; // 1 DOGE
    let send_request = SendRequest {
        destination_address: another_dogecoin_address.clone(),
        amount_in_koinu: send_amount,
    };
    update_candid::<_, (String,)>(
        &pic,
        dogecoin_example_canister_id,
        "send_from_p2pkh_address",
        (send_request,),
    )
    .unwrap();

    loop {
        if get_balance(
            &pic,
            dogecoin_example_canister_id,
            another_dogecoin_address.clone(),
        ) == send_amount
        {
            break;
        } else {
            doge_rpc
                .generate_to_address(
                    1,
                    &Address::from_str(&dogecoin_address)
                        .unwrap()
                        .assume_checked(),
                )
                .unwrap();
        }
    }
}
