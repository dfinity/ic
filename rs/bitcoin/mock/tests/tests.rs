#![allow(deprecated)]
use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use candid::{Decode, Encode};
use hex::FromHex;
use ic_base_types::{CanisterId, PrincipalId};
use ic_bitcoin_canister_mock::PushUtxosToAddress;
use ic_btc_interface::{
    GetCurrentFeePercentilesRequest, GetUtxosRequest, GetUtxosResponse, MillisatoshiPerByte,
    Network, NetworkInRequest, OutPoint, Txid, Utxo,
};
use ic_cdk::api::management_canister::bitcoin::{BitcoinNetwork, SendTransactionRequest};
use ic_state_machine_tests::{StateMachine, StateMachineBuilder};
use ic_test_utilities_load_wasm::load_wasm;
use ic_types::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use rand::{Rng, thread_rng};
use std::str::FromStr;

fn generate_tx_id() -> Txid {
    let mut rng = thread_rng();
    let mut bytes = [1u8; 32];
    rng.fill(&mut bytes);
    bytes.into()
}

fn bitcoin_mock_wasm() -> Vec<u8> {
    load_wasm(
        std::env::var("CARGO_MANIFEST_DIR").unwrap(),
        "ic-bitcoin-canister-mock",
        &[],
    )
}

fn testnet_bitcoin_canister_id() -> CanisterId {
    CanisterId::try_from(
        PrincipalId::from_str(ic_config::execution_environment::BITCOIN_TESTNET_CANISTER_ID)
            .unwrap(),
    )
    .unwrap()
}

fn install_bitcoin_mock_canister(env: &StateMachine) {
    let args = Network::Regtest;
    let cid = testnet_bitcoin_canister_id();
    env.create_canister_with_cycles(Some(cid.into()), Cycles::new(0), None);

    env.install_existing_canister(cid, bitcoin_mock_wasm(), Encode!(&args).unwrap())
        .unwrap();
}

#[test]
fn test_install_bitcoin_mock_canister() {
    let management_canister = CanisterId::try_from(PrincipalId::default()).unwrap();
    let mock_id = testnet_bitcoin_canister_id();

    let env = StateMachineBuilder::new()
        .with_default_canister_range()
        .with_extra_canister_range(mock_id..=mock_id)
        .build();

    let caller = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), vec![], None)
        .expect("failed to install the universal canister");
    install_bitcoin_mock_canister(&env);

    let proxy_call = |method, args| {
        env.execute_ingress(
            caller,
            "update",
            wasm()
                .call_simple(management_canister, method, call_args().other_side(args))
                .build(),
        )
    };

    let btc_address0 = "31xxvrZWyZohLR5CKE3wTqur6rbEfi5HUz";
    let btc_address1 = "36d8AewQvoKjHPbaeFFkqJHpoZ8wnrTMeU";

    let value: u64 = 100_000_000;

    let _ = env.execute_ingress(
        mock_id,
        "push_utxos_to_address",
        Encode!(&PushUtxosToAddress {
            address: btc_address0.to_string(),
            utxos: vec![Utxo {
                height: 0,
                outpoint: OutPoint {
                    txid: generate_tx_id(),
                    vout: 1_u32,
                },
                value,
            }],
        })
        .unwrap(),
    );

    // This transaction correspond to one input and two outputs.
    // You can decode it online using the following tool:
    // https://live.blockcypher.com/btc/decodetx/
    let tx = "01000000000101b5cee87f1a60915c38bb0bc26aaf2b67be2b890bbc54bb4be1e40272e0d2fe0b0000000000ffffffff025529000000000000225120106daad8a5cb2e6fc74783714273bad554a148ca2d054e7a19250e9935366f3033760000000000002200205e6d83c44f57484fd2ef2a62b6d36cdcd6b3e06b661e33fd65588a28ad0dbe060141df9d1bfce71f90d68bf9e9461910b3716466bfe035c7dbabaa7791383af6c7ef405a3a1f481488a91d33cd90b098d13cb904323a3e215523aceaa04e1bb35cdb0100000000";
    let _ = proxy_call(
        "bitcoin_send_transaction",
        Encode!(&SendTransactionRequest {
            transaction: Vec::from_hex(tx).unwrap(),
            network: BitcoinNetwork::Regtest,
        })
        .unwrap(),
    )
    .expect("failed to send a bitcoin transaction");

    let result = Decode!(
        &proxy_call(
            "bitcoin_get_utxos",
            Encode!(&GetUtxosRequest {
                address: btc_address0.to_string(),
                filter: None,
                network: NetworkInRequest::Regtest
            })
            .unwrap(),
        )
        .unwrap()
        .bytes(),
        GetUtxosResponse
    )
    .expect("failed to decode bitcoin_get_utxos response");
    assert_eq!(result.utxos.len(), 1);

    let result = Decode!(
        &proxy_call(
            "bitcoin_get_utxos",
            Encode!(&GetUtxosRequest {
                address: btc_address1.to_string(),
                filter: None,
                network: NetworkInRequest::Regtest
            })
            .unwrap(),
        )
        .unwrap()
        .bytes(),
        GetUtxosResponse
    )
    .expect("failed to decode bitcoin_get_utxos response");
    assert_eq!(result.utxos.len(), 0);

    let mempool: Vec<Vec<u8>> = Decode!(
        &env.execute_ingress(mock_id, "get_mempool", Encode!().unwrap())
            .unwrap()
            .bytes(),
        Vec<Vec<u8>>
    )
    .expect("failed to decode get_mempool response");
    assert_eq!(mempool.len(), 1);

    let tx: Transaction = deserialize(&mempool[0]).expect("failed to parse transaction");
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);

    let _ = env.execute_ingress(mock_id, "reset_mempool", Encode!().unwrap());
    let mempool: Vec<Vec<u8>> = Decode!(
        &env.execute_ingress(mock_id, "get_mempool", Encode!().unwrap())
            .unwrap()
            .bytes(),
        Vec<Vec<u8>>
    )
    .expect("failed to decode get_mempool response");
    assert_eq!(mempool.len(), 0);

    let fee_percentiles: Vec<MillisatoshiPerByte> = [100; 100].into();
    let _ = env.execute_ingress(
        mock_id,
        "set_fee_percentiles",
        Encode!(&fee_percentiles).unwrap(),
    );

    let decoded_percentiles = Decode!(
        &proxy_call(
            "bitcoin_get_current_fee_percentiles",
            Encode!(&GetCurrentFeePercentilesRequest {
                network: NetworkInRequest::Regtest
            })
            .unwrap(),
        )
        .unwrap()
        .bytes(),
        Vec<MillisatoshiPerByte>
    )
    .expect("failed to decode bitcoin_get_current_fee_percentiles");

    assert_eq!(fee_percentiles, decoded_percentiles);
}
