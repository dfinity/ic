use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use candid::{Decode, Encode, Principal};
use hex::FromHex;
use ic_base_types::CanisterId;
use ic_bitcoin_canister_mock::PushUtxoToAddress;
use ic_btc_interface::{
    GetCurrentFeePercentilesRequest, GetUtxosRequest, GetUtxosResponse, MillisatoshiPerByte,
    Network, NetworkInRequest, OutPoint, SendTransactionRequest, Utxo,
};
use ic_state_machine_tests::StateMachine;
use ic_test_utilities_load_wasm::load_wasm;
use rand::{thread_rng, Rng};

fn generate_tx_id() -> Vec<u8> {
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

fn install_bitcoin_mock_canister(env: &StateMachine) -> CanisterId {
    let args = Network::Regtest;
    env.install_canister(bitcoin_mock_wasm(), Encode!(&args).unwrap(), None)
        .unwrap()
}

#[test]
fn test_install_bitcoin_mock_canister() {
    let env = StateMachine::new();
    let mock_id = install_bitcoin_mock_canister(&env);

    let p1 = Principal::management_canister();
    let btc_address0 = "31xxvrZWyZohLR5CKE3wTqur6rbEfi5HUz";
    let btc_address1 = "36d8AewQvoKjHPbaeFFkqJHpoZ8wnrTMeU";

    let value: u64 = 100_000_000;

    let _ = env.execute_ingress_as(
        p1.into(),
        mock_id,
        "push_utxo_to_address",
        Encode!(&PushUtxoToAddress {
            address: btc_address0.to_string(),
            utxo: Utxo {
                height: 0,
                outpoint: OutPoint {
                    txid: generate_tx_id(),
                    vout: 1_u32,
                },
                value,
            },
        })
        .unwrap(),
    );

    // This transaction correspond to one input and two outputs.
    // You can decode it online using the following tool:
    // https://live.blockcypher.com/btc/decodetx/
    let tx = "01000000000101b5cee87f1a60915c38bb0bc26aaf2b67be2b890bbc54bb4be1e40272e0d2fe0b0000000000ffffffff025529000000000000225120106daad8a5cb2e6fc74783714273bad554a148ca2d054e7a19250e9935366f3033760000000000002200205e6d83c44f57484fd2ef2a62b6d36cdcd6b3e06b661e33fd65588a28ad0dbe060141df9d1bfce71f90d68bf9e9461910b3716466bfe035c7dbabaa7791383af6c7ef405a3a1f481488a91d33cd90b098d13cb904323a3e215523aceaa04e1bb35cdb0100000000";
    let _ = env.execute_ingress_as(
        p1.into(),
        mock_id,
        "bitcoin_send_transaction",
        Encode!(&SendTransactionRequest {
            transaction: Vec::from_hex(tx).unwrap(),
            network: NetworkInRequest::Mainnet
        })
        .unwrap(),
    );

    let result = Decode!(
        &env.execute_ingress_as(
            p1.into(),
            mock_id,
            "bitcoin_get_utxos",
            Encode!(&GetUtxosRequest {
                address: btc_address0.to_string(),
                filter: None,
                network: NetworkInRequest::Mainnet
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
        &env.execute_ingress_as(
            p1.into(),
            mock_id,
            "bitcoin_get_utxos",
            Encode!(&GetUtxosRequest {
                address: btc_address1.to_string(),
                filter: None,
                network: NetworkInRequest::Mainnet
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
        &env.execute_ingress_as(p1.into(), mock_id, "get_mempool", Encode!().unwrap())
            .unwrap()
            .bytes(),
        Vec<Vec<u8>>
    )
    .expect("failed to decode get_mempool response");
    assert_eq!(mempool.len(), 1);

    let tx = deserialize::<Transaction>(&mempool[0]).expect("failed to parse transaction");
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);

    let _ = env.execute_ingress_as(p1.into(), mock_id, "reset_mempool", Encode!().unwrap());
    let mempool: Vec<Vec<u8>> = Decode!(
        &env.execute_ingress_as(p1.into(), mock_id, "get_mempool", Encode!().unwrap())
            .unwrap()
            .bytes(),
        Vec<Vec<u8>>
    )
    .expect("failed to decode get_mempool response");
    assert_eq!(mempool.len(), 0);

    let fee: Vec<MillisatoshiPerByte> = [100; 100].into();
    let _ = env.execute_ingress_as(
        p1.into(),
        mock_id,
        "set_fee_percentiles",
        Encode!(&fee).unwrap(),
    );

    let median_fee = Decode!(
        &env.execute_ingress_as(
            p1.into(),
            mock_id,
            "bitcoin_get_current_fee_percentiles",
            Encode!(&GetCurrentFeePercentilesRequest {
                network: NetworkInRequest::Mainnet
            })
            .unwrap(),
        )
        .unwrap()
        .bytes(),
        Vec<MillisatoshiPerByte>
    )
    .expect("failed to decode bitcoin_get_current_fee_percentiles");

    assert_eq!(fee[50], median_fee[50]);
}
