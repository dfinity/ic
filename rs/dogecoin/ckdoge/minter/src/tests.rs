use crate::dogecoin_canister::get_dogecoin_canister_id;

#[test]
fn should_have_correct_dogecoin_canister_id() {
    assert_eq!(
        get_dogecoin_canister_id(&ic_cdk::bitcoin_canister::Network::Mainnet).to_string(),
        "gordg-fyaaa-aaaan-aaadq-cai"
    );

    assert_eq!(
        get_dogecoin_canister_id(&ic_cdk::bitcoin_canister::Network::Testnet).to_string(),
        "hd7hi-kqaaa-aaaan-aaaea-cai"
    );

    assert_eq!(
        get_dogecoin_canister_id(&ic_cdk::bitcoin_canister::Network::Regtest).to_string(),
        "hd7hi-kqaaa-aaaan-aaaea-cai"
    );
}
