use crate::Network;
use crate::dogecoin_canister::get_dogecoin_canister_id;

#[test]
fn should_have_correct_dogecoin_canister_id() {
    assert_eq!(
        get_dogecoin_canister_id(&Network::Mainnet).to_string(),
        "gordg-fyaaa-aaaan-aaadq-cai"
    );

    assert_eq!(
        get_dogecoin_canister_id(&Network::Testnet).to_string(),
        "hd7hi-kqaaa-aaaan-aaaea-cai"
    );

    assert_eq!(
        get_dogecoin_canister_id(&Network::Regtest).to_string(),
        "hd7hi-kqaaa-aaaan-aaaea-cai"
    );
}
