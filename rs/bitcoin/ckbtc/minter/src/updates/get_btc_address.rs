use crate::{
    logs::P1,
    state::{mutate_state, read_state, CkBtcMinterState},
    ECDSAPublicKey,
};
use candid::{CandidType, Deserialize, Principal};
use ic_canister_log::log;
use ic_management_canister_types::DerivationPath;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use serde::Serialize;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GetBtcAddressArgs {
    pub owner: Option<Principal>,
    pub subaccount: Option<Subaccount>,
}

/// PRECONDITION: s.ecdsa_public_key.is_some()
pub fn account_to_p2wpkh_address_from_state(s: &CkBtcMinterState, account: &Account) -> String {
    crate::address::account_to_p2wpkh_address(
        s.btc_network,
        s.ecdsa_public_key
            .as_ref()
            .expect("bug: the ECDSA public key must be initialized"),
        account,
    )
}

pub async fn get_btc_address(args: GetBtcAddressArgs) -> String {
    let owner = args.owner.unwrap_or_else(ic_cdk::caller);

    init_ecdsa_public_key().await;

    read_state(|s| {
        account_to_p2wpkh_address_from_state(
            s,
            &Account {
                owner,
                subaccount: args.subaccount,
            },
        )
    })
}

/// Initializes the Minter ECDSA public key. This function must be called
/// before any endpoint runs its logic.
pub async fn init_ecdsa_public_key() -> ECDSAPublicKey {
    if let Some(key) = read_state(|s| s.ecdsa_public_key.clone()) {
        return key;
    };
    let key_name = read_state(|s| s.ecdsa_key_name.clone());
    log!(P1, "Fetching the ECDSA public key {}", &key_name);
    let ecdsa_public_key =
        crate::management::ecdsa_public_key(key_name, DerivationPath::new(vec![]))
            .await
            .unwrap_or_else(|e| ic_cdk::trap(&format!("failed to retrieve ECDSA public key: {e}")));
    log!(
        P1,
        "ECDSA public key set to {}, chain code to {}",
        hex::encode(&ecdsa_public_key.public_key),
        hex::encode(&ecdsa_public_key.chain_code)
    );
    mutate_state(|s| {
        s.ecdsa_public_key = Some(ecdsa_public_key.clone());
    });
    ecdsa_public_key
}

#[cfg(test)]
mod tests {
    use ic_btc_interface::Network;

    use crate::address::network_and_public_key_to_p2wpkh;

    fn check_network_and_public_key_result(network: Network, pk_hex: &str, expected: &str) {
        assert_eq!(
            network_and_public_key_to_p2wpkh(network, &hex::decode(pk_hex).unwrap()),
            expected,
            "network: {} pk_hey: {}",
            network,
            pk_hex
        );
    }

    #[test]
    fn network_and_public_key_to_p2wpkh_mainnet() {
        // example taken from https://en.bitcoin.it/wiki/BIP_0173
        check_network_and_public_key_result(
            Network::Mainnet,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        );
    }

    #[test]
    fn network_and_public_key_to_p2wpkh_testnet() {
        // example taken from https://en.bitcoin.it/wiki/BIP_0173
        check_network_and_public_key_result(
            Network::Testnet,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        );
    }

    #[test]
    fn network_and_public_key_to_p2wpkh_test() {
        // example taken from http://bitcoinscri.pt/pages/segwit_native_p2wpkh_address
        check_network_and_public_key_result(
            Network::Mainnet,
            "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7",
            "bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck",
        );
    }

    #[test]
    fn network_and_public_key_to_p2wpkh_random() {
        // generated from https://secretscan.org/Bech32
        let pk_p2wpkhs = [
            (
                "02cc66d74b61bc47ea4985692974e49354f4e2c6623a470db3b2452be83fba341c",
                "bc1qs78u0r46979lgtv6dyrmwc859s35k2tn355r9d",
            ),
            (
                "035dcb63b5f7485efbd5d4546d87adde5d3410dc42063e21989f0abcc2ba06ce92",
                "bc1qcu2ah8ed2f4p3xyz9za3t56kcttdz0lchc20ws",
            ),
            (
                "036459e0847455a60ead262da40169fff31b2fcfb89f0398d328760c67d2848d91",
                "bc1q4plljhyk2wrp5j3eucq2seng8lczsspfuczvd9",
            ),
            (
                "03fe5aae628ef0311c567b6cca0229a66ce1000b09aaadfbe7fdfb51a299578f39",
                "bc1q7vv3ux23nfrf3qnampcyl2apljsyhz29twdazt",
            ),
            (
                "02c7961cebf8565ea23ab79d9b82e9afd34ac0490bc44590f58b6fd5a2d9f341f8",
                "bc1qjlkzt2fvc44j2kzex88lsjffcn7g4l4ren0e0w",
            ),
        ];
        for (pk, p2wpkhs) in pk_p2wpkhs {
            check_network_and_public_key_result(Network::Mainnet, pk, p2wpkhs);
        }
    }
}
