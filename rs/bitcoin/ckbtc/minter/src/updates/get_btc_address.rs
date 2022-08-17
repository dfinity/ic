use crate::{
    state::{mutate_state, read_state},
    ECDSAPublicKey,
};
use bech32::{u5, Variant};
use candid::{CandidType, Deserialize};
use ic_base_types::ic_types::Principal;
use ic_base_types::PrincipalId;
use ic_btc_types::Network;
use ic_crypto_extended_bip32::{DerivationIndex, DerivationPath, ExtendedBip32DerivationOutput};
use ic_crypto_sha::Sha256;
use ic_ic00_types::{ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId};
use ic_icrc1::{Account, Subaccount};
use ripemd::{Digest, Ripemd160};
use serde::Serialize;

const SCHEMA_V1: u8 = 1;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetBtcAddressArgs {
    pub subaccount: Option<Subaccount>,
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetBtcAddressResult {
    pub address: String,
}

/// Returns a valid extended BIP-32 derivation path from an Account (Principal + subaccount)
fn derive_public_key(account: Account) -> ECDSAPublicKey {
    let ECDSAPublicKey {
        public_key,
        chain_code,
    } = read_state(|s| s.ecdsa_public_key.clone().unwrap());
    let derivation_schema = vec![
        DerivationIndex(vec![SCHEMA_V1]),
        DerivationIndex(account.owner.as_slice().to_vec()),
        DerivationIndex(account.effective_subaccount().to_vec()),
    ];
    let ExtendedBip32DerivationOutput {
        derived_public_key,
        derived_chain_code,
    } = DerivationPath::new(derivation_schema)
        .key_derivation(&public_key, &chain_code)
        .unwrap(); // the derivation should always be possible
    ECDSAPublicKey {
        public_key: derived_public_key,
        chain_code: derived_chain_code,
    }
}

/// Calculates the p2wpkh address as described in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
///
/// Note: the public key must be compressed.
fn network_and_public_key_to_p2wpkh(network: Network, public_key: Vec<u8>) -> String {
    let data: [u8; 20] = Ripemd160::digest(&Sha256::hash(&public_key)).into();
    let witness_version: u5 = u5::try_from_u8(0).unwrap();
    let data: Vec<u5> = std::iter::once(witness_version)
        .chain(
            bech32::convert_bits(&data[..], 8, 5, true)
                .unwrap()
                .into_iter()
                .map(|b| u5::try_from_u8(b).unwrap()),
        )
        .collect();
    let hrp = match network {
        ic_btc_types::Network::Mainnet => "bc",   // mainnet
        ic_btc_types::Network::Testnet => "tb",   // testnet
        ic_btc_types::Network::Regtest => "bcrt", // it doesn't matter
    };
    bech32::encode(hrp, data, Variant::Bech32).unwrap()
}

pub async fn get_btc_address(args: GetBtcAddressArgs) -> GetBtcAddressResult {
    init_ecdsa_public_key().await;
    let caller = PrincipalId(ic_cdk::caller());
    let public_key = derive_public_key(Account {
        owner: caller,
        subaccount: args.subaccount,
    })
    .public_key;
    let address = network_and_public_key_to_p2wpkh(read_state(|s| s.btc_network), public_key);
    GetBtcAddressResult { address }
}

/// Fetches the ECDSA public key of the canister
async fn ecdsa_public_key(key_name: String, derivation_path: Vec<Vec<u8>>) -> ECDSAPublicKey {
    // Retrieve the public key of this canister at the given derivation path
    // from the ECDSA API.
    let res: (ECDSAPublicKeyResponse,) = ic_cdk::call(
        Principal::management_canister(),
        "ecdsa_public_key",
        (ECDSAPublicKeyArgs {
            canister_id: None,
            derivation_path,
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name,
            },
        },),
    )
    .await
    .unwrap();

    ECDSAPublicKey {
        public_key: res.0.public_key,
        chain_code: res.0.chain_code,
    }
}

/// Initializes the Minter ECDSA public key. This function must be called
/// before any endpoint runs its logic.
pub async fn init_ecdsa_public_key() {
    if read_state(|s| s.ecdsa_public_key.is_some()) {
        return;
    }
    let key_name = read_state(|s| s.ecdsa_key_name.clone());
    ic_cdk::println!("Fetching the ECDSA public key {}", &key_name);
    let ecdsa_public_key = ecdsa_public_key(key_name, vec![]).await;
    ic_cdk::println!(
        "ECDSA public key set to {}, chain code to {}",
        hex::encode(&ecdsa_public_key.public_key),
        hex::encode(&ecdsa_public_key.chain_code)
    );
    mutate_state(|s| {
        s.ecdsa_public_key = Some(ecdsa_public_key);
    });
}

#[cfg(test)]
mod tests {
    use ic_btc_types::Network;

    use super::network_and_public_key_to_p2wpkh;

    fn check_network_and_public_key_result(network: Network, pk_hex: &str, expected: &str) {
        assert_eq!(
            network_and_public_key_to_p2wpkh(network, hex::decode(pk_hex).unwrap()),
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
