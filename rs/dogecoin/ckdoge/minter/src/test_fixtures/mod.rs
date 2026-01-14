#[cfg(test)]
mod tests;

use crate::address::DogecoinAddress;
use crate::fees::DogecoinFeeEstimator;
use crate::lifecycle::init::Network;
use ic_ckbtc_minter::ECDSAPublicKey;

pub mod arbitrary;
pub mod mock;

pub fn dogecoin_fee_estimator() -> DogecoinFeeEstimator {
    const RETRIEVE_DOGE_MIN_AMOUNT: u64 = 50 * 100_000_000;
    DogecoinFeeEstimator::new(Network::Mainnet, RETRIEVE_DOGE_MIN_AMOUNT)
}

pub fn dogecoin_address_to_bitcoin(
    address: DogecoinAddress,
) -> ic_ckbtc_minter::address::BitcoinAddress {
    match address {
        DogecoinAddress::P2pkh(hash) => ic_ckbtc_minter::address::BitcoinAddress::P2pkh(hash),
        DogecoinAddress::P2sh(hash) => ic_ckbtc_minter::address::BitcoinAddress::P2sh(hash),
    }
}

pub fn canister_public_key_pair() -> (ECDSAPublicKey, ic_secp256k1::PrivateKey) {
    let canister_id = candid::Principal::from_text("ypu6c-niaaa-aaaar-qbzxa-cai").unwrap();
    let master_private_key = ic_secp256k1::PrivateKey::generate_from_seed(&[42; 32]);
    let derivation_path =
        ic_secp256k1::DerivationPath::from_canister_id_and_path(canister_id.as_slice(), &[]);
    let (canister_private_key, chain_code) = master_private_key.derive_subkey(&derivation_path);
    let canister_public_key = canister_private_key.public_key().serialize_sec1(true);

    (
        ECDSAPublicKey {
            public_key: canister_public_key,
            chain_code: chain_code.to_vec(),
        },
        canister_private_key,
    )
}
