use crate::address::DogecoinAddress;
use crate::candid_api::GetDogeAddressArgs;
use crate::lifecycle::init::Network;
use candid::Principal;
use ic_ckbtc_minter::ECDSAPublicKey;
use ic_ckbtc_minter::state::{CkBtcMinterState, read_state};
use icrc_ledger_types::icrc1::account::Account;

pub async fn get_doge_address(
    GetDogeAddressArgs { owner, subaccount }: GetDogeAddressArgs,
) -> String {
    let owner = owner.unwrap_or_else(ic_cdk::api::msg_caller);
    let account = Account { owner, subaccount };
    assert_ne!(
        owner,
        Principal::anonymous(),
        "the owner must be non-anonymous"
    );
    ic_ckbtc_minter::updates::get_btc_address::init_ecdsa_public_key().await;
    read_state(|s| {
        account_to_p2pkh_address_from_state(s, &account)
            .display(&Network::try_from(s.btc_network).expect("BUG: unsupported network"))
    })
}

pub fn account_to_p2pkh_address_from_state(
    state: &CkBtcMinterState,
    account: &Account,
) -> DogecoinAddress {
    let ecdsa_public_key = state
        .ecdsa_public_key
        .as_ref()
        .cloned()
        .expect("bug: the ECDSA public key must be initialized");
    let public_key: [u8; 33] = derive_public_key(&ecdsa_public_key, account)
        .public_key
        .try_into()
        .expect("BUG: invalid ECDSA compressed public key");
    DogecoinAddress::from_compressed_public_key(&public_key)
}

/// Returns the derivation path that should be used to sign a message from a
/// specified account.
fn derivation_path(account: &Account) -> Vec<Vec<u8>> {
    const SCHEMA_V1: u8 = 1;
    const PREFIX: [u8; 4] = *b"doge";

    vec![
        vec![SCHEMA_V1],
        PREFIX.to_vec(),
        account.owner.as_slice().to_vec(),
        account.effective_subaccount().to_vec(),
    ]
}

fn derive_public_key(ecdsa_public_key: &ECDSAPublicKey, account: &Account) -> ECDSAPublicKey {
    use ic_secp256k1::{DerivationIndex, DerivationPath};

    let path = DerivationPath::new(
        derivation_path(account)
            .into_iter()
            .map(DerivationIndex)
            .collect(),
    );
    ic_ckbtc_minter::address::derive_public_key(ecdsa_public_key, &path)
}
