use crate::address::DogecoinAddress;
use crate::candid_api::GetDogeAddressArgs;
use crate::lifecycle::init::Network;
use candid::Principal;
use ic_cdk::management_canister::EcdsaPublicKeyResult;
use ic_ckbtc_minter::state::read_state;
use icrc_ledger_types::icrc1::account::Account;

pub async fn get_doge_address(
    GetDogeAddressArgs { owner, subaccount }: GetDogeAddressArgs,
) -> Result<String, ic_cdk::call::Error> {
    let owner = owner.unwrap_or_else(ic_cdk::api::msg_caller);
    let account = Account { owner, subaccount };
    assert_ne!(
        owner,
        Principal::anonymous(),
        "the owner must be non-anonymous"
    );
    ic_ckbtc_minter::updates::get_btc_address::init_ecdsa_public_key().await;
    let (ecdsa_key_name, network) =
        read_state(|s| (s.ecdsa_key_name.clone(), Network::from(s.btc_network)));
    let public_key: [u8; 33] = derive_public_key(ecdsa_key_name, &account)
        .await?
        .public_key
        .try_into()
        .expect("BUG: invalid ECDSA compressed public key");
    Ok(DogecoinAddress::from_compressed_public_key(&public_key).display(&network))
}

/// Returns the derivation path that should be used to sign a message from a
/// specified account.
pub fn derivation_path(account: &Account) -> Vec<Vec<u8>> {
    const SCHEMA_V1: u8 = 1;
    const PREFIX: [u8; 4] = [b'd', b'o', b'g', b'e'];

    vec![
        vec![SCHEMA_V1],
        PREFIX.to_vec(),
        account.owner.as_slice().to_vec(),
        account.effective_subaccount().to_vec(),
    ]
}

pub async fn derive_public_key(
    ecdsa_key_name: String,
    account: &Account,
) -> Result<EcdsaPublicKeyResult, ic_cdk::call::Error> {
    use ic_cdk::management_canister as mgmt;

    mgmt::ecdsa_public_key(&mgmt::EcdsaPublicKeyArgs {
        derivation_path: derivation_path(account),
        key_id: mgmt::EcdsaKeyId {
            curve: mgmt::EcdsaCurve::Secp256k1,
            name: ecdsa_key_name,
        },
        ..Default::default()
    })
    .await
}
