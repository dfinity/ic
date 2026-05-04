use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;
use icrc_ledger_types::icrc1::account::{Account, DEFAULT_SUBACCOUNT, Subaccount};

use super::get_btc_address::init_ecdsa_public_key;

/// Deterministically computes a ckBTC Ledger account ID based on the ckBTC Minter’s principal ID and the caller’s principal ID.
pub async fn get_withdrawal_account() -> Account {
    let caller = PrincipalId(ic_cdk::api::msg_caller());
    init_ecdsa_public_key().await;
    let ck_btc_principal = ic_cdk::api::canister_self();
    let caller_subaccount: Subaccount = compute_subaccount(caller, 0);
    // Check that the computed subaccount doesn't collide with minting account.
    if &caller_subaccount == DEFAULT_SUBACCOUNT {
        panic!("Subaccount collision with principal {caller}. Please contact DFINITY support.");
    }
    Account {
        owner: ck_btc_principal,
        subaccount: Some(caller_subaccount),
    }
}

/// Compute the subaccount of a principal based on a given nonce.
pub fn compute_subaccount(controller: PrincipalId, nonce: u64) -> Subaccount {
    const DOMAIN: &[u8] = b"ckbtc";
    const DOMAIN_LENGTH: [u8; 1] = [0x05];

    let mut hasher = Sha256::new();
    hasher.write(&DOMAIN_LENGTH);
    hasher.write(DOMAIN);
    hasher.write(controller.as_slice());
    hasher.write(&nonce.to_be_bytes());
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use crate::updates::get_withdrawal_account::compute_subaccount;
    use ic_base_types::PrincipalId;
    use std::str::FromStr;

    #[test]
    fn test_compute_subaccount() {
        let pid: PrincipalId = PrincipalId::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
        let expected: [u8; 32] = [
            211, 145, 143, 138, 238, 246, 17, 130, 84, 217, 3, 153, 163, 32, 123, 31, 160, 98, 150,
            15, 94, 27, 22, 100, 63, 46, 142, 251, 144, 173, 213, 69,
        ];
        assert_eq!(expected, compute_subaccount(pid, 0));
    }
}
