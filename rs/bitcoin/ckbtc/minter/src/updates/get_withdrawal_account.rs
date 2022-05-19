use candid::{CandidType, Deserialize};
use ic_base_types::PrincipalId;
use ic_ckbtc_minter::runtime::Runtime;
use ic_crypto_sha::Sha256;
use ic_ledger_types::{AccountIdentifier, Subaccount, DEFAULT_SUBACCOUNT};
use serde::Serialize;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetWithdrawalAccountResult {
    pub account: AccountIdentifier,
}

/// Deterministically computes a ckBTC Ledger account ID based on the ckBTC Minter’s principal ID and the caller’s principal ID.
pub fn get_withdrawal_account(runtime: &dyn Runtime) -> GetWithdrawalAccountResult {
    let ck_btc_principal = runtime.id();
    let caller = runtime.caller();
    let caller_subaccount: Subaccount = compute_subaccount(PrincipalId(caller), 0);
    // Check that the computed subaccount doesn't collide with minting account.
    if caller_subaccount == DEFAULT_SUBACCOUNT {
        panic!(
            "Subaccount collision with principal {}. Please contact DFINITY support.",
            caller
        );
    }
    let account = AccountIdentifier::new(&ck_btc_principal, &caller_subaccount);
    GetWithdrawalAccountResult { account }
}

/// Compute the subaccount of a principal based on a given nonce.
fn compute_subaccount(controller: PrincipalId, nonce: u64) -> Subaccount {
    const DOMAIN: &[u8] = b"ckbtc";
    const DOMAIN_LENGTH: [u8; 1] = [0x05];
    Subaccount({
        let mut hasher = Sha256::new();
        hasher.write(&DOMAIN_LENGTH);
        hasher.write(DOMAIN);
        hasher.write(controller.as_slice());
        hasher.write(&nonce.to_be_bytes());
        hasher.finish()
    })
}

#[cfg(test)]
mod tests {
    use crate::updates::get_withdrawal_account::compute_subaccount;
    use ic_base_types::PrincipalId;
    use ic_ledger_types::Subaccount;
    use std::str::FromStr;

    #[test]
    fn test_compute_subaccount() {
        let pid: PrincipalId = PrincipalId::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
        let expected: [u8; 32] = [
            211, 145, 143, 138, 238, 246, 17, 130, 84, 217, 3, 153, 163, 32, 123, 31, 160, 98, 150,
            15, 94, 27, 22, 100, 63, 46, 142, 251, 144, 173, 213, 69,
        ];
        assert_eq!(Subaccount(expected), compute_subaccount(pid, 0));
    }
}
