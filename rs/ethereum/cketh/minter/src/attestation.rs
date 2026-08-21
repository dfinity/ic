//! The one-time attestation that binds a deposit address to the IC account its funds are credited
//! to, so that sweeping can be permissionless: the sweeper delegate recovers it and refuses any
//! account other than the attested one.
//!
//! Running as a delegate, the contract's `address(this)` is the deposit address, so only a
//! signature by *that* address' key recovers to it — a caller substituting their own principal
//! fails the check. The attestation is a public fact rather than a secret: replaying it can only
//! credit the account it already names.

#[cfg(test)]
mod tests;

use crate::deposit_address::{DepositAddressSchema, deposit_derivation_path};
use crate::eth_logs::encode_principal;
use crate::eth_rpc::Hash;
use crate::tx::sign_digest;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;

/// Domain separator of the attestation preimage. Its first byte (`0x63`) cannot collide with any
/// other preimage the minter's key signs: typed transactions start `0x00`-`0x04`, EIP-7702
/// authorizations `0x05`, EIP-191/712 `0x19` and legacy-transaction RLP `>= 0xc0`.
const DOMAIN_SEPARATOR: &[u8] = b"ck-deposit-owner";

/// A deposit address' attestation of the account it credits, as the `(r, s, v)` components the
/// delegate passes to `ecrecover`.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct Attestation {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// The digest a deposit address signs to attest that it credits `account`, mirroring
/// `CkSweeperAttested._attestationDigest`:
/// `keccak256("ck-deposit-owner" || chain_id || helper || principal || subaccount)`.
///
/// Every field is fixed-length, so no two field assignments share a preimage. `chain_id` prevents
/// replay onto another chain and `helper` binds the attestation to one helper deployment.
pub fn attestation_digest(chain_id: u64, helper: &Address, account: &Account) -> Hash {
    let mut chain_id_bytes = [0_u8; 32];
    chain_id_bytes[24..].copy_from_slice(&chain_id.to_be_bytes());
    let preimage = [
        DOMAIN_SEPARATOR,
        &chain_id_bytes,
        helper.as_ref(),
        &encode_principal(&account.owner),
        account.effective_subaccount(),
    ]
    .concat();
    Hash(ic_sha3::Keccak256::hash(preimage))
}

/// Sign [`attestation_digest`] with the deposit address' own derived key.
///
/// # Errors
/// * a description of why the threshold-ECDSA signature could not be produced.
pub async fn sign_attestation(
    chain_id: u64,
    helper: &Address,
    schema: DepositAddressSchema,
    account: &Account,
) -> Result<Attestation, String> {
    let digest = attestation_digest(chain_id, helper, account);
    let signature = sign_digest(&digest, &deposit_derivation_path(schema, account)).await?;
    Ok(Attestation {
        r: signature.r.to_be_bytes(),
        s: signature.s.to_be_bytes(),
        v: 27 + u8::from(signature.signature_y_parity),
    })
}
