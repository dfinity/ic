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
use crate::tx::{TransactionSignature, sign_digest};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;

/// Domain separator of the attestation preimage. Its first byte (`0x63`) cannot collide with any
/// other preimage the minter's key signs: typed transactions start `0x00`-`0x04`, EIP-7702
/// authorizations `0x05`, EIP-191/712 `0x19` and legacy-transaction RLP `>= 0xc0`.
const DOMAIN_SEPARATOR: &[u8] = b"ck-deposit-owner";

/// What a deposit address attests to: the account its funds are credited to, bound to one chain and
/// one deposit-helper deployment.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AttestationRequest {
    /// Prevents replaying the attestation onto another chain.
    pub chain_id: u64,
    /// The **deposit helper** contract, the one whose deposit events name the account an address
    /// credits — not the sweeper delegate, whose own address is `address(this)` in the delegate
    /// call and is deliberately absent from the preimage. Attesting under the wrong one produces a
    /// signature the delegate's `ecrecover` rejects, which shows up only on chain.
    pub deposit_helper: Address,
    pub account: Account,
}

impl AttestationRequest {
    /// `"ck-deposit-owner" || chain_id || deposit_helper || principal || subaccount`, exactly what
    /// `abi.encodePacked` produces in `CkSweeperAttested._attestationDigest`. Every field is
    /// fixed-length, so no two requests share a preimage.
    pub fn preimage(&self) -> Vec<u8> {
        let mut chain_id = [0_u8; 32];
        chain_id[24..].copy_from_slice(&self.chain_id.to_be_bytes());
        [
            DOMAIN_SEPARATOR,
            &chain_id,
            self.deposit_helper.as_ref(),
            &encode_principal(&self.account.owner),
            self.account.effective_subaccount(),
        ]
        .concat()
    }

    /// The digest the deposit address signs, i.e. what the delegate recovers against its own
    /// address.
    pub fn digest(&self) -> Hash {
        Hash(ic_sha3::Keccak256::hash(self.preimage()))
    }
}

/// Sign `request` with the deposit address' own derived key. The delegate wants the signature as
/// `(r, s, v)`, which is where [`crate::sweeper_contract`] encodes it.
///
/// # Errors
/// * a description of why the threshold-ECDSA signature could not be produced.
pub async fn sign_attestation(
    request: &AttestationRequest,
    schema: DepositAddressSchema,
) -> Result<TransactionSignature, String> {
    sign_digest(
        &request.digest(),
        &deposit_derivation_path(schema, &request.account),
    )
    .await
}
