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
use minicbor::{Decode, Encode};

/// Domain separator of the attestation preimage. Its first byte (`0x63`) cannot collide with any
/// other preimage the minter's key signs: typed transactions start `0x00`-`0x04`, EIP-7702
/// authorizations `0x05`, EIP-191/712 `0x19` and legacy-transaction RLP `>= 0xc0`.
const DOMAIN_SEPARATOR: &[u8] = b"ck-deposit-owner";

/// What a deposit address attests to: the account its funds are credited to, bound to one chain and
/// one deposit-helper deployment.
///
/// The fields are private and must come from one configuration: a chain id, helper or schema that
/// does not match what the minter runs against yields a well-formed signature the delegate's
/// `ecrecover` rejects, and nothing notices until the sweep reverts on chain.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Decode, Encode)]
pub struct AttestationRequest {
    /// Prevents replaying the attestation onto another chain.
    #[n(0)]
    chain_id: u64,
    /// The **deposit helper** contract, the one whose deposit events name the account an address
    /// credits — not the sweeper delegate, whose own address is `address(this)` in the delegate
    /// call and is deliberately absent from the preimage.
    #[n(1)]
    deposit_helper: Address,
    #[cbor(n(2), with = "cbor_account")]
    account: Account,
    /// Which deposit-address scheme derives the key that signs, so the signing path cannot
    /// disagree with the digest.
    #[n(3)]
    schema: DepositAddressSchema,
}

impl AttestationRequest {
    /// Prefer [`crate::state::State::attestation_request`], which is the only caller that composes
    /// a request out of a chain, a helper and a schema; everything else reconstructs a request the
    /// minter already built (event replay, the Candid layer, tests).
    pub fn new(
        chain_id: u64,
        deposit_helper: Address,
        schema: DepositAddressSchema,
        account: Account,
    ) -> Self {
        Self {
            chain_id,
            deposit_helper,
            account,
            schema,
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn deposit_helper(&self) -> &Address {
        &self.deposit_helper
    }

    pub fn account(&self) -> &Account {
        &self.account
    }

    pub fn schema(&self) -> DepositAddressSchema {
        self.schema
    }

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
) -> Result<TransactionSignature, String> {
    sign_digest(
        &request.digest(),
        &deposit_derivation_path(request.schema, &request.account),
    )
    .await
}

/// Encodes the [`Account`] of an [`AttestationRequest`] the way every other event splits one: an
/// owner and an optional 32-byte subaccount.
mod cbor_account {
    use candid::Principal;
    use icrc_ledger_types::icrc1::account::Account;
    use minicbor::decode::{Decoder, Error};
    use minicbor::encode::{Encoder, Write};
    use minicbor::{Decode, Encode};

    #[derive(Decode, Encode)]
    struct CborAccount {
        #[cbor(n(0), with = "icrc_cbor::principal")]
        owner: Principal,
        #[cbor(n(1), with = "minicbor::bytes")]
        subaccount: Option<[u8; 32]>,
    }

    pub fn decode<Ctx>(d: &mut Decoder<'_>, ctx: &mut Ctx) -> Result<Account, Error> {
        let CborAccount { owner, subaccount } = CborAccount::decode(d, ctx)?;
        Ok(Account { owner, subaccount })
    }

    pub fn encode<Ctx, W: Write>(
        v: &Account,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        CborAccount {
            owner: v.owner,
            subaccount: v.subaccount,
        }
        .encode(e, ctx)
    }
}
