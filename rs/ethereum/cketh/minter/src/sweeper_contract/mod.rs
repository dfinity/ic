//! The sweeper delegate contract's interface, as the minter calls it.
//!
//! A sweep transaction is sent to the deployed delegate instance, whose batch entry point calls
//! every deposit address in turn. Each address runs the same delegate code in its own context, so
//! `address(this)` is the deposit address and the attestation it carries must recover to it.

#[cfg(test)]
mod tests;

use crate::deposit_address::DepositAddress;
use crate::eth_logs::encode_principal;
use crate::tx::TransactionSignature;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use minicbor::{Decode, Encode};

/// First 4 bytes of
/// keccak256("sweepErc20Batch((address,bytes32,bytes32,bytes32,bytes32,uint8)[],address[])").
const SWEEP_ERC20_BATCH_SELECTOR: [u8; 4] = hex_literal::hex!("3a7ce054");

/// A 6-word ABI head: `(address, bytes32, bytes32, bytes32, bytes32, uint8)`. Every component is
/// static, so the elements of a `SweepItem[]` are encoded inline rather than behind offsets.
const WORDS_PER_ITEM: usize = 6;

const WORD: usize = 32;

/// One deposit address in a batch sweep: the address, the IC account its balance is credited to,
/// and that account's attestation, signed by the address' own key.
#[derive(Clone, Eq, PartialEq, Debug, Decode, Encode)]
pub struct SweepItem {
    #[n(0)]
    pub deposit: DepositAddress,
    #[n(1)]
    pub account: Account,
    #[n(2)]
    pub attestation: TransactionSignature,
}

/// Encode `sweepErc20Batch(SweepItem[] items, address[] tokens)` on the deployed delegate, which
/// sweeps every `token` balance held by every `item`'s deposit address to the minter's main address
/// through the deposit helper.
///
/// The tokens apply to every item, so a batch mixing addresses that hold different tokens pays a
/// `balanceOf` call per pair that holds nothing.
/// TODO(DEFI-2980): group a batch by token so every pair in it holds a balance.
///
/// See the [Contract ABI Specification](https://docs.soliditylang.org/en/develop/abi-spec.html#contract-abi-specification):
/// both arguments are dynamic, so the head holds one offset each and the two blocks follow.
pub fn encode_sweep_erc20_batch(items: &[SweepItem], tokens: &[Address]) -> Vec<u8> {
    let items_block_len = WORD + items.len() * WORDS_PER_ITEM * WORD;
    let head_len = 2 * WORD;

    let mut data = Vec::with_capacity(
        SWEEP_ERC20_BATCH_SELECTOR.len() + head_len + items_block_len + WORD + tokens.len() * WORD,
    );
    data.extend(SWEEP_ERC20_BATCH_SELECTOR);
    data.extend(word(head_len));
    data.extend(word(head_len + items_block_len));

    data.extend(word(items.len()));
    for item in items {
        data.extend(<[u8; 32]>::from(item.deposit.as_address()));
        data.extend(encode_principal(&item.account.owner));
        data.extend(item.account.effective_subaccount());
        data.extend(item.attestation.r.to_be_bytes());
        data.extend(item.attestation.s.to_be_bytes());
        // `ecrecover` wants v as 27 or 28, where the signature carries the parity bit.
        data.extend(word(usize::from(
            27 + u8::from(item.attestation.signature_y_parity),
        )));
    }

    data.extend(word(tokens.len()));
    for token in tokens {
        data.extend(<[u8; 32]>::from(token));
    }
    data
}

fn word(value: usize) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[WORD - size_of::<usize>()..].copy_from_slice(&value.to_be_bytes());
    bytes
}
