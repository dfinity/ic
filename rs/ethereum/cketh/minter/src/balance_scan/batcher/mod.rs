use crate::numeric::Erc20Value;
use ic_ethereum_types::Address;

#[cfg(test)]
mod tests;

/// Number of bytes in a single ABI word.
const WORD: usize = 32;

/// Deployless balance-batcher creation bytecode.
///
/// This is a self-contained EVM program executed via a create-style `eth_call`
/// (`to` omitted): the node runs it as init code and returns whatever it
/// `RETURN`s, without deploying anything or changing state. It reads its inputs
/// from the calldata appended right after this bytecode
/// (`[n][ (token, holder) x n ]`, one 32-byte word each) and, for each pair,
/// `STATICCALL`s `token.balanceOf(holder)`, multiplying the result by the call's
/// success flag so a reverting or non-contract token yields `0` (mirroring
/// Multicall3's `allowFailure`). It returns the balances as a flat `n x 32`-byte
/// array (no ABI array header), decoded positionally by
/// [`decode_balance_batch`].
///
/// The program is fixed regardless of `n` (only the appended args grow). It was
/// assembled from the documented opcode sequence and validated against Ethereum
/// mainnet across all four providers used by the minter (identical bytes),
/// including reverting/empty-return tokens mapping to `0`; see
/// `rs/ethereum/cketh/docs/deposit_from_cex.md`.
pub const BATCHER_INITCODE: [u8; 163] = [
    0x7f, 0x70, 0xa0, 0x82, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x60, 0x00, 0x52, 0x60, 0x20, 0x61, 0x00, 0xa3, 0x60, 0x60, 0x39, 0x61, 0x00, 0xc3, 0x60,
    0xa0, 0x52, 0x60, 0x00, 0x60, 0x40, 0x52, 0x5b, 0x60, 0x60, 0x51, 0x60, 0x40, 0x51, 0x10, 0x15,
    0x61, 0x00, 0x98, 0x57, 0x60, 0x40, 0x51, 0x60, 0x40, 0x02, 0x60, 0xa0, 0x51, 0x01, 0x60, 0xc0,
    0x52, 0x60, 0x20, 0x60, 0xc0, 0x51, 0x60, 0x80, 0x39, 0x60, 0x20, 0x60, 0xc0, 0x51, 0x60, 0x20,
    0x01, 0x60, 0x04, 0x39, 0x60, 0x20, 0x60, 0x40, 0x51, 0x60, 0x20, 0x02, 0x61, 0x01, 0x00, 0x01,
    0x60, 0x24, 0x60, 0x00, 0x60, 0x80, 0x51, 0x5a, 0xfa, 0x60, 0x40, 0x51, 0x60, 0x20, 0x02, 0x61,
    0x01, 0x00, 0x01, 0x80, 0x51, 0x82, 0x02, 0x81, 0x52, 0x50, 0x50, 0x60, 0x40, 0x51, 0x60, 0x01,
    0x01, 0x60, 0x40, 0x52, 0x61, 0x00, 0x37, 0x56, 0x5b, 0x60, 0x60, 0x51, 0x60, 0x20, 0x02, 0x61,
    0x01, 0x00, 0xf3,
];

/// Function selector for `balanceOf(address)`, i.e. `keccak256("balanceOf(address)")[..4]`.
/// Embedded in [`BATCHER_INITCODE`] right after its leading `PUSH32` opcode.
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// One `balanceOf(holder)` sub-call to be executed against an ERC-20 `token` contract.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BalanceOfCall {
    pub token: Address,
    pub holder: Address,
}

/// Error encountered while decoding a balance-batch return blob.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum BatcherDecodeError {
    /// The return blob is not exactly `n` 32-byte words.
    WrongLength { expected: usize, got: usize },
}

/// Build the create-call `input` for a batch of `balanceOf` sub-calls:
/// `BATCHER_INITCODE ++ [n] ++ [ (token, holder) x n ]`, every value a 32-byte word.
pub fn encode_balance_batch(calls: &[BalanceOfCall]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BATCHER_INITCODE.len() + WORD * (1 + 2 * calls.len()));
    out.extend_from_slice(&BATCHER_INITCODE);
    out.extend_from_slice(&word_from_usize(calls.len()));
    for call in calls {
        out.extend_from_slice(&left_padded_address(&call.token));
        out.extend_from_slice(&left_padded_address(&call.holder));
    }
    out
}

/// Decode the flat `n x 32`-byte return blob into `n` balances, in call order.
///
/// A `balanceOf` that reverted or targeted a non-contract already reads back as
/// `0` (the batcher multiplies each result by the sub-call's success flag), so a
/// failed sub-call is indistinguishable from a zero balance here — which is
/// exactly what filter 1 needs (a zero is never a candidate). Returns `Err` if
/// the blob length is not exactly `n` words; never panics.
pub fn decode_balance_batch(ret: &[u8], n: usize) -> Result<Vec<Erc20Value>, BatcherDecodeError> {
    let expected = n * WORD;
    if ret.len() != expected {
        return Err(BatcherDecodeError::WrongLength {
            expected,
            got: ret.len(),
        });
    }
    let mut balances = Vec::with_capacity(n);
    for i in 0..n {
        let word: [u8; WORD] = ret[i * WORD..(i + 1) * WORD]
            .try_into()
            .expect("BUG: slice is exactly one word");
        balances.push(Erc20Value::from_be_bytes(word));
    }
    Ok(balances)
}

fn left_padded_address(address: &Address) -> [u8; WORD] {
    let mut word = [0_u8; WORD];
    word[WORD - 20..].copy_from_slice(address.as_ref());
    word
}

fn word_from_usize(value: usize) -> [u8; WORD] {
    let mut word = [0_u8; WORD];
    word[WORD - 8..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}
