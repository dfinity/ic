use crate::deposit_address::DepositAddress;
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
/// `STATICCALL`s `token.balanceOf(holder)`. The token list is a trusted
/// whitelist, so a sub-call that reverts or does not return exactly 32 bytes
/// (e.g. a non-contract address) is an anomaly, not "no balance": the whole
/// call `REVERT`s rather than masking it, surfacing loudly as an `eth_call`
/// error. On success it returns the balances as a flat `n x 32`-byte array (no
/// ABI array header), decoded positionally by [`decode_balance_batch`].
///
/// The program is fixed regardless of `n` (only the appended args grow). It was
/// assembled from the documented opcode sequence and validated against Ethereum
/// mainnet across all four providers used by the minter (identical bytes), with
/// reverting / non-contract tokens reverting the whole call; see
/// `rs/ethereum/cketh/docs/deposit_from_cex.md`.
pub const BATCHER_INITCODE: [u8; 165] = [
    0x7f, 0x70, 0xa0, 0x82, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x60, 0x00, 0x52, 0x60, 0x20, 0x61, 0x00, 0xa5, 0x60, 0x60, 0x39, 0x61, 0x00, 0xc5, 0x60,
    0xa0, 0x52, 0x60, 0x00, 0x60, 0x40, 0x52, 0x5b, 0x60, 0x60, 0x51, 0x60, 0x40, 0x51, 0x10, 0x15,
    0x61, 0x00, 0x94, 0x57, 0x60, 0x40, 0x51, 0x60, 0x40, 0x02, 0x60, 0xa0, 0x51, 0x01, 0x60, 0xc0,
    0x52, 0x60, 0x20, 0x60, 0xc0, 0x51, 0x60, 0x80, 0x39, 0x60, 0x20, 0x60, 0xc0, 0x51, 0x60, 0x20,
    0x01, 0x60, 0x04, 0x39, 0x60, 0x20, 0x60, 0x40, 0x51, 0x60, 0x20, 0x02, 0x61, 0x01, 0x00, 0x01,
    0x60, 0x24, 0x60, 0x00, 0x60, 0x80, 0x51, 0x5a, 0xfa, 0x15, 0x61, 0x00, 0x9f, 0x57, 0x3d, 0x60,
    0x20, 0x14, 0x15, 0x61, 0x00, 0x9f, 0x57, 0x60, 0x40, 0x51, 0x60, 0x01, 0x01, 0x60, 0x40, 0x52,
    0x61, 0x00, 0x37, 0x56, 0x5b, 0x60, 0x60, 0x51, 0x60, 0x20, 0x02, 0x61, 0x01, 0x00, 0xf3, 0x5b,
    0x60, 0x00, 0x60, 0x00, 0xfd,
];

/// Maximum size of deployed contract code, per [EIP-170] (Spurious Dragon). A create-style call
/// treats the blob its initcode `RETURN`s as code to deploy, so nodes reject a returned blob
/// beyond this size even for a deployless `eth_call`.
///
/// [EIP-170]: https://eips.ethereum.org/EIPS/eip-170
const MAX_CODE_SIZE: usize = 24_576;

/// Maximum size of the initcode of a create-style call, per [EIP-3860] (Shanghai).
///
/// [EIP-3860]: https://eips.ethereum.org/EIPS/eip-3860
const MAX_INITCODE_SIZE: usize = 2 * MAX_CODE_SIZE;

/// Maximum number of `balanceOf` sub-calls in a single deployless-batcher `eth_call`.
///
/// A create-style `eth_call` is bounded at both ends: the initcode it carries is rejected beyond
/// [`MAX_INITCODE_SIZE`] (EIP-3860), and the blob the program `RETURN`s is rejected beyond
/// [`MAX_CODE_SIZE`] (EIP-170). [`encode_balance_batch`] appends one length word plus two words
/// per call to [`BATCHER_INITCODE`], and the program returns one word per call; both derivations
/// below follow that encoding instead of drifting from it, and the cap is the smaller of the two.
/// Today the initcode side binds (764 calls vs 768), but only by four calls.
///
/// Gas is the looser bound. A `debug_traceCall` of an 8-call batch against proxied stablecoins
/// (ckUSDC + ckUSDT, the priciest shape: `STATICCALL` → proxy `SLOAD` → `DELEGATECALL` → balance
/// `SLOAD`) used 153_452 gas, i.e. ~19k gas/call, so a full batch is ~14.5M gas — well under the
/// 50M `eth_call` cap providers commonly apply (geth's `--rpc.gascap` default). Payloads stay
/// small as well: 64 bytes of calldata and 32 bytes of return per call, far below the 2 MiB
/// HTTPS-outcall limit.
///
/// The cap must not be set above what every provider accepts: `scan_balances` splits the
/// registered pairs into chunks of this size and advances each chunk all-or-nothing, so a
/// whole-call failure re-does that chunk on the next tick — and a chunk that always exceeds a
/// provider limit fails *every* time, permanently stalling its pairs.
pub const MAX_CALLS_PER_BATCH: usize = {
    let by_initcode_size = (MAX_INITCODE_SIZE - BATCHER_INITCODE.len() - WORD) / (2 * WORD);
    let by_returned_code_size = MAX_CODE_SIZE / WORD;
    if by_initcode_size < by_returned_code_size {
        by_initcode_size
    } else {
        by_returned_code_size
    }
};

/// Deployless ETH balance-batcher creation bytecode.
///
/// The native-ETH sibling of [`BATCHER_INITCODE`], executed the same way (create-style
/// `eth_call`, `to` omitted). It reads its inputs from the calldata appended right after this
/// bytecode (`[n][ holder x n ]`, one 32-byte word each) and, for each holder, reads its ETH
/// balance with the `BALANCE` opcode — no sub-calls, so unlike the ERC-20 batcher nothing here
/// can fail and the program has no revert path. On success it returns the balances as a flat
/// `n x 32`-byte array (no ABI array header), decoded positionally by [`decode_balance_batch`].
///
/// The program is fixed regardless of `n` (only the appended args grow). It was assembled from
/// the opcode listing in `eth_initcode_matches_readable_assembly` and validated against a live
/// anvil node; see `rs/ethereum/cketh/minter/tests/deposit_from_cex.rs`.
pub const ETH_BATCHER_INITCODE: [u8; 78] = [
    0x60, 0x20, 0x61, 0x00, 0x4e, 0x60, 0x00, 0x39, 0x60, 0x00, 0x60, 0x20, 0x52, 0x5b, 0x60, 0x00,
    0x51, 0x60, 0x20, 0x51, 0x10, 0x15, 0x61, 0x00, 0x44, 0x57, 0x60, 0x20, 0x60, 0x20, 0x51, 0x60,
    0x20, 0x02, 0x61, 0x00, 0x6e, 0x01, 0x60, 0x40, 0x39, 0x60, 0x40, 0x51, 0x31, 0x60, 0x20, 0x51,
    0x60, 0x20, 0x02, 0x60, 0x60, 0x01, 0x52, 0x60, 0x20, 0x51, 0x60, 0x01, 0x01, 0x60, 0x20, 0x52,
    0x61, 0x00, 0x0d, 0x56, 0x5b, 0x60, 0x00, 0x51, 0x60, 0x20, 0x02, 0x60, 0x60, 0xf3,
];

/// Function selector for `balanceOf(address)`, i.e. `keccak256("balanceOf(address)")[..4]`.
/// Embedded in [`BATCHER_INITCODE`] right after its leading `PUSH32` opcode; asserted by tests.
#[cfg(test)]
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// One `balanceOf(holder)` sub-call to be executed against an ERC-20 `token` contract.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BalanceOfCall {
    pub token: Address,
    pub holder: DepositAddress,
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
        out.extend_from_slice(&left_padded_address(call.holder.as_address()));
    }
    out
}

/// Build the create-call `input` for a batch of ETH balance reads:
/// `ETH_BATCHER_INITCODE ++ [n] ++ [ holder x n ]`, every value a 32-byte word.
pub fn encode_eth_balance_batch(holders: &[DepositAddress]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ETH_BATCHER_INITCODE.len() + WORD * (1 + holders.len()));
    out.extend_from_slice(&ETH_BATCHER_INITCODE);
    out.extend_from_slice(&word_from_usize(holders.len()));
    for holder in holders {
        out.extend_from_slice(&left_padded_address(holder.as_address()));
    }
    out
}

/// Decode the flat `n x 32`-byte return blob into `n` balances, in call order.
///
/// Every entry is a genuine `balanceOf` result: the batcher reverts the whole
/// call if any sub-call fails, so a successful return means all `n` balances are
/// present (a failed batch surfaces as an `eth_call` error upstream, never as a
/// `0` here). Returns `Err` if the blob length is not exactly `n` words; never
/// panics.
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
