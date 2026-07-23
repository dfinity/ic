use crate::numeric::Erc20Value;
use ic_ethereum_types::Address;

#[cfg(test)]
mod tests;

/// The canonical Multicall3 deployment address, identical across all EVM chains:
/// `0xcA11bde05977b3631167028862bE2a173976CA11`.
pub const MULTICALL3_ADDRESS: Address = Address::new([
    0xca, 0x11, 0xbd, 0xe0, 0x59, 0x77, 0xb3, 0x63, 0x11, 0x67, 0x02, 0x88, 0x62, 0xbe, 0x2a, 0x17,
    0x39, 0x76, 0xca, 0x11,
]);

/// Function selector for `balanceOf(address)`, i.e. `keccak256("balanceOf(address)")[..4]`.
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

/// Function selector for `aggregate3((address,bool,bytes)[])`,
/// i.e. `keccak256("aggregate3((address,bool,bytes)[])")[..4]`.
const AGGREGATE3_SELECTOR: [u8; 4] = [0x82, 0xad, 0x56, 0xcb];

/// Number of bytes in a single ABI word.
const WORD: usize = 32;

/// Size in bytes of the inner `balanceOf(address)` calldata: selector + one word.
const BALANCE_OF_CALLDATA_LEN: usize = 4 + WORD;

/// One `balanceOf(holder)` sub-call to be executed against an ERC-20 `token` contract.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BalanceOfCall {
    pub token: Address,
    pub holder: Address,
}

/// Structural error encountered while decoding an `aggregate3` return blob.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Multicall3DecodeError {
    /// Reading a 32-byte word or a data slice would run past the end of the buffer.
    UnexpectedEnd {
        offset: usize,
        needed: usize,
        len: usize,
    },
    /// An ABI offset/length word encodes a value too large to index the buffer.
    ValueTooLarge { word: [u8; 32] },
    /// The array length word claims more elements than the buffer could possibly hold,
    /// even for the head-offset array alone.
    ArrayTooLong { n: usize, max: usize },
}

/// Encode the full calldata for
/// `aggregate3([Call3{ token, allowFailure: true, balanceOf(holder) } ...])`.
///
/// The returned bytes are `AGGREGATE3_SELECTOR ++ abi_encode(Call3[])`.
pub fn encode_balance_of_aggregate3(calls: &[BalanceOfCall]) -> Vec<u8> {
    let n = calls.len();
    // selector + array offset word + length word + N head words + N tuples.
    let tuple_len = 4 * WORD + BALANCE_OF_CALLDATA_LEN.next_multiple_of(WORD);
    let mut out = Vec::with_capacity(4 + WORD + WORD + n * WORD + n * tuple_len);

    out.extend_from_slice(&AGGREGATE3_SELECTOR);
    // Offset from the start of the args to the array = one word.
    out.extend_from_slice(&word_from_usize(WORD));
    // Array length.
    out.extend_from_slice(&word_from_usize(n));
    // Head: offset of each tuple relative to the start of the array's data area
    // (i.e. the word right after the length). offset_i = N*32 + i*tuple_len.
    for i in 0..n {
        out.extend_from_slice(&word_from_usize(n * WORD + i * tuple_len));
    }
    // Tail: the tuple encodings, concatenated.
    for call in calls {
        // target
        out.extend_from_slice(&left_padded_address(&call.token));
        // allowFailure = true
        out.extend_from_slice(&bool_word(true));
        // offset to callData within the tuple = after the 3 head words.
        out.extend_from_slice(&word_from_usize(3 * WORD));
        // callData length
        out.extend_from_slice(&word_from_usize(BALANCE_OF_CALLDATA_LEN));
        // callData, right-padded with zeros to a multiple of a word.
        let calldata = encode_balance_of(&call.holder);
        out.extend_from_slice(&calldata);
        let pad = BALANCE_OF_CALLDATA_LEN.next_multiple_of(WORD) - BALANCE_OF_CALLDATA_LEN;
        out.resize(out.len() + pad, 0);
    }
    out
}

/// Encode the inner `balanceOf(address)` calldata (selector + left-padded holder address).
pub fn encode_balance_of(holder: &Address) -> [u8; BALANCE_OF_CALLDATA_LEN] {
    let mut calldata = [0_u8; BALANCE_OF_CALLDATA_LEN];
    calldata[..4].copy_from_slice(&BALANCE_OF_SELECTOR);
    calldata[4..].copy_from_slice(&left_padded_address(holder));
    calldata
}

/// Decode the ABI return of `aggregate3`, a `(bool success, bytes returnData)[]`.
///
/// Returns one entry per sub-call, in order: `Some(balance)` when the sub-call succeeded and
/// its `returnData` is exactly one 32-byte word, otherwise `None` (failed call, or malformed
/// / short `returnData`). Never panics; returns `Err` on structurally invalid input such as
/// out-of-range offsets or lengths overflowing the buffer.
pub fn decode_balance_of_aggregate3(
    ret: &[u8],
) -> Result<Vec<Option<Erc20Value>>, Multicall3DecodeError> {
    let len = ret.len();

    // Top-level: a single dynamic array; word 0 is the offset to the array block.
    let array_offset = word_to_usize(&read_word(ret, 0)?)?;
    let n = word_to_usize(&read_word(ret, array_offset)?)?;
    // Head offsets are relative to the start of the array's data area, i.e. right after
    // the length word.
    let head_base = add(array_offset, WORD, len)?;

    // The head-offset array alone requires `n * WORD` bytes to exist in the buffer starting
    // at `head_base`, so `n` cannot exceed `(len - head_base) / WORD`. Reject an implausible
    // `n` before allocating, otherwise a crafted blob could force a multi-GB allocation.
    let max_n = len.saturating_sub(head_base) / WORD;
    if n > max_n {
        return Err(Multicall3DecodeError::ArrayTooLong { n, max: max_n });
    }

    let mut results = Vec::with_capacity(n);
    for i in 0..n {
        let head_pos = add(head_base, mul(i, WORD, len)?, len)?;
        let tuple_offset = word_to_usize(&read_word(ret, head_pos)?)?;
        let tuple_start = add(head_base, tuple_offset, len)?;

        // Tuple (bool success, bytes returnData).
        let success = read_word(ret, tuple_start)?;
        let return_data_offset = word_to_usize(&read_word(ret, add(tuple_start, WORD, len)?)?)?;
        let return_data_pos = add(tuple_start, return_data_offset, len)?;
        let return_data_len = word_to_usize(&read_word(ret, return_data_pos)?)?;
        let data_start = add(return_data_pos, WORD, len)?;
        let data_end = add(data_start, return_data_len, len)?;
        let data = ret
            .get(data_start..data_end)
            .ok_or(Multicall3DecodeError::UnexpectedEnd {
                offset: data_start,
                needed: return_data_len,
                len,
            })?;

        let succeeded = success != [0_u8; WORD];
        if succeeded && return_data_len == WORD {
            let word: [u8; 32] = data.try_into().expect("BUG: slice is exactly one word");
            results.push(Some(Erc20Value::from_be_bytes(word)));
        } else {
            results.push(None);
        }
    }
    Ok(results)
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

fn bool_word(value: bool) -> [u8; WORD] {
    let mut word = [0_u8; WORD];
    word[WORD - 1] = value as u8;
    word
}

fn read_word(ret: &[u8], offset: usize) -> Result<[u8; WORD], Multicall3DecodeError> {
    let end = add(offset, WORD, ret.len())?;
    let slice = ret
        .get(offset..end)
        .ok_or(Multicall3DecodeError::UnexpectedEnd {
            offset,
            needed: WORD,
            len: ret.len(),
        })?;
    Ok(slice.try_into().expect("BUG: slice is exactly one word"))
}

fn word_to_usize(word: &[u8; WORD]) -> Result<usize, Multicall3DecodeError> {
    if word[..WORD - 8].iter().any(|&b| b != 0) {
        return Err(Multicall3DecodeError::ValueTooLarge { word: *word });
    }
    let value = u64::from_be_bytes(word[WORD - 8..].try_into().expect("BUG: 8 bytes"));
    usize::try_from(value).map_err(|_| Multicall3DecodeError::ValueTooLarge { word: *word })
}

fn add(a: usize, b: usize, len: usize) -> Result<usize, Multicall3DecodeError> {
    a.checked_add(b)
        .ok_or(Multicall3DecodeError::UnexpectedEnd {
            offset: a,
            needed: b,
            len,
        })
}

fn mul(a: usize, b: usize, len: usize) -> Result<usize, Multicall3DecodeError> {
    a.checked_mul(b)
        .ok_or(Multicall3DecodeError::UnexpectedEnd {
            offset: a,
            needed: b,
            len,
        })
}
