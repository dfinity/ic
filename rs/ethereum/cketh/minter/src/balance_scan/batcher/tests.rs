use super::*;

const TOKEN0: Address = Address::new([0x22; 20]);
const HOLDER0: DepositAddress = DepositAddress::new(Address::new([0x11; 20]));
const TOKEN1: Address = Address::new([0x44; 20]);
const HOLDER1: DepositAddress = DepositAddress::new(Address::new([0x33; 20]));

fn word(value: u64) -> [u8; WORD] {
    word_from_usize(value as usize)
}

#[test]
fn initcode_matches_readable_assembly() {
    use Op::*;

    // The byte-for-byte source of truth for BATCHER_INITCODE, as a commented EVM assembly listing.
    // A create-style `eth_call` runs this as init code; it reads its args appended right after the
    // code (`[n][ (token, holder) x n ]`, from code offset ARGS_START) and RETURNs the balances.
    //
    // Memory layout (all offsets in bytes):
    //   [0x00..0x04] balanceOf(address) selector   [0x04..0x24] holder arg (rewritten per iteration)
    //   [0x40]       loop counter i                 [0x60]       n
    //   [0x80]       token (STATICCALL callee)      [0xa0]       base = code offset of the first pair
    //   [0xc0]       scratch: code offset of pair i [OUTPUT..]   returned balances (n x 32 bytes)
    const ARGS_START: u16 = 0xa5; // == BATCHER_INITCODE.len(): the `n` word sits right after the code
    const FIRST_PAIR: u16 = 0xc5; // == ARGS_START + WORD: first (token, holder) pair
    const OUTPUT: u16 = 0x0100; // start of the returned balances region in memory
    const LOOP: u16 = 0x37; // JUMPDEST at the top of the per-address loop
    const DONE: u16 = 0x94; // JUMPDEST for the success (RETURN) path
    const FAIL: u16 = 0x9f; // JUMPDEST for the fail-loud (REVERT) path

    let mut selector = [0_u8; WORD];
    selector[..4].copy_from_slice(&BALANCE_OF_SELECTOR);

    #[rustfmt::skip]
    let program = assemble(&[
        // mem[0x00] = balanceOf selector (in the top 4 bytes of the word)
        Push32(selector), Push1(0x00), Mstore,
        // mem[0x60] = n  (one word copied from code[ARGS_START])
        Push1(0x20), Push2(ARGS_START), Push1(0x60), Codecopy,
        // mem[0xa0] = FIRST_PAIR  (base for pair offsets)
        Push2(FIRST_PAIR), Push1(0xa0), Mstore,
        // mem[0x40] = i = 0
        Push1(0x00), Push1(0x40), Mstore,
        Jumpdest, // LOOP
        // if !(i < n) goto DONE
        Push1(0x60), Mload, Push1(0x40), Mload, Lt, IsZero, Push2(DONE), Jumpi,
        // mem[0xc0] = FIRST_PAIR + i * 0x40   (code offset of pair i; 0x40 = two words per pair)
        Push1(0x40), Mload, Push1(0x40), Mul, Push1(0xa0), Mload, Add, Push1(0xc0), Mstore,
        // mem[0x80] = token = code[pair]           (copy one word)
        Push1(0x20), Push1(0xc0), Mload, Push1(0x80), Codecopy,
        // mem[0x04] = holder = code[pair + 0x20]   (right after the selector)
        Push1(0x20), Push1(0xc0), Mload, Push1(0x20), Add, Push1(0x04), Codecopy,
        // STATICCALL(gas, token, args = [0x00, 0x24), ret = [OUTPUT + i*0x20, +0x20))
        Push1(0x20), Push1(0x40), Mload, Push1(0x20), Mul, Push2(OUTPUT), Add,
        Push1(0x24), Push1(0x00), Push1(0x80), Mload, Gas, StaticCall,
        // if the call failed, fail loud
        IsZero, Push2(FAIL), Jumpi,
        // require exactly 32 bytes of return data, else fail loud
        ReturnDataSize, Push1(0x20), Eq, IsZero, Push2(FAIL), Jumpi,
        // i += 1; goto LOOP
        Push1(0x40), Mload, Push1(0x01), Add, Push1(0x40), Mstore, Push2(LOOP), Jump,
        Jumpdest, // DONE: RETURN(OUTPUT, n * 0x20)
        Push1(0x60), Mload, Push1(0x20), Mul, Push2(OUTPUT), Return,
        Jumpdest, // FAIL: REVERT(0, 0)
        Push1(0x00), Push1(0x00), Revert,
    ]);

    assert_eq!(program, BATCHER_INITCODE);
    // Offsets baked into the code must match the actual layout.
    assert_eq!(ARGS_START as usize, BATCHER_INITCODE.len());
    assert_eq!(FIRST_PAIR, ARGS_START + WORD as u16);
}

#[test]
fn encode_single_call_golden_vector() {
    let encoded = encode_balance_batch(&[BalanceOfCall {
        token: TOKEN0,
        holder: HOLDER0,
    }]);

    assert_eq!(encoded.len(), BATCHER_INITCODE.len() + 3 * WORD);
    assert_eq!(&encoded[..BATCHER_INITCODE.len()], &BATCHER_INITCODE);
    let args = &encoded[BATCHER_INITCODE.len()..];
    assert_eq!(&args[0..32], &word(1)); // n
    assert_eq!(&args[32..64], &left_padded_address(&TOKEN0));
    assert_eq!(&args[64..96], &left_padded_address(HOLDER0.as_address()));
}

#[test]
fn encode_two_calls_layout() {
    let encoded = encode_balance_batch(&[
        BalanceOfCall {
            token: TOKEN0,
            holder: HOLDER0,
        },
        BalanceOfCall {
            token: TOKEN1,
            holder: HOLDER1,
        },
    ]);

    assert_eq!(encoded.len(), BATCHER_INITCODE.len() + WORD * (1 + 2 * 2));
    let args = &encoded[BATCHER_INITCODE.len()..];
    assert_eq!(&args[0..32], &word(2));
    assert_eq!(&args[32..64], &left_padded_address(&TOKEN0));
    assert_eq!(&args[64..96], &left_padded_address(HOLDER0.as_address()));
    assert_eq!(&args[96..128], &left_padded_address(&TOKEN1));
    assert_eq!(&args[128..160], &left_padded_address(HOLDER1.as_address()));
}

#[test]
fn decode_round_trip() {
    let mut ret = Vec::new();
    for v in [1_000_000_u64, 0, u64::MAX] {
        ret.extend_from_slice(&word(v));
    }

    let balances = decode_balance_batch(&ret, 3).unwrap();

    assert_eq!(
        balances,
        vec![
            Erc20Value::from(1_000_000_u64),
            Erc20Value::from(0_u64),
            Erc20Value::from(u64::MAX),
        ]
    );
}

#[test]
fn decode_empty_batch_is_ok() {
    assert_eq!(
        decode_balance_batch(&[], 0).unwrap(),
        Vec::<Erc20Value>::new()
    );
}

#[test]
fn decode_wrong_length_is_err() {
    // One word short of two.
    let ret = vec![0_u8; WORD + 1];
    assert_eq!(
        decode_balance_batch(&ret, 2),
        Err(BatcherDecodeError::WrongLength {
            expected: 2 * WORD,
            got: WORD + 1,
        })
    );
}

/// A minimal EVM instruction, enough to spell out [`BATCHER_INITCODE`] in [`assemble`].
enum Op {
    Push1(u8),
    Push2(u16),
    Push32([u8; WORD]),
    Add,
    Mul,
    Lt,
    Eq,
    IsZero,
    Codecopy,
    Gas,
    Mload,
    Mstore,
    Jump,
    Jumpi,
    Jumpdest,
    ReturnDataSize,
    StaticCall,
    Return,
    Revert,
}

fn assemble(ops: &[Op]) -> Vec<u8> {
    let mut out = Vec::new();
    for op in ops {
        match op {
            Op::Push1(x) => out.extend_from_slice(&[0x60, *x]),
            Op::Push2(x) => {
                out.push(0x61);
                out.extend_from_slice(&x.to_be_bytes());
            }
            Op::Push32(word) => {
                out.push(0x7f);
                out.extend_from_slice(word);
            }
            Op::Add => out.push(0x01),
            Op::Mul => out.push(0x02),
            Op::Lt => out.push(0x10),
            Op::Eq => out.push(0x14),
            Op::IsZero => out.push(0x15),
            Op::Codecopy => out.push(0x39),
            Op::Gas => out.push(0x5a),
            Op::Mload => out.push(0x51),
            Op::Mstore => out.push(0x52),
            Op::Jump => out.push(0x56),
            Op::Jumpi => out.push(0x57),
            Op::Jumpdest => out.push(0x5b),
            Op::ReturnDataSize => out.push(0x3d),
            Op::StaticCall => out.push(0xfa),
            Op::Return => out.push(0xf3),
            Op::Revert => out.push(0xfd),
        }
    }
    out
}
