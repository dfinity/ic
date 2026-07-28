use super::*;

const TOKEN0: Address = Address::new([0x22; 20]);
const HOLDER0: Address = Address::new([0x11; 20]);
const TOKEN1: Address = Address::new([0x44; 20]);
const HOLDER1: Address = Address::new([0x33; 20]);

fn word(value: u64) -> [u8; WORD] {
    word_from_usize(value as usize)
}

#[test]
fn initcode_is_a_create_program_embedding_balance_of_selector() {
    // Leading PUSH32 (0x7f) then the balanceOf selector in the top 4 bytes of the word.
    assert_eq!(BATCHER_INITCODE[0], 0x7f);
    assert_eq!(&BATCHER_INITCODE[1..5], &BALANCE_OF_SELECTOR);
    // Has a RETURN (success path) and terminates with REVERT (fail-loud path).
    assert!(BATCHER_INITCODE.contains(&0xf3));
    assert_eq!(*BATCHER_INITCODE.last().unwrap(), 0xfd);
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
    assert_eq!(&args[64..96], &left_padded_address(&HOLDER0));
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
    assert_eq!(&args[64..96], &left_padded_address(&HOLDER0));
    assert_eq!(&args[96..128], &left_padded_address(&TOKEN1));
    assert_eq!(&args[128..160], &left_padded_address(&HOLDER1));
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
