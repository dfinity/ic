use super::*;
use ic_sha3::Keccak256;

const TOKEN0: Address = Address::new([0xaa; 20]);
const HOLDER0: Address = Address::new([0xbb; 20]);
const TOKEN1: Address = Address::new([0xcc; 20]);
const HOLDER1: Address = Address::new([0xdd; 20]);

#[test]
fn selectors_match_keccak_of_signatures() {
    assert_eq!(
        &BALANCE_OF_SELECTOR[..],
        &Keccak256::hash(b"balanceOf(address)")[..4]
    );
    assert_eq!(
        &AGGREGATE3_SELECTOR[..],
        &Keccak256::hash(b"aggregate3((address,bool,bytes)[])")[..4]
    );
}

#[test]
fn multicall3_address_is_canonical() {
    assert_eq!(
        MULTICALL3_ADDRESS.to_string().to_lowercase(),
        "0xca11bde05977b3631167028862be2a173976ca11"
    );
}

#[test]
fn encode_single_call_golden_vector() {
    let calls = [BalanceOfCall {
        token: TOKEN0,
        holder: HOLDER0,
    }];

    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x82, 0xad, 0x56, 0xcb]); // aggregate3 selector
    expected.extend_from_slice(&word(0x20)); // offset to array
    expected.extend_from_slice(&word(1)); // array length
    expected.extend_from_slice(&word(32)); // head offset for tuple 0 = N*32, N=1
    expected.extend_from_slice(&tuple(&TOKEN0, &HOLDER0));

    let encoded = encode_balance_of_aggregate3(&calls);

    // Sanity checks on the individual pieces.
    assert_eq!(&encoded[..4], &[0x82, 0xad, 0x56, 0xcb]);
    assert_eq!(&encoded[4..36], &word(0x20));
    assert_eq!(&encoded[36..68], &word(1));
    assert_eq!(&encoded[68..100], &word(32));
    assert_eq!(&encoded[100..], &tuple(&TOKEN0, &HOLDER0)[..]);

    assert_eq!(encoded, expected);
}

#[test]
fn encode_two_calls_golden_vector() {
    let calls = [
        BalanceOfCall {
            token: TOKEN0,
            holder: HOLDER0,
        },
        BalanceOfCall {
            token: TOKEN1,
            holder: HOLDER1,
        },
    ];

    let mut expected = Vec::new();
    expected.extend_from_slice(&[0x82, 0xad, 0x56, 0xcb]);
    expected.extend_from_slice(&word(0x20));
    expected.extend_from_slice(&word(2)); // length
    expected.extend_from_slice(&word(2 * 32)); // head offset 0 = N*32
    expected.extend_from_slice(&word(2 * 32 + 192)); // head offset 1 = N*32 + tuple_size
    expected.extend_from_slice(&tuple(&TOKEN0, &HOLDER0));
    expected.extend_from_slice(&tuple(&TOKEN1, &HOLDER1));

    let encoded = encode_balance_of_aggregate3(&calls);

    assert_eq!(&encoded[36..68], &word(2)); // length word
    assert_eq!(&encoded[68..100], &word(64)); // head offset 0
    assert_eq!(&encoded[100..132], &word(256)); // head offset 1

    assert_eq!(encoded, expected);
}

#[test]
fn decode_round_trip_success_and_failure() {
    let balance_word = u256_word(1_000_000_000_000_000_000);
    let expected_balance = Erc20Value::from_be_bytes(balance_word);

    let mut ret = Vec::new();
    ret.extend_from_slice(&word(0x20)); // offset to array
    ret.extend_from_slice(&word(2)); // array length (head_base is here + 32)
    ret.extend_from_slice(&word(64)); // head offset 0 = N*32
    ret.extend_from_slice(&word(192)); // head offset 1 = N*32 + tuple0_size (128)
    // tuple 0: success = true, returnData = 32-byte balance
    ret.extend_from_slice(&bool_true()); // success
    ret.extend_from_slice(&word(0x40)); // offset to returnData
    ret.extend_from_slice(&word(32)); // returnData length
    ret.extend_from_slice(&balance_word); // returnData
    // tuple 1: success = false, returnData = empty
    ret.extend_from_slice(&word(0)); // success = false
    ret.extend_from_slice(&word(0x40)); // offset to returnData
    ret.extend_from_slice(&word(0)); // returnData length

    let decoded = decode_balance_of_aggregate3(&ret).unwrap();
    assert_eq!(decoded, vec![Some(expected_balance), None]);
}

#[test]
fn decode_success_with_non_word_return_data_yields_none() {
    let mut ret = Vec::new();
    ret.extend_from_slice(&word(0x20)); // offset to array
    ret.extend_from_slice(&word(1)); // length
    ret.extend_from_slice(&word(32)); // head offset 0
    ret.extend_from_slice(&bool_true()); // success = true
    ret.extend_from_slice(&word(0x40)); // offset to returnData
    ret.extend_from_slice(&word(4)); // returnData length = 4 (not a full word)
    ret.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // 4 bytes of data
    ret.extend_from_slice(&[0_u8; 28]); // padding to a full word

    let decoded = decode_balance_of_aggregate3(&ret).unwrap();
    assert_eq!(decoded, vec![None]);
}

#[test]
fn decode_empty_array_is_ok() {
    let mut ret = Vec::new();
    ret.extend_from_slice(&word(0x20));
    ret.extend_from_slice(&word(0));
    let decoded = decode_balance_of_aggregate3(&ret).unwrap();
    assert_eq!(decoded, Vec::<Option<Erc20Value>>::new());
}

#[test]
fn decode_truncated_input_is_err_not_panic() {
    for len in 0..64 {
        let ret = vec![0_u8; len];
        // A buffer that cannot even hold the words it references must error, never panic.
        let _ = decode_balance_of_aggregate3(&ret);
    }
    assert!(matches!(
        decode_balance_of_aggregate3(&[]),
        Err(Multicall3DecodeError::UnexpectedEnd { .. })
    ));
}

#[test]
fn decode_offset_out_of_word_range_is_err() {
    // Word 0 (the array offset) has non-zero high bytes -> too large to index.
    let ret = vec![0xff_u8; 32];
    assert_eq!(
        decode_balance_of_aggregate3(&ret),
        Err(Multicall3DecodeError::ValueTooLarge { word: [0xff; 32] })
    );
}

#[test]
fn decode_offset_pointing_past_buffer_is_err() {
    let mut ret = Vec::new();
    ret.extend_from_slice(&word(0x1000)); // array offset points far past the buffer
    assert!(matches!(
        decode_balance_of_aggregate3(&ret),
        Err(Multicall3DecodeError::UnexpectedEnd { .. })
    ));
}

#[test]
fn decode_return_data_length_overflowing_buffer_is_err() {
    let mut ret = Vec::new();
    ret.extend_from_slice(&word(0x20)); // offset to array
    ret.extend_from_slice(&word(1)); // length
    ret.extend_from_slice(&word(32)); // head offset 0
    ret.extend_from_slice(&bool_true()); // success = true
    ret.extend_from_slice(&word(0x40)); // offset to returnData
    ret.extend_from_slice(&word(1_000_000)); // returnData length way beyond the buffer
    // no actual data follows

    assert!(matches!(
        decode_balance_of_aggregate3(&ret),
        Err(Multicall3DecodeError::UnexpectedEnd { .. })
    ));
}

#[test]
fn decode_huge_array_length_is_err_not_panic() {
    let mut ret = Vec::new();
    ret.extend_from_slice(&word(0x20)); // offset to array
    ret.extend_from_slice(&word(u64::MAX)); // enormous length, no element data follows

    assert!(matches!(
        decode_balance_of_aggregate3(&ret),
        Err(Multicall3DecodeError::ArrayTooLong { .. })
    ));
}

#[test]
fn encode_decode_selector_and_inner_calldata() {
    let calldata = encode_balance_of(&HOLDER0);
    assert_eq!(&calldata[..4], &[0x70, 0xa0, 0x82, 0x31]);
    assert_eq!(&calldata[4..], &addr_word(&HOLDER0));
}

#[test]
fn cross_check_with_cast_if_available() {
    use std::process::Command;

    // Only run when the foundry `cast` CLI is available; otherwise skip silently.
    let calldata = Command::new("cast")
        .args([
            "calldata",
            "balanceOf(address)",
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .output();
    let Ok(output) = calldata else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let expected = String::from_utf8(output.stdout).unwrap();
    let expected = expected.trim().trim_start_matches("0x");
    assert_eq!(hex::encode(encode_balance_of(&HOLDER0)), expected);
}

fn word(value: u64) -> [u8; 32] {
    let mut w = [0_u8; 32];
    w[24..].copy_from_slice(&value.to_be_bytes());
    w
}

fn u256_word(value: u128) -> [u8; 32] {
    let mut w = [0_u8; 32];
    w[16..].copy_from_slice(&value.to_be_bytes());
    w
}

fn addr_word(address: &Address) -> [u8; 32] {
    let mut w = [0_u8; 32];
    w[12..].copy_from_slice(address.as_ref());
    w
}

fn bool_true() -> [u8; 32] {
    let mut w = [0_u8; 32];
    w[31] = 1;
    w
}

fn balance_of_calldata(holder: &Address) -> Vec<u8> {
    let mut v = vec![0x70, 0xa0, 0x82, 0x31];
    v.extend_from_slice(&addr_word(holder));
    v
}

fn tuple(token: &Address, holder: &Address) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&addr_word(token)); // target
    v.extend_from_slice(&bool_true()); // allowFailure = true
    v.extend_from_slice(&word(0x60)); // offset to callData
    v.extend_from_slice(&word(0x24)); // callData length = 36
    v.extend_from_slice(&balance_of_calldata(holder)); // 36 bytes
    v.extend_from_slice(&[0_u8; 28]); // padding to a multiple of a word
    v
}
