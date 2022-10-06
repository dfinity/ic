use crate::KeyId;

// TODO CRP-468: Move all stability tests from CRP-1640 to here

#[test]
fn should_provide_stable_string_value_from_hex() {
    let key_id = KeyId::from(hex_to_bytes(
        "e1299603ca276e7164d25be3596f98c6139202959b6a83195acf0c5121d57742",
    ));
    let string_value = key_id.to_string();

    assert_eq!(
        string_value,
        "KeyId(0xe1299603ca276e7164d25be3596f98c6139202959b6a83195acf0c5121d57742)"
    )
}

#[test]
fn should_provide_stable_string_value_from_bytes() {
    let key_id = KeyId::from([0u8; 32]);
    let string_value = key_id.to_string();
    assert_eq!(
        string_value,
        "KeyId(0x0000000000000000000000000000000000000000000000000000000000000000)"
    );

    let key_id = KeyId::from([1u8; 32]);
    let string_value = key_id.to_string();
    assert_eq!(
        string_value,
        "KeyId(0x0101010101010101010101010101010101010101010101010101010101010101)"
    )
}

fn hex_to_bytes<T: AsRef<[u8]>, const N: usize>(data: T) -> [u8; N] {
    hex::decode(data)
        .expect("error decoding hex")
        .try_into()
        .expect("wrong size of array")
}
