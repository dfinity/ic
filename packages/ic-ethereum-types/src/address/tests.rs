use crate::Address;
use proptest::{prop_assert, prop_assert_eq, proptest};
use std::str::FromStr;

mod from_string {
    use super::*;

    proptest! {
        #[test]
        fn should_accept_20_bytes_address(valid_address in "0x[0-9a-fA-F]{40}") {
            let address = Address::from_str(&valid_address).unwrap();
            let raw_bytes = hex::decode(&valid_address[2..]).unwrap();
            prop_assert_eq!(address.as_ref(), &raw_bytes[..]);
        }
    }

    proptest! {
        #[test]
        fn should_fail_when_address_too_short(invalid_address in "0x[0-9a-fA-F]{0, 39}") {
            prop_assert!(Address::from_str(&invalid_address).is_err());
        }
    }

    proptest! {
        #[test]
        fn should_fail_when_address_too_long(invalid_address in "0x[0-9a-fA-F]{41,100}") {
            prop_assert!(Address::from_str(&invalid_address).is_err());
        }
    }
}

mod from_32_bytes {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn should_deserialize_address_from_32_bytes_hex_string() {
        let address_hex = thirty_two_bytes_from_ethereum_string(
            "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
        );

        let address = Address::try_from(&address_hex).unwrap();

        assert_eq!(
            format!("{address:x}"),
            "0xdd2851cdd40ae6536831558dd46db62fac7a844d".to_string()
        );
    }

    #[test]
    fn should_fail_deserializing_address_when_non_leading_zero() {
        let address_hex = thirty_two_bytes_from_ethereum_string(
            "0x000000000100000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
        );

        assert_matches!(
            Address::try_from(&address_hex),
            Err(err) if err.starts_with("address has leading non-zero bytes")
        );
    }

    #[test]
    fn should_fail_deserializing_when_address_larger_than_20_bytes() {
        let address_hex = thirty_two_bytes_from_ethereum_string(
            "0x000000000100000000000001dd2851cdd40ae6536831558dd46db62fac7a844d",
        );

        assert_matches!(
            Address::try_from(&address_hex),
            Err(err) if err.starts_with("address has leading non-zero bytes")
        );
    }

    fn thirty_two_bytes_from_ethereum_string(s: &str) -> [u8; 32] {
        assert!(s.starts_with("0x"), "string must start with 0x");
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s[2..], &mut bytes).unwrap();
        bytes
    }
}

#[test]
fn should_display_using_mixed_case() {
    assert_eq!(
        Address::from_str("0x7574EB42CA208A4f6960ECCAfDF186D627DCC175")
            .unwrap()
            .to_string(),
        "0x7574eB42cA208A4f6960ECCAfDF186D627dCC175"
    );
}

// See https://eips.ethereum.org/EIPS/eip-55#test-cases
#[test]
fn should_display_eip_55_test_cases() {
    const EXAMPLES: &[&str] = &[
        // All caps
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        // All Lower
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        // Normal
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];
    for example in EXAMPLES {
        let addr = Address::from_str(example).unwrap();
        assert_eq!(&addr.to_string(), example);
    }
}
