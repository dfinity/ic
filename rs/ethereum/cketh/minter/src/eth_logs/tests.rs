mod parse_principal_from_slice {
    use crate::eth_logs::parse_principal_from_slice;
    use crate::eth_rpc::FixedSizeData;
    use assert_matches::assert_matches;
    use candid::Principal;
    use std::str::FromStr;

    const PRINCIPAL: &str = "2chl6-4hpzw-vqaaa-aaaaa-c";

    #[test]
    fn should_deserialize_principal() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let encoded_principal = to_bytes_with_size_prefix(&principal);
        let parsed_principal = parse_principal_from_slice(&encoded_principal);

        assert_eq!(parsed_principal, Ok(principal));
    }

    #[test]
    fn should_fail_when_first_byte_is_zero() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let mut encoded_principal = to_bytes_with_size_prefix(&principal);
        encoded_principal.insert(0, 0);
        let parsed_principal = parse_principal_from_slice(&encoded_principal);

        assert_matches!(parsed_principal, Err(_));
    }

    #[test]
    fn should_fail_when_first_byte_larger_than_29() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        for i in 30..u8::MAX {
            let mut encoded_principal = to_bytes_with_size_prefix(&principal);
            encoded_principal.insert(0, i);
            assert_matches!(parse_principal_from_slice(&encoded_principal), Err(_));
        }
    }

    #[test]
    fn should_fail_when_length_shorter_than_value_in_first_byte() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let mut encoded_principal = to_bytes_with_size_prefix(&principal);

        while encoded_principal.pop().is_some() {
            assert_matches!(parse_principal_from_slice(&encoded_principal), Err(_));
        }
    }

    #[test]
    fn should_fail_when_non_trailing_zeroes() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let mut encoded_principal = to_bytes_with_size_prefix(&principal);
        encoded_principal.append(&mut vec![0, 0, 0, 1, 0]);

        assert_matches!(parse_principal_from_slice(&encoded_principal), Err(_));
    }

    #[test]
    fn should_fail_when_slice_longer_than_32_bytes() {
        let mut encoded_principal = [0_u8; 34];
        encoded_principal[0] = 33;

        assert_matches!(parse_principal_from_slice(&encoded_principal), Err(_));
    }

    #[test]
    fn should_not_accept_management_canister_principal() {
        let principal = Principal::management_canister();
        let encoded_principal = to_bytes_with_size_prefix(&principal);
        let parsed_principal = parse_principal_from_slice(&encoded_principal);

        assert_matches!(parsed_principal, Err(err) if err.contains("management canister"));
    }

    #[test]
    fn should_not_accept_anonymous_principal() {
        let principal = Principal::anonymous();
        let encoded_principal = to_bytes_with_size_prefix(&principal);
        let parsed_principal = parse_principal_from_slice(&encoded_principal);

        assert_matches!(parsed_principal, Err(err) if err.contains("anonymous principal"));
    }

    #[test]
    fn should_encode_to_and_decode_from_eth_hex_string() {
        let principal = Principal::from_str(PRINCIPAL).unwrap();
        let encoded_principal = format!(
            "0x{}",
            hex::encode(to_32_bytes_with_size_prefix(&principal))
        );
        assert_eq!(
            encoded_principal,
            "0x09efcdab00000000000100000000000000000000000000000000000000000000"
        );

        let decoded_principal = parse_principal_from_slice(
            FixedSizeData::from_str(&encoded_principal)
                .unwrap()
                .as_ref(),
        );

        assert_eq!(decoded_principal, Ok(principal));
    }

    fn to_bytes_with_size_prefix(principal: &Principal) -> Vec<u8> {
        let mut principal_bytes = principal.as_slice().to_vec();
        let size = principal_bytes.len() as u8;
        principal_bytes.insert(0, size);
        principal_bytes
    }

    fn to_32_bytes_with_size_prefix(principal: &Principal) -> [u8; 32] {
        let mut principal_bytes = [0_u8; 32];
        for (index, byte) in to_bytes_with_size_prefix(principal).iter().enumerate() {
            principal_bytes[index] = *byte;
        }
        principal_bytes
    }
}
