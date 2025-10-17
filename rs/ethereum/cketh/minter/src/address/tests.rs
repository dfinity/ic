mod validate_address_as_destination {
    use crate::address::{Address, AddressValidationError, validate_address_as_destination};
    use crate::blocklist::SAMPLE_BLOCKED_ADDRESS;
    use assert_matches::assert_matches;
    use proptest::{prop_assert_eq, prop_assume, proptest};
    use std::str::FromStr;

    #[test]
    fn should_fail_when_contract_creation_address_as_destination() {
        assert_eq!(
            validate_address_as_destination("0x0000000000000000000000000000000000000000"),
            Err(AddressValidationError::NotSupported(Address::ZERO))
        );
    }

    #[test]
    fn should_fail_when_address_is_blocked() {
        let blocked_address: Address = SAMPLE_BLOCKED_ADDRESS;
        assert_eq!(
            validate_address_as_destination(SAMPLE_BLOCKED_ADDRESS.to_string().as_str()),
            Err(AddressValidationError::Blocked(blocked_address))
        );
    }

    // The probability that we hit a blocked address is negligible:
    // there are 115 blocked addresses for a total of 2^(160) possible addresses.
    // 20 bytes represent 40 hexadecimal characters
    proptest! {
        #[test]
        fn should_validate_non_zero_addresses(valid_address in "0x[0-9a-fA-F]{40}") {
            prop_assume!(valid_address != "0x0000000000000000000000000000000000000000");
            let address = Address::from_str(&valid_address).unwrap();
            prop_assert_eq!(validate_address_as_destination(&valid_address), Ok(address));
        }
    }

    proptest! {
        #[test]
        fn should_fail_when_address_too_short(invalid_address in "0x[0-9a-fA-F]{0, 39}") {
            assert_matches!(
                validate_address_as_destination(&invalid_address),
                Err(AddressValidationError::Invalid { .. })
            );

        }
    }

    proptest! {
        #[test]
        fn should_fail_when_address_too_long(invalid_address in "0x[0-9a-fA-F]{41,100}") {
            assert_matches!(
                validate_address_as_destination(&invalid_address),
                Err(AddressValidationError::Invalid { .. })
            );

        }
    }
}
