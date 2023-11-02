mod validate_address_as_destination {
    use crate::address::{validate_address_as_destination, Address, AddressValidationError};
    use proptest::{array::uniform20, prelude::any, proptest};

    #[test]
    fn should_fail_when_contract_creation_address_as_destination() {
        assert_eq!(
            validate_address_as_destination(Address::ZERO),
            Err(AddressValidationError::ContractCreation)
        );
    }

    proptest! {
        #[test]
        fn should_validate_non_zero_addresses(bytes in uniform20(any::<u8>())) {
            let address = Address::new(bytes);
            assert_eq!(validate_address_as_destination(address), Ok(address));
        }
    }
}
