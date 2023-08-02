mod mint_transaction {
    use crate::endpoints::ReceivedEthEvent;
    use crate::eth_logs::mint_transaction;
    use crate::eth_rpc::Hash;
    use candid::{Nat, Principal};
    use std::collections::BTreeSet;
    use std::str::FromStr;

    #[test]
    fn should_mint_new_transaction_from_event() {
        let mut minted_transactions = BTreeSet::new();
        let event = received_eth_event();

        mint_transaction(&mut minted_transactions, event.clone());

        assert!(minted_transactions.contains(&Hash::from_str(&event.transaction_hash).unwrap()));
    }

    #[test]
    fn should_ignore_events_with_same_transaction_hash() {
        let mut minted_transactions = BTreeSet::new();
        let event = received_eth_event();
        let invalid_event_with_same_hash = ReceivedEthEvent {
            value: Nat::from(50_000_000_000_000_000_u128),
            ..event.clone()
        };
        assert_ne!(event, invalid_event_with_same_hash);
        assert_eq!(
            event.transaction_hash,
            invalid_event_with_same_hash.transaction_hash
        );
        mint_transaction(&mut minted_transactions, event);

        let minted_transactions_before = minted_transactions.clone();
        mint_transaction(&mut minted_transactions, invalid_event_with_same_hash);
        let minted_transactions_after = minted_transactions.clone();

        assert_eq!(minted_transactions_before, minted_transactions_after);
    }

    #[test]
    fn should_process_events_after_event_with_duplicated_transaction_hash() {
        let mut minted_transactions = BTreeSet::new();
        let event = received_eth_event();
        let other_event = ReceivedEthEvent {
            transaction_hash: "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89ccA"
                .to_string(),
            ..event.clone()
        };
        assert_ne!(event.transaction_hash, other_event.transaction_hash);

        mint_transaction(&mut minted_transactions, event.clone());
        mint_transaction(&mut minted_transactions, event.clone());
        mint_transaction(&mut minted_transactions, other_event.clone());

        assert_eq!(minted_transactions.len(), 2);
        assert!(minted_transactions.contains(&Hash::from_str(&event.transaction_hash).unwrap()));
        assert!(
            minted_transactions.contains(&Hash::from_str(&other_event.transaction_hash).unwrap())
        );
    }

    fn received_eth_event() -> ReceivedEthEvent {
        ReceivedEthEvent {
            transaction_hash: "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2"
                .to_string(),
            block_number: Nat::from(3960623),
            log_index: Nat::from(29),
            from_address: "0xdd2851cdd40ae6536831558dd46db62fac7a844d".to_string(),
            value: Nat::from(10_000_000_000_000_000_u128),
            principal: Principal::from_slice(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0,
            ]),
        }
    }
}

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
