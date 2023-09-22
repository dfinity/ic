mod mint_transaction {
    use crate::endpoints::InitArg;
    use crate::eth_logs::{LogIndex, ReceivedEthEvent};
    use crate::eth_rpc::BlockNumber;
    use crate::numeric::{LedgerMintIndex, Wei};
    use crate::state::State;
    use candid::{Nat, Principal};
    use ethnum::u256;

    #[test]
    fn should_record_mint_task_from_event() {
        let mut state = dummy_state();
        let event = received_eth_event();

        state.record_event_to_mint(event.clone());

        assert!(state.events_to_mint.contains(&event));

        let block_index = LedgerMintIndex::new(1u64);

        state.record_successful_mint(&event, block_index);

        assert!(!state.events_to_mint.contains(&event));
        assert_eq!(state.minted_events.get(&event.source()), Some(&block_index));
    }

    #[test]
    fn should_allow_minting_events_with_equal_txhash() {
        let mut state = dummy_state();
        let event_1 = ReceivedEthEvent {
            log_index: LogIndex::new(u256::from(1u128)),
            ..received_eth_event()
        };
        let event_2 = ReceivedEthEvent {
            log_index: LogIndex::new(u256::from(2u128)),
            ..received_eth_event()
        };

        assert_ne!(event_1, event_2);

        state.record_event_to_mint(event_1.clone());

        assert!(state.events_to_mint.contains(&event_1));

        state.record_event_to_mint(event_2.clone());

        assert!(state.events_to_mint.contains(&event_2));

        assert_eq!(2, state.events_to_mint.len());
    }

    #[test]
    #[should_panic = "unknown event"]
    fn should_not_allow_unknown_mints() {
        let mut state = dummy_state();
        let event = received_eth_event();

        assert!(!state.events_to_mint.contains(&event));
        state.record_successful_mint(&event, LedgerMintIndex::new(1));
    }

    #[test]
    #[should_panic = "invalid"]
    fn should_not_record_invalid_deposit_already_recorded_as_valid() {
        let mut state = dummy_state();
        let event = received_eth_event();

        state.record_event_to_mint(event.clone());

        assert!(state.events_to_mint.contains(&event));

        state.record_invalid_deposit(event.source());
    }

    fn dummy_state() -> State {
        State::from(InitArg {
            ecdsa_key_name: "test_key_1".to_string(),
            ledger_id: Principal::anonymous(),
            ethereum_network: Default::default(),
            next_transaction_nonce: Nat::from(0u64),
        })
    }

    fn received_eth_event() -> ReceivedEthEvent {
        ReceivedEthEvent {
            transaction_hash: "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2"
                .parse()
                .unwrap(),
            block_number: BlockNumber::new(3960623u128),
            log_index: LogIndex::new(u256::from(29u128)),
            from_address: "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
                .parse()
                .unwrap(),
            value: Wei::from(10_000_000_000_000_000_u128),
            principal: "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
                .parse()
                .unwrap(),
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
