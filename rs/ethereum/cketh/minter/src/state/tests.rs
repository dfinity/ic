use crate::lifecycle::init::InitArg;
use crate::numeric::wei_from_milli_ether;
use crate::state::State;

mod next_request_id {
    use crate::state::tests::a_state;

    #[test]
    fn should_retrieve_and_increment_counter() {
        let mut state = a_state();

        assert_eq!(state.next_request_id(), 0);
        assert_eq!(state.next_request_id(), 1);
        assert_eq!(state.next_request_id(), 2);
        assert_eq!(state.next_request_id(), 3);
    }

    #[test]
    fn should_wrap_to_0_when_overflow() {
        let mut state = a_state();
        state.http_request_counter = u64::MAX;

        assert_eq!(state.next_request_id(), u64::MAX);
        assert_eq!(state.next_request_id(), 0);
    }
}

fn a_state() -> State {
    use candid::Principal;
    State::try_from(InitArg {
        ethereum_network: Default::default(),
        ecdsa_key_name: "test_key_1".to_string(),
        ethereum_contract_address: None,
        ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
            .expect("BUG: invalid principal"),
        ethereum_block_height: Default::default(),
        minimum_withdrawal_amount: wei_from_milli_ether(10).into(),
        next_transaction_nonce: Default::default(),
    })
    .expect("init args should be valid")
}

mod mint_transaction {
    use crate::eth_logs::{EventSourceError, ReceivedEthEvent};
    use crate::lifecycle::init::InitArg;
    use crate::numeric::{wei_from_milli_ether, BlockNumber, LedgerMintIndex, LogIndex, Wei};
    use crate::state::{MintedEvent, State};

    #[test]
    fn should_record_mint_task_from_event() {
        let mut state = dummy_state();
        let event = received_eth_event();

        state.record_event_to_mint(event.clone());

        assert!(state.events_to_mint.contains_key(&event.source()));

        let block_index = LedgerMintIndex::new(1u64);

        let minted_event = MintedEvent {
            deposit_event: event.clone(),
            mint_block_index: block_index,
        };

        state.record_successful_mint(event.source(), block_index);

        assert!(!state.events_to_mint.contains_key(&event.source()));
        assert_eq!(
            state.minted_events.get(&event.source()),
            Some(&minted_event)
        );
    }

    #[test]
    fn should_allow_minting_events_with_equal_txhash() {
        let mut state = dummy_state();
        let event_1 = ReceivedEthEvent {
            log_index: LogIndex::from(1u8),
            ..received_eth_event()
        };
        let event_2 = ReceivedEthEvent {
            log_index: LogIndex::from(2u8),
            ..received_eth_event()
        };

        assert_ne!(event_1, event_2);

        state.record_event_to_mint(event_1.clone());

        assert!(state.events_to_mint.contains_key(&event_1.source()));

        state.record_event_to_mint(event_2.clone());

        assert!(state.events_to_mint.contains_key(&event_2.source()));

        assert_eq!(2, state.events_to_mint.len());
    }

    #[test]
    #[should_panic = "unknown event"]
    fn should_not_allow_unknown_mints() {
        let mut state = dummy_state();
        let event = received_eth_event();

        assert!(!state.events_to_mint.contains_key(&event.source()));
        state.record_successful_mint(event.source(), LedgerMintIndex::new(1));
    }

    #[test]
    #[should_panic = "invalid"]
    fn should_not_record_invalid_deposit_already_recorded_as_valid() {
        let mut state = dummy_state();
        let event = received_eth_event();

        state.record_event_to_mint(event.clone());

        assert!(state.events_to_mint.contains_key(&event.source()));

        state.record_invalid_deposit(
            event.source(),
            EventSourceError::InvalidEvent("bad".to_string()).to_string(),
        );
    }

    #[test]
    fn should_not_update_already_recorded_invalid_deposit() {
        let mut state = dummy_state();
        let event = received_eth_event();
        let error = EventSourceError::InvalidEvent("first".to_string());
        let other_error = EventSourceError::InvalidEvent("second".to_string());
        assert_ne!(error, other_error);

        assert!(state.record_invalid_deposit(event.source(), error.to_string()));
        assert_eq!(state.invalid_events[&event.source()], error.to_string());

        assert!(!state.record_invalid_deposit(event.source(), other_error.to_string()));
        assert_eq!(state.invalid_events[&event.source()], error.to_string());
    }

    #[test]
    fn should_have_readable_debug_representation() {
        let expected = "ReceivedEthEvent { \
          transaction_hash: 0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2, \
          block_number: 3_960_623, \
          log_index: 29, \
          from_address: 0xdd2851Cdd40aE6536831558DD46db62fAc7A844d, \
          value: 10_000_000_000_000_000, \
          principal: k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae \
        }";
        assert_eq!(format!("{:?}", received_eth_event()), expected);
    }

    fn dummy_state() -> State {
        use candid::Principal;
        State::try_from(InitArg {
            ethereum_network: Default::default(),
            ecdsa_key_name: "test_key_1".to_string(),
            ethereum_contract_address: None,
            ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
                .expect("BUG: invalid principal"),
            ethereum_block_height: Default::default(),
            minimum_withdrawal_amount: wei_from_milli_ether(10).into(),
            next_transaction_nonce: Default::default(),
        })
        .expect("init args should be valid")
    }

    fn received_eth_event() -> ReceivedEthEvent {
        ReceivedEthEvent {
            transaction_hash: "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2"
                .parse()
                .unwrap(),
            block_number: BlockNumber::new(3960623u128),
            log_index: LogIndex::from(29u8),
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

mod upgrade {
    use crate::address::Address;
    use crate::eth_rpc::BlockTag;
    use crate::lifecycle::upgrade::UpgradeArg;
    use crate::numeric::{wei_from_milli_ether, TransactionNonce, Wei};
    use crate::state::{InvalidStateError, State};
    use assert_matches::assert_matches;
    use candid::Nat;
    use num_bigint::BigUint;
    use std::str::FromStr;

    #[test]
    fn should_fail_when_upgrade_args_invalid() {
        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                next_transaction_nonce: Some(Nat(BigUint::from_bytes_be(
                    &ethnum::u256::MAX.to_be_bytes(),
                ) + 1_u8)),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidTransactionNonce(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                minimum_withdrawal_amount: Some(Nat::from(0)),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidMinimumWithdrawalAmount(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                ethereum_contract_address: Some("invalid".to_string()),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidEthereumContractAddress(_))
        );

        let mut state = initial_state();
        assert_matches!(
            state.upgrade(UpgradeArg {
                ethereum_contract_address: Some(
                    "0x0000000000000000000000000000000000000000".to_string(),
                ),
                ..Default::default()
            }),
            Err(InvalidStateError::InvalidEthereumContractAddress(_))
        );
    }

    #[test]
    fn should_succeed() {
        use crate::endpoints::CandidBlockTag;
        let mut state = initial_state();
        let upgrade_arg = UpgradeArg {
            next_transaction_nonce: Some(Nat::from(15)),
            minimum_withdrawal_amount: Some(Nat::from(100)),
            ethereum_contract_address: Some(
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
            ),
            ethereum_block_height: Some(CandidBlockTag::Safe),
        };

        state.upgrade(upgrade_arg).expect("valid upgrade args");

        assert_eq!(state.next_transaction_nonce, TransactionNonce::from(15_u64));
        assert_eq!(state.minimum_withdrawal_amount, Wei::from(100_u64));
        assert_eq!(
            state.ethereum_contract_address,
            Some(Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap())
        );
        assert_eq!(state.ethereum_block_height, BlockTag::Safe);
    }

    fn initial_state() -> State {
        use crate::lifecycle::init::InitArg;
        use candid::Principal;
        State::try_from(InitArg {
            ethereum_network: Default::default(),
            ecdsa_key_name: "test_key_1".to_string(),
            ethereum_contract_address: None,
            ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
                .expect("BUG: invalid principal"),
            ethereum_block_height: Default::default(),
            minimum_withdrawal_amount: wei_from_milli_ether(10).into(),
            next_transaction_nonce: Default::default(),
        })
        .expect("valid init args")
    }
}
