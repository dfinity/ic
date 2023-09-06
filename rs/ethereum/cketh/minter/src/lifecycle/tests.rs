mod init {
    use crate::lifecycle::init::InitArg;
    use crate::numeric::{TransactionNonce, Wei};
    use crate::state::{InvalidStateError, State};
    use assert_matches::assert_matches;
    use candid::{Nat, Principal};
    use num_bigint::BigUint;

    #[test]
    fn should_fail_when_init_args_invalid() {
        assert_matches!(
            State::try_from(InitArg {
                ecdsa_key_name: "     ".to_string(),
                ..valid_init_arg()
            }),
            Err(InvalidStateError::InvalidEcdsaKeyName(_))
        );

        assert_matches!(
            State::try_from(InitArg {
                minimum_withdrawal_amount: Nat::from(0),
                ..valid_init_arg()
            }),
            Err(InvalidStateError::InvalidMinimumWithdrawalAmount(_))
        );

        assert_matches!(
            State::try_from(InitArg {
                ethereum_contract_address: Some("invalid".to_string()),
                ..valid_init_arg()
            }),
            Err(InvalidStateError::InvalidEthereumContractAddress(_))
        );

        assert_matches!(
            State::try_from(InitArg {
                ethereum_contract_address: Some(
                    "0x0000000000000000000000000000000000000000".to_string(),
                ),
                ..valid_init_arg()
            }),
            Err(InvalidStateError::InvalidEthereumContractAddress(_))
        );

        assert_matches!(
            State::try_from(InitArg {
                ledger_id: Principal::anonymous(),
                ..valid_init_arg()
            }),
            Err(InvalidStateError::InvalidLedgerId(_))
        );

        assert_matches!(
            State::try_from(InitArg {
                next_transaction_nonce: Nat(BigUint::from_bytes_be(
                    &ethnum::u256::MAX.to_be_bytes(),
                ) + 1_u8),
                ..valid_init_arg()
            }),
            Err(InvalidStateError::InvalidTransactionNonce(_))
        );
    }

    #[test]
    fn should_succeed() {
        let init_arg = valid_init_arg();

        let state = State::try_from(init_arg.clone()).expect("valid init args");

        assert_eq!(state.ethereum_network, init_arg.ethereum_network);
        assert_eq!(state.ecdsa_key_name, init_arg.ecdsa_key_name);
        assert_eq!(state.ethereum_contract_address, None);
        assert_eq!(state.ledger_id, init_arg.ledger_id);
        assert_eq!(state.minimum_withdrawal_amount, Wei::TWO);
        assert_eq!(state.next_transaction_nonce, TransactionNonce::ZERO);
    }

    fn valid_init_arg() -> InitArg {
        InitArg {
            ethereum_network: Default::default(),
            ecdsa_key_name: "test_key_1".to_string(),
            ethereum_contract_address: None,
            ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
                .expect("BUG: invalid principal"),
            minimum_withdrawal_amount: Wei::TWO.into(),
            next_transaction_nonce: TransactionNonce::ZERO.into(),
        }
    }
}

mod upgrade {
    use crate::address::Address;
    use crate::lifecycle::upgrade::UpgradeArg;
    use crate::numeric::{TransactionNonce, Wei};
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
        let mut state = initial_state();
        let upgrade_arg = UpgradeArg {
            next_transaction_nonce: Some(Nat::from(15)),
            minimum_withdrawal_amount: Some(Nat::from(100)),
            ethereum_contract_address: Some(
                "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34".to_string(),
            ),
        };

        state.upgrade(upgrade_arg).expect("valid upgrade args");

        assert_eq!(state.next_transaction_nonce, TransactionNonce::from(15_u64));
        assert_eq!(state.minimum_withdrawal_amount, Wei::from(100_u64));
        assert_eq!(
            state.ethereum_contract_address,
            Some(Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap())
        );
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
            minimum_withdrawal_amount: Wei::from_milliether(10).into(),
            next_transaction_nonce: Default::default(),
        })
        .expect("valid init args")
    }
}
