mod init {
    use crate::lifecycle::init::InitArg;
    use crate::numeric::{TransactionNonce, Wei};
    use crate::state::eth_logs_scraping::LogScrapingId;
    use crate::state::{InvalidStateError, State};
    use crate::test_fixtures::valid_init_arg;
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
                minimum_withdrawal_amount: Nat::from(0_u8),
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

        assert_matches!(
            State::try_from(InitArg {
                last_scraped_block_number: Nat(BigUint::from_bytes_be(
                    &ethnum::u256::MAX.to_be_bytes(),
                )),
                ..valid_init_arg()
            }),
            Err(InvalidStateError::InvalidLastScrapedBlockNumber(_))
        );
    }

    #[test]
    fn should_succeed() {
        let init_arg = valid_init_arg();

        let state = State::try_from(init_arg.clone()).expect("valid init args");

        assert_eq!(state.ethereum_network, init_arg.ethereum_network);
        assert_eq!(state.ecdsa_key_name, init_arg.ecdsa_key_name);
        assert_eq!(
            state
                .log_scrapings
                .contract_address(LogScrapingId::EthDepositWithoutSubaccount),
            None
        );
        assert_eq!(state.cketh_ledger_id, init_arg.ledger_id);
        assert_eq!(
            state.cketh_minimum_withdrawal_amount,
            Wei::new(10_000_000_000_000_000)
        );
        assert_eq!(
            state.eth_transactions.next_transaction_nonce(),
            TransactionNonce::ZERO
        );
    }
}
