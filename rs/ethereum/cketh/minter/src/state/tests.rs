use crate::eth_rpc::BlockTag;
use crate::lifecycle::init::InitArg;
use crate::numeric::Wei;
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
        ethereum_block_height: BlockTag::Finalized,
        minimum_withdrawal_amount: Wei::from_milliether(10).into(),
        next_transaction_nonce: Default::default(),
    })
    .expect("init args should be valid")
}
