use crate::EVM_RPC_ID_STAGING;
use crate::eth_logs::LedgerSubaccount;
use crate::lifecycle::init::InitArg;
use crate::numeric::{LedgerBurnIndex, Wei};
use crate::state::State;
use crate::state::eth_logs_scraping::LogScrapingId;
use crate::state::transactions::EthWithdrawalRequest;
use crate::tx::TransactionSignature;
use candid::{Nat, Principal};
use ethnum::u256;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;

pub fn expect_panic_with_message<F: FnOnce() -> R, R: std::fmt::Debug>(
    f: F,
    expected_message: &str,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let error = result.expect_err(&format!(
        "Expected panic with message containing: {expected_message}"
    ));
    let panic_message = {
        if let Some(s) = error.downcast_ref::<String>() {
            s.to_string()
        } else if let Some(s) = error.downcast_ref::<&str>() {
            s.to_string()
        } else {
            format!("{error:?}")
        }
    };
    assert!(
        panic_message.contains(expected_message),
        "Expected panic message to contain: {expected_message}, but got: {panic_message}"
    );
}

pub fn initial_state() -> State {
    State::try_from(valid_init_arg()).expect("BUG: invalid init arg")
}

/// [`initial_state`] with `deposit_helper` configured as the deposit helper whose events name the
/// account an address credits, which is the one the deposit and sweep paths read.
pub fn state_with_deposit_helper(deposit_helper: Address) -> State {
    let mut state = initial_state();
    state.log_scrapings.set_contract_address(
        LogScrapingId::EthOrErc20DepositWithSubaccount,
        deposit_helper,
    );
    state
}

/// An account a deposit address is derived for. Its subaccount is explicit, so a test that clears
/// it changes the value instead of falling back to the default subaccount.
pub fn account() -> Account {
    Account {
        owner: Principal::from_slice(&[1, 2, 3, 4]),
        subaccount: Some([42_u8; 32]),
    }
}

/// The deposit helper whose events name the account an address credits.
pub fn deposit_helper() -> Address {
    "0x2D39863d30716aaf2B7fFFd85Dd03Dda2BFC2E38"
        .parse()
        .expect("BUG: invalid address")
}

/// A well-formed signature that stands for no particular one, for tests that only check it is
/// carried around unchanged.
pub fn transaction_signature() -> TransactionSignature {
    TransactionSignature {
        signature_y_parity: true,
        r: u256::from_be_bytes([0xaa; 32]),
        s: u256::from_be_bytes([0xbb; 32]),
    }
}

/// A sweeper funding request of `withdrawal_amount`, as the funding task builds one: burned from the
/// minter's own fee subaccount, sent to its sweeper address.
pub fn sweeper_funding_request(withdrawal_amount: Wei) -> EthWithdrawalRequest {
    EthWithdrawalRequest {
        withdrawal_amount,
        destination: "0x5353535353535353535353535353535353535353"
            .parse()
            .unwrap(),
        ledger_burn_index: LedgerBurnIndex::new(0),
        from: "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
            .parse()
            .unwrap(),
        from_subaccount: LedgerSubaccount::from_bytes(crate::CKETH_FEE_SUBACCOUNT),
        created_at: Some(1699527697000000000),
    }
}

/// Install `state` into the global thread-local `STATE`, so `read_state`/`mutate_state` see it in a
/// unit test. Each test runs on its own thread, so the `thread_local!` `STATE` is per-test.
pub fn init_state(state: State) {
    crate::state::STATE.with_borrow_mut(|cell| *cell = Some(state));
}

pub fn valid_init_arg() -> InitArg {
    InitArg {
        ethereum_network: Default::default(),
        ecdsa_key_name: "test_key_1".to_string(),
        ethereum_contract_address: None,
        ledger_id: Principal::from_text("apia6-jaaaa-aaaar-qabma-cai")
            .expect("BUG: invalid principal"),
        ethereum_block_height: Default::default(),
        minimum_withdrawal_amount: Nat::from(10_000_000_000_000_000_u64),
        next_transaction_nonce: Default::default(),
        last_scraped_block_number: Default::default(),
        evm_rpc_id: Some(EVM_RPC_ID_STAGING),
        ethereum_sweeper_contract_address: None,
        next_sweeper_transaction_nonce: None,
    }
}

pub mod mock {
    use crate::time::TimeProvider;
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub TimeProvider {}

        impl TimeProvider for TimeProvider {
            fn time(&self) -> u64;
        }

        impl Clone for TimeProvider {
            fn clone(&self) -> Self;
        }
    }
}

pub mod arb {
    use crate::checked_amount::CheckedAmountOf;
    use crate::eth_logs::LedgerSubaccount;
    use crate::eth_rpc::Hash;
    use crate::numeric::BlockRangeInclusive;
    use candid::Principal;
    use ic_ethereum_types::Address;
    use proptest::{
        array::{uniform20, uniform32},
        collection::vec,
        prelude::{Strategy, any},
    };

    pub fn arb_checked_amount_of<Unit>() -> impl Strategy<Value = CheckedAmountOf<Unit>> {
        use proptest::arbitrary::any;
        use proptest::array::uniform32;
        uniform32(any::<u8>()).prop_map(CheckedAmountOf::from_be_bytes)
    }

    pub fn arb_block_range_inclusive() -> impl Strategy<Value = BlockRangeInclusive> {
        (arb_checked_amount_of(), arb_checked_amount_of())
            .prop_map(|(start, end)| BlockRangeInclusive::new(start, end))
    }

    pub fn arb_principal() -> impl Strategy<Value = Principal> {
        vec(any::<u8>(), 0..=29).prop_map(|bytes| Principal::from_slice(&bytes))
    }

    pub fn arb_ledger_subaccount() -> impl Strategy<Value = Option<LedgerSubaccount>> {
        uniform32(any::<u8>()).prop_map(LedgerSubaccount::from_bytes)
    }

    pub fn arb_address() -> impl Strategy<Value = Address> {
        uniform20(any::<u8>()).prop_map(Address::new)
    }

    pub fn arb_hash() -> impl Strategy<Value = Hash> {
        uniform32(any::<u8>()).prop_map(Hash)
    }
}
