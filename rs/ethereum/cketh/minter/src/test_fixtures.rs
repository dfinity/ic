use crate::EVM_RPC_ID_STAGING;
use crate::attestation::AttestationRequest;
use crate::deposit_address::DepositAddress;
use crate::eth_logs::LedgerSubaccount;
use crate::eth_rpc::Hash;
use crate::eth_rpc_client::responses::{TransactionReceipt, TransactionStatus};
use crate::lifecycle::init::InitArg;
use crate::numeric::{
    BlockNumber, Erc20Value, GasAmount, LedgerBurnIndex, TransactionNonce, Wei, WeiPerGas,
};
use crate::state::audit::{EventType, apply_state_transition};
use crate::state::automatic_deposits::AutomaticDeposits;
use crate::state::eth_logs_scraping::LogScrapingId;
use crate::state::event::AutomaticDeposit;
use crate::state::transactions::{EthWithdrawalRequest, SweepRequest};
use crate::state::{State, read_state};
use crate::sweep::create_pending_sweeper_requests;
use crate::tx::{
    AccessList, AuthorizationRequest, Eip1559TransactionRequest, FinalizedEip1559Transaction,
    GasFeeEstimate, Signed, TransactionSignature,
};
use candid::{Nat, Principal};
use ethnum::u256;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeSet;

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

/// A second account, for tests that need two deposit addresses in one sweep.
pub fn another_account() -> Account {
    Account {
        owner: Principal::from_slice(&[5, 6, 7, 8]),
        subaccount: Some([43_u8; 32]),
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

pub fn deposit_address(account: &Account) -> DepositAddress {
    let mut preimage = account.owner.as_slice().to_vec();
    preimage.extend_from_slice(account.effective_subaccount());
    let hash = ic_sha3::Keccak256::hash(&preimage);
    let mut bytes = [0_u8; 20];
    bytes.copy_from_slice(&hash[12..32]);
    DepositAddress::new(Address::new(bytes))
}

pub fn usdc() -> Address {
    Address::new([0xaa; 20])
}

pub fn usdt() -> Address {
    Address::new([0xbb; 20])
}

pub fn automatic_deposit() -> AutomaticDeposit {
    AutomaticDeposit {
        owner: account().owner,
        subaccount: account().subaccount,
        address: DepositAddress::new(Address::new([0xa1; 20])),
        erc20_contract_address: Address::new([0x22; 20]),
        last_scanned_block: BlockNumber::new(1_000),
        scan_count: 1,
        scanned_balance: Erc20Value::from(1_000_000_u64),
    }
}

/// An [`AutomaticDeposits`] whose sweep queue holds exactly these funded pairs, all taken by the
/// one sweep [`create_pending_sweeper_requests`] enqueued for them, returned along with that
/// request.
pub async fn deposits_with_enqueued_sweep(
    pairs: &[(Account, Address)],
) -> (AutomaticDeposits, SweepRequest) {
    let (state, request) = state_with_enqueued_sweep(pairs).await;
    (state.automatic_deposits, request)
}

pub const PREPAID_SWEEP_GAS: Wei = Wei::new(1_000_000_000_000_000_000);

/// A finalized funding transaction that carried `amount` and paid `transaction_fee` for gas: one
/// unit of gas priced at the whole fee, so the receipt reports exactly that fee.
pub fn finalized_funding(
    amount: Wei,
    transaction_fee: Wei,
    status: TransactionStatus,
) -> FinalizedEip1559Transaction {
    let effective_gas_price: WeiPerGas = transaction_fee.change_units();
    let signed = Signed::from((
        Eip1559TransactionRequest {
            chain_id: 1,
            nonce: TransactionNonce::ZERO,
            max_priority_fee_per_gas: WeiPerGas::ZERO,
            max_fee_per_gas: effective_gas_price,
            gas_limit: GasAmount::ONE,
            destination: Address::new([0x5e; 20]),
            amount,
            data: Vec::new(),
            access_list: AccessList::new(),
        },
        transaction_signature(),
    ));
    let receipt = TransactionReceipt {
        block_hash: Hash([0x11; 32]),
        block_number: BlockNumber::new(4_190_269),
        effective_gas_price,
        gas_used: GasAmount::ONE,
        status,
        transaction_hash: signed.hash(),
    };
    signed
        .try_finalize(receipt)
        .expect("test setup: the receipt matches the signed transaction")
}

pub fn prepay_sweep_gas(state: &mut State) {
    state.sweeper_funding.record_burn(PREPAID_SWEEP_GAS);
    state
        .sweeper_funding
        .record_finalized_funding(&finalized_funding(
            PREPAID_SWEEP_GAS,
            Wei::ZERO,
            TransactionStatus::Success,
        ));
}

/// A [`State`] whose sweep queue holds exactly these funded pairs, all taken by the one sweep
/// [`create_pending_sweeper_requests`] enqueued for them, returned along with that request. The
/// deposits, attestations and authorizations the enqueue pairs up arrive through the event log, so
/// the sweep is assembled by the production path without the runtime signing anything.
pub async fn state_with_enqueued_sweep(pairs: &[(Account, Address)]) -> (State, SweepRequest) {
    const SWEEP_DECIDED_AT: u64 = 1_620_328_630_000_000_000;

    let mut state = state_with_deposit_helper(deposit_helper());
    prepay_sweep_gas(&mut state);
    state.sweeper_contract_address = Some(sweeper_contract());
    state.last_transaction_price_estimate = Some((SWEEP_DECIDED_AT, gas_fee_estimate()));
    let chain_id = state.ethereum_network.chain_id();
    for (account, token) in pairs {
        apply_state_transition(
            &mut state,
            &EventType::AutomaticDepositReceived(AutomaticDeposit {
                owner: account.owner,
                subaccount: account.subaccount,
                address: deposit_address(account),
                erc20_contract_address: *token,
                ..automatic_deposit()
            }),
        );
    }
    for account in pairs
        .iter()
        .map(|(account, _token)| *account)
        .collect::<BTreeSet<_>>()
    {
        apply_state_transition(
            &mut state,
            &EventType::AttestedDepositAddress {
                request: AttestationRequest::new(chain_id, deposit_helper(), account),
                signature: transaction_signature(),
            },
        );
        apply_state_transition(
            &mut state,
            &EventType::AuthorizedDepositAddress {
                request: AuthorizationRequest::new(
                    account,
                    chain_id,
                    sweeper_contract(),
                    TransactionNonce::ZERO,
                ),
                signature: transaction_signature(),
            },
        );
    }
    init_state(state);
    let mut runtime = mock::MockCanisterRuntime::new();
    runtime.expect_time().return_const(SWEEP_DECIDED_AT);

    create_pending_sweeper_requests(&runtime).await;

    read_state(|s| {
        let [request] =
            <[SweepRequest; 1]>::try_from(s.automatic_deposits.sweep_requests_batch(usize::MAX))
                .expect("BUG: expected the pairs to become exactly one sweep");
        (s.clone(), request)
    })
}

pub fn sweeper_contract() -> Address {
    Address::new([0x5e; 20])
}

/// The estimate every sweep fixture prices and creates with, so a fixture sweep's transaction fee
/// always fits the cap its request was priced against.
pub fn gas_fee_estimate() -> GasFeeEstimate {
    GasFeeEstimate {
        base_fee_per_gas: WeiPerGas::new(10),
        max_priority_fee_per_gas: WeiPerGas::new(1),
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
    use crate::management::CallError;
    use crate::runtime::CanisterRuntime;
    use crate::time::TimeProvider;
    use async_trait::async_trait;
    use ic_cdk_management_canister::EcdsaPublicKeyResult;
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

    mock! {
        #[derive(Debug)]
        pub CanisterRuntime {}

        impl TimeProvider for CanisterRuntime {
            fn time(&self) -> u64;
        }

        #[async_trait]
        impl CanisterRuntime for CanisterRuntime {
            async fn sign_with_ecdsa(
                &self,
                key_name: String,
                derivation_path: Vec<Vec<u8>>,
                message_hash: [u8; 32],
            ) -> Result<[u8; 64], CallError>;

            async fn ecdsa_public_key(
                &self,
                key_name: String,
                derivation_path: Vec<Vec<u8>>,
            ) -> Result<EcdsaPublicKeyResult, CallError>;
        }

        impl Clone for CanisterRuntime {
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
