use super::{
    MAX_DEPOSITS_PER_SWEEP, PreparedDeposit, SweepBatch, attested_addresses,
    delegation_authorization, prepared_deposits, stored_authorizations, sweep_batches_by_token,
};
use crate::deposit_address::DepositAddress;
use crate::numeric::{BlockNumber, Erc20Value, TransactionNonce};
use crate::state::State;
use crate::state::audit::{EventType, apply_state_transition};
use crate::state::automatic_deposits::SweepTarget;
use crate::state::event::AutomaticDeposit;
use crate::state::transactions::{SweepId, SweptDeposit};
use crate::test_fixtures::{deposit_helper, state_with_deposit_helper, transaction_signature};
use crate::tx::SignedAuthorization;
use candid::Principal;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeMap;

mod sweep_batch {
    use super::{
        SweepBatch, account, authorization, deposit_address, prepared_for, queued_targets, usdc,
        usdt,
    };
    use std::collections::BTreeSet;

    #[test]
    fn should_name_a_multi_token_account_once_in_the_call_data() {
        let targets = queued_targets(&[(0, usdc()), (0, usdt()), (1, usdc())]);

        let batch = SweepBatch::from(prepared_for(&targets));

        assert_eq!(
            batch
                .items
                .iter()
                .map(|item| (item.deposit, item.account))
                .collect::<Vec<_>>(),
            vec![
                (deposit_address(0), account(0)),
                (deposit_address(1), account(1))
            ]
        );
        assert_eq!(batch.tokens, vec![usdc(), usdt()]);
        assert_eq!(batch.authorizations, vec![authorization(); 2]);
    }

    #[test]
    fn should_keep_one_deposit_per_account_and_token() {
        let targets = queued_targets(&[(0, usdc()), (0, usdt()), (1, usdc())]);

        let batch = SweepBatch::from(prepared_for(&targets));

        assert_eq!(
            batch
                .deposits
                .iter()
                .map(|deposit| (deposit.account, deposit.erc20_contract_address))
                .collect::<Vec<_>>(),
            vec![
                (account(0), usdc()),
                (account(0), usdt()),
                (account(1), usdc())
            ]
        );
    }

    #[test]
    fn should_authorize_every_address_it_sweeps_exactly_once() {
        let targets = queued_targets(&[(0, usdc()), (0, usdt()), (1, usdc())]);

        let batch = SweepBatch::from(prepared_for(&targets));

        let addresses: BTreeSet<_> = batch
            .deposits
            .iter()
            .map(|deposit| deposit.address)
            .collect();
        assert_eq!(addresses.len(), 2);
        assert_eq!(batch.authorizations.len(), addresses.len());
    }

    #[test]
    fn should_authorize_an_address_again_in_a_second_sweep_of_the_same_round() {
        // Each token is its own sweep, so an address holding two of them is swept twice in one
        // round. Both tuples are signed for nonce 0: the first installs the delegation, the second
        // is skipped, and neither sweep waits for the other.
        let usdc_sweep = SweepBatch::from(prepared_for(&queued_targets(&[(0, usdc())])));
        let usdt_sweep = SweepBatch::from(prepared_for(&queued_targets(&[(0, usdt())])));

        assert_eq!(usdc_sweep.authorizations, vec![authorization()]);
        assert_eq!(usdt_sweep.authorizations, vec![authorization()]);
    }
}

mod sweep_batches_by_token {
    use super::{
        MAX_DEPOSITS_PER_SWEEP, account, authorization, deposit_address, fail_a_sweep_of,
        queued_state, sweep_batches_by_token, sweeper_contract, usdc, usdt,
    };
    use crate::numeric::{Wei, WeiPerGas};
    use crate::state::sweeper_funding::SweeperFundingConfig;
    use crate::state::transactions::{SweepId, SweepRequest, SweptDeposit};
    use crate::tx::GasFeeEstimate;

    #[test]
    fn should_batch_a_token_at_a_time() {
        let state = queued_state(&[(0, usdc()), (0, usdt()), (1, usdt())]);

        let batches = sweep_batches_by_token(&state);

        assert_eq!(
            batches.keys().copied().collect::<Vec<_>>(),
            vec![usdc(), usdt()]
        );
        assert_eq!(
            batches[&usdc()]
                .iter()
                .map(|target| target.account())
                .collect::<Vec<_>>(),
            vec![account(0)]
        );
        // The account holding both tokens is swept once per token, in different transactions.
        assert_eq!(
            batches[&usdt()]
                .iter()
                .map(|target| (target.account(), target.address()))
                .collect::<Vec<_>>(),
            vec![
                (account(0), deposit_address(0)),
                (account(1), deposit_address(1))
            ]
        );
    }

    #[test]
    fn should_leave_out_a_deposit_whose_sweep_failed() {
        let mut state = queued_state(&[(0, usdc()), (1, usdc()), (2, usdc())]);
        fail_a_sweep_of(&mut state, &[(1, usdc())]);

        let batches = sweep_batches_by_token(&state);

        assert_eq!(
            batches[&usdc()]
                .iter()
                .map(|target| target.account())
                .collect::<Vec<_>>(),
            vec![account(0), account(2)]
        );
    }

    #[test]
    fn should_cap_every_token_batch_on_its_own() {
        let queued: Vec<_> = (0..u8::try_from(MAX_DEPOSITS_PER_SWEEP).unwrap() + 3)
            .flat_map(|index| [(index, usdc()), (index, usdt())])
            .collect();

        let batches = sweep_batches_by_token(&queued_state(&queued));

        assert_eq!(batches[&usdc()].len(), MAX_DEPOSITS_PER_SWEEP);
        assert_eq!(batches[&usdt()].len(), MAX_DEPOSITS_PER_SWEEP);
    }

    #[test]
    fn should_keep_a_full_batch_within_what_a_single_sweep_may_prepay() {
        // Mainnet's minimum withdrawal amount, which is what sets the sweeper's funding: a target
        // of ten of them, and a low-water mark of half the target.
        let funding =
            SweeperFundingConfig::for_minimum_withdrawal_amount(Wei::new(30_000_000_000_000_000))
                .expect("BUG: the target must not overflow");

        let prepaid = GasFeeEstimate {
            base_fee_per_gas: WeiPerGas::from(10_000_000_000_u64),
            max_priority_fee_per_gas: WeiPerGas::from(1_000_000_000_u64),
        }
        .to_price(full_batch_request().gas_limit())
        .max_transaction_fee();

        assert!(
            prepaid <= funding.low_water_mark,
            "a full single-token batch prepays {prepaid:?}, above the {:?} a sweep may lock, so \
             every sweep would be refused at 10 gwei",
            funding.low_water_mark
        );
    }

    /// A sweep of a full batch of addresses holding one token, each carrying its authorization: the
    /// most gas [`MAX_DEPOSITS_PER_SWEEP`] deposits can come to.
    fn full_batch_request() -> SweepRequest {
        let deposits = u8::try_from(MAX_DEPOSITS_PER_SWEEP).expect("BUG: the cap must fit a u8");
        SweepRequest {
            id: SweepId(0),
            destination: sweeper_contract(),
            amount: Wei::ZERO,
            data: vec![],
            max_transaction_fee: Wei::ZERO,
            created_at: 0,
            authorizations: (0..deposits).map(|_| authorization()).collect(),
            deposits: (0..deposits)
                .map(|index| SweptDeposit {
                    account: account(index),
                    erc20_contract_address: usdc(),
                    address: deposit_address(index),
                })
                .collect(),
        }
    }
}

mod prepared_deposits {
    use super::{
        account, authorization, authorized, deposit_address, prepared_deposits, queued_targets,
        transaction_signature, usdc, usdt,
    };
    use crate::tx::TransactionSignature;
    use icrc_ledger_types::icrc1::account::Account;
    use std::collections::BTreeMap;

    #[test]
    fn should_drop_a_deposit_whose_authorization_could_not_be_signed() {
        let targets = queued_targets(&[(0, usdc()), (1, usdc())]);
        let attestations = attested(&[0, 1]);
        // Only account 1's authorization came back.
        let authorizations = authorized(&[1]);

        let prepared = prepared_deposits(&targets, &attestations, &authorizations);

        // Sweeping account 0 without it risks calling an address whose code was never installed,
        // and that reverts the whole batch.
        assert_eq!(
            prepared
                .iter()
                .map(|deposit| deposit.target.address())
                .collect::<Vec<_>>(),
            vec![deposit_address(1)]
        );
        assert_eq!(
            prepared[0].authorization,
            authorization(),
            "the deposit that is kept must carry the authorization this sweep installs"
        );
    }

    #[test]
    fn should_keep_every_deposit_of_an_authorized_account() {
        let targets = queued_targets(&[(0, usdc()), (0, usdt())]);

        let prepared = prepared_deposits(&targets, &attested(&[0]), &authorized(&[0]));

        assert_eq!(prepared.len(), 2);
    }

    #[test]
    fn should_drop_a_deposit_whose_attestation_could_not_be_signed() {
        let targets = queued_targets(&[(0, usdc()), (1, usdc())]);

        let prepared = prepared_deposits(&targets, &attested(&[1]), &authorized(&[0, 1]));

        assert_eq!(
            prepared
                .iter()
                .map(|deposit| deposit.target.address())
                .collect::<Vec<_>>(),
            vec![deposit_address(1)]
        );
    }

    fn attested(indices: &[u8]) -> BTreeMap<Account, TransactionSignature> {
        indices
            .iter()
            .map(|index| (account(*index), transaction_signature()))
            .collect()
    }
}

mod delegation_authorization {
    use super::{delegation_authorization, sweeper_contract};
    use crate::numeric::TransactionNonce;

    #[test]
    fn should_authorize_the_configured_delegate_at_nonce_zero() {
        let authorization = delegation_authorization(11155111, sweeper_contract());

        // Nonce 0 is what makes the tuple correct whether or not the address is already delegated,
        // so it is never read from chain and never anything else.
        assert_eq!(authorization.nonce, TransactionNonce::ZERO);
        assert_eq!(authorization.delegate, sweeper_contract());
        assert_eq!(authorization.chain_id, 11155111);
    }
}

mod attested_addresses {
    use super::{account, attested_addresses, deposit_address, queued_targets, usdc, usdt};
    use crate::test_fixtures::transaction_signature;
    use std::collections::BTreeMap;

    #[test]
    fn should_hold_one_address_per_attested_account() {
        let targets = queued_targets(&[(0, usdc()), (0, usdt()), (1, usdc())]);
        let attestations = BTreeMap::from([(account(0), transaction_signature())]);

        // Account 1 has no attestation, so authorizing its address would spend a signature on a
        // deposit that drops out of the sweep anyway.
        assert_eq!(
            attested_addresses(&targets, &attestations),
            BTreeMap::from([(account(0), deposit_address(0))])
        );
    }
}

mod stored_authorizations {
    use super::{
        account, authorization, deposit_address, queued_state, stored_authorizations,
        sweeper_contract, usdc,
    };
    use crate::deposit_address::DepositAddress;
    use crate::state::State;
    use crate::test_fixtures::init_state;
    use crate::tx::SignedAuthorization;
    use ic_ethereum_types::Address;
    use icrc_ledger_types::icrc1::account::Account;
    use std::collections::BTreeMap;

    #[test]
    fn should_reuse_the_tuple_stored_for_the_configured_delegate() {
        init_state(state_authorizing(sweeper_contract()));

        let stored = stored_authorizations(&addresses());

        assert_eq!(stored, BTreeMap::from([(account(0), authorization())]));
    }

    #[test]
    fn should_re_sign_a_tuple_stored_for_a_retired_delegate() {
        init_state(state_authorizing(previous_sweeper_contract()));

        let stored = stored_authorizations(&addresses());

        assert_eq!(stored, BTreeMap::new());
    }

    #[test]
    fn should_hold_nothing_for_an_address_never_authorized() {
        init_state(configured_state());

        let stored = stored_authorizations(&addresses());

        assert_eq!(stored, BTreeMap::new());
    }

    fn addresses() -> BTreeMap<Account, DepositAddress> {
        BTreeMap::from([(account(0), deposit_address(0))])
    }

    /// A configured state that has already recorded account 0's authorization to `delegate`.
    fn state_authorizing(delegate: Address) -> State {
        let mut state = configured_state();
        state.record_authorization(
            deposit_address(0),
            SignedAuthorization {
                delegate,
                ..authorization()
            },
        );
        state
    }

    fn configured_state() -> State {
        let mut state = queued_state(&[(0, usdc())]);
        state.sweeper_contract_address = Some(sweeper_contract());
        state
    }

    /// The sweeper contract a previous deployment delegated to.
    fn previous_sweeper_contract() -> Address {
        Address::new([0xdd; 20])
    }
}

/// The sweep queue of a state holding one funded pair per given `(account index, token)`, each at
/// its account's [`deposit_address`].
fn queued_targets(pairs: &[(u8, Address)]) -> Vec<SweepTarget> {
    let state = queued_state(pairs);
    state.automatic_deposits.sweep_targets_iter().collect()
}

/// A state whose deposit helper is configured, so every queued account has an attestation request,
/// and whose sweep queue holds one funded pair per given `(account index, token)`.
fn queued_state(pairs: &[(u8, Address)]) -> State {
    let mut state = state_with_deposit_helper(deposit_helper());
    for (index, token) in pairs {
        apply_state_transition(
            &mut state,
            &EventType::AutomaticDepositReceived(AutomaticDeposit {
                owner: account(*index).owner,
                subaccount: account(*index).subaccount,
                address: deposit_address(*index),
                erc20_contract_address: *token,
                last_scanned_block: BlockNumber::new(900),
                scan_count: 1,
                scanned_balance: Erc20Value::new(1_000),
            }),
        );
    }
    state
}

/// Take the given `(account index, token)` pairs into a sweep and have that sweep fail, which is how
/// a queued deposit comes to have a failure to its name.
fn fail_a_sweep_of(state: &mut State, pairs: &[(u8, Address)]) {
    let deposits: Vec<_> = pairs
        .iter()
        .map(|(index, token)| SweptDeposit {
            account: account(*index),
            erc20_contract_address: *token,
            address: deposit_address(*index),
        })
        .collect();
    let sweep_id = SweepId(0);
    state
        .automatic_deposits
        .record_sweep_scheduled(sweep_id, &deposits);
    state
        .automatic_deposits
        .record_sweep_failed(sweep_id, &deposits);
}

/// One [`PreparedDeposit`] per target, all attested and all authorized.
fn prepared_for(targets: &[SweepTarget]) -> Vec<PreparedDeposit> {
    targets
        .iter()
        .map(|target| PreparedDeposit {
            target: *target,
            attestation: transaction_signature(),
            authorization: authorization(),
        })
        .collect()
}

/// An authorization for the account of every given index.
fn authorized(indices: &[u8]) -> BTreeMap<Account, SignedAuthorization> {
    indices
        .iter()
        .map(|index| (account(*index), authorization()))
        .collect()
}

fn authorization() -> SignedAuthorization {
    SignedAuthorization {
        chain_id: 11155111,
        delegate: sweeper_contract(),
        nonce: TransactionNonce::ZERO,
        y_parity: transaction_signature().signature_y_parity,
        r: transaction_signature().r,
        s: transaction_signature().s,
    }
}

fn account(index: u8) -> Account {
    Account {
        owner: Principal::from_slice(&[index]),
        subaccount: Some([index; 32]),
    }
}

fn deposit_address(index: u8) -> DepositAddress {
    DepositAddress::new(Address::new([index; 20]))
}

fn sweeper_contract() -> Address {
    Address::new([0xde; 20])
}

fn usdc() -> Address {
    Address::new([0xaa; 20])
}

fn usdt() -> Address {
    Address::new([0xbb; 20])
}
