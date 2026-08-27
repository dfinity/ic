use super::{
    MAX_DEPOSITS_PER_SWEEP, PreparedDeposit, SweepBatch, SweepContext, attested_addresses,
    delegation_authorization, enqueue_token_sweep, prepared_deposits, sweep_batches_by_token,
};
use crate::deposit_address::{DepositAddress, DepositAddressSchema, deposit_derivation_path};
use crate::eth_rpc::Hash;
use crate::numeric::{BlockNumber, Erc20Value, TransactionNonce, WeiPerGas};
use crate::state::audit::{EventType, apply_state_transition};
use crate::state::automatic_deposits::SweepTarget;
use crate::state::event::AutomaticDeposit;
use crate::state::transactions::{SweepId, SweepRequest, SweptDeposit};
use crate::state::{State, read_state};
use crate::test_fixtures::{
    deposit_helper, init_state, state_with_deposit_helper, transaction_signature,
};
use crate::tx::{EcdsaSigner, GasFeeEstimate, SignedAuthorization, TransactionSignature};
use candid::Principal;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use mockall::mock;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

mod enqueue_token_sweep {
    use super::{
        CREATED_AT, MockSigner, account, attestation_of, authorization_of, context,
        deposit_address, enqueue_token_sweep, enqueued_sweep, enqueued_sweeps, expect_once,
        gas_fee_estimate, install, queued_state, queued_targets_len, refusing, signing_anything,
        sweeper_contract, transaction_signature, usdc,
    };
    use crate::numeric::{Wei, WeiPerGas};
    use crate::state::audit::{EventType, apply_state_transition};
    use crate::state::read_state;
    use crate::state::transactions::{SweepId, SweepRequest, SweptDeposit};
    use crate::sweeper_contract::{SweepItem, encode_sweep_erc20_batch};
    use crate::test_fixtures::{init_state, initial_state};
    use crate::tx::GasFeeEstimate;
    use icrc_ledger_types::icrc1::account::Account;

    #[tokio::test]
    async fn should_be_no_op_when_targets_empty() {
        install(queued_state(&[(0, usdc())]));
        // An empty mock: a token with nothing queued must ask for no signature, and a request
        // nothing expects fails the test.
        let context = context(MockSigner::new());

        enqueue_token_sweep((usdc(), vec![]), &context).await;

        assert_eq!(enqueued_sweeps(), vec![]);
        assert_eq!(read_state(|s| s.next_sweep_id), SweepId(0));
        assert_eq!(
            queued_targets_len(),
            1,
            "nothing may be taken off the queue"
        );
    }

    #[tokio::test]
    async fn should_be_no_op_when_helper_deposit_smart_contract_not_configured() {
        let targets = install(queued_state(&[(0, usdc())]));
        // Without the helper there is no attestation preimage, so no deposit address can prove which
        // account it credits and the delegate would refuse every item of the batch.
        init_state(initial_state());
        let context = context(MockSigner::new());

        enqueue_token_sweep((usdc(), targets), &context).await;

        assert_eq!(enqueued_sweeps(), vec![]);
        assert_eq!(read_state(|s| s.next_sweep_id), SweepId(0));
    }

    #[tokio::test]
    async fn should_sweep_every_queued_deposit_of_the_token() {
        let targets = install(queued_state(&[(0, usdc()), (1, usdc())]));

        enqueue_token_sweep((usdc(), targets), &context(signing_anything())).await;

        let sweep = enqueued_sweep();
        assert_eq!(sweep.id, SweepId(0));
        assert_eq!(sweep.destination, sweeper_contract());
        assert_eq!(sweep.amount, Wei::ZERO, "an ERC-20 sweep moves no ETH");
        assert_eq!(sweep.created_at, CREATED_AT);
        assert_eq!(
            sweep.deposits,
            vec![
                SweptDeposit {
                    account: account(0),
                    erc20_contract_address: usdc(),
                    address: deposit_address(0),
                },
                SweptDeposit {
                    account: account(1),
                    erc20_contract_address: usdc(),
                    address: deposit_address(1),
                },
            ]
        );
        assert_eq!(
            sweep.data,
            encode_sweep_erc20_batch(
                &[
                    SweepItem {
                        deposit: deposit_address(0),
                        account: account(0),
                        attestation: transaction_signature(),
                    },
                    SweepItem {
                        deposit: deposit_address(1),
                        account: account(1),
                        attestation: transaction_signature(),
                    },
                ],
                &[usdc()],
            ),
            "every attested address must reach the call data carrying its own attestation"
        );
    }

    #[tokio::test]
    async fn should_sign_over_the_attestation_and_the_authorization_of_every_address() {
        let targets = install(queued_state(&[(0, usdc()), (1, usdc())]));
        let mut signer = MockSigner::new();
        // The sweep's whole cryptographic cost: one attestation digest per account, one
        // authorization tuple per deposit address, and nothing else. Each must be asked for exactly
        // once, and a request outside them has no expectation to match.
        for signable in [
            attestation_of(0),
            attestation_of(1),
            authorization_of(0),
            authorization_of(1),
        ] {
            expect_once(&mut signer, signable, Ok(transaction_signature()));
        }

        enqueue_token_sweep((usdc(), targets), &context(signer)).await;

        assert_eq!(
            swept_accounts(&enqueued_sweep()),
            vec![account(0), account(1)]
        );
    }

    #[tokio::test]
    async fn should_record_the_attestation_it_signed() {
        let targets = install(queued_state(&[(0, usdc())]));

        enqueue_token_sweep((usdc(), targets), &context(signing_anything())).await;

        // An attestation outlives the sweep that paid for it, so it is recorded rather than
        // recomputed: this is what lets the next sweep of the address skip the signature.
        assert_eq!(
            read_state(|s| s.attestation(account(0)).cloned()),
            Some(transaction_signature())
        );
    }

    #[tokio::test]
    async fn should_reuse_a_stored_attestation_instead_of_signing_it_again() {
        let mut state = queued_state(&[(0, usdc())]);
        let request = state
            .attestation_request(account(0))
            .expect("BUG: the deposit helper is configured");
        apply_state_transition(
            &mut state,
            &EventType::AttestedDepositAddress {
                request,
                signature: transaction_signature(),
            },
        );
        let targets = install(state);
        let mut signer = MockSigner::new();
        // Only the authorization. Nothing expects the attestation, so asking for it fails the test:
        // it names the account and the helper, neither of which a sweep changes, and the minter
        // already holds a signature over that digest.
        expect_once(
            &mut signer,
            authorization_of(0),
            Ok(transaction_signature()),
        );

        enqueue_token_sweep((usdc(), targets), &context(signer)).await;

        assert_eq!(swept_accounts(&enqueued_sweep()), vec![account(0)]);
    }

    #[tokio::test]
    async fn should_take_the_deposits_it_sweeps_out_of_the_queue() {
        let targets = install(queued_state(&[(0, usdc()), (1, usdc())]));

        enqueue_token_sweep((usdc(), targets), &context(signing_anything())).await;

        // A deposit gets one sweep and no more: taken by this one, it is no longer a target the next
        // tick would sweep again. The entry itself stays, attributed to the sweep, so that its
        // outcome can be applied to it.
        assert_eq!(queued_targets_len(), 0);
        assert_eq!(read_state(|s| s.automatic_deposits.sweep_len()), 2);
    }

    #[tokio::test]
    async fn should_advance_the_next_sweep_id() {
        let targets = install(queued_state(&[(0, usdc())]));

        enqueue_token_sweep((usdc(), targets), &context(signing_anything())).await;

        // The next token's sweep in the same tick reads this, so it must not reuse the id.
        assert_eq!(read_state(|s| s.next_sweep_id), SweepId(1));
    }

    #[tokio::test]
    async fn should_leave_out_a_deposit_whose_attestation_could_not_be_signed() {
        let targets = install(queued_state(&[(0, usdc()), (1, usdc())]));

        enqueue_token_sweep((usdc(), targets), &context(refusing(&[attestation_of(0)]))).await;

        assert_eq!(swept_accounts(&enqueued_sweep()), vec![account(1)]);
    }

    #[tokio::test]
    async fn should_leave_out_a_deposit_whose_authorization_could_not_be_signed() {
        let targets = install(queued_state(&[(0, usdc()), (1, usdc())]));

        enqueue_token_sweep(
            (usdc(), targets),
            &context(refusing(&[authorization_of(0)])),
        )
        .await;

        // solc guards the delegate call with `extcodesize`, so sweeping an address whose code was
        // never installed would revert the whole batch.
        assert_eq!(swept_accounts(&enqueued_sweep()), vec![account(1)]);
    }

    #[tokio::test]
    async fn should_still_record_the_attestation_of_a_deposit_it_could_not_authorize() {
        let targets = install(queued_state(&[(0, usdc()), (1, usdc())]));

        enqueue_token_sweep(
            (usdc(), targets),
            &context(refusing(&[authorization_of(0)])),
        )
        .await;

        // Account 0 drops out of this sweep, but its attestation was signed and is good forever:
        // losing it would make the next sweep pay for it again.
        assert_eq!(
            read_state(|s| s.attestation(account(0)).cloned()),
            Some(transaction_signature())
        );
    }

    #[tokio::test]
    async fn should_not_authorize_an_address_it_could_not_attest() {
        let targets = install(queued_state(&[(0, usdc()), (1, usdc())]));
        let mut signer = MockSigner::new();
        expect_once(
            &mut signer,
            attestation_of(0),
            Err("no attestation".to_string()),
        );
        expect_once(&mut signer, attestation_of(1), Ok(transaction_signature()));
        expect_once(
            &mut signer,
            authorization_of(1),
            Ok(transaction_signature()),
        );
        // Nothing expects account 0's authorization: it drops out of the sweep either way, so
        // authorizing it would spend a threshold-ECDSA signature on nothing.

        enqueue_token_sweep((usdc(), targets), &context(signer)).await;

        assert_eq!(swept_accounts(&enqueued_sweep()), vec![account(1)]);
    }

    #[tokio::test]
    async fn should_skip_the_token_when_nothing_could_be_signed_for() {
        let targets = install(queued_state(&[(0, usdc()), (1, usdc())]));

        enqueue_token_sweep(
            (usdc(), targets),
            &context(refusing(&[attestation_of(0), attestation_of(1)])),
        )
        .await;

        assert_eq!(enqueued_sweeps(), vec![]);
    }

    #[tokio::test]
    async fn should_skip_the_token_when_the_sweep_would_prepay_above_the_ceiling() {
        let targets = install(queued_state(&[(0, usdc())]));
        let mut context = context(signing_anything());
        // A fee this high puts the prepayment far above the low-water mark the sweeper address is
        // kept above, so this is a sweep the minter could not pay for.
        context.gas_fee_estimate = GasFeeEstimate {
            base_fee_per_gas: WeiPerGas::from(10_000_000_000_000_u64),
            max_priority_fee_per_gas: WeiPerGas::from(1_000_000_000_u64),
        };

        enqueue_token_sweep((usdc(), targets), &context).await;

        // The deposits stay queued for the next tick, at whatever the fee is then.
        assert_eq!(enqueued_sweeps(), vec![]);
        assert_eq!(queued_targets_len(), 1);
    }

    #[tokio::test]
    async fn should_price_the_sweep_at_the_gas_estimate() {
        let targets = install(queued_state(&[(0, usdc())]));

        enqueue_token_sweep((usdc(), targets), &context(signing_anything())).await;

        let sweep = enqueued_sweep();
        assert_eq!(
            sweep.max_transaction_fee,
            gas_fee_estimate()
                .to_price(sweep.gas_limit())
                .max_transaction_fee()
        );
        assert_ne!(sweep.max_transaction_fee, Wei::ZERO);
    }

    /// The accounts a sweep names, in the order its call data sweeps them.
    fn swept_accounts(sweep: &SweepRequest) -> Vec<Account> {
        sweep
            .deposits
            .iter()
            .map(|deposit| deposit.account)
            .collect()
    }
}

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

/// The IC time the sweeps a test enqueues are created at.
const CREATED_AT: u64 = 1_699_527_697_000_000_000;

/// A [`SweepContext`] over `signer`, at a gas fee the ceiling does not refuse.
fn context<S>(signer: S) -> SweepContext<S> {
    SweepContext {
        signer,
        sweeper_contract: sweeper_contract(),
        gas_fee_estimate: gas_fee_estimate(),
        created_at: CREATED_AT,
    }
}

fn gas_fee_estimate() -> GasFeeEstimate {
    GasFeeEstimate {
        base_fee_per_gas: WeiPerGas::from(10_000_000_000_u64),
        max_priority_fee_per_gas: WeiPerGas::from(1_000_000_000_u64),
    }
}

/// Install `state` so `read_state` sees it, and hand back its sweep queue — which is what the
/// enqueue path is given.
fn install(state: State) -> Vec<SweepTarget> {
    let targets = state.automatic_deposits.sweep_targets_iter().collect();
    init_state(state);
    targets
}

/// How many queued deposits are still sweep targets, i.e. what the next tick would batch.
fn queued_targets_len() -> usize {
    read_state(|s| s.automatic_deposits.sweep_targets_iter().count())
}

/// The sweeps the enqueue path has put on the sweeper pipeline.
fn enqueued_sweeps() -> Vec<SweepRequest> {
    read_state(|s| s.sweeper_transactions.requests_iter().cloned().collect())
}

/// The single sweep the enqueue path has put on the sweeper pipeline.
fn enqueued_sweep() -> SweepRequest {
    let mut sweeps = enqueued_sweeps();
    assert_eq!(sweeps.len(), 1, "expected exactly one sweep: {sweeps:?}");
    sweeps.remove(0)
}

/// What the signer is asked for when the account at `index` attests to owning its deposit address.
fn attestation_of(index: u8) -> Signable {
    let request = read_state(|s| s.attestation_request(account(index)))
        .expect("BUG: the deposit helper must be configured");
    (request.digest(), derivation_path(index))
}

/// What the signer is asked for when the deposit address of `index` delegates its code to the
/// sweeper contract. Every address signs the same tuple — nonce 0 on the one chain and delegate —
/// so only the derivation path tells two of these apart.
fn authorization_of(index: u8) -> Signable {
    let chain_id = read_state(State::ethereum_network).chain_id();
    (
        delegation_authorization(chain_id, sweeper_contract()).hash(),
        derivation_path(index),
    )
}

fn derivation_path(index: u8) -> Vec<ByteBuf> {
    deposit_derivation_path(DepositAddressSchema::CkErc20, &account(index))
}

/// A digest and the derivation path it is signed under: all an [`EcdsaSigner`] is told, and so all
/// an expectation on [`MockSigner`] can match on.
type Signable = (Hash, Vec<ByteBuf>);

mock! {
    pub Signer {}

    impl EcdsaSigner for Signer {
        async fn sign_digest(
            &self,
            digest: &Hash,
            derivation_path: &[ByteBuf],
        ) -> Result<TransactionSignature, String>;
    }
}

/// A signer that answers whatever it is asked with [`transaction_signature`].
///
/// For a test whose subject is not which signatures a sweep spends. Where that *is* the subject,
/// name the signables one at a time with [`expect_once`] instead: a request nothing expects then
/// fails the test, so what a sweep must not sign needs no assertion of its own.
fn signing_anything() -> MockSigner {
    let mut signer = MockSigner::new();
    signer
        .expect_sign_digest()
        .returning(|_digest, _derivation_path| Ok(transaction_signature()));
    signer
}

/// A signer that answers anything but `refused`, whose threshold-ECDSA call fails.
fn refusing(refused: &[Signable]) -> MockSigner {
    let refused = refused.to_vec();
    let mut signer = MockSigner::new();
    signer
        .expect_sign_digest()
        .withf(move |digest, derivation_path| {
            refused.contains(&(*digest, derivation_path.to_vec()))
        })
        .returning(|_digest, _derivation_path| Err("no signature".to_string()));
    signer
        .expect_sign_digest()
        .returning(|_digest, _derivation_path| Ok(transaction_signature()));
    signer
}

/// Have `signer` answer `signable` with `answer`, exactly once — and require that it be asked, which
/// the mock checks when it is dropped.
fn expect_once(
    signer: &mut MockSigner,
    signable: Signable,
    answer: Result<TransactionSignature, String>,
) {
    signer
        .expect_sign_digest()
        .withf(move |digest, derivation_path| (*digest, derivation_path.to_vec()) == signable)
        .times(1)
        .return_once(move |_digest, _derivation_path| answer);
}
