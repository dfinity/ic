//! Sending transactions **from the minter's dedicated sweeper address** on the sweeper's own nonce
//! sequence, so a stuck sweep can never head-of-line-block a withdrawal on the main address'
//! pipeline.
//!
//! It drives the sweeper [`TransactionPipeline`] through the same
//! create → sign → send → resubmit → finalize state machine as user withdrawals
//! ([`crate::withdraw`]), reusing that module's sender-agnostic RPC helpers
//! (`latest_transaction_count`, `finalized_transaction_count`, `send_signed_transactions`,
//! `fetch_finalized_receipts`), but signing with the sweeper derivation path (`[3]`) and reading
//! the sweeper address' own transaction count.
//!
//! [`enqueue_batched_sweep`] is what feeds it: it takes the deposits the balance scan queued, signs
//! one delegation authorization and one ownership attestation per address, and enqueues one
//! [`SweepRequest`] per token, whose call data sweeps that token from every address in the batch
//! through the deployed delegate.

#[cfg(test)]
mod tests;

use crate::{
    attestation::{AttestationRequest, sign_attestation},
    deposit_address::{
        DepositAddress, DepositAddressSchema, deposit_derivation_path, sweeper_derivation_path,
    },
    eth_rpc_client::responses::{TransactionReceipt, TransactionStatus},
    guard::TimerGuard,
    logs::{DEBUG, INFO},
    numeric::{TransactionCount, TransactionNonce, Wei},
    state::{
        State, TaskType,
        audit::{EventType, process_event},
        automatic_deposits::SweepTarget,
        mutate_state, read_state,
        transactions::{CreateSweepTransactionError, PipelineRequest, SweepRequest, SweptDeposit},
    },
    sweeper_contract::{SweepItem, encode_sweep_erc20_batch},
    tx::{
        Authorization, GasFeeEstimate, SignedAuthorization, TransactionSignature,
        lazy_refresh_gas_fee_estimate,
    },
    withdraw::{
        fetch_finalized_receipts, finalized_transaction_count, latest_transaction_count,
        send_signed_transactions,
    },
};
use futures::future::join_all;
use ic_canister_log::log;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::{BTreeMap, BTreeSet};

/// Deposits swept in one transaction, which with one token per sweep is also the addresses it
/// touches.
///
/// This is what bounds a sweep's gas, but only because the batch carries a single token: the
/// delegate applies its whole token list to every address, so a one-token batch pays one balance
/// check and at most one transfer per address and [`SweepRequest::gas_limit`] stays linear in the
/// batch — ~1.7M gas at ten deposits. A batch spanning several tokens would grow as their product
/// instead, which is why [`sweep_batches_by_token`] never builds one.
///
/// Ten, because that is where batching has bought what it can. `deposit_from_cex_demo`'s measured
/// attested scenarios put a deposit at 98'000 gas alone, 60'943 in a batch of ten and 59'645 in a
/// batch of twenty: the second doubling saves ~2%, one transaction's intrinsic gas spread over the
/// extra deposits. A wider batch does not pay for what it costs — `sweepErc20Batch` has no
/// per-item error handling, so it doubles how many deposits one revert drops (see
/// [`sweep_batches_by_token`]), and it doubles what a single sweep prepays against the sweeper's
/// low-water mark (see [`max_sweep_transaction_fee`]).
const MAX_DEPOSITS_PER_SWEEP: usize = 10;

const SWEEP_REQUESTS_BATCH_SIZE: usize = 5;
const SWEEP_TRANSACTIONS_TO_SIGN_BATCH_SIZE: usize = 5;
const SWEEP_TRANSACTIONS_TO_SEND_BATCH_SIZE: usize = 5;

pub async fn process_sweeper_transactions() {
    let _guard = match TimerGuard::new(TaskType::SweeperSend) {
        Ok(guard) => guard,
        Err(e) => {
            log!(
                DEBUG,
                "Failed retrieving timer guard to process sweeper transactions: {e:?}",
            );
            return;
        }
    };

    if read_state(|s| !s.sweeper_transactions.has_pending_requests()) {
        return;
    }

    let Some(sender) = read_state(State::sweeper_address) else {
        log!(
            DEBUG,
            "[process_sweeper_transactions]: SKIPPING: the sweeper address is unknown (ECDSA public key not cached yet)"
        );
        return;
    };

    let gas_fee_estimate = match lazy_refresh_gas_fee_estimate().await {
        Some(gas_fee_estimate) => gas_fee_estimate,
        None => {
            // The withdrawal task refreshes the same estimate under a shared guard and runs first
            // on an equal cadence, so losing that race is expected rather than exceptional. Retry
            // instead of waiting a whole interval: by then the refresh it was holding has cached an
            // estimate this task can reuse.
            log!(
                INFO,
                "[process_sweeper_transactions]: failed retrieving gas fee estimate, retrying",
            );
            schedule_retry();
            return;
        }
    };

    let latest_transaction_count = latest_transaction_count(sender).await;
    resubmit_transactions_batch(latest_transaction_count, &gas_fee_estimate).await;
    create_transactions_batch(&gas_fee_estimate);
    sign_transactions_batch().await;
    send_transactions_batch(sender, latest_transaction_count).await;
    finalize_transactions_batch(sender).await;

    if read_state(|s| s.sweeper_transactions.has_pending_requests()) {
        schedule_retry();
    }
}

fn schedule_retry() {
    ic_cdk_timers::set_timer(crate::PROCESS_SWEEPER_TRANSACTIONS_RETRY_INTERVAL, async {
        process_sweeper_transactions().await
    });
}

async fn resubmit_transactions_batch(
    latest_transaction_count: Option<TransactionCount>,
    gas_fee_estimate: &GasFeeEstimate,
) {
    if read_state(|s| s.sweeper_transactions.is_sent_tx_empty()) {
        return;
    }
    let Some(latest_transaction_count) = latest_transaction_count else {
        return;
    };
    let transactions_to_resubmit = read_state(|s| {
        s.sweeper_transactions
            .create_resubmit_transactions(latest_transaction_count, gas_fee_estimate.clone())
    });
    for result in transactions_to_resubmit {
        match result {
            Ok((sweep_id, transaction)) => {
                log!(
                    INFO,
                    "[process_sweeper_transactions]: resubmitting sweep transaction {transaction:?}"
                );
                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::ReplacedSweeperTransaction {
                            sweep_id,
                            transaction,
                        },
                    )
                });
            }
            Err(e) => {
                log!(
                    INFO,
                    "[process_sweeper_transactions]: failed to resubmit sweep transaction: {e:?}"
                );
            }
        }
    }
}

fn create_transactions_batch(gas_fee_estimate: &GasFeeEstimate) {
    for request in read_state(|s| {
        s.sweeper_transactions
            .requests_batch(SWEEP_REQUESTS_BATCH_SIZE)
    }) {
        let ethereum_network = read_state(State::ethereum_network);
        let nonce = read_state(|s| s.sweeper_transactions.next_transaction_nonce());
        let sweep_id = request.id;
        match request.create_transaction(
            nonce,
            gas_fee_estimate.clone(),
            request.gas_limit(),
            ethereum_network,
        ) {
            Ok(transaction) => {
                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::CreatedSweeperTransaction {
                            sweep_id,
                            transaction,
                        },
                    );
                });
            }
            Err(CreateSweepTransactionError::InsufficientTransactionFee {
                allowed_max_transaction_fee,
                actual_max_transaction_fee,
                ..
            }) => {
                log!(
                    INFO,
                    "[process_sweeper_transactions]: Sweep {sweep_id:?} has prepaid gas {allowed_max_transaction_fee:?}, below the current transaction fee {actual_max_transaction_fee:?}. Sweep moved back to end of queue."
                );
                // TODO(DEFI-2933): a sweep whose prepaid allowance stays below the current fee
                // reschedules indefinitely, and only a fee drop gets it moving again.
                mutate_state(|s| s.sweeper_transactions.reschedule_request(sweep_id));
            }
        }
    }
}

async fn sign_transactions_batch() {
    let transactions_batch: Vec<_> = read_state(|s| {
        s.sweeper_transactions
            .transactions_to_sign_batch(SWEEP_TRANSACTIONS_TO_SIGN_BATCH_SIZE)
    });
    let results = join_all(
        transactions_batch
            .into_iter()
            .map(|(sweep_id, tx)| async move {
                (
                    sweep_id,
                    crate::tx::sign(tx, sweeper_derivation_path()).await,
                )
            }),
    )
    .await;
    for (sweep_id, result) in results {
        match result {
            Ok(transaction) => mutate_state(|s| {
                process_event(
                    s,
                    EventType::SignedSweeperTransaction {
                        sweep_id,
                        transaction,
                    },
                )
            }),
            Err(e) => log!(
                INFO,
                "[process_sweeper_transactions]: error signing sweep {sweep_id:?}: {e:?}"
            ),
        }
    }
}

async fn send_transactions_batch(
    sender: Address,
    latest_transaction_count: Option<TransactionCount>,
) {
    let Some(latest_transaction_count) = latest_transaction_count else {
        return;
    };
    let transactions_to_send: Vec<_> = read_state(|s| {
        s.sweeper_transactions.transactions_to_send_batch(
            latest_transaction_count,
            SWEEP_TRANSACTIONS_TO_SEND_BATCH_SIZE,
        )
    });
    send_signed_transactions(sender, &transactions_to_send).await;
}

async fn finalize_transactions_batch(sender: Address) {
    if read_state(|s| s.sweeper_transactions.is_sent_tx_empty()) {
        return;
    }
    match finalized_transaction_count(sender).await {
        Ok(finalized_tx_count) => {
            let txs_to_finalize = read_state(|s| {
                s.sweeper_transactions
                    .sent_transactions_to_finalize(&finalized_tx_count)
            });
            if let Some(receipts) = fetch_finalized_receipts(txs_to_finalize).await {
                for (sweep_id, transaction_receipt) in receipts {
                    let transaction_receipt = TransactionReceipt::from(transaction_receipt);
                    if transaction_receipt.status == TransactionStatus::Failure {
                        log!(
                            INFO,
                            "[process_sweeper_transactions]: sweep {sweep_id:?} FAILED in transaction {}, burning {:?}. It moved nothing.",
                            transaction_receipt.transaction_hash,
                            transaction_receipt.gas_used
                        );
                    }
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::FinalizedSweeperTransaction {
                                sweep_id,
                                transaction_receipt,
                            },
                        );
                    });
                }
            }
        }
        Err(e) => {
            log!(
                INFO,
                "[process_sweeper_transactions]: failed to get finalized transaction count: {e:?}"
            );
        }
    }
}

/// Enqueue a sweep of everything the balance scan has queued, one transaction per token, each
/// moving up to [`MAX_DEPOSITS_PER_SWEEP`] deposits.
///
/// Each deposit contributes an ownership attestation and an EIP-7702 authorization delegating its
/// address (see [`sign_authorizations_batch`]), so every sweep is a type-`0x04` transaction.
pub async fn enqueue_batched_sweep() {
    let _guard = match TimerGuard::new(TaskType::SweeperEnqueue) {
        Ok(guard) => guard,
        Err(e) => {
            log!(
                DEBUG,
                "Failed retrieving timer guard to enqueue a batched sweep: {e:?}",
            );
            return;
        }
    };

    let Some(sweeper_contract) = read_state(|s| s.sweeper_contract_address) else {
        log!(
            DEBUG,
            "[enqueue_batched_sweep]: SKIPPING: no sweeper contract address is configured"
        );
        return;
    };
    let batches = read_state(sweep_batches_by_token);
    if batches.is_empty() {
        return;
    }

    // Fetched before anything is signed: nothing about the estimate depends on the signatures,
    // and an unavailable one drops every sweep — along with each threshold-ECDSA signature it
    // would have cost.
    // TODO(DEFI-2933): gate this on the gas the sweeper address has actually been prepaid.
    let Some(gas_fee_estimate) = lazy_refresh_gas_fee_estimate().await else {
        log!(
            INFO,
            "[enqueue_batched_sweep]: SKIPPING: failed retrieving gas fee estimate"
        );
        return;
    };

    for batch in batches {
        enqueue_token_sweep(batch, sweeper_contract, &gas_fee_estimate).await;
    }
}

/// The sweep queue folded into one batch per token, each holding that token's queued deposits in
/// queue order, up to [`MAX_DEPOSITS_PER_SWEEP`] of them.
///
/// One sweep per token, never a batch spanning several. The delegate's batch entry point runs its
/// whole token list against every deposit address it touches, so a mixed batch pays a `balanceOf` at
/// every `(address, token)` pair — including the pairs holding nothing, which is most of them once
/// several tokens are supported — and its gas grows as addresses × tokens rather than with the
/// deposits it moves. Grouping keeps that product equal to the addresses, which is what lets
/// [`MAX_DEPOSITS_PER_SWEEP`] bound a sweep's gas at all. It costs one transaction's 21'000
/// intrinsic gas per token, which a multi-token sweep pays anyway in the cold storage write each
/// token's balance at the minter needs.
///
/// Every deposit gets one sweep and no more. `sweepErc20Batch` has no per-item error handling, so
/// whatever makes a sweep revert — one address blacklisted for the token, say — reverts every batch
/// that deposit is in; a failed sweep therefore drops its whole batch from the queue rather than
/// leaving anything behind to retry (DEFI-2981).
fn sweep_batches_by_token(state: &State) -> BTreeMap<Address, Vec<SweepTarget>> {
    let mut batches: BTreeMap<Address, Vec<SweepTarget>> = BTreeMap::new();
    for target in state.automatic_deposits.sweep_targets_iter() {
        let batch = batches.entry(target.token()).or_default();
        if batch.len() < MAX_DEPOSITS_PER_SWEEP {
            batch.push(target);
        }
    }
    batches
}

/// Enqueue one sweep of `token`, moving as many of `targets` as could be signed for.
///
/// Skips the token — leaving its deposits queued for the next tick — when nothing could be signed
/// for, or when the sweep would prepay more than [`max_sweep_transaction_fee`].
async fn enqueue_token_sweep(
    (token, targets): (Address, Vec<SweepTarget>),
    sweeper_contract: Address,
    gas_fee_estimate: &GasFeeEstimate,
) {
    let Some(requests) = attestation_requests(&targets) else {
        log!(
            DEBUG,
            "[enqueue_batched_sweep]: SKIPPING: no deposit helper with subaccount is configured"
        );
        return;
    };

    let prepared = prepare_deposits(&targets, &requests, sweeper_contract).await;
    if prepared.is_empty() {
        log!(
            INFO,
            "[enqueue_batched_sweep]: SKIPPING the {token} sweep: none of its {} queued deposits could be signed for",
            targets.len()
        );
        return;
    }
    let batch = SweepBatch::from(prepared);
    let mut request = SweepRequest {
        id: read_state(|s| s.next_sweep_id),
        destination: sweeper_contract,
        amount: Wei::ZERO,
        data: encode_sweep_erc20_batch(&batch.items, &batch.tokens),
        max_transaction_fee: Wei::ZERO,
        created_at: ic_cdk::api::time(),
        authorizations: batch.authorizations,
        deposits: batch.deposits,
    };
    request.max_transaction_fee = gas_fee_estimate
        .clone()
        .to_price(request.gas_limit())
        .max_transaction_fee();
    let ceiling = read_state(max_sweep_transaction_fee);
    if request.max_transaction_fee > ceiling {
        log!(
            INFO,
            "[enqueue_batched_sweep]: SKIPPING the {token} sweep of {} deposits: it would prepay {:?}, above the {ceiling:?} a single sweep may lock",
            request.deposits.len(),
            request.max_transaction_fee
        );
        return;
    }
    log!(
        INFO,
        "[enqueue_batched_sweep]: sweeping {} deposits of {token} from {} addresses, via {sweeper_contract}",
        request.deposits.len(),
        request.authorizations.len()
    );
    mutate_state(|s| process_event(s, EventType::AcceptedSweepRequest(request)));
}

/// The most a single sweep may prepay: the balance the sweeper address is kept above, so that a
/// sweep is payable out of the funding the funding task maintains.
///
/// The EVM demands `gas_limit × max_fee_per_gas` up front, and a sweep the sweeper cannot pay for is
/// unrecoverable rather than merely wasted: the pipeline has already committed the sweep's nonce,
/// sending fails with `InsufficientFunds` and is retried forever, resubmission cannot lower the fee
/// because it already sits at the sweep's own allowance, and every later sweep on the lane waits
/// behind that nonce. No receipt ever arrives, so nothing counts it as a failed sweep either.
/// Refusing to enqueue is the one place this is cheap to catch: the deposits stay queued and the
/// next tick tries again, at whatever the fee is then.
///
/// The mark is not a guarantee — the balance dips below it between fundings, which no enqueue-time
/// check can see — but a sweep that fits under it is payable whenever the funding task has done its
/// job, and one that does not fit is a sweep this minter should not be building.
///
/// Against mainnet's 0.03 ETH minimum withdrawal amount, a full single-token batch prepays ~0.07 ETH
/// at 10 gwei, inside the 0.15 ETH mark, so the ceiling does not bind. A minter configured with a
/// much smaller minimum withdrawal amount has a proportionally smaller mark, and its full batches
/// are refused at that fee until it drops — visible in the log above, and DEFI-2933's calibration to
/// settle, rather than something to paper over by sending a sweep that cannot be paid for.
fn max_sweep_transaction_fee(state: &State) -> Wei {
    state.sweeper_funding_config().low_water_mark
}

/// The attestation each of the `targets` needs signed, keyed by the account it names. One per
/// account: all of an account's tokens sit at the one deposit address the attestation covers, and
/// the request itself names no token. `None` while the deposit helper it binds to is unknown.
fn attestation_requests(targets: &[SweepTarget]) -> Option<BTreeMap<Account, AttestationRequest>> {
    read_state(|s| {
        targets
            .iter()
            .map(|target| {
                let account = target.account();
                s.attestation_request(account)
                    .map(|request| (account, request))
            })
            .collect()
    })
}

/// What one sweep carries, assembled from what its deposits contributed.
///
/// A deposit address is derived per account, so all of an account's tokens share one address, one
/// attestation and one authorization: `items` and `authorizations` hold one entry per account, while
/// `deposits` keeps one per `(account, token)`, which is the granularity the sweep queue is keyed
/// at. With one token per sweep an account contributes a single deposit anyway; keying by it is what
/// makes that an invariant of the call data rather than a property of how the batch was picked. A
/// second item for the same address would make the delegate walk it twice over the token list, and a
/// second copy of its authorization would cost intrinsic gas for a tuple the first copy already
/// applied.
struct SweepBatch {
    items: Vec<SweepItem>,
    /// The distinct tokens the batch sweeps, which is one: the delegate applies the whole list to
    /// every item, so [`sweep_batches_by_token`] gives each sweep a single token. Derived from the
    /// deposits rather than taken on trust, so the list cannot disagree with them.
    tokens: Vec<Address>,
    authorizations: Vec<SignedAuthorization>,
    deposits: Vec<SweptDeposit>,
}

impl From<Vec<PreparedDeposit>> for SweepBatch {
    fn from(prepared: Vec<PreparedDeposit>) -> Self {
        let mut items = BTreeMap::new();
        let mut authorizations = BTreeMap::new();
        let mut tokens = BTreeSet::new();
        let mut deposits = Vec::with_capacity(prepared.len());
        for PreparedDeposit {
            target,
            attestation,
            authorization,
        } in prepared
        {
            let account = target.account();
            authorizations.entry(account).or_insert(authorization);
            items.entry(account).or_insert_with(|| SweepItem {
                deposit: target.address(),
                account,
                attestation,
            });
            tokens.insert(target.token());
            deposits.push(SweptDeposit {
                account,
                erc20_contract_address: target.token(),
                address: target.address(),
            });
        }
        Self {
            items: items.into_values().collect(),
            tokens: tokens.into_iter().collect(),
            authorizations: authorizations.into_values().collect(),
            deposits,
        }
    }
}

/// What one deposit contributes to a sweep: the attestation naming the account it credits, and the
/// EIP-7702 authorization delegating its address. All of an account's deposits carry the same pair,
/// since they share one deposit address.
struct PreparedDeposit {
    target: SweepTarget,
    attestation: TransactionSignature,
    authorization: SignedAuthorization,
}

/// Everything the queued `targets` need signed, in target order. Each threshold-ECDSA signature is
/// an outcall, so the attestations are signed in one batch and the authorizations in another, one of
/// each per deposit address rather than per queued token.
async fn prepare_deposits(
    targets: &[SweepTarget],
    requests: &BTreeMap<Account, AttestationRequest>,
    sweeper_contract: Address,
) -> Vec<PreparedDeposit> {
    let attestations = sign_attestations_batch(requests).await;
    // Only the attested accounts: a deposit that could not be attested drops out of the sweep
    // anyway, so authorizing it would spend a signature on nothing.
    let addresses = attested_addresses(targets, &attestations);
    let authorizations = sign_authorizations_batch(&addresses, sweeper_contract).await;
    prepared_deposits(targets, &attestations, &authorizations)
}

/// The targets that got everything they need: their account's attestation and its authorization.
///
/// A deposit missing either drops out of the sweep rather than sinking it, since nothing the others
/// contribute depends on it — and it must drop out: solc guards the delegate call with
/// `extcodesize`, so an address that ends up with no code reverts, and one such item reverts the
/// whole batch.
fn prepared_deposits(
    targets: &[SweepTarget],
    attestations: &BTreeMap<Account, TransactionSignature>,
    authorizations: &BTreeMap<Account, SignedAuthorization>,
) -> Vec<PreparedDeposit> {
    targets
        .iter()
        .filter_map(|target| {
            let account = target.account();
            Some(PreparedDeposit {
                target: *target,
                attestation: attestations.get(&account)?.clone(),
                authorization: authorizations.get(&account)?.clone(),
            })
        })
        .collect()
}

/// The attestation of each request, keyed by the account it names, missing where it could not be
/// signed. An attestation is signed once per address and reused by every later sweep — it names the
/// account and the helper, neither of which a sweep changes — so only the ones the minter does not
/// have yet cost a signature, and each is recorded the moment it exists.
async fn sign_attestations_batch(
    requests: &BTreeMap<Account, AttestationRequest>,
) -> BTreeMap<Account, TransactionSignature> {
    let mut attestations: BTreeMap<Account, TransactionSignature> = read_state(|s| {
        requests
            .keys()
            .filter_map(|account| {
                s.attestation(*account)
                    .map(|attestation| (*account, attestation.clone()))
            })
            .collect()
    });
    let signed = join_all(
        requests
            .iter()
            .filter(|(account, _request)| !attestations.contains_key(*account))
            .map(|(account, request)| async move {
                (*account, request, sign_attestation(request).await)
            }),
    )
    .await;
    let mut errors = Vec::new();
    for (account, request, result) in signed {
        match result {
            Ok(attestation) => {
                mutate_state(|s| {
                    process_event(
                        s,
                        EventType::AttestedDepositAddress {
                            request: request.clone(),
                            signature: attestation.clone(),
                        },
                    )
                });
                attestations.insert(account, attestation);
            }
            Err(e) => errors.push(format!("{account:?}: {e}")),
        }
    }
    if !errors.is_empty() {
        log!(
            INFO,
            "[enqueue_batched_sweep]: leaving out the deposits this sweep could not attest: {errors:?}"
        );
    }
    attestations
}

/// The deposit address of every target whose account got an attestation, keyed by that account.
fn attested_addresses(
    targets: &[SweepTarget],
    attestations: &BTreeMap<Account, TransactionSignature>,
) -> BTreeMap<Account, DepositAddress> {
    targets
        .iter()
        .filter(|target| attestations.contains_key(&target.account()))
        .map(|target| (target.account(), target.address()))
        .collect()
}

/// The authorizations the minter already holds for these addresses, keyed by account.
///
/// Only the ones still usable: [`State::authorization`] checks a stored tuple against the chain and
/// the delegate the minter runs against, so an address delegated by a retired sweeper contract falls
/// through to a fresh signature rather than being swept through the wrong delegate.
fn stored_authorizations(
    addresses: &BTreeMap<Account, DepositAddress>,
) -> BTreeMap<Account, SignedAuthorization> {
    read_state(|s| {
        addresses
            .iter()
            .filter_map(|(account, address)| {
                s.authorization(address)
                    .map(|authorization| (*account, authorization.clone()))
            })
            .collect()
    })
}

/// One authorization per account, keyed by it, missing where it could not be signed.
///
/// A tuple is signed once per address and reused by every later sweep of it: it names the chain and
/// the delegate, and its nonce is fixed at 0, so nothing a sweep does can invalidate it. Only the
/// addresses the minter holds no usable tuple for cost a signature, and each is recorded the moment
/// it exists.
///
/// Reuse is a cost optimization, not correctness state — see [`delegation_authorization`]. A tuple
/// the store never had, or one it holds under a delegate the minter no longer calls, costs one
/// threshold-ECDSA signature; it can never cost a sweep.
async fn sign_authorizations_batch(
    addresses: &BTreeMap<Account, DepositAddress>,
    sweeper_contract: Address,
) -> BTreeMap<Account, SignedAuthorization> {
    let mut authorizations = stored_authorizations(addresses);
    let chain_id = read_state(State::ethereum_network).chain_id();
    let signed = join_all(
        addresses
            .iter()
            .filter(|(account, _address)| !authorizations.contains_key(*account))
            .map(|(account, address)| {
                let (account, address) = (*account, *address);
                let authorization = delegation_authorization(chain_id, sweeper_contract);
                async move {
                    (
                        account,
                        address,
                        authorization
                            .sign(deposit_derivation_path(
                                DepositAddressSchema::CkErc20,
                                &account,
                            ))
                            .await,
                    )
                }
            }),
    )
    .await;
    let mut errors = Vec::new();
    for (account, address, result) in signed {
        match result {
            Ok(authorization) => {
                mutate_state(|s| s.record_authorization(address, authorization.clone()));
                authorizations.insert(account, authorization);
            }
            Err(e) => errors.push(format!("{account:?}: {e}")),
        }
    }
    if !errors.is_empty() {
        log!(
            INFO,
            "[enqueue_batched_sweep]: leaving out the deposits this sweep could not authorize: {errors:?}"
        );
    }
    authorizations
}

/// The tuple every deposit address signs to delegate its code to `sweeper_contract`: the minter's
/// chain, that delegate, and **nonce 0**, whatever nonce the address actually holds.
///
/// Applying an EIP-7702 authorization increments the authority's nonce, and nothing else ever
/// touches a deposit address' nonce — the minter never broadcasts a transaction from a deposit key,
/// it only signs attestation digests and authorization tuples with it, and receiving an ERC-20
/// transfer spends no nonce. So a deposit address holds nonce 0 exactly while it has never been
/// delegated, and a tuple signed for nonce 0 either
///
/// * installs the delegation, the address never having had one; or
/// * is skipped, the address already being delegated and its nonce no longer matching. The
///   transaction stays valid, the delegation designator already in place is untouched, and the
///   delegated call works.
///
/// Both outcomes are correct, in every ordering of the sweeps that carry them, with nothing stored
/// and nothing read from chain. That is what lets a sweep authorize every address it touches instead
/// of tracking which ones are delegated: two sweeps of the same address in one round each carry
/// their own tuple, the second one is skipped, and neither has to wait for the other. The price is
/// the tuple's intrinsic gas — 12'500 for a skipped one, which [`SweepRequest::gas_limit`] budgets
/// for every address.
///
/// The one thing this forecloses is **re-delegation**: an address delegated to an earlier sweeper
/// contract holds nonce >= 1, so a nonce-0 tuple naming the new one is skipped and its code keeps
/// pointing at the old contract. Its sweeps still execute, through that old delegate, which is
/// harmless while the helper it calls is unchanged and reverts if it is not. Supporting
/// re-delegation would mean reading the authority's real nonce for exactly those addresses — the
/// ones whose stored authorization names a different delegate, which is itself the signal that the
/// address is delegated to something else.
fn delegation_authorization(chain_id: u64, sweeper_contract: Address) -> Authorization {
    Authorization {
        chain_id,
        delegate: sweeper_contract,
        nonce: TransactionNonce::ZERO,
    }
}
