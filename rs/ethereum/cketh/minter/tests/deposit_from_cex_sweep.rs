use assert_matches::assert_matches;
use candid::{Nat, Principal};
use ic_cketh_minter::endpoints::DepositStatus;
use ic_cketh_minter::endpoints::events::EventPayload;
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_test_utils::anvil::{SentTransaction, address_from_hex};
use ic_cketh_test_utils::ckerc20::{CkErc20Setup, Erc20Token};
use ic_cketh_test_utils::live::{Holding, LiveSetup};
use ic_cketh_test_utils::{MINTER_ADDRESS, SWEEPER_ADDRESS};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

/// The whole deposit-from-CEX flow against a real EVM, end to end: twenty users — each its own
/// principal *and* subaccount — register deposit addresses, ten for USDC and ten for USDT, a
/// CEX-style plain `transfer` funds each, and the minter then detects all twenty and credits every
/// user in full with no further user action.
///
/// The minter sweeps them in **two** transactions, one per token. That is
/// [DEFI-2980](https://dfinity.atlassian.net/browse/DEFI-2980): the delegate's batch entry point
/// runs its whole token list against every address it touches, so one mixed transaction would pay
/// for a `balanceOf` at all twenty (address, token) pairs to move twenty balances, half of them
/// holding nothing.
///
/// Everything runs for real: a live PocketIC hosting the minter, the EVM RPC canister, the
/// orchestrator and the ckUSDC/ckUSDT ledgers, making genuine HTTPS outcalls to an anvil node that
/// holds the deployed `CkDeposit` helper and `CkSweeperAttested` delegate. Only the sweeper
/// address' gas is shortcut: anvil credits it directly instead of the ckETH burn pipeline.
#[test]
fn should_credit_twenty_cex_deposits_through_one_sweep_per_token() {
    /// Ten depositors per token, so each sweep is a ten-deposit single-token batch — directly
    /// comparable with `deposit_from_cex_demo`'s measured scenarios.
    const DEPOSITORS_PER_TOKEN: u64 = 10;
    // 6-decimal amounts, both far above the ~$10 per-token candidate minimum.
    const USDC_DEPOSIT: u128 = 100_000_000;
    const USDT_DEPOSIT: u128 = 150_000_000;
    /// Enough for both batch sweeps at anvil's gas price, with room for a fee bump.
    const SWEEPER_GAS_WEI: u128 = 1_000_000_000_000_000_000;

    let sweeper = address_from_hex(SWEEPER_ADDRESS);
    let setup = LiveSetup::new_sweep(&sweeper, SWEEPER_GAS_WEI);
    let contracts = setup.sweep_contracts();
    let [usdc, usdt] = setup.supported_erc20_tokens() else {
        panic!("expected exactly 2 supported tokens")
    };

    // Every depositor gets a distinct principal and a distinct subaccount, so no two share a
    // deposit address and each attestation binds a different account.
    let deposits: Vec<Deposit> = (0..2 * DEPOSITORS_PER_TOKEN)
        .map(|index| {
            let (token, amount) = if index < DEPOSITORS_PER_TOKEN {
                (usdc, USDC_DEPOSIT)
            } else {
                (usdt, USDT_DEPOSIT)
            };
            let owner = setup.depositor(index);
            let subaccount = [u8::try_from(index).unwrap(); 32];
            Deposit {
                owner,
                subaccount,
                token,
                amount,
                address: setup.register_deposit_address(owner, subaccount, token),
            }
        })
        .collect();

    let distinct: BTreeSet<_> = deposits.iter().map(|deposit| deposit.address).collect();
    assert_eq!(
        distinct.len(),
        deposits.len(),
        "every account must get its own deposit address"
    );
    for deposit in &deposits {
        assert!(
            setup.anvil().code(&deposit.address).is_empty(),
            "a deposit address starts with no code"
        );
        assert_eq!(
            setup.anvil().balance(&deposit.address),
            0,
            "a deposit address never needs ETH of its own"
        );
    }

    // The CEX withdrawals: a plain ERC-20 transfer to each address, carrying no principal.
    let holdings: Vec<Holding<'_>> = deposits
        .iter()
        .map(|deposit| Holding {
            deposit: deposit.address,
            token: deposit.token,
            amount: deposit.amount,
        })
        .collect();
    setup.credit_deposits(&holdings);

    for deposit in &deposits {
        assert_matches!(
            setup.drive_scan(deposit.owner, deposit.subaccount, deposit.token).status,
            DepositStatus::AwaitingSweep(detected) if detected.scanned_balance == deposit.amount
        );
    }

    // One sweep per token, and nothing more.
    let sweeps = await_sweeps(&setup, &sweeper, 2);
    for sweep in &sweeps {
        assert_eq!(
            sweep.transaction_type, 4,
            "a first sweep installs delegations, so it must be an EIP-7702 transaction: {sweep:?}"
        );
        assert!(sweep.succeeded, "the sweep reverted: {sweep:?}");
    }
    report_gas(&sweeps, DEPOSITORS_PER_TOKEN);

    // The funds left every deposit address and landed at the minter's main address.
    let minter = address_from_hex(MINTER_ADDRESS);
    for deposit in &deposits {
        assert_eq!(
            setup
                .anvil()
                .erc20_balance(&contract_address(deposit.token), &deposit.address),
            Erc20Value::from(0_u8),
            "the deposit address should have been swept empty"
        );
    }
    for (token, amount) in [
        (usdc, USDC_DEPOSIT * u128::from(DEPOSITORS_PER_TOKEN)),
        (usdt, USDT_DEPOSIT * u128::from(DEPOSITORS_PER_TOKEN)),
    ] {
        assert_eq!(
            setup
                .anvil()
                .erc20_balance(&contract_address(token), &minter),
            Erc20Value::from(amount),
            "the minter's main address should hold everything swept of {}",
            token.contract.address
        );
    }

    // Every address is now delegated, by the 23-byte EIP-7702 designator `0xef0100 || delegate`.
    let mut designator = vec![0xef, 0x01, 0x00];
    designator.extend_from_slice(contracts.delegate.as_ref());
    for deposit in &deposits {
        assert_eq!(
            setup.anvil().code(&deposit.address),
            designator,
            "the sweep should have installed the delegation"
        );
    }
    assert!(
        setup.anvil().balance(&sweeper) < SWEEPER_GAS_WEI,
        "the sweeper address pays for the sweeps out of its own prepaid gas"
    );

    // Only now the mint, which the unchanged deposit pipeline drives off each sweep's own helper
    // event — downstream of every effect asserted above.
    let ledgers = [
        (usdc, setup.ckerc20_token("ckUSDC").ledger_canister_id),
        (usdt, setup.ckerc20_token("ckUSDT").ledger_canister_id),
    ];
    for deposit in &deposits {
        let (_, ledger_id) = ledgers
            .iter()
            .find(|(token, _)| token.contract.address == deposit.token.contract.address)
            .expect("every deposited token has a ledger");
        await_credited(
            &setup,
            *ledger_id,
            account(deposit.owner, deposit.subaccount),
            deposit.amount,
        );
    }
}

/// One user's deposit: who it credits, which token, and the address the CEX sends to.
struct Deposit<'a> {
    owner: Principal,
    subaccount: [u8; 32],
    token: &'a Erc20Token,
    amount: u128,
    address: Address,
}

/// A budget, not a cost: the sweep path crosses the enqueue, send, and finalization timers, and
/// driving stops the moment the expected transactions are on chain.
const SWEEP_TICKS: u32 = 8;

/// The mint follows the sweep through the log scrape, one more timer downstream.
const CREDIT_TICKS: u32 = 6;

/// Prints what each sweep cost next to `deposit_from_cex_demo`'s measurements for the same delegate,
/// so a change in either shows up as a difference rather than having to be recomputed by hand.
fn report_gas(sweeps: &[SentTransaction], deposits_per_sweep: u64) {
    // `ATTESTED_SCENARIOS` in deposit_from_cex_demo.rs, EIP-7702 (first sweep) column.
    const DEMO_ONE_DEPOSIT: u64 = 98_000;
    const DEMO_TEN_DEPOSITS: u64 = 609_431;

    for sweep in sweeps {
        let per_deposit = sweep.gas_used / deposits_per_sweep;
        println!(
            "[gas] {} deposits: {} total, {} per deposit \
             (demo: {DEMO_TEN_DEPOSITS} total, {} per deposit for ten; {DEMO_ONE_DEPOSIT} for one)",
            deposits_per_sweep,
            sweep.gas_used,
            per_deposit,
            DEMO_TEN_DEPOSITS / 10,
        );
    }
}

/// Waits for the sweeper address to send exactly `expected` transactions, returning what each did.
/// An extra sweep is caught rather than ignored: sending more than `expected` fails immediately.
fn await_sweeps(
    setup: &LiveSetup<CkErc20Setup>,
    sweeper: &Address,
    expected: u64,
) -> Vec<SentTransaction> {
    setup.drive_until(
        SWEEP_TICKS,
        |setup| {
            format!(
                "the sweeper {sweeper} sent {} of {expected} transactions (stages: {})",
                setup.anvil().transaction_count(sweeper),
                sweep_stages(setup),
            )
        },
        |setup| {
            let sent = setup.anvil().transaction_count(sweeper);
            assert!(
                sent <= expected,
                "the sweeper sent {sent} transactions, more than the {expected} expected"
            );
            sent == expected
        },
    );
    setup.anvil().transactions_of(sweeper)
}

/// How far the sweep pipeline has got, counted off the minter's audit events. Unlike its canister
/// log, which is a rolling buffer the EVM RPC canister's tracing evicts within minutes, the event
/// log is durable — so this says which stage stalled even late in a run.
fn sweep_stages(setup: &LiveSetup<CkErc20Setup>) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for event in setup.minter_events() {
        let stage = match event.payload {
            EventPayload::AutomaticDepositReceived { .. } => "detected",
            EventPayload::AcceptedSweepRequest { .. } => "accepted",
            EventPayload::CreatedSweeperTransaction { .. } => "created",
            EventPayload::SignedSweeperTransaction { .. } => "signed",
            EventPayload::ReplacedSweeperTransaction { .. } => "replaced",
            EventPayload::FinalizedSweeperTransaction { .. } => "finalized",
            EventPayload::AcceptedDeposit { .. } | EventPayload::MintedCkErc20 { .. } => "minted",
            _ => continue,
        };
        *counts.entry(stage).or_default() += 1;
    }
    format!("{counts:?}")
}

/// Waits until `account` holds exactly `expected` on `ledger_id`. The mint follows the sweep's own
/// finalized helper event through the minter's unchanged deposit pipeline, so this is what proves
/// the whole chain ran.
fn await_credited(
    setup: &LiveSetup<CkErc20Setup>,
    ledger_id: Principal,
    account: Account,
    expected: u128,
) {
    let credited = Nat::from(expected);
    setup.drive_until(
        CREDIT_TICKS,
        |setup| {
            format!(
                "{account:?} was credited {} instead of {expected} (stages: {})",
                setup.balance_of_ledger(ledger_id, account),
                sweep_stages(setup),
            )
        },
        |setup| setup.balance_of_ledger(ledger_id, account) == credited,
    );
}

fn account(owner: Principal, subaccount: [u8; 32]) -> Account {
    Account {
        owner,
        subaccount: Some(subaccount),
    }
}

fn contract_address(token: &Erc20Token) -> Address {
    Address::from_str(&token.contract.address).unwrap()
}
