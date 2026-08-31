//! Integration tests showcasing the support of deposits from central exchanges:
//! 1) the user notifies the minter of an upcoming deposit of a given token.
//! 2) the minter watches the balance of that address for roughly 24H
//! 3) if the address' balance is sufficient (roughly at least $10 equivalent), the minter proceeds with consolidating the funds.
//! 4) the deposit address delegates to a sweeper contract,
//!    whose purpose is to move the ERC-20 from the deposit address by calling the helper smart contract (DepositHelperWithSubaccount.sol),
//!    to trigger the original deposit flow. This requires in particular the minter attesting that the given deposit address is for a given
//!    principal and subaccount.

use assert_matches::assert_matches;
use candid::Principal;
use ic_cketh_minter::balance_scan::batcher::{
    BalanceOfCall, decode_balance_batch, encode_balance_batch,
};
use ic_cketh_minter::deposit_address::DepositAddress;
use ic_cketh_minter::endpoints::DepositStatus;
use ic_cketh_minter::endpoints::events::EventPayload;
use ic_cketh_minter::numeric::Erc20Value;
use ic_cketh_test_utils::anvil::{
    Anvil, DEV_ACCOUNT, SentTransaction, address_from_hex, deploy_mock_erc20,
};
use ic_cketh_test_utils::ckerc20::Erc20Token;
use ic_cketh_test_utils::live::{Holding, LiveSetup, contract_address};
use ic_cketh_test_utils::{MINTER_ADDRESS, SWEEPER_ADDRESS};
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;
use std::collections::BTreeSet;
use std::str::FromStr;

#[test]
fn should_read_erc20_balances_across_tokens_and_holders() {
    let anvil = Anvil::start();
    let dev = address_from_hex(DEV_ACCOUNT);

    // Two ERC-20s so we exercise positional decoding across different tokens.
    let token_a = deploy_mock_erc20(&anvil, &dev);
    let token_b = deploy_mock_erc20(&anvil, &dev);

    let h1 = Address::new([0x11; 20]);
    let h2 = Address::new([0x22; 20]);
    let h3 = Address::new([0x33; 20]); // never funded -> balance 0

    anvil.fund(&token_a, &dev, &h1, 100);
    anvil.fund(&token_a, &dev, &h2, 250);
    anvil.fund(&token_b, &dev, &h1, 7);
    anvil.fund(&token_b, &dev, &h3, 999);

    let calls = vec![
        BalanceOfCall {
            token: token_a,
            holder: DepositAddress::new(h1),
        },
        BalanceOfCall {
            token: token_a,
            holder: DepositAddress::new(h2),
        },
        BalanceOfCall {
            token: token_a,
            holder: DepositAddress::new(h3),
        },
        BalanceOfCall {
            token: token_b,
            holder: DepositAddress::new(h1),
        },
        BalanceOfCall {
            token: token_b,
            holder: DepositAddress::new(h2),
        },
        BalanceOfCall {
            token: token_b,
            holder: DepositAddress::new(h3),
        },
    ];

    let out = anvil
        .eth_call_create(&dev, &encode_balance_batch(&calls))
        .expect("the balance batch must not revert");
    let balances = decode_balance_batch(&out, calls.len()).expect("decode failed");

    assert_eq!(
        balances,
        vec![
            Erc20Value::from(100_u64),
            Erc20Value::from(250_u64),
            Erc20Value::from(0_u64),
            Erc20Value::from(7_u64),
            Erc20Value::from(0_u64),
            Erc20Value::from(999_u64),
        ]
    );

    // The batcher must agree with anvil's own view of every balance.
    for call in &calls {
        let expected = anvil.erc20_balance(&call.token, call.holder.as_address());
        let single = anvil
            .eth_call_create(&dev, &encode_balance_batch(std::slice::from_ref(call)))
            .expect("single-call batch reverted");
        assert_eq!(decode_balance_batch(&single, 1).unwrap()[0], expected);
    }
}

#[test]
fn should_read_many_balances_in_a_single_call() {
    let anvil = Anvil::start();
    let dev = address_from_hex(DEV_ACCOUNT);
    let token = deploy_mock_erc20(&anvil, &dev);

    // A single create-style eth_call carrying many balanceOf sub-calls, to
    // exercise the loop and the per-pair CODECOPY offset arithmetic at scale.
    const N: u64 = 32;
    let holders: Vec<Address> = (0..N).map(holder_at).collect();
    for (i, holder) in holders.iter().enumerate() {
        anvil.fund(&token, &dev, holder, (i as u128 + 1) * 1_000);
    }

    let calls: Vec<BalanceOfCall> = holders
        .iter()
        .map(|holder| BalanceOfCall {
            token,
            holder: DepositAddress::new(*holder),
        })
        .collect();

    let out = anvil
        .eth_call_create(&dev, &encode_balance_batch(&calls))
        .expect("the balance batch must not revert");
    let balances = decode_balance_batch(&out, calls.len()).expect("decode failed");

    let expected: Vec<Erc20Value> = (0..N)
        .map(|i| Erc20Value::from((i as u128 + 1) * 1_000))
        .collect();
    assert_eq!(balances, expected);
}

#[test]
fn should_revert_the_whole_call_when_a_token_is_not_a_contract() {
    let anvil = Anvil::start();
    let dev = address_from_hex(DEV_ACCOUNT);
    let token = deploy_mock_erc20(&anvil, &dev);
    let holder = DepositAddress::new(Address::new([0x11; 20]));
    anvil.fund(&token, &dev, holder.as_address(), 500);

    // A "token" with no code: STATICCALL succeeds with empty return data, which
    // is not the 32 bytes the batcher requires, so it reverts the whole call
    // rather than reporting a phantom zero balance.
    let not_a_contract = Address::new([0x99; 20]);
    assert!(
        anvil.code(&not_a_contract).is_empty(),
        "the bad token must genuinely have no code"
    );

    // The same batch without the bad token succeeds, so the revert is caused by
    // the non-contract token and nothing else.
    let good = vec![BalanceOfCall { token, holder }];
    assert!(
        anvil
            .eth_call_create(&dev, &encode_balance_batch(&good))
            .is_ok(),
        "the well-formed batch should succeed"
    );

    let bad = vec![
        BalanceOfCall { token, holder },
        BalanceOfCall {
            token: not_a_contract,
            holder,
        },
    ];
    assert!(
        anvil
            .eth_call_create(&dev, &encode_balance_batch(&bad))
            .is_err(),
        "a batch touching a non-contract token must revert"
    );
}

/// End-to-end balance scan against a real EVM: a live PocketIC runs the minter and the *real* EVM
/// RPC canister (configured to route every provider to the harness' anvil node), so the minter's
/// periodic balance scan makes genuine outcalls through the IC's HTTPS-outcalls feature — reaching
/// anvil over HTTP — and reads real ERC-20 balances from it.
///
/// Three independent depositors each fund a single token — 20 USDT, 15 USDC and 1 USDT — so the
/// scan reads several addresses and tokens and must apply the per-token minimum to each. Only the
/// two at-or-above-minimum deposits are flagged as candidates; the 1 USDT deposit is scanned but,
/// being below the ~$10 minimum, is not.
#[test]
fn should_flag_only_deposits_at_or_above_the_per_token_minimum() {
    const DEPOSIT_SUBACCOUNT: [u8; 32] = [42; 32];
    // 6-decimal amounts; ckUSDC and ckUSDT share a 10_000_000 (~$10) candidate minimum.
    const USDT_ABOVE_MINIMUM: u128 = 20_000_000;
    const USDC_ABOVE_MINIMUM: u128 = 15_000_000;
    const USDT_BELOW_MINIMUM: u128 = 1_000_000;

    let setup = LiveSetup::new_balance_scan();
    // `supported_erc20_tokens()` registers ckUSDC then ckUSDT, in that order.
    let [usdc, usdt] = setup.supported_erc20_tokens() else {
        panic!("expected exactly 2 supported tokens")
    };
    let deposits = [
        (setup.depositor(1), usdt, USDT_ABOVE_MINIMUM),
        (setup.depositor(2), usdc, USDC_ABOVE_MINIMUM),
        (setup.depositor(3), usdt, USDT_BELOW_MINIMUM),
    ];

    let holdings: Vec<Holding<'_>> = deposits
        .iter()
        .map(|&(depositor, token, amount)| Holding {
            deposit: setup.register_deposit_address(depositor, DEPOSIT_SUBACCOUNT, token),
            token,
            amount,
        })
        .collect();
    setup.credit_deposits(&holdings);

    assert_matches!(
        setup.await_scan(setup.depositor(1), DEPOSIT_SUBACCOUNT, usdt).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.erc20_contract_address == usdt.contract.address
                && detected.scanned_balance == USDT_ABOVE_MINIMUM
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(2), DEPOSIT_SUBACCOUNT, usdc).status,
        DepositStatus::AwaitingSweep(detected)
            if detected.erc20_contract_address == usdc.contract.address
                && detected.scanned_balance == USDC_ABOVE_MINIMUM
                && detected.detected_at_block > 0_u8
    );
    assert_matches!(
        setup.await_scan(setup.depositor(3), DEPOSIT_SUBACCOUNT, usdt).status,
        DepositStatus::Scanning { scan_count, last_scanned_block, .. }
            if scan_count >= 1 && last_scanned_block.is_some()
    );
}

/// A budget, not a cost: driving stops the moment the transfer lands, so this only has to be more
/// ticks than the run needs. One sends the transfer; the spares cover a tick landing before the
/// funding task has burned, and a tick lost to an outcall the jump timed out.
const FUNDING_TICKS: u32 = 6;

#[test]
fn should_fund_the_sweeper_address_by_burning_cketh_from_the_fee_account() {
    let setup = LiveSetup::new_funding();

    // Only the fee account is funded: sweep gas must come from there and nowhere else. Read before
    // the minter is armed, since the funding decision reads nothing off the chain and so its first
    // run burns within milliseconds of the upgrade below — far too fast to snapshot after it.
    let supply_before = setup.cketh_total_supply();
    let fee_account_before = setup.cketh_balance_of(setup.fee_account());
    let minter_eth_before = setup.anvil_eth_balance(&setup.minter_address());

    setup.upgrade_minter();
    let sweeper = setup.await_sweeper_address();
    assert_eq!(
        setup.anvil_eth_balance(&sweeper),
        0,
        "the sweeper address must start empty, so any balance proves the funding landed"
    );

    let received = setup.await_eth_received(&sweeper, FUNDING_TICKS);

    let burned = supply_before
        .checked_sub(setup.cketh_total_supply())
        .expect("the funding must have burned ckETH, not minted it");
    assert!(burned > 0, "funding must burn ckETH");
    assert_eq!(
        fee_account_before - setup.cketh_balance_of(setup.fee_account()),
        burned,
        "the burn must be debited from the fee account"
    );

    // The ETH moved, and never more than was burned — the backing invariant, observed end to end.
    let spent = minter_eth_before - setup.anvil_eth_balance(&setup.minter_address());
    assert!(
        received > 0 && received < burned,
        "the sweeper receives the burned amount minus the fee, got received={received} burned={burned}"
    );
    assert!(
        spent <= burned,
        "the ETH debited from the main address ({spent}) must never exceed the ckETH \
         burned for it ({burned})"
    );
}

#[test]
fn should_credit_twenty_cex_deposits_through_one_sweep_per_token() {
    /// Ten depositors per token, so each sweep is a ten-deposit single-token batch — directly
    /// comparable with `deposit_from_cex_demo`'s measured scenarios.
    const DEPOSITORS_PER_TOKEN: u64 = 10;
    // 6-decimal amounts, both far above the ~$10 per-token candidate minimum.
    const USDC_DEPOSIT: u128 = 100_000_000;
    const USDT_DEPOSIT: u128 = 150_000_000;

    let sweeper = address_from_hex(SWEEPER_ADDRESS);
    let setup = LiveSetup::new_sweep();
    let funded_gas = setup.anvil_eth_balance(&sweeper);
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
    let holdings: Vec<Holding<'_>> = deposits.iter().map(Deposit::holding).collect();
    setup.credit_deposits(&holdings);

    for deposit in &deposits {
        assert_matches!(
            setup.await_scan(deposit.owner, deposit.subaccount, deposit.token).status,
            DepositStatus::AwaitingSweep(detected) if detected.scanned_balance == deposit.amount
        );
    }

    // One sweep per token, and nothing more.
    let sweeps = setup.await_sweeps(&sweeper, 2);
    for sweep in &sweeps {
        assert_eq!(
            sweep.transaction_type, 4,
            "a first sweep installs delegations, so it must be an EIP-7702 transaction: {sweep:?}"
        );
        assert!(sweep.succeeded, "the sweep reverted: {sweep:?}");
    }
    assert_sweep_gas_near_demo(&sweeps, DEPOSITORS_PER_TOKEN);

    // What each sweep actually batched, so that two transactions cannot pass as one per token.
    let mut batched: Vec<(Address, usize)> = setup
        .minter_events()
        .into_iter()
        .filter_map(|event| match event.payload {
            EventPayload::AcceptedSweepRequest { token, items, .. } => Some((
                Address::from_str(&token).expect("BUG: the sweep names an invalid token"),
                items.len(),
            )),
            _ => None,
        })
        .collect();
    batched.sort();
    let per_token = usize::try_from(DEPOSITORS_PER_TOKEN).unwrap();
    let mut expected = vec![
        (contract_address(usdc), per_token),
        (contract_address(usdt), per_token),
    ];
    expected.sort();
    assert_eq!(
        batched, expected,
        "each sweep must batch one token's ten deposits, not a mixed batch and a redundant one"
    );

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
        setup.anvil().balance(&sweeper) < funded_gas,
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
        let account = Account {
            owner: deposit.owner,
            subaccount: Some(deposit.subaccount),
        };
        setup.await_credited(*ledger_id, account, deposit.amount);
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

impl<'a> Deposit<'a> {
    fn holding(&self) -> Holding<'a> {
        Holding {
            deposit: self.address,
            token: self.token,
            amount: self.amount,
        }
    }
}

fn assert_sweep_gas_near_demo(sweeps: &[SentTransaction], deposits_per_sweep: u64) {
    // `ATTESTED_SCENARIOS` in deposit_from_cex_demo.rs, EIP-7702 (first sweep) column.
    const DEMO_ONE_DEPOSIT: u64 = 98_000;
    const DEMO_TEN_DEPOSITS: u64 = 609_431;
    const GAS_BAND_PERCENT: u64 = 10;

    assert_eq!(
        deposits_per_sweep, 10,
        "the demo baseline is measured for ten-deposit sweeps"
    );
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
        assert!(
            sweep.gas_used.abs_diff(DEMO_TEN_DEPOSITS) * 100
                <= DEMO_TEN_DEPOSITS * GAS_BAND_PERCENT,
            "a ten-deposit sweep used {} gas, more than {GAS_BAND_PERCENT}% away from the \
             demo-measured {DEMO_TEN_DEPOSITS}: {sweep:?}",
            sweep.gas_used,
        );
    }
}

fn holder_at(index: u64) -> Address {
    let mut bytes = [0_u8; 20];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    // Offset so no holder collides with the deployer or a low reserved address.
    bytes[0] = 0xd0;
    Address::new(bytes)
}
