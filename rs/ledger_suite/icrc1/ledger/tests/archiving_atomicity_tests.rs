//! Regression test for the atomicity of a ledger transfer with respect to the
//! archiving that the ledger performs before replying.
//!
//! `execute_transfer` applies the transaction synchronously — balances, total
//! supply, the block log and the certified data all change — and only then
//! awaits `archive_blocks`. The await is a commit point: everything applied
//! before it is durable even if a later continuation of the same call traps.
//! When that happens the caller receives a reject for a transfer that did take
//! effect.
//!
//! A caller cannot distinguish that reject from one where nothing happened.
//! The ck minters read it as "the mint did not happen" and retry, which mints
//! the same deposit twice (reported as ICPBB-369).
//!
//! The trap is triggered here the same way it can be triggered on mainnet: the
//! subnet is pushed above its storage-reservation threshold while the ledger is
//! suspended in the archive await, so the memory growth performed by the
//! archive continuation is rejected with `IC0534`
//! (`ReservedCyclesLimitExceededInMemoryGrow`). Unlike a trap in the
//! synchronous part of the message, that one cannot roll the transfer back.
//!
//! The subnet-wide thresholds are scaled down through the test's
//! `HypervisorConfig` rather than reproduced at their mainnet size, and the
//! filler canister only grows *logical* stable memory (it never writes to it),
//! so no meaningful amount of host storage is used.

use candid::{Decode, Encode, Nat};
use ic_base_types::PrincipalId;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_icrc1_ledger::{InitArgs, LedgerArgument};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_suite_state_machine_helpers::{balance_of, icrc3_get_blocks, list_archives};
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    StateMachine, StateMachineBuilder, StateMachineConfig, UserError, WasmResult,
};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::{CanisterId, NumBytes};
use ic_types_cycles::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, wasm};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use num_traits::ToPrimitive;

const WASM_PAGE_SIZE: u64 = 64 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;

/// Storage reservation starts above this much subnet memory (750 GiB on
/// mainnet). It only has to be larger than what the canisters under test use.
const SUBNET_MEMORY_THRESHOLD: u64 = 4 * GIB;
/// A single message can only grow memory by `(capacity - usage) /
/// scheduler_cores` — both the available memory and the saturation a canister
/// sees are scaled down by the number of scheduler cores, see
/// `ExecutionEnvironment::subnet_memory_saturation`. Keeping the capacity well
/// above the threshold leaves the filler's grows plenty of room.
const SUBNET_MEMORY_CAPACITY: u64 = 64 * GIB;

/// Logical stable memory the filler holds before the ledger call starts.
const FILLER_BASE_PAGES: u64 = 3 * GIB / WASM_PAGE_SIZE;
/// Logical stable memory the filler adds while the ledger is suspended in the
/// archive await. This crosses the threshold, leaving the subnet ~4 GiB above
/// it, where growing a single 64 KiB page reserves ~388M cycles.
const FILLER_CROSSING_PAGES: u64 = 5 * GIB / WASM_PAGE_SIZE;

/// Small enough that the first page the archive continuation grows exceeds it.
const LEDGER_RESERVED_CYCLES_LIMIT: u128 = 100_000_000;

/// `create_and_initialize_node_canister` requires at least 4.5T for the archive
/// and at least 10T left over in the ledger.
const CYCLES_FOR_ARCHIVE_CREATION: u64 = 20_000_000_000_000;
const LEDGER_CYCLES: u128 = 200_000_000_000_000;
const FILLER_CYCLES: u128 = 100_000_000_000_000_000;

const ARCHIVE_TRIGGER_THRESHOLD: usize = 10;
const NUM_BLOCKS_TO_ARCHIVE: usize = 5;
const TRANSFER_FEE: u64 = 10_000;
const MINT_AMOUNT: u64 = 1_000_000;

fn ledger_wasm() -> Vec<u8> {
    std::fs::read(std::env::var("IC_ICRC1_LEDGER_WASM_PATH").unwrap()).unwrap()
}

fn minter() -> PrincipalId {
    PrincipalId::new_user_test_id(0)
}

fn beneficiary() -> Account {
    Account::from(PrincipalId::new_user_test_id(1).0)
}

fn hypervisor_config() -> HypervisorConfig {
    HypervisorConfig {
        subnet_memory_threshold: NumBytes::new(SUBNET_MEMORY_THRESHOLD),
        subnet_memory_capacity: NumBytes::new(SUBNET_MEMORY_CAPACITY),
        // Memory held back for response callbacks. Keeping it at the mainnet
        // value (10 GiB) would leave the scaled-down capacity negative for
        // update calls.
        subnet_memory_reservation: NumBytes::new(0),
        ..HypervisorConfig::default()
    }
}

fn ledger_init_args() -> Vec<u8> {
    Encode!(&LedgerArgument::Init(InitArgs {
        minting_account: minter().0.into(),
        fee_collector_account: None,
        initial_balances: vec![],
        transfer_fee: TRANSFER_FEE.into(),
        token_name: "Test Token".to_string(),
        decimals: Some(8),
        token_symbol: "XTST".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: ARCHIVE_TRIGGER_THRESHOLD,
            num_blocks_to_archive: NUM_BLOCKS_TO_ARCHIVE,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: minter(),
            more_controller_ids: None,
            cycles_for_archive_creation: Some(CYCLES_FOR_ARCHIVE_CREATION),
            max_transactions_per_response: None,
        },
        max_memo_length: None,
        feature_flags: None,
        index_principal: None,
    }))
    .unwrap()
}

fn mint_arg(amount: u64) -> Vec<u8> {
    Encode!(&TransferArg {
        from_subaccount: None,
        to: beneficiary(),
        fee: None,
        // The ck minters do the same, which is what makes a retry after an
        // ambiguous reject a second, valid mint.
        created_at_time: None,
        memo: None,
        amount: Nat::from(amount),
    })
    .unwrap()
}

fn chain_length(env: &StateMachine, ledger: CanisterId) -> u64 {
    icrc3_get_blocks(env, ledger, 0, 0)
        .log_length
        .0
        .to_u64()
        .unwrap()
}

/// Grows the filler's *logical* stable memory. The pages are never written to,
/// so they cost the host nothing while still counting towards the subnet's
/// memory usage, which is what drives the storage reservation.
fn grow_filler(env: &StateMachine, filler: CanisterId, pages: u64) {
    let reply = env
        .execute_ingress(
            filler,
            "update",
            wasm().stable64_grow(pages).reply_int64().build(),
        )
        .expect("failed to call the filler canister");
    let previous_size = u64::from_le_bytes(reply.bytes()[..8].try_into().unwrap());
    assert_ne!(
        previous_size,
        u64::MAX,
        "stable64_grow({pages}) failed on the filler canister"
    );
}

/// Memory usage in bytes and reserved cycles, as reported by `canister_status`.
fn memory_and_reservation(env: &StateMachine, canister_id: CanisterId) -> (u64, u128) {
    let status = env
        .canister_status_as(minter(), canister_id)
        .expect("failed to call canister_status")
        .expect("canister_status returned an error");
    (status.memory_size().get(), status.reserved_cycles())
}

fn canister_settings(reserved_cycles_limit: u128) -> CanisterSettingsArgsBuilder {
    CanisterSettingsArgsBuilder::new()
        .with_controllers(vec![minter()])
        .with_reserved_cycles_limit(reserved_cycles_limit)
}

/// Returns the reply of the `icrc1_transfer` that triggers archiving, together
/// with the state committed by the time the reply was produced.
struct TriggeringTransfer {
    result: Result<WasmResult, UserError>,
    /// Whether the ledger had already committed the block while the call was
    /// still outstanding, i.e. whether the call really did reach the archive
    /// await.
    committed_while_outstanding: bool,
    balance_after: u64,
    chain_length_after: u64,
}

fn setup() -> (StateMachine, CanisterId, CanisterId) {
    let env = StateMachineBuilder::new()
        .with_config(Some(StateMachineConfig::new(
            SubnetConfig::new(SubnetType::Application),
            hypervisor_config(),
        )))
        .build();

    let filler = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            // The filler pays a large storage reservation when it crosses the
            // threshold; it must not be capped by the default 5T limit.
            Some(canister_settings(FILLER_CYCLES).build()),
            Cycles::new(FILLER_CYCLES),
        )
        .expect("failed to install the filler canister");

    let ledger = env
        .install_canister_with_cycles(
            ledger_wasm(),
            ledger_init_args(),
            Some(canister_settings(LEDGER_RESERVED_CYCLES_LIMIT).build()),
            Cycles::new(LEDGER_CYCLES),
        )
        .expect("failed to install the ledger canister");

    // Put the subnet under storage pressure. The ledger has not grown any
    // memory of its own at this point, so it has reserved nothing yet.
    grow_filler(&env, filler, FILLER_BASE_PAGES);
    let (filler_memory, _) = memory_and_reservation(&env, filler);
    assert!(
        filler_memory >= FILLER_BASE_PAGES * WASM_PAGE_SIZE,
        "the filler's stable memory growth did not take effect"
    );

    (env, ledger, filler)
}

/// Brings the ledger to one block short of the archive trigger threshold, so
/// that the next transfer is the one that awaits `archive_blocks`.
fn fill_up_to_archive_trigger(env: &StateMachine, ledger: CanisterId) {
    for _ in 0..(ARCHIVE_TRIGGER_THRESHOLD - 1) {
        env.execute_ingress_as(minter(), ledger, "icrc1_transfer", mint_arg(MINT_AMOUNT))
            .expect("failed to mint");
    }
    assert_eq!(
        chain_length(env, ledger),
        ARCHIVE_TRIGGER_THRESHOLD as u64 - 1
    );
    assert!(
        list_archives(env, ledger).is_empty(),
        "archiving must not have been triggered yet"
    );
}

fn submit_triggering_transfer(
    env: &StateMachine,
    ledger: CanisterId,
    filler: CanisterId,
) -> TriggeringTransfer {
    let chain_length_before = chain_length(env, ledger);
    let message = env.send_ingress(minter(), ledger, "icrc1_transfer", mint_arg(MINT_AMOUNT));

    // Let the ledger apply the transaction and suspend in the archive await.
    let mut committed_while_outstanding = false;
    for _ in 0..100 {
        if chain_length(env, ledger) > chain_length_before {
            committed_while_outstanding = matches!(
                env.ingress_status(&message),
                IngressStatus::Known {
                    state: IngressState::Processing | IngressState::Received,
                    ..
                }
            );
            break;
        }
        env.tick();
    }
    assert_eq!(
        chain_length(env, ledger),
        chain_length_before + 1,
        "the ledger did not commit the transfer"
    );

    // Raise the storage pressure further while the archive work is in flight,
    // so that the next page the ledger grows costs more than its reservation
    // limit. This is an ordinary update call to an unrelated canister.
    grow_filler(env, filler, FILLER_CROSSING_PAGES);
    let (filler_memory, filler_reserved) = memory_and_reservation(env, filler);
    assert!(
        filler_memory >= (FILLER_BASE_PAGES + FILLER_CROSSING_PAGES) * WASM_PAGE_SIZE,
        "the filler's stable memory growth did not take effect"
    );
    assert!(
        filler_reserved > 0,
        "the subnet is not above the storage reservation threshold"
    );

    let result = env.await_ingress(message, 100);
    TriggeringTransfer {
        result,
        committed_while_outstanding,
        balance_after: balance_of(env, ledger, beneficiary()),
        chain_length_after: chain_length(env, ledger),
    }
}

/// Archiving must recover once the condition that killed it is gone.
///
/// The archiving lock is taken before the first await, so a trapped
/// continuation could leave `archiving_in_progress` set and silently stop the
/// ledger from ever archiving again. It should be cleared while the task is
/// canceled. Now that a failure to archive is invisible to callers, a stuck
/// lock would be easy to miss.
#[test]
fn archiving_recovers_after_a_trapped_attempt() {
    let (env, ledger, filler) = setup();
    fill_up_to_archive_trigger(&env, ledger);

    let transfer = submit_triggering_transfer(&env, ledger, filler);
    assert!(
        transfer.result.is_ok(),
        "the transfer should have succeeded: {:?}",
        transfer.result
    );
    assert!(
        list_archives(&env, ledger).is_empty(),
        "expected the archive continuation to have been trapped"
    );

    // Raise the reservation limit, as an operator would once alerted, and let
    // the ledger reach the archive trigger threshold again.
    env.update_settings(
        &ledger,
        canister_settings(LEDGER_CYCLES / 2).build(),
    )
    .expect("failed to raise the ledger's reserved cycles limit");
    env.execute_ingress_as(minter(), ledger, "icrc1_transfer", mint_arg(MINT_AMOUNT))
        .expect("failed to mint");

    for _ in 0..20 {
        if !list_archives(&env, ledger).is_empty() {
            return;
        }
        env.tick();
    }
    panic!("the ledger never archived again after a trapped archiving attempt");
}

/// A rejected `icrc1_transfer` must not leave a committed block behind.
///
/// Before archiving was moved off the reply path this failed: the ledger
/// replied with `IC0534` raised by its archive continuation, while the mint it
/// had already committed stayed in the ledger.
#[test]
fn transfer_reject_must_not_leave_a_committed_block() {
    let (env, ledger, filler) = setup();
    fill_up_to_archive_trigger(&env, ledger);

    let balance_before = balance_of(&env, ledger, beneficiary());
    let chain_length_before = chain_length(&env, ledger);
    let transfer = submit_triggering_transfer(&env, ledger, filler);

    println!(
        "committed_while_outstanding={} chain_length={}->{} balance={}->{} archives={:?}",
        transfer.committed_while_outstanding,
        chain_length_before,
        transfer.chain_length_after,
        balance_before,
        transfer.balance_after,
        list_archives(&env, ledger),
    );

    // Preconditions. Without these the test would pass vacuously: it has to
    // reach the state where the ledger has committed the transfer and its
    // archive continuation has then been killed.
    assert_eq!(
        transfer.chain_length_after,
        chain_length_before + 1,
        "the ledger did not commit the transfer, so this run never reached the \
         post-commit failure the test is about"
    );
    assert!(
        list_archives(&env, ledger).is_empty(),
        "expected the archive continuation to have been trapped, but an archive \
         was created; the test is not exercising a post-commit failure"
    );

    // The invariant: having committed the transfer, the ledger must not reply
    // with a reject.
    match transfer.result {
        Err(err) => panic!(
            "the ledger rejected the transfer with `{err}`, but had already committed it: \
             chain length {chain_length_before} -> {}, beneficiary balance {balance_before} -> {}. \
             A caller cannot tell this reject apart from one where nothing happened.",
            transfer.chain_length_after, transfer.balance_after,
        ),
        Ok(reply) => {
            let block_index = Decode!(&reply.bytes(), Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>)
                .expect("failed to decode icrc1_transfer response")
                .expect("the transfer should have succeeded");
            assert_eq!(block_index, Nat::from(chain_length_before));
            assert_eq!(transfer.balance_after, balance_before + MINT_AMOUNT);
        }
    }
}
