#![allow(deprecated)]
#[cfg(feature = "canbench-rs")]
mod benches;

use candid::Principal;
use candid::types::number::Nat;
use ic_canister_log::{declare_log_buffer, export, log};
use ic_cdk::api::stable::StableReader;
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};

use ic_cdk::api::instruction_counter;
#[cfg(not(feature = "canbench-rs"))]
use ic_cdk::init;
use ic_cdk::{post_upgrade, pre_upgrade, query, update};
use ic_icrc1::{
    Operation, Transaction,
    endpoints::{StandardRecord, convert_transfer_error},
};
use ic_icrc1_ledger::{InitArgs, Ledger, LedgerArgument, LedgerField, LedgerState};
use ic_icrc1_ledger::{
    LEDGER_VERSION, UPGRADES_MEMORY, balances_len, clear_stable_allowance_data,
    clear_stable_balances_data, clear_stable_blocks_data, get_allowances, is_ready, ledger_state,
    panic_if_not_ready, read_first_balance, set_ledger_state, wasm_token_type,
};
use ic_ledger_canister_core::ledger::{
    LedgerAccess, LedgerContext, LedgerData, TransferError as CoreTransferError, apply_transaction,
    archive_blocks,
};
use ic_ledger_canister_core::runtime::heap_memory_size_bytes;
use ic_ledger_core::block::BlockIndex;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::Zero;
use ic_stable_structures::reader::{BufferedReader, Reader};
use ic_stable_structures::writer::{BufferedWriter, Writer};
#[cfg(not(feature = "get-blocks-disabled"))]
use icrc_ledger_types::icrc3::blocks::GetBlocksResponse;
use icrc_ledger_types::icrc3::blocks::ICRC3DataCertificate;
use icrc_ledger_types::icrc21::{
    errors::Icrc21Error, lib::build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints,
    requests::ConsentMessageRequest, responses::ConsentInfo,
};
use icrc_ledger_types::icrc103::get_allowances::{
    Allowances, GetAllowancesArgs, GetAllowancesError,
};
use icrc_ledger_types::icrc106::errors::Icrc106Error;
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue as Value,
    icrc3::{
        archive::ArchiveInfo,
        blocks::GetBlocksRequest,
        transactions::{GetTransactionsRequest, GetTransactionsResponse},
    },
};
use icrc_ledger_types::{
    icrc1::account::Account,
    icrc2::allowance::{Allowance, AllowanceArgs},
};
use icrc_ledger_types::{
    icrc1::transfer::Memo,
    icrc3::{
        archive::{GetArchivesArgs, GetArchivesResult},
        blocks::GetBlocksResult,
    },
};
use icrc_ledger_types::{
    icrc1::transfer::{TransferArg, TransferError},
    icrc2::transfer_from::{TransferFromArgs, TransferFromError},
};
use icrc_ledger_types::{
    icrc2::approve::{ApproveArgs, ApproveError},
    icrc107::set_fee_collector::{SetFeeCollectorArgs, SetFeeCollectorError},
};
use icrc_ledger_types::{icrc3::blocks::DataCertificate, icrc107::schema::SET_FEE_COL_107};
use num_traits::{ToPrimitive, bounds::Bounded};
use serde_bytes::ByteBuf;
use std::{
    cell::RefCell,
    io::{Read, Write},
    time::Duration,
};

const MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

#[cfg(not(feature = "u256-tokens"))]
pub type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
pub type Tokens = ic_icrc1_tokens_u256::U256;

thread_local! {
    static LEDGER: RefCell<Option<Ledger>> = const { RefCell::new(None) };
    static PRE_UPGRADE_INSTRUCTIONS_CONSUMED: RefCell<u64> = const { RefCell::new(0) };
    static POST_UPGRADE_INSTRUCTIONS_CONSUMED: RefCell<u64> = const { RefCell::new(0) };
    static STABLE_UPGRADE_MIGRATION_STEPS: RefCell<u64> = const { RefCell::new(0) };
    static TOTAL_VOLUME: RefCell<f64> = const { RefCell::new(0f64) };
    static TOTAL_VOLUME_DENOMINATOR: RefCell<f64> = const { RefCell::new(1f64) };
    static TOTAL_VOLUME_FEE_IN_DECIMALS: RefCell<f64> = const { RefCell::new(0f64) };
}

declare_log_buffer!(name = LOG, capacity = 1000);

struct Access;
impl LedgerAccess for Access {
    type Ledger = Ledger;

    fn with_ledger<R>(f: impl FnOnce(&Self::Ledger) -> R) -> R {
        LEDGER.with(|cell| {
            f(cell
                .borrow()
                .as_ref()
                .expect("ledger state not initialized"))
        })
    }

    fn with_ledger_mut<R>(f: impl FnOnce(&mut Self::Ledger) -> R) -> R {
        LEDGER.with(|cell| {
            f(cell
                .borrow_mut()
                .as_mut()
                .expect("ledger state not initialized"))
        })
    }
}

#[cfg(not(feature = "canbench-rs"))]
#[init]
fn init(args: LedgerArgument) {
    match args {
        LedgerArgument::Init(init_args) => init_state(init_args),
        LedgerArgument::Upgrade(_) => {
            panic!(
                "Cannot initialize the canister with an Upgrade argument. Please provide an Init argument."
            );
        }
    }
    ic_cdk::api::set_certified_data(&Access::with_ledger(Ledger::root_hash));
}

fn init_state(init_args: InitArgs) {
    let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());
    LEDGER.with(|cell| *cell.borrow_mut() = Some(Ledger::from_init_args(&LOG, init_args, now)));
    initialize_total_volume();
}

// We use 8MiB buffer
const BUFFER_SIZE: usize = 8388608;

#[pre_upgrade]
fn pre_upgrade() {
    #[cfg(feature = "canbench-rs")]
    let _p = canbench_rs::bench_scope("pre_upgrade");

    let start = ic_cdk::api::instruction_counter();
    UPGRADES_MEMORY.with_borrow_mut(|bs| {
        Access::with_ledger(|ledger| {
            if !is_ready() {
                // This means that migration did not complete and the correct state
                // of the ledger is still in UPGRADES_MEMORY.
                log_message("Ledger not ready, skipping write to UPGRADES_MEMORY.");
                return;
            }
            let writer = Writer::new(bs, 0);
            let mut buffered_writer = BufferedWriter::new(BUFFER_SIZE, writer);
            ciborium::ser::into_writer(ledger, &mut buffered_writer)
                .expect("Failed to write the Ledger state in stable memory");
            let end = ic_cdk::api::instruction_counter();
            let instructions_consumed = end - start;
            let counter_bytes: [u8; 8] = instructions_consumed.to_le_bytes();
            buffered_writer
                .write_all(&counter_bytes)
                .expect("failed to write instructions consumed to UPGRADES_MEMORY");
        });
    });
}

#[cfg(not(feature = "low-upgrade-instruction-limits"))]
const MAX_INSTRUCTIONS_PER_UPGRADE: u64 = 199_950_000_000;
#[cfg(not(feature = "low-upgrade-instruction-limits"))]
const MAX_INSTRUCTIONS_PER_TIMER_CALL: u64 = 1_950_000_000;

#[cfg(feature = "low-upgrade-instruction-limits")]
const MAX_INSTRUCTIONS_PER_UPGRADE: u64 = 13_000_000;
#[cfg(feature = "low-upgrade-instruction-limits")]
const MAX_INSTRUCTIONS_PER_TIMER_CALL: u64 = 500_000;

#[post_upgrade]
fn post_upgrade(args: Option<LedgerArgument>) {
    post_upgrade_internal(args);
    if is_ready() {
        // Set the certified data to the root hash of the ledger state, using the correct ICRC-3 labels.
        // This cannot be called in `post_upgrade_internal`, since that is benchmarked using
        // canbench, and canbench calls functions as non-replicated queries, and `set_certified_data`
        // cannot be called in non-replicated queries.
        ic_cdk::api::set_certified_data(&Access::with_ledger(Ledger::root_hash));
    }
}

fn post_upgrade_internal(args: Option<LedgerArgument>) {
    #[cfg(feature = "canbench-rs")]
    let _p = canbench_rs::bench_scope("post_upgrade");

    let start = ic_cdk::api::instruction_counter();

    let mut magic_bytes_reader = StableReader::default();
    const MAGIC_BYTES: &[u8; 3] = b"MGR";
    let mut first_bytes = [0u8; 3];
    let memory_manager_found = match magic_bytes_reader.read_exact(&mut first_bytes) {
        Ok(_) => first_bytes == *MAGIC_BYTES,
        Err(_) => false,
    };

    let mut pre_upgrade_instructions_consumed = 0;

    if !memory_manager_found {
        let msg =
            "Cannot upgrade from scratch stable memory, please upgrade to memory manager first.";
        log_message(msg);
        panic!("{msg}");
    }

    let state: Ledger = UPGRADES_MEMORY.with_borrow(|bs| {
        let reader = Reader::new(bs, 0);
        let mut buffered_reader = BufferedReader::new(BUFFER_SIZE, reader);
        let state = ciborium::de::from_reader(&mut buffered_reader).expect(
            "Failed to read the Ledger state from memory manager managed stable structures",
        );
        let mut pre_upgrade_instructions_counter_bytes = [0u8; 8];
        pre_upgrade_instructions_consumed =
            match buffered_reader.read_exact(&mut pre_upgrade_instructions_counter_bytes) {
                Ok(_) => u64::from_le_bytes(pre_upgrade_instructions_counter_bytes),
                Err(_) => {
                    // If upgrading from a version that didn't write the instructions counter to stable memory
                    0u64
                }
            };
        state
    });
    ic_cdk::println!("Successfully read state from memory manager managed stable structures");

    if state.token_type != wasm_token_type() {
        panic!(
            "Incompatible token type, the upgraded ledger token type is {}, current wasm token type is {}",
            state.token_type,
            wasm_token_type()
        );
    }

    LEDGER.with_borrow_mut(|ledger| *ledger = Some(state));

    let upgrade_from_version = Access::with_ledger_mut(|ledger| {
        if ledger.ledger_version > LEDGER_VERSION {
            panic!(
                "Trying to downgrade from incompatible version {}. Current version is {}.",
                ledger.ledger_version, LEDGER_VERSION
            );
        }
        let upgrade_from_version = ledger.ledger_version;
        ledger.ledger_version = LEDGER_VERSION;
        upgrade_from_version
    });

    if let Some(args) = args {
        match args {
            LedgerArgument::Init(_) => panic!(
                "Cannot upgrade the canister with an Init argument. Please provide an Upgrade argument."
            ),
            LedgerArgument::Upgrade(upgrade_args) => {
                if let Some(upgrade_args) = upgrade_args {
                    Access::with_ledger_mut(|ledger| ledger.upgrade(&LOG, upgrade_args));
                }
            }
        }
    }

    PRE_UPGRADE_INSTRUCTIONS_CONSUMED.with(|n| *n.borrow_mut() = pre_upgrade_instructions_consumed);

    initialize_total_volume();

    if upgrade_from_version < 3 {
        set_ledger_state(LedgerState::Migrating(LedgerField::Blocks));
        log_message(format!("Upgrading from version {upgrade_from_version} which does not store blocks in stable structures, clearing stable blocks data.").as_str());
        clear_stable_blocks_data();
    }
    if upgrade_from_version < 2 {
        set_ledger_state(LedgerState::Migrating(LedgerField::Balances));
        log_message(format!("Upgrading from version {upgrade_from_version} which does not store balances in stable structures, clearing stable balances data.").as_str());
        clear_stable_balances_data();
        Access::with_ledger_mut(|ledger| {
            ledger.copy_token_pool();
        });
    }
    if upgrade_from_version == 0 {
        set_ledger_state(LedgerState::Migrating(LedgerField::Allowances));
        log_message(
            "Upgrading from version 0 which does not use stable structures, clearing stable allowance data.",
        );
        clear_stable_allowance_data();
        Access::with_ledger_mut(|ledger| {
            ledger.clear_arrivals();
        });
    }
    if !is_ready() {
        log_message("Migration started.");
        migrate_next_part(
            MAX_INSTRUCTIONS_PER_UPGRADE.saturating_sub(pre_upgrade_instructions_consumed),
        );
    }

    // This will fail if we try to upgrade a u64 ledger with a u256 wasm and at least one balance is present.
    // The wasms use incompatible encodings for storing numbers in stable structures.
    // If the upgrade was successful, the ledger would later fail when trying to read the balances map.
    // Upgrading a u256 ledger with a u64 wasm will fail earlier, while reading the `UPGRADES_MEMORY`.
    read_first_balance();

    let end = ic_cdk::api::instruction_counter();
    let instructions_consumed = end - start;
    POST_UPGRADE_INSTRUCTIONS_CONSUMED.with(|n| *n.borrow_mut() = instructions_consumed);
}

fn initialize_total_volume() {
    let denominator = 10f64.powf(Access::with_ledger(|ledger| ledger.decimals()) as f64);
    let fee = Access::with_ledger(|ledger| ledger.transfer_fee());
    TOTAL_VOLUME_DENOMINATOR.with(|n| *n.borrow_mut() = denominator);
    if fee != Tokens::ZERO {
        TOTAL_VOLUME_FEE_IN_DECIMALS.with(|n| *n.borrow_mut() = tokens_to_f64(fee) / denominator);
    }
}

fn migrate_next_part(instruction_limit: u64) {
    let instructions_migration_start = instruction_counter();
    STABLE_UPGRADE_MIGRATION_STEPS.with(|n| *n.borrow_mut() += 1);
    let mut migrated_allowances = 0;
    let mut migrated_expirations = 0;
    let mut migrated_balances = 0;
    let mut migrated_blocks = 0;

    log_message("Migrating part of the ledger state.");

    Access::with_ledger_mut(|ledger| {
        while instruction_counter() < instruction_limit {
            let field = match ledger_state() {
                LedgerState::Migrating(ledger_field) => ledger_field,
                LedgerState::Ready => break,
            };
            match field {
                LedgerField::Allowances => {
                    if ledger.migrate_one_allowance() {
                        migrated_allowances += 1;
                    } else {
                        set_ledger_state(LedgerState::Migrating(
                            LedgerField::AllowancesExpirations,
                        ));
                    }
                }
                LedgerField::AllowancesExpirations => {
                    if ledger.migrate_one_expiration() {
                        migrated_expirations += 1;
                    } else {
                        set_ledger_state(LedgerState::Migrating(LedgerField::Balances));
                    }
                }
                LedgerField::Balances => {
                    if ledger.migrate_one_balance() {
                        migrated_balances += 1;
                    } else {
                        set_ledger_state(LedgerState::Migrating(LedgerField::Blocks));
                    }
                }
                LedgerField::Blocks => {
                    if ledger.migrate_one_block() {
                        migrated_blocks += 1;
                    } else {
                        set_ledger_state(LedgerState::Ready);
                    }
                }
            }
        }
        let instructions_migration = instruction_counter() - instructions_migration_start;
        let msg = format!(
            "Number of elements migrated: allowances: {migrated_allowances} expirations: {migrated_expirations} balances: {migrated_balances} blocks: {migrated_blocks}. Migration step instructions: {instructions_migration}, total instructions used in message: {}.",
            instruction_counter()
        );
        if !is_ready() {
            log_message(
                format!("Migration partially done. Scheduling the next part. {msg}").as_str(),
            );
            ic_cdk_timers::set_timer(Duration::from_secs(0), async {
                migrate_next_part(MAX_INSTRUCTIONS_PER_TIMER_CALL)
            });
        } else {
            log_message(format!("Migration completed! {msg}").as_str());
            // Set the certified data to the root hash of the ledger state, using the correct ICRC-3 labels.
            ic_cdk::api::set_certified_data(&ledger.root_hash());
        }
    });
}

fn log_message(msg: &str) {
    ic_cdk::println!("{msg}");
    log!(&LOG, "{msg}");
}

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "ledger_stable_memory_pages",
        ic_cdk::api::stable::stable_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "stable_memory_bytes",
        (ic_cdk::api::stable::stable_size() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister measured in bytes.",
    )?;
    w.encode_gauge(
        "heap_memory_bytes",
        heap_memory_size_bytes() as f64,
        "Size of the heap memory allocated by this canister measured in bytes.",
    )?;

    let cycle_balance = ic_cdk::api::canister_balance128() as f64;
    w.encode_gauge(
        "ledger_cycle_balance",
        cycle_balance,
        "Cycle balance on the ledger canister.",
    )?;
    w.gauge_vec("cycle_balance", "Cycle balance on the ledger canister.")?
        .value(&[("canister", "icrc1-ledger")], cycle_balance)?;
    let pre_upgrade_instructions = PRE_UPGRADE_INSTRUCTIONS_CONSUMED.with(|n| *n.borrow());
    let post_upgrade_instructions = POST_UPGRADE_INSTRUCTIONS_CONSUMED.with(|n| *n.borrow());
    let stable_upgrade_migration_steps = STABLE_UPGRADE_MIGRATION_STEPS.with(|n| *n.borrow());
    w.encode_gauge(
        "ledger_pre_upgrade_instructions_consumed",
        pre_upgrade_instructions as f64,
        "Number of instructions consumed during the last pre-upgrade.",
    )?;
    w.encode_gauge(
        "ledger_post_upgrade_instructions_consumed",
        post_upgrade_instructions as f64,
        "Number of instructions consumed during the last post-upgrade.",
    )?;
    w.encode_gauge(
        "ledger_total_upgrade_instructions_consumed",
        pre_upgrade_instructions.saturating_add(post_upgrade_instructions) as f64,
        "Total number of instructions consumed during the last upgrade.",
    )?;
    w.encode_counter(
        "ledger_stable_upgrade_migration_steps",
        stable_upgrade_migration_steps as f64,
        "Number of steps used to migrate data to stable structures.",
    )?;
    w.encode_counter(
        "total_volume",
        TOTAL_VOLUME.with(|n| *n.borrow()),
        "Total volume of ledger transactions.",
    )?;

    Access::with_ledger(|ledger| {
        w.encode_gauge(
            "ledger_transactions_by_hash_cache_entries",
            ledger.transactions_by_hash().len() as f64,
            "Total number of entries in the transactions_by_hash cache.",
        )?;
        w.encode_gauge(
            "ledger_transactions_by_height_entries",
            ledger.transactions_by_height().len() as f64,
            "Total number of entries in the transaction_by_height queue.",
        )?;
        w.encode_gauge(
            "ledger_transactions",
            ledger.blockchain().num_unarchived_blocks() as f64,
            "Total number of transactions stored in the main memory.",
        )?;
        w.encode_gauge(
            "ledger_archived_transactions",
            ledger.blockchain().num_archived_blocks as f64,
            "Total number of transactions sent to the archive.",
        )?;
        // The sum of the two gauges above. It is necessary to have this metric explicitly exported
        // in order to be able to accurately calculate the total transaction rate.
        w.encode_gauge(
            "ledger_total_transactions",
            ledger.blockchain().num_archived_blocks.saturating_add(ledger.blockchain().num_unarchived_blocks()) as f64,
            "Total number of transactions stored in the main memory, plus total number of transactions sent to the archive.",
        )?;
        if is_ready() {
            let token_pool: Nat = ledger.balances().token_pool.into();
            w.encode_gauge(
                "ledger_balances_token_pool",
                token_pool.0.to_f64().unwrap_or(f64::INFINITY),
                "Total number of Tokens in the pool.",
            )?;
            let total_supply: Nat = ledger.balances().total_supply().into();
            w.encode_gauge(
                "ledger_total_supply",
                total_supply.0.to_f64().unwrap_or(f64::INFINITY),
                "Total number of tokens in circulation.",
            )?;
            w.encode_gauge(
                "ledger_balance_store_entries",
                balances_len() as f64,
                "Total number of accounts in the balance store.",
            )?;
        }
        w.encode_gauge(
            "ledger_most_recent_block_time_seconds",
            (ledger
                .blockchain()
                .last_timestamp
                .as_nanos_since_unix_epoch()
                / 1_000_000_000) as f64,
            "IC timestamp of the most recent block.",
        )?;
        w.encode_counter(
            "ledger_archiving_failures",
            ledger.get_archiving_failure_metric() as f64,
            "Number of archiving failures since canister initialization.",
        )?;
        match ledger.blockchain().archive.read() {
            Ok(archive_guard) => {
                let num_archives = archive_guard
                    .as_ref()
                    .iter()
                    .fold(0, |sum, archive| sum + archive.nodes().iter().len());
                w.encode_counter(
                    "ledger_num_archives",
                    num_archives as f64,
                    "Total number of archives.",
                )?;
            }
            Err(err) => Err(std::io::Error::other(format!(
                "Failed to read number of archives: {err}"
            )))?,
        }
        if is_ready() {
            w.encode_gauge(
                "ledger_num_approvals",
                ledger.approvals().get_num_approvals() as f64,
                "Total number of approvals.",
            )?;
        }
        Ok(())
    })
}

/// Update the total volume of token transactions. Since the total volume counter is an `f64`, it
/// can handle large amounts, but the accuracy may suffer. Only the rate of increase of the counter
/// should be used, since the total amount will be reset to zero each time the canister is upgraded.
fn update_total_volume(amount: Tokens, with_fee: bool) {
    let mut total_volume = TOTAL_VOLUME.with(|n| *n.borrow());
    let denominator = TOTAL_VOLUME_DENOMINATOR.with(|n| *n.borrow());
    if amount != Tokens::ZERO {
        let amount = tokens_to_f64(amount) / denominator;
        total_volume = f64_saturating_add(total_volume, amount);
    }
    if with_fee {
        total_volume = f64_saturating_add(
            total_volume,
            TOTAL_VOLUME_FEE_IN_DECIMALS.with(|n| *n.borrow()),
        );
    }
    TOTAL_VOLUME.with(|n| *n.borrow_mut() = total_volume);
}

fn f64_saturating_add(a: f64, b: f64) -> f64 {
    let sum = a + b;

    if sum.is_infinite() && sum.is_sign_positive() {
        // If positive infinity, clamp to f64::MAX
        f64::MAX
    } else if sum.is_infinite() && sum.is_sign_negative() {
        // If negative infinity, clamp to f64::MIN
        f64::MIN
    } else {
        // Otherwise, return the regular sum
        sum
    }
}

#[cfg(not(feature = "u256-tokens"))]
fn tokens_to_f64(tokens: Tokens) -> f64 {
    tokens.to_u64() as f64
}

#[cfg(feature = "u256-tokens")]
fn tokens_to_f64(tokens: Tokens) -> f64 {
    tokens.to_u256().as_f64()
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .header("Cache-Control", "no-store")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err}"))
                    .build()
            }
        }
    } else if req.path() == "/logs" {
        use std::io::Write;
        let mut buf = vec![];
        for entry in export(&LOG) {
            writeln!(
                &mut buf,
                "{} {}:{} {}",
                entry.timestamp, entry.file, entry.line, entry.message
            )
            .unwrap();
        }
        HttpResponseBuilder::ok()
            .header("Content-Type", "text/plain; charset=utf-8")
            .with_body_and_content_length(buf)
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

#[query]
fn icrc1_name() -> String {
    Access::with_ledger(|ledger| ledger.token_name().to_string())
}

#[query]
fn icrc1_symbol() -> String {
    Access::with_ledger(|ledger| ledger.token_symbol().to_string())
}

#[query]
fn icrc1_decimals() -> u8 {
    Access::with_ledger(|ledger| ledger.decimals())
}

#[query]
fn icrc1_fee() -> Nat {
    Access::with_ledger(|ledger| ledger.transfer_fee().into())
}

#[query]
fn icrc1_metadata() -> Vec<(String, Value)> {
    Access::with_ledger(|ledger| ledger.metadata())
}

#[query]
fn icrc1_minting_account() -> Option<Account> {
    Access::with_ledger(|ledger| Some(*ledger.minting_account()))
}

#[query(name = "icrc1_balance_of")]
fn icrc1_balance_of(account: Account) -> Nat {
    Access::with_ledger(|ledger| ledger.balances().account_balance(&account).into())
}

#[query(name = "icrc1_total_supply")]
fn icrc1_total_supply() -> Nat {
    Access::with_ledger(|ledger| ledger.balances().total_supply().into())
}

async fn execute_transfer(
    from_account: Account,
    to: Account,
    spender: Option<Account>,
    fee: Option<Nat>,
    amount: Nat,
    memo: Option<Memo>,
    created_at_time: Option<u64>,
) -> Result<Nat, CoreTransferError<Tokens>> {
    let block_idx = execute_transfer_not_async(
        from_account,
        to,
        spender,
        fee,
        amount,
        memo,
        created_at_time,
    )?;

    // NB. we need to set the certified data before the first async call to make sure that the
    // blockchain state agrees with the certificate while archiving is in progress.
    ic_cdk::api::set_certified_data(&Access::with_ledger(Ledger::root_hash));

    archive_blocks::<Access>(&LOG, MAX_MESSAGE_SIZE).await;
    Ok(Nat::from(block_idx))
}

fn execute_transfer_not_async(
    from_account: Account,
    to: Account,
    spender: Option<Account>,
    fee: Option<Nat>,
    amount: Nat,
    memo: Option<Memo>,
    created_at_time: Option<u64>,
) -> Result<BlockIndex, ic_ledger_canister_core::ledger::TransferError<Tokens>> {
    Access::with_ledger_mut(|ledger| {
        let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());
        let created_at_time = created_at_time.map(TimeStamp::from_nanos_since_unix_epoch);

        match memo.as_ref() {
            Some(memo) if memo.0.len() > ledger.max_memo_length() as usize => {
                ic_cdk::trap(format!(
                    "the memo field size of {} bytes is above the allowed limit of {} bytes",
                    memo.0.len(),
                    ledger.max_memo_length()
                ))
            }
            _ => {}
        };
        let amount = match Tokens::try_from(amount.clone()) {
            Ok(n) => n,
            Err(_) => {
                // No one can have so many tokens
                let balance_tokens = ledger.balances().account_balance(&from_account);
                let balance = Nat::from(balance_tokens);
                assert!(balance < amount);
                return Err(CoreTransferError::InsufficientFunds {
                    balance: balance_tokens,
                });
            }
        };

        let (tx, effective_fee) = if &to == ledger.minting_account() {
            let expected_fee = Tokens::zero();
            if fee.is_some() && fee.as_ref() != Some(&expected_fee.into()) {
                return Err(CoreTransferError::BadFee { expected_fee });
            }

            let balance = ledger.balances().account_balance(&from_account);
            let min_burn_amount = ledger.transfer_fee().min(balance);
            if amount < min_burn_amount {
                return Err(CoreTransferError::BadBurn { min_burn_amount });
            }
            if Tokens::is_zero(&amount) {
                return Err(CoreTransferError::BadBurn {
                    min_burn_amount: ledger.transfer_fee(),
                });
            }

            (
                Transaction {
                    operation: Operation::Burn {
                        from: from_account,
                        spender,
                        amount,
                        fee: None,
                    },
                    created_at_time: created_at_time.map(|t| t.as_nanos_since_unix_epoch()),
                    memo,
                },
                Tokens::zero(),
            )
        } else if &from_account == ledger.minting_account() {
            if spender.is_some() {
                ic_cdk::trap("the minter account cannot delegate mints")
            }
            let expected_fee = Tokens::zero();
            if fee.is_some() && fee.as_ref() != Some(&expected_fee.into()) {
                return Err(CoreTransferError::BadFee { expected_fee });
            }
            (
                Transaction::mint(to, amount, created_at_time, memo),
                Tokens::zero(),
            )
        } else {
            let expected_fee_tokens = ledger.transfer_fee();
            if fee.is_some() && fee.as_ref() != Some(&expected_fee_tokens.into()) {
                return Err(CoreTransferError::BadFee {
                    expected_fee: expected_fee_tokens,
                });
            }
            (
                Transaction::transfer(
                    from_account,
                    to,
                    spender,
                    amount,
                    fee.map(|_| expected_fee_tokens),
                    created_at_time,
                    memo,
                ),
                expected_fee_tokens,
            )
        };

        let (block_idx, _) = apply_transaction(ledger, tx, now, effective_fee)?;
        update_total_volume(amount, effective_fee != Tokens::zero());
        Ok(block_idx)
    })
}

#[update]
async fn icrc1_transfer(arg: TransferArg) -> Result<Nat, TransferError> {
    panic_if_not_ready();
    let from_account = Account {
        owner: ic_cdk::api::caller(),
        subaccount: arg.from_subaccount,
    };
    execute_transfer(
        from_account,
        arg.to,
        None,
        arg.fee,
        arg.amount,
        arg.memo,
        arg.created_at_time,
    )
    .await
    .map_err(convert_transfer_error)
    .map_err(|err| {
        let err: TransferError = match err.try_into() {
            Ok(err) => err,
            Err(err) => ic_cdk::trap(&err),
        };
        err
    })
}

#[update]
async fn icrc2_transfer_from(arg: TransferFromArgs) -> Result<Nat, TransferFromError> {
    panic_if_not_ready();
    let spender_account = Account {
        owner: ic_cdk::api::caller(),
        subaccount: arg.spender_subaccount,
    };
    execute_transfer(
        arg.from,
        arg.to,
        Some(spender_account),
        arg.fee,
        arg.amount,
        arg.memo,
        arg.created_at_time,
    )
    .await
    .map_err(convert_transfer_error)
    .map_err(|err| {
        let err: TransferFromError = match err.try_into() {
            Ok(err) => err,
            Err(err) => ic_cdk::trap(&err),
        };
        err
    })
}

#[query]
fn archives() -> Vec<ArchiveInfo> {
    Access::with_ledger(|ledger| {
        ledger
            .blockchain()
            .archive
            .read()
            .unwrap()
            .as_ref()
            .iter()
            .flat_map(|archive| {
                archive
                    .index()
                    .into_iter()
                    .map(|((start, end), canister_id)| ArchiveInfo {
                        canister_id: canister_id.get().0,
                        block_range_start: Nat::from(start),
                        block_range_end: Nat::from(end),
                    })
            })
            .collect()
    })
}

#[query(name = "icrc1_supported_standards")]
fn supported_standards() -> Vec<StandardRecord> {
    let standards = vec![
        StandardRecord {
            name: "ICRC-1".to_string(),
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1".to_string(),
        },
        StandardRecord {
            name: "ICRC-2".to_string(),
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2".to_string(),
        },
        StandardRecord {
            name: "ICRC-3".to_string(),
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3".to_string(),
        },
        StandardRecord {
            name: "ICRC-10".to_string(),
            url: "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-10/ICRC-10.md".to_string(),
        },
        StandardRecord {
            name: "ICRC-21".to_string(),
            url: "https://github.com/dfinity/wg-identity-authentication/blob/main/topics/ICRC-21/icrc_21_consent_msg.md".to_string(),
        },
        StandardRecord {
            name: "ICRC-103".to_string(),
            url: "https://github.com/dfinity/ICRC/tree/main/ICRCs/ICRC-103".to_string(),
        },
        StandardRecord {
            name: "ICRC-106".to_string(),
            url: "https://github.com/dfinity/ICRC/pull/106".to_string(),
        },
    ];
    standards
}

#[query]
fn get_transactions(req: GetTransactionsRequest) -> GetTransactionsResponse {
    panic_if_not_ready();
    let (start, length) = req
        .as_start_and_length()
        .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));
    Access::with_ledger(|ledger| ledger.get_transactions(start, length as usize))
}

#[cfg(not(feature = "get-blocks-disabled"))]
#[query]
fn get_blocks(req: GetBlocksRequest) -> GetBlocksResponse {
    panic_if_not_ready();
    let (start, length) = req
        .as_start_and_length()
        .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));
    Access::with_ledger(|ledger| ledger.get_blocks(start, length as usize))
}

#[query]
fn get_data_certificate() -> DataCertificate {
    panic_if_not_ready();
    let hash_tree = Access::with_ledger(|ledger| ledger.construct_hash_tree());
    let mut tree_buf = vec![];
    ciborium::ser::into_writer(&hash_tree, &mut tree_buf).unwrap();
    DataCertificate {
        certificate: ic_cdk::api::data_certificate().map(ByteBuf::from),
        hash_tree: ByteBuf::from(tree_buf),
    }
}

fn icrc2_approve_not_async(caller: Principal, arg: ApproveArgs) -> Result<u64, ApproveError> {
    panic_if_not_ready();
    let block_idx = Access::with_ledger_mut(|ledger| {
        let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());

        let from_account = Account {
            owner: caller,
            subaccount: arg.from_subaccount,
        };
        if from_account.owner == arg.spender.owner {
            ic_cdk::trap("self approval is not allowed")
        }
        if &from_account == ledger.minting_account() {
            ic_cdk::trap("the minting account cannot delegate mints")
        }
        match arg.memo.as_ref() {
            Some(memo) if memo.0.len() > ledger.max_memo_length() as usize => {
                ic_cdk::trap("the memo field is too large")
            }
            _ => {}
        };
        let amount = Tokens::try_from(arg.amount).unwrap_or_else(|_| Tokens::max_value());
        let expected_allowance = match arg.expected_allowance {
            Some(n) => match Tokens::try_from(n) {
                Ok(n) => Some(n),
                Err(_) => {
                    let current_allowance = ledger
                        .approvals()
                        .allowance(&from_account, &arg.spender, now)
                        .amount;
                    return Err(ApproveError::AllowanceChanged {
                        current_allowance: current_allowance.into(),
                    });
                }
            },
            None => None,
        };

        let expected_fee_tokens = ledger.transfer_fee();
        let expected_fee: Nat = expected_fee_tokens.into();
        if arg.fee.is_some() && arg.fee.as_ref() != Some(&expected_fee) {
            return Err(ApproveError::BadFee { expected_fee });
        }

        let tx = Transaction {
            operation: Operation::Approve {
                from: from_account,
                spender: arg.spender,
                amount,
                expected_allowance,
                expires_at: arg.expires_at,
                fee: arg.fee.map(|_| expected_fee_tokens),
            },
            created_at_time: arg.created_at_time,
            memo: arg.memo,
        };

        let (block_idx, _) = apply_transaction(ledger, tx, now, expected_fee_tokens)
            .map_err(convert_transfer_error)
            .map_err(|err| {
                let err: ApproveError = match err.try_into() {
                    Ok(err) => err,
                    Err(err) => ic_cdk::trap(&err),
                };
                err
            })?;
        Ok(block_idx)
    })?;

    update_total_volume(Tokens::zero(), true);

    Ok(block_idx)
}

#[update]
async fn icrc2_approve(arg: ApproveArgs) -> Result<Nat, ApproveError> {
    let block_idx = icrc2_approve_not_async(ic_cdk::api::caller(), arg)?;

    // NB. we need to set the certified data before the first async call to make sure that the
    // blockchain state agrees with the certificate while archiving is in progress.
    ic_cdk::api::set_certified_data(&Access::with_ledger(Ledger::root_hash));

    archive_blocks::<Access>(&LOG, MAX_MESSAGE_SIZE).await;
    Ok(Nat::from(block_idx))
}

#[query]
fn icrc2_allowance(arg: AllowanceArgs) -> Allowance {
    Access::with_ledger(|ledger| {
        let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());
        let allowance = ledger
            .approvals()
            .allowance(&arg.account, &arg.spender, now);
        Allowance {
            allowance: allowance.amount.into(),
            expires_at: allowance.expires_at.map(|t| t.as_nanos_since_unix_epoch()),
        }
    })
}

#[query]
fn icrc3_get_archives(args: GetArchivesArgs) -> GetArchivesResult {
    Access::with_ledger(|ledger| ledger.icrc3_get_archives(args))
}

#[query]
fn icrc3_get_tip_certificate() -> Option<ICRC3DataCertificate> {
    panic_if_not_ready();
    let certificate = ByteBuf::from(ic_cdk::api::data_certificate()?);
    let hash_tree = Access::with_ledger(|ledger| ledger.construct_hash_tree());
    let mut tree_buf = vec![];
    ciborium::ser::into_writer(&hash_tree, &mut tree_buf).unwrap();
    Some(ICRC3DataCertificate {
        certificate,
        hash_tree: ByteBuf::from(tree_buf),
    })
}

#[query]
fn icrc3_supported_block_types() -> Vec<icrc_ledger_types::icrc3::blocks::SupportedBlockType> {
    use icrc_ledger_types::icrc3::blocks::SupportedBlockType;

    vec![
        SupportedBlockType {
            block_type: "1burn".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "1mint".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "1xfer".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "2approve".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "2xfer".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
    ]
}

#[query]
fn icrc3_get_blocks(args: Vec<GetBlocksRequest>) -> GetBlocksResult {
    panic_if_not_ready();
    Access::with_ledger(|ledger| ledger.icrc3_get_blocks(args))
}

#[query]
fn icrc10_supported_standards() -> Vec<StandardRecord> {
    supported_standards()
}

#[query]
fn icrc106_get_index_principal() -> Result<Principal, Icrc106Error> {
    Access::with_ledger(|ledger| match ledger.index_principal() {
        None => Err(Icrc106Error::IndexPrincipalNotSet),
        Some(index_principal) => Ok(index_principal),
    })
}

#[update]
fn icrc21_canister_call_consent_message(
    consent_msg_request: ConsentMessageRequest,
) -> Result<ConsentInfo, Icrc21Error> {
    let caller_principal = ic_cdk::api::caller();
    let ledger_fee = icrc1_fee();
    let token_symbol = icrc1_symbol();
    let token_name = icrc1_name();
    let decimals = icrc1_decimals();

    build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints(
        consent_msg_request,
        caller_principal,
        ledger_fee,
        token_symbol,
        token_name,
        decimals,
    )
}

#[query]
fn is_ledger_ready() -> bool {
    is_ready()
}

#[query]
fn icrc103_get_allowances(arg: GetAllowancesArgs) -> Result<Allowances, GetAllowancesError> {
    let from_account = arg.from_account.unwrap_or_else(|| Account {
        owner: ic_cdk::api::caller(),
        subaccount: None,
    });
    let max_take_allowances = Access::with_ledger(|ledger| ledger.max_take_allowances());
    let max_results = arg
        .take
        .map(|take| take.0.to_u64().unwrap_or(max_take_allowances))
        .map(|take| std::cmp::min(take, max_take_allowances))
        .unwrap_or(max_take_allowances);
    Ok(get_allowances(
        from_account,
        arg.prev_spender,
        max_results,
        ic_cdk::api::time(),
    ))
}

#[update]
async fn icrc107_set_fee_collector(arg: SetFeeCollectorArgs) -> Result<Nat, SetFeeCollectorError> {
    let caller = ic_cdk::api::caller();

    if !ic_cdk::api::is_controller(&caller) {
        return Err(SetFeeCollectorError::AccessDenied(
            "The `icrc107_set_fee_collector` endpoint can only be called by the canister controller".to_string(),
        ));
    }

    let tx = Transaction {
        operation: Operation::FeeCollector {
            fee_collector: arg.fee_collector,
            caller: Some(caller),
            mthd: Some(SET_FEE_COL_107.to_string()),
        },
        created_at_time: Some(arg.created_at_time),
        memo: None,
    };

    let (block_idx, _) = Access::with_ledger_mut(|ledger| {
        let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());
        apply_transaction(ledger, tx, now, Tokens::ZERO)
            .map_err(convert_transfer_error)
            .map_err(|err| match err.0 {
                CoreTransferError::TxDuplicate { duplicate_of } => {
                    SetFeeCollectorError::Duplicate {
                        duplicate_of: Nat::from(duplicate_of),
                    }
                }
                _ => ic_cdk::trap("unable to convert error"),
            })
    })?;

    // NB. we need to set the certified data before the first async call to make sure that the
    // blockchain state agrees with the certificate while archiving is in progress.
    ic_cdk::api::set_certified_data(&Access::with_ledger(Ledger::root_hash));

    archive_blocks::<Access>(&LOG, MAX_MESSAGE_SIZE).await;
    Ok(Nat::from(block_idx))
}

candid::export_service!();

#[query]
fn __get_candid_interface_tmp_hack() -> String {
    __export_service()
}

fn main() {}

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{CandidSource, service_equal};

    let new_interface = __export_service();
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let old_interface = manifest_dir.join("ledger.did");
    service_equal(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap_or_else(|e| {
        panic!(
            "the ledger interface is not compatible with {}: {:?}",
            old_interface.display(),
            e
        )
    });
}
