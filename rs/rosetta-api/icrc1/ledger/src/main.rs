#[cfg(feature = "canbench-rs")]
mod benches;

use candid::candid_method;
use candid::types::number::Nat;
use ic_canister_log::{declare_log_buffer, export};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::stable::{StableReader, StableWriter};

#[cfg(not(feature = "canbench-rs"))]
use ic_cdk_macros::init;
use ic_cdk_macros::{post_upgrade, pre_upgrade, query, update};
use ic_icrc1::{
    endpoints::{convert_transfer_error, StandardRecord},
    Operation, Transaction,
};
use ic_icrc1_ledger::{InitArgs, Ledger, LedgerArgument};
use ic_ledger_canister_core::ledger::{
    apply_transaction, archive_blocks, LedgerAccess, LedgerContext, LedgerData,
    TransferError as CoreTransferError,
};
use ic_ledger_canister_core::runtime::total_memory_size_bytes;
use ic_ledger_core::block::BlockIndex;
use ic_ledger_core::timestamp::TimeStamp;
use ic_ledger_core::tokens::Zero;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc21::{
    errors::Icrc21Error, lib::build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints,
    requests::ConsentMessageRequest, responses::ConsentInfo,
};
use icrc_ledger_types::icrc3::blocks::DataCertificate;
#[cfg(not(feature = "get-blocks-disabled"))]
use icrc_ledger_types::icrc3::blocks::GetBlocksResponse;
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
use num_traits::{bounds::Bounded, ToPrimitive};
use serde_bytes::ByteBuf;
use std::cell::RefCell;
use std::io::{Read, Write};

const MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

#[cfg(not(feature = "u256-tokens"))]
pub type Tokens = ic_icrc1_tokens_u64::U64;

#[cfg(feature = "u256-tokens")]
pub type Tokens = ic_icrc1_tokens_u256::U256;

thread_local! {
    static LEDGER: RefCell<Option<Ledger<Tokens>>> = const { RefCell::new(None) };
    static PRE_UPGRADE_INSTRUCTIONS_CONSUMED: RefCell<u64> = const { RefCell::new(0) };
    static POST_UPGRADE_INSTRUCTIONS_CONSUMED: RefCell<u64> = const { RefCell::new(0) };
}

declare_log_buffer!(name = LOG, capacity = 1000);

struct Access;
impl LedgerAccess for Access {
    type Ledger = Ledger<Tokens>;

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
#[candid_method(init)]
#[init]
fn init(args: LedgerArgument) {
    match args {
        LedgerArgument::Init(init_args) => init_state(init_args),
        LedgerArgument::Upgrade(_) => {
            panic!("Cannot initialize the canister with an Upgrade argument. Please provide an Init argument.");
        }
    }
    ic_cdk::api::set_certified_data(&Access::with_ledger(Ledger::root_hash));
}

fn init_state(init_args: InitArgs) {
    let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());
    LEDGER.with(|cell| {
        *cell.borrow_mut() = Some(Ledger::<Tokens>::from_init_args(&LOG, init_args, now))
    })
}

#[pre_upgrade]
fn pre_upgrade() {
    #[cfg(feature = "canbench-rs")]
    let _p = canbench_rs::bench_scope("pre_upgrade");

    let start = ic_cdk::api::instruction_counter();
    let mut stable_writer = StableWriter::default();
    Access::with_ledger(|ledger| ciborium::ser::into_writer(ledger, &mut stable_writer))
        .expect("failed to encode ledger state");
    let end = ic_cdk::api::instruction_counter();
    let instructions_consumed = end - start;
    let counter_bytes: [u8; 8] = instructions_consumed.to_le_bytes();
    stable_writer
        .write_all(&counter_bytes)
        .expect("failed to write instructions consumed to stable memory");
}

#[post_upgrade]
fn post_upgrade(args: Option<LedgerArgument>) {
    #[cfg(feature = "canbench-rs")]
    let _p = canbench_rs::bench_scope("post_upgrade");

    let start = ic_cdk::api::instruction_counter();
    let mut stable_reader = StableReader::default();
    LEDGER.with(|cell| {
        *cell.borrow_mut() = Some(
            ciborium::de::from_reader(&mut stable_reader).expect("failed to decode ledger state"),
        );
    });

    if let Some(args) = args {
        match args {
            LedgerArgument::Init(_) => panic!("Cannot upgrade the canister with an Init argument. Please provide an Upgrade argument."),
            LedgerArgument::Upgrade(upgrade_args) => {
                if let Some(upgrade_args) = upgrade_args {
                    Access::with_ledger_mut(|ledger| ledger.upgrade(&LOG, upgrade_args));
                }
            }
        }
    }
    let mut pre_upgrade_instructions_counter_bytes = [0u8; 8];
    let pre_upgrade_instructions_consumed =
        match stable_reader.read_exact(&mut pre_upgrade_instructions_counter_bytes) {
            Ok(_) => u64::from_le_bytes(pre_upgrade_instructions_counter_bytes),
            Err(_) => {
                // If upgrading from a version that didn't write the instructions counter to stable memory
                0u64
            }
        };
    PRE_UPGRADE_INSTRUCTIONS_CONSUMED.with(|n| *n.borrow_mut() = pre_upgrade_instructions_consumed);

    let end = ic_cdk::api::instruction_counter();
    let instructions_consumed = end - start;
    POST_UPGRADE_INSTRUCTIONS_CONSUMED.with(|n| *n.borrow_mut() = instructions_consumed);
}

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "ledger_stable_memory_pages",
        ic_cdk::api::stable::stable64_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "ledger_stable_memory_bytes",
        (ic_cdk::api::stable::stable64_size() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister.",
    )?;
    w.encode_gauge(
        "ledger_total_memory_bytes",
        total_memory_size_bytes() as f64,
        "Total amount of memory (heap, stable memory, etc) that has been allocated by this canister.",
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
            ledger.blockchain().blocks.len() as f64,
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
            ledger.blockchain().num_archived_blocks.saturating_add(ledger.blockchain().blocks.len() as u64) as f64,
            "Total number of transactions stored in the main memory, plus total number of transactions sent to the archive.",
        )?;
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
            ledger.balances().store.len() as f64,
            "Total number of accounts in the balance store.",
        )?;
        w.encode_gauge(
            "ledger_most_recent_block_time_seconds",
            (ledger
                .blockchain()
                .last_timestamp
                .as_nanos_since_unix_epoch()
                / 1_000_000_000) as f64,
            "IC timestamp of the most recent block.",
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
            Err(err) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read number of archives: {}", err),
            ))?,
        }
        w.encode_gauge(
            "ledger_num_approvals",
            ledger.approvals().get_num_approvals() as f64,
            "Total number of approvals.",
        )?;
        Ok(())
    })
}

#[query(hidden = true, decoding_quota = 10000)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
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
#[candid_method(query)]
fn icrc1_name() -> String {
    Access::with_ledger(|ledger| ledger.token_name().to_string())
}

#[query]
#[candid_method(query)]
fn icrc1_symbol() -> String {
    Access::with_ledger(|ledger| ledger.token_symbol().to_string())
}

#[query]
#[candid_method(query)]
fn icrc1_decimals() -> u8 {
    Access::with_ledger(|ledger| ledger.decimals())
}

#[query]
#[candid_method(query)]
fn icrc1_fee() -> Nat {
    Access::with_ledger(|ledger| ledger.transfer_fee().into())
}

#[query]
#[candid_method(query)]
fn icrc1_metadata() -> Vec<(String, Value)> {
    Access::with_ledger(|ledger| ledger.metadata())
}

#[query]
#[candid_method(query)]
fn icrc1_minting_account() -> Option<Account> {
    Access::with_ledger(|ledger| Some(*ledger.minting_account()))
}

#[query(name = "icrc1_balance_of")]
#[candid_method(query, rename = "icrc1_balance_of")]
fn icrc1_balance_of(account: Account) -> Nat {
    Access::with_ledger(|ledger| ledger.balances().account_balance(&account).into())
}

#[query(name = "icrc1_total_supply")]
#[candid_method(query, rename = "icrc1_total_supply")]
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
                ic_cdk::trap(&format!(
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
        Ok(block_idx)
    })
}

#[update]
#[candid_method(update)]
async fn icrc1_transfer(arg: TransferArg) -> Result<Nat, TransferError> {
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
#[candid_method(update)]
async fn icrc2_transfer_from(arg: TransferFromArgs) -> Result<Nat, TransferFromError> {
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
#[candid_method(query, rename = "icrc1_supported_standards")]
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
            name: "ICRC-21".to_string(),
            url: "https://github.com/dfinity/wg-identity-authentication/blob/main/topics/ICRC-21/icrc_21_consent_msg.md".to_string(),
        },
    ];
    standards
}

#[query]
#[candid_method(query)]
fn get_transactions(req: GetTransactionsRequest) -> GetTransactionsResponse {
    let (start, length) = req
        .as_start_and_length()
        .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));
    Access::with_ledger(|ledger| ledger.get_transactions(start, length as usize))
}

#[cfg(not(feature = "get-blocks-disabled"))]
#[query]
#[candid_method(query)]
fn get_blocks(req: GetBlocksRequest) -> GetBlocksResponse {
    let (start, length) = req
        .as_start_and_length()
        .unwrap_or_else(|msg| ic_cdk::api::trap(&msg));
    Access::with_ledger(|ledger| ledger.get_blocks(start, length as usize))
}

#[query]
#[candid_method(query)]
fn get_data_certificate() -> DataCertificate {
    let hash_tree = Access::with_ledger(|ledger| ledger.construct_hash_tree());
    let mut tree_buf = vec![];
    ciborium::ser::into_writer(&hash_tree, &mut tree_buf).unwrap();
    DataCertificate {
        certificate: ic_cdk::api::data_certificate().map(ByteBuf::from),
        hash_tree: ByteBuf::from(tree_buf),
    }
}

#[update]
#[candid_method(update)]
async fn icrc2_approve(arg: ApproveArgs) -> Result<Nat, ApproveError> {
    let block_idx = Access::with_ledger_mut(|ledger| {
        let now = TimeStamp::from_nanos_since_unix_epoch(ic_cdk::api::time());

        let from_account = Account {
            owner: ic_cdk::api::caller(),
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

    // NB. we need to set the certified data before the first async call to make sure that the
    // blockchain state agrees with the certificate while archiving is in progress.
    ic_cdk::api::set_certified_data(&Access::with_ledger(Ledger::root_hash));

    archive_blocks::<Access>(&LOG, MAX_MESSAGE_SIZE).await;
    Ok(Nat::from(block_idx))
}

#[query]
#[candid_method(query)]
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
#[candid_method(query)]
fn icrc3_get_archives(args: GetArchivesArgs) -> GetArchivesResult {
    Access::with_ledger(|ledger| ledger.icrc3_get_archives(args))
}

#[query]
#[candid_method(query)]
fn icrc3_get_tip_certificate() -> Option<icrc_ledger_types::icrc3::blocks::ICRC3DataCertificate> {
    let certificate = ByteBuf::from(ic_cdk::api::data_certificate()?);
    let hash_tree = Access::with_ledger(|ledger| ledger.construct_hash_tree());
    let mut tree_buf = vec![];
    ciborium::ser::into_writer(&hash_tree, &mut tree_buf).unwrap();
    Some(icrc_ledger_types::icrc3::blocks::ICRC3DataCertificate {
        certificate,
        hash_tree: ByteBuf::from(tree_buf),
    })
}

#[query]
#[candid_method(query)]
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
#[candid_method(query)]
fn icrc3_get_blocks(args: Vec<GetBlocksRequest>) -> GetBlocksResult {
    Access::with_ledger(|ledger| ledger.icrc3_get_blocks(args))
}

#[query]
#[candid_method(query)]
fn icrc10_supported_standards() -> Vec<StandardRecord> {
    supported_standards()
}

#[update]
#[candid_method(update)]
fn icrc21_canister_call_consent_message(
    consent_msg_request: ConsentMessageRequest,
) -> Result<ConsentInfo, Icrc21Error> {
    let caller_principal = ic_cdk::api::caller();
    let ledger_fee = icrc1_fee();
    let token_symbol = icrc1_symbol();
    let decimals = icrc1_decimals();

    build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints(
        consent_msg_request,
        caller_principal,
        ledger_fee,
        token_symbol,
        decimals,
    )
}

candid::export_service!();

#[query]
fn __get_candid_interface_tmp_hack() -> String {
    __export_service()
}

fn main() {}

#[test]
fn check_candid_interface() {
    use candid_parser::utils::{service_equal, CandidSource};

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
