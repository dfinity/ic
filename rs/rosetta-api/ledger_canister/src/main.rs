use candid::candid_method;
use dfn_candid::{candid, candid_one, CandidOne};
use dfn_core::{
    api::{
        call_bytes_with_cleanup, call_with_cleanup, caller, data_certificate, set_certified_data,
        trap_with, Funds,
    },
    endpoint::over_async_may_reject_explicit,
    over, over_async, over_init, printer, setup, stable, BytesS,
};
use dfn_protobuf::{protobuf, ProtoBuf};
use ic_types::CanisterId;
use ledger_canister::*;
use on_wire::IntoWire;
use std::time::Duration;

use archive::FailedToArchiveBlocks;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

// Helper to print messages in magenta
fn print<S: std::convert::AsRef<str>>(s: S)
where
    yansi::Paint<S>: std::string::ToString,
{
    dfn_core::api::print(yansi::Paint::magenta(s).to_string());
}

/// Initialize the ledger canister
///
/// # Arguments
///
/// * `minting_account` -  The minting canister is given 2^64 - 1 tokens and it
///   then transfers tokens to addresses specified in the initial state.
///   Currently this is the only way to create tokens.
/// * `initial_values` - The list of accounts that will get balances at genesis.
///   This balances are paid out from the minting canister using 'Send'
///   transfers.
/// * `max_message_size_bytes` - The maximum message size that this subnet
/// * `transaction_window` - The [Ledger] transaction window.
/// * `archive_options` - The options of the canister that manages the store of
///   old blocks.
/// * `send_whitelist` - The [Ledger] canister whitelist.
fn init(
    minting_account: AccountIdentifier,
    initial_values: HashMap<AccountIdentifier, Tokens>,
    max_message_size_bytes: Option<usize>,
    transaction_window: Option<Duration>,
    archive_options: Option<archive::ArchiveOptions>,
    send_whitelist: HashSet<CanisterId>,
) {
    print(format!(
        "[ledger] init(): minting account is {}",
        minting_account
    ));
    LEDGER.write().unwrap().from_init(
        initial_values,
        minting_account,
        dfn_core::api::now().into(),
        transaction_window,
        send_whitelist,
    );
    match max_message_size_bytes {
        None => {
            print(format!(
                "[ledger] init(): using default maximum message size: {}",
                MAX_MESSAGE_SIZE_BYTES.read().unwrap()
            ));
        }
        Some(max_message_size_bytes) => {
            *MAX_MESSAGE_SIZE_BYTES.write().unwrap() = max_message_size_bytes;
            print(format!(
                "[ledger] init(): using maximum message size: {}",
                max_message_size_bytes
            ));
        }
    }
    set_certified_data(
        &LEDGER
            .read()
            .unwrap()
            .blockchain
            .last_hash
            .map(|h| h.into_bytes())
            .unwrap_or([0u8; 32]),
    );

    if let Some(archive_options) = archive_options {
        LEDGER.write().unwrap().blockchain.archive =
            Arc::new(RwLock::new(Some(archive::Archive::new(archive_options))))
    }
}

fn add_payment(
    memo: Memo,
    operation: Operation,
    created_at_time: Option<TimeStamp>,
) -> (BlockHeight, HashOf<EncodedBlock>) {
    let (height, hash) = ledger_canister::add_payment(memo, operation, created_at_time);
    set_certified_data(&hash.into_bytes());
    (height, hash)
}

/// This is the only operation that changes the state of the canister blocks and
/// balances after init. This creates a payment from the caller's account. It
/// returns the index of the resulting transaction
///
/// # Arguments
///
/// * `memo` -  A 8 byte "message" you can attach to transactions to help the
///   receiver disambiguate transactions.
/// * `amount` - The number of Tokens the recipient gets. The number of Tokens
///   withdrawn is equal to the amount + the fee.
/// * `fee` - The maximum fee that the sender is willing to pay. If the required
///   fee is greater than this the transaction will be rejected otherwise the
///   required fee will be paid. TODO(ROSETTA1-45): automatically pay a lower
///   fee if possible.
/// * `from_subaccount` - The subaccount you want to draw funds from.
/// * `to` - The account you want to send the funds to.
/// * `created_at_time`: When the transaction has been created. If not set then
///   now is used.
async fn send(
    memo: Memo,
    amount: Tokens,
    fee: Tokens,
    from_subaccount: Option<Subaccount>,
    to: AccountIdentifier,
    created_at_time: Option<TimeStamp>,
) -> Result<BlockHeight, TransferError> {
    let caller_principal_id = caller();

    if !LEDGER.read().unwrap().can_send(&caller_principal_id) {
        panic!("Sending from {} is not allowed", caller_principal_id);
    }

    let from = AccountIdentifier::new(caller_principal_id, from_subaccount);
    let minting_acc = LEDGER
        .read()
        .unwrap()
        .minting_account_id
        .expect("Minting canister id not initialized");

    let transfer = if from == minting_acc {
        assert_eq!(fee, Tokens::ZERO, "Fee for minting should be zero");
        assert_ne!(
            to, minting_acc,
            "It is illegal to mint to a minting_account"
        );
        Operation::Mint { to, amount }
    } else if to == minting_acc {
        assert_eq!(fee, Tokens::ZERO, "Fee for burning should be zero");
        if amount < MIN_BURN_AMOUNT {
            panic!("Burns lower than {} are not allowed", MIN_BURN_AMOUNT);
        }
        Operation::Burn { from, amount }
    } else {
        if fee != TRANSACTION_FEE {
            return Err(TransferError::BadFee {
                expected_fee: TRANSACTION_FEE,
            });
        }
        Operation::Transfer {
            from,
            to,
            amount,
            fee,
        }
    };
    let (height, hash) = LEDGER
        .write()
        .unwrap()
        .add_payment(memo, transfer, created_at_time)?;
    set_certified_data(&hash.into_bytes());

    // Don't put anything that could ever trap after this call or people using this
    // endpoint. If something did panic the payment would appear to fail, but would
    // actually succeed on chain.
    archive_blocks().await;
    Ok(height)
}

/// You can notify a canister that you have made a payment to it. The
/// payment must have been made to the account of a canister and from the
/// callers account. You cannot notify a canister about a transaction it has
/// already been successfully notified of. If the canister rejects the
/// notification call it is not considered to have been notified.
///
/// # Arguments
///
/// * `block_height` -  The height of the block you would like to send a
///   notification about.
/// * `max_fee` - The fee of the payment.
/// * `from_subaccount` - The subaccount that made the payment.
/// * `to_canister` - The canister that received the payment.
/// * `to_subaccount` - The subaccount that received the payment.
/// * `notify_using_protobuf` - Whether the notification should be encoded using
///   protobuf or candid.
pub async fn notify(
    block_height: BlockHeight,
    max_fee: Tokens,
    from_subaccount: Option<Subaccount>,
    to_canister: CanisterId,
    to_subaccount: Option<Subaccount>,
    notify_using_protobuf: bool,
) -> Result<BytesS, String> {
    let caller_principal_id = caller();

    if !LEDGER.read().unwrap().can_send(&caller_principal_id) {
        panic!("Notifying from {} is not allowed", caller_principal_id);
    }

    if !LEDGER.read().unwrap().can_be_notified(&to_canister) {
        panic!(
            "Notifying non-whitelisted canister is not allowed: {}",
            to_canister
        );
    }

    let expected_from = AccountIdentifier::new(caller_principal_id, from_subaccount);

    let expected_to = AccountIdentifier::new(to_canister.get(), to_subaccount);

    if max_fee != TRANSACTION_FEE {
        panic!("Transaction fee should be {}", TRANSACTION_FEE);
    }

    let raw_block: EncodedBlock =
        match block(block_height).unwrap_or_else(|| panic!("Block {} not found", block_height)) {
            Ok(raw_block) => raw_block,
            Err(cid) => {
                print(format!(
                    "Searching canister {} for block {}",
                    cid, block_height
                ));
                // Lookup the block on the archive
                let BlockRes(res) = call_with_cleanup(cid, "get_block_pb", protobuf, block_height)
                    .await
                    .map_err(|e| format!("Failed to fetch block {}", e.1))?;
                res.ok_or("Block not found")?
                    .map_err(|c| format!("Tried to redirect lookup a second time to {}", c))?
            }
        };

    let block = raw_block.decode().unwrap();

    let (from, to, amount) = match block.transaction().operation {
        Operation::Transfer {
            from, to, amount, ..
        } => (from, to, amount),
        _ => panic!("Notification failed transfer must be of type send"),
    };

    assert_eq!(
        (from, to),
        (expected_from, expected_to),
        "sender and recipient must match the specified block"
    );

    let transaction_notification_args = TransactionNotification {
        from: caller_principal_id,
        from_subaccount,
        to: to_canister,
        to_subaccount,
        block_height,
        amount,
        memo: block.transaction().memo,
    };

    let block_timestamp = block.timestamp();

    change_notification_state(block_height, block_timestamp, true).expect("Notification failed");

    // This transaction provides an on chain record that a notification was
    // attempted
    let transfer = Operation::Transfer {
        from: expected_from,
        to: expected_to,
        amount: Tokens::ZERO,
        fee: max_fee,
    };

    // While this payment has been made here, it isn't actually committed until you
    // make an inter canister call. As such we don't reject without rollback until
    // an inter-canister call has definitely been made
    add_payment(Memo(block_height), transfer, None);

    let response = if notify_using_protobuf {
        let bytes = ProtoBuf(transaction_notification_args)
            .into_bytes()
            .expect("transaction notification serialization failed");
        call_bytes_with_cleanup(
            to_canister,
            "transaction_notification_pb",
            &bytes[..],
            Funds::zero(),
        )
        .await
    } else {
        let bytes = candid::encode_one(transaction_notification_args)
            .expect("transaction notification serialization failed");
        call_bytes_with_cleanup(
            to_canister,
            "transaction_notification",
            &bytes[..],
            Funds::zero(),
        )
        .await
    };
    // Don't panic after here or the notification might look like it succeeded
    // when actually it failed

    // propagate the response/rejection from 'to_canister' if it's shorter than this
    // length.
    // This could be done better because we still read in the whole
    // String/Vec as is
    pub const MAX_LENGTH: usize = 8192;

    match response {
        Ok(bs) => {
            if bs.len() > MAX_LENGTH {
                let caller = caller();
                Err(format!(
                    "Notification succeeded, but the canister '{}' returned too large of a response",
                    caller,
                ))
            } else {
                Ok(BytesS(bs))
            }
        }
        Err((_code, err)) => {
            // It may be that by the time this callback is made the block will have been
            // garbage collected. That is fine because we don't inspect the
            // response here.
            let _ = change_notification_state(block_height, block_timestamp, false);
            if err.len() > MAX_LENGTH {
                let caller = caller();
                Err(format!(
                    "Notification failed, but the canister '{}' returned too large of a response",
                    caller,
                ))
            } else {
                Err(format!("Notification failed with message '{}'", err))
            }
        }
    }
}

/// This gives you the index of the last block added to the chain
/// together with certification
fn tip_of_chain() -> TipOfChainRes {
    let last_block_idx = &LEDGER
        .read()
        .unwrap()
        .blockchain
        .chain_length()
        .checked_sub(1)
        .unwrap();
    let certification = data_certificate();
    TipOfChainRes {
        certification,
        tip_index: *last_block_idx,
    }
}

// This is going away and being replaced by getblocks
fn block(block_index: BlockHeight) -> Option<Result<EncodedBlock, CanisterId>> {
    let state = LEDGER.read().unwrap();
    if block_index < state.blockchain.num_archived_blocks() {
        // The block we are looking for better be in the archive because it has
        // a height smaller than the number of blocks we've archived so far
        let result = state
            .find_block_in_archive(block_index)
            .expect("block not found in the archive");
        Some(Err(result))
    // Or the block may be in the ledger, or the block may not exist
    } else {
        print(format!(
            "[ledger] Checking the ledger for block [{}]",
            block_index
        ));
        state.blockchain.get(block_index).cloned().map(Ok)
    }
}

/// Get an account balance.
/// If the account does not exist it will return 0 Tokens
fn account_balance(account: AccountIdentifier) -> Tokens {
    LEDGER.read().unwrap().balances.account_balance(&account)
}

/// The total number of Tokens not inside the minting canister
fn total_supply() -> Tokens {
    LEDGER.read().unwrap().balances.total_supply()
}

#[candid_method(init)]
fn canister_init(arg: LedgerCanisterInitPayload) {
    init(
        arg.minting_account,
        arg.initial_values,
        arg.max_message_size_bytes,
        arg.transaction_window,
        arg.archive_options,
        arg.send_whitelist,
    )
}

#[export_name = "canister_init"]
fn main() {
    over_init(|CandidOne(arg)| canister_init(arg))
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        let mut ledger = LEDGER.write().unwrap();
        *ledger = serde_cbor::from_reader(&mut stable::StableReader::new())
            .expect("Decoding stable memory failed");

        set_certified_data(
            &ledger
                .blockchain
                .last_hash
                .map(|h| h.into_bytes())
                .unwrap_or([0u8; 32]),
        );
    })
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    use std::io::Write;

    setup::START.call_once(|| {
        printer::hook();
    });

    let ledger = LEDGER
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut writer = stable::StableWriter::new();
    serde_cbor::to_writer(&mut writer, &*ledger).unwrap();
    writer
        .flush()
        .expect("failed to flush stable memory writer");
}

/// Upon reaching a `trigger_threshold` we will archive `num_blocks`.
/// This really should be an action on the ledger canister, but since we don't
/// want to hold a mutable lock on the whole ledger while we're archiving, we
/// split this method up into the parts that require async (this function) and
/// the parts that require a lock (Ledger::get_blocks_for_archiving).
async fn archive_blocks() {
    let ledger_guard = LEDGER.try_read().expect("Failed to get ledger read lock");
    let archive_arc = ledger_guard.blockchain.archive.clone();
    let mut archive_guard = match archive_arc.try_write() {
        Ok(g) => g,
        Err(_) => {
            print("Ledger is currently archiving. Skipping archive_blocks()");
            return;
        }
    };
    if archive_guard.is_none() {
        return; // Archiving not enabled
    }
    let archive = archive_guard.as_mut().unwrap();

    let blocks_to_archive = ledger_guard
        .get_blocks_for_archiving(archive.trigger_threshold, archive.num_blocks_to_archive);
    if blocks_to_archive.is_empty() {
        return;
    }

    drop(ledger_guard); // Drop the lock on the ledger

    let num_blocks = blocks_to_archive.len();
    print(format!("[ledger] archiving {} blocks", num_blocks,));

    let max_msg_size = *MAX_MESSAGE_SIZE_BYTES.read().unwrap();
    let res = archive
        .send_blocks_to_archive(blocks_to_archive, max_msg_size)
        .await;

    let mut ledger = LEDGER.try_write().expect("Failed to get ledger write lock");
    match res {
        Ok(num_sent_blocks) => ledger.remove_archived_blocks(num_sent_blocks),
        Err((num_sent_blocks, FailedToArchiveBlocks(err))) => {
            ledger.remove_archived_blocks(num_sent_blocks);
            print(format!(
                "[ledger] Archiving failed. Archived {} out of {} blocks. Error {}",
                num_sent_blocks, num_blocks, err
            ));
        }
    }
}

/// Canister endpoints
#[export_name = "canister_update send_pb"]
fn send_() {
    over_async(
        protobuf,
        |SendArgs {
             memo,
             amount,
             fee,
             from_subaccount,
             to,
             created_at_time,
         }| async move {
            send(memo, amount, fee, from_subaccount, to, created_at_time)
                .await
                .unwrap_or_else(|e| {
                    trap_with(&e.to_string());
                    unreachable!()
                })
        },
    );
}

#[candid_method(update, rename = "send_dfx")]
async fn send_dfx(arg: SendArgs) -> BlockHeight {
    transfer_candid(arg.into()).await.unwrap()
}

/// Do not use call this from code, this is only here so dfx has something to
/// call when making a payment. This will be changed in ways that are not
/// backwards compatible with previous interfaces.
///
/// I STRONGLY recommend that you use "send_pb" instead.
#[export_name = "canister_update send_dfx"]
fn send_dfx_() {
    over_async(candid_one, send_dfx);
}

#[export_name = "canister_update notify_pb"]
fn notify_() {
    // we use over_init because it doesn't reply automatically so we can do explicit
    // replies in the callback
    over_async_may_reject_explicit(
        |ProtoBuf(NotifyCanisterArgs {
             block_height,
             max_fee,
             from_subaccount,
             to_canister,
             to_subaccount,
         })| async move {
            notify(
                block_height,
                max_fee,
                from_subaccount,
                to_canister,
                to_subaccount,
                true,
            )
            .await
        },
    );
}

#[candid_method(update, rename = "transfer")]
async fn transfer_candid(arg: TransferArgs) -> Result<BlockHeight, TransferError> {
    let to_account = AccountIdentifier::from_address(arg.to).unwrap_or_else(|e| {
        trap_with(&format!("Invalid account identifier: {}", e));
        unreachable!()
    });
    send(
        arg.memo,
        arg.amount,
        arg.fee,
        arg.from_subaccount,
        to_account,
        arg.created_at_time,
    )
    .await
}

#[export_name = "canister_update transfer"]
fn transfer() {
    over_async(candid_one, transfer_candid)
}

/// See caveats of use on send_dfx
#[export_name = "canister_update notify_dfx"]
fn notify_dfx_() {
    // we use over_init because it doesn't reply automatically so we can do explicit
    // replies in the callback
    over_async_may_reject_explicit(
        |CandidOne(NotifyCanisterArgs {
             block_height,
             max_fee,
             from_subaccount,
             to_canister,
             to_subaccount,
         })| {
            notify(
                block_height,
                max_fee,
                from_subaccount,
                to_canister,
                to_subaccount,
                false,
            )
        },
    );
}

#[export_name = "canister_query block_pb"]
fn block_() {
    over(protobuf, |BlockArg(height)| BlockRes(block(height)));
}

#[export_name = "canister_query tip_of_chain_pb"]
fn tip_of_chain_() {
    over(protobuf, |protobuf::TipOfChainRequest {}| tip_of_chain());
}

#[export_name = "canister_query get_archive_index_pb"]
fn get_archive_index_() {
    over(protobuf, |()| {
        let state = LEDGER.read().unwrap();
        let entries = match &state
            .blockchain
            .archive
            .try_read()
            .expect("Failed to get lock on archive")
            .as_ref()
        {
            None => vec![],
            Some(archive) => archive
                .index()
                .into_iter()
                .map(
                    |((height_from, height_to), canister_id)| protobuf::ArchiveIndexEntry {
                        height_from,
                        height_to,
                        canister_id: Some(canister_id.get()),
                    },
                )
                .collect(),
        };
        protobuf::ArchiveIndexResponse { entries }
    });
}

#[export_name = "canister_query account_balance_pb"]
fn account_balance_() {
    over(protobuf, |AccountBalanceArgs { account }| {
        account_balance(account)
    })
}

#[candid_method(query, rename = "account_balance")]
fn account_balance_candid_(arg: BinaryAccountBalanceArgs) -> Tokens {
    let account = AccountIdentifier::from_address(arg.account).unwrap_or_else(|e| {
        trap_with(&format!("Invalid account identifier: {}", e));
        unreachable!()
    });
    account_balance(account)
}

#[export_name = "canister_query account_balance"]
fn account_balance_candid() {
    over(candid_one, account_balance_candid_)
}

#[candid_method(query, rename = "account_balance_dfx")]
fn account_balance_dfx_(args: AccountBalanceArgs) -> Tokens {
    account_balance(args.account)
}

/// See caveats of use on send_dfx
#[export_name = "canister_query account_balance_dfx"]
fn account_balance_dfx() {
    over(candid_one, account_balance_dfx_);
}

#[export_name = "canister_query total_supply_pb"]
fn total_supply_() {
    over(protobuf, |_: TotalSupplyArgs| total_supply())
}

/// Get multiple blocks by *offset into the container* (not BlockHeight) and
/// length. Note that this simply iterates the blocks available in the Ledger
/// without taking into account the archive. For example, if the ledger contains
/// blocks with heights [100, 199] then iter_blocks(0, 1) will return the block
/// with height 100.
#[export_name = "canister_query iter_blocks_pb"]
fn iter_blocks_() {
    over(protobuf, |IterBlocksArgs { start, length }| {
        let blocks = &LEDGER.read().unwrap().blockchain.blocks;
        ledger_canister::iter_blocks(blocks, start, length)
    });
}

/// Get multiple blocks by BlockHeight and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_blocks_pb"]
fn get_blocks_() {
    over(protobuf, |GetBlocksArgs { start, length }| {
        let blockchain: &Blockchain = &LEDGER.read().unwrap().blockchain;
        let start_offset = blockchain.num_archived_blocks();
        ledger_canister::get_blocks(&blockchain.blocks, start_offset, start, length)
    });
}

#[export_name = "canister_query get_nodes"]
fn get_nodes_() {
    over(candid, |()| -> Vec<CanisterId> {
        LEDGER
            .read()
            .unwrap()
            .blockchain
            .archive
            .try_read()
            .expect("Failed to get lock on archive")
            .as_ref()
            .map(|archive| archive.nodes().to_vec())
            .unwrap_or_default()
    });
}

fn encode_metrics(w: &mut metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let ledger = LEDGER.try_read().map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to get a LEDGER for read: {}", err),
        )
    })?;

    w.encode_gauge(
        "ledger_max_message_size_bytes",
        *MAX_MESSAGE_SIZE_BYTES.read().unwrap() as f64,
        "Maximum inter-canister message size in bytes.",
    )?;
    w.encode_gauge(
        "ledger_stable_memory_pages",
        dfn_core::api::stable_memory_size_in_pages() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "ledger_stable_memory_bytes",
        (dfn_core::api::stable_memory_size_in_pages() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister.",
    )?;
    w.encode_gauge(
        "ledger_transactions_by_hash_cache_entries",
        ledger.transactions_by_hash_len() as f64,
        "Total number of entries in the transactions_by_hash cache.",
    )?;
    w.encode_gauge(
        "ledger_transactions_by_height_entries",
        ledger.transactions_by_height_len() as f64,
        "Total number of entries in the transaction_by_height queue.",
    )?;
    w.encode_gauge(
        "ledger_blocks",
        ledger.blockchain.blocks.len() as f64,
        "Total number of blocks stored in the main memory.",
    )?;
    // This value can go down -- the number is increased before archiving, and if
    // archiving fails it is decremented.
    w.encode_gauge(
        "ledger_archived_blocks",
        ledger.blockchain.num_archived_blocks as f64,
        "Total number of blocks sent to the archive.",
    )?;
    w.encode_gauge(
        "ledger_balances_token_pool",
        ledger.balances.token_pool.get_tokens() as f64,
        "Total number of Tokens in the pool.",
    )?;
    w.encode_gauge(
        "ledger_balance_store_entries",
        ledger.balances.store.len() as f64,
        "Total number of accounts in the balance store.",
    )?;
    w.encode_gauge(
        "ledger_most_recent_block_time_seconds",
        ledger.blockchain.last_timestamp.timestamp_nanos as f64 / 1_000_000_000.0,
        "IC timestamp of the most recent block.",
    )?;
    Ok(())
}

#[export_name = "canister_query http_request"]
fn http_request() {
    ledger_canister::http_request::serve_metrics(encode_metrics);
}

#[test]
fn check_candid_interface_compatibility() {
    use candid::types::subtype::{subtype, Gamma};
    use candid::types::Type;
    use std::io::Write;
    use std::path::PathBuf;

    candid::export_service!();

    let actual_interface = __export_service();
    println!("Generated DID:\n {}", actual_interface);
    let mut tmp = tempfile::NamedTempFile::new().expect("failed to create a temporary file");
    write!(tmp, "{}", actual_interface).expect("failed to write interface to a temporary file");
    let (mut env1, t1) =
        candid::pretty_check_file(tmp.path()).expect("failed to check generated candid file");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ledger.did");
    let (env2, t2) =
        candid::pretty_check_file(path.as_path()).expect("failed to open ledger.did file");

    let (t1_ref, t2) = match (t1.as_ref().unwrap(), t2.unwrap()) {
        (Type::Class(_, s1), Type::Class(_, s2)) => (s1.as_ref(), *s2),
        (Type::Class(_, s1), s2 @ Type::Service(_)) => (s1.as_ref(), s2),
        (s1 @ Type::Service(_), Type::Class(_, s2)) => (s1, *s2),
        (t1, t2) => (t1, t2),
    };

    let mut gamma = Gamma::new();
    let t2 = env1.merge_type(env2, t2);
    subtype(&mut gamma, &env1, t1_ref, &t2)
        .expect("ledger canister interface is not compatible with the ledger.did file");
}
