use dfn_candid::{candid_one, CandidOne};
use dfn_core::{
    api::{
        call_bytes_with_cleanup, call_with_cleanup, caller, data_certificate, set_certified_data,
        Funds,
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
    collections::{HashMap, HashSet, VecDeque},
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
/// * `archive_canister` - The canister that manages the store of old blocks.
/// * `max_message_size_bytes` - The maximum message size that this subnet
///   supports. This is used for egressing block to the archive canister.
fn init(
    minting_account: AccountIdentifier,
    initial_values: HashMap<AccountIdentifier, ICPTs>,
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
    transfer: Transfer,
    created_at_time: Option<TimeStamp>,
) -> (BlockHeight, HashOf<EncodedBlock>) {
    let (height, hash) = ledger_canister::add_payment(memo, transfer, created_at_time);
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
///   receiver disambiguate transactions
/// * `amount` - The number of ICPTs the recipient gets. The number of ICPTs
///   withdrawn is equal to the amount + the fee
/// * `fee` - The maximum fee that the sender is willing to pay. If the required
///   fee is greater than this the transaction will be rejected otherwise the
///   required fee will be paid. TODO(ROSETTA1-45): automatically pay a lower
///   fee if possible
/// * `from_subaccount` - The subaccount you want to draw funds from
/// * `to` - The account you want to send the funds to
/// * `to_subaccount` - The subaccount you want to send funds to
async fn send(
    memo: Memo,
    amount: ICPTs,
    fee: ICPTs,
    from_subaccount: Option<Subaccount>,
    to: AccountIdentifier,
    created_at_time: Option<TimeStamp>,
) -> BlockHeight {
    let caller_principal_id = caller();

    if !LEDGER.read().unwrap().can_send(&caller_principal_id) {
        panic!(
            "Sending from non-self-authenticating principal or non-whitelisted canister is not allowed: {}",
            caller_principal_id
        );
    }

    let from = AccountIdentifier::new(caller_principal_id, from_subaccount);
    let minting_acc = LEDGER
        .read()
        .unwrap()
        .minting_account_id
        .expect("Minting canister id not initialized");

    let transfer = if from == minting_acc {
        assert_eq!(fee, ICPTs::ZERO, "Fee for minting should be zero");
        assert_ne!(
            to, minting_acc,
            "It is illegal to mint to a minting_account"
        );
        Transfer::Mint { to, amount }
    } else if to == minting_acc {
        assert_eq!(fee, ICPTs::ZERO, "Fee for burning should be zero");
        if amount < MIN_BURN_AMOUNT {
            panic!("Burns lower than {} are not allowed", MIN_BURN_AMOUNT);
        }
        Transfer::Burn { from, amount }
    } else {
        if fee != TRANSACTION_FEE {
            panic!("Transaction fee should be {}", TRANSACTION_FEE);
        }
        Transfer::Send {
            from,
            to,
            amount,
            fee,
        }
    };
    let (height, _) = add_payment(memo, transfer, created_at_time);
    // Don't put anything that could ever trap after this call or people using this
    // endpoint. If something did panic the payment would appear to fail, but would
    // actually succeed on chain.
    archive_blocks().await;
    height
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
///   notification about
/// * `to_canister` - The canister that received the payment
/// * `to_subaccount` - The subaccount that received the payment
pub async fn notify(
    block_height: BlockHeight,
    max_fee: ICPTs,
    from_subaccount: Option<Subaccount>,
    to_canister: CanisterId,
    to_subaccount: Option<Subaccount>,
    notify_using_protobuf: bool,
) -> Result<BytesS, String> {
    let caller_principal_id = caller();

    if !LEDGER.read().unwrap().can_send(&caller_principal_id) {
        panic!(
            "Notifying from non-self-authenticating principal or non-whitelisted canister is not allowed: {}",
            caller_principal_id
        );
    }

    let expected_from = AccountIdentifier::new(caller_principal_id, from_subaccount);

    let expected_to = AccountIdentifier::new(to_canister.get(), to_subaccount);

    if max_fee != TRANSACTION_FEE {
        panic!("Transaction fee should be {}", TRANSACTION_FEE);
    }

    // This transaction provides and on chain record that a notification was
    // attempted
    let transfer = Transfer::Send {
        from: expected_from,
        to: expected_to,
        amount: ICPTs::ZERO,
        fee: max_fee,
    };

    // While this payment has been made here, it isn't actually committed until you
    // make an inter canister call. As such we don't reject without rollback until
    // an inter-canister call has definitely been made
    add_payment(Memo(block_height), transfer, None);

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

    let (from, to, amount) = match block.transaction().transfer {
        Transfer::Send {
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
    // Don't panic after here or the notification may be locked like it succeeded
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
        match state.blockchain.get(block_index).cloned() {
            // Block in the ledger
            Some(block) => Some(Ok(block)),
            // Not in the ledger and not in the archive. Thus, does not exist
            None => None,
        }
    }
}

/// Get an account balance.
/// If the account does not exist it will return 0 ICPTs
fn account_balance(account: AccountIdentifier) -> ICPTs {
    LEDGER.read().unwrap().balances.account_balance(&account)
}

/// The total number of ICPTs not inside the minting canister
fn total_supply() -> ICPTs {
    LEDGER.read().unwrap().balances.total_supply()
}

/// Start and upgrade methods
#[export_name = "canister_init"]
fn main() {
    over_init(
        |CandidOne(LedgerCanisterInitPayload {
             minting_account,
             initial_values,
             max_message_size_bytes,
             transaction_window,
             archive_options,
             send_whitelist,
         })| {
            init(
                minting_account,
                initial_values,
                max_message_size_bytes,
                transaction_window,
                archive_options,
                send_whitelist,
            )
        },
    )
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    over_init(|_: BytesS| {
        let bytes = stable::get();
        let mut ledger = LEDGER.write().unwrap();
        *ledger = serde_cbor::from_slice(&bytes).expect("Decoding stable memory failed");

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
    setup::START.call_once(|| {
        printer::hook();
    });

    let ledger = LEDGER
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let bytes = serde_cbor::to_vec(&*ledger).unwrap();
    stable::set(&bytes);
}

/// Upon reaching a `trigger_threshold` we will archive `num_blocks`.
/// This really should be an action on the ledger canister, but since we don't
/// want to hold a mutable lock on the whole ledger while we're archiving, we
/// split this method up into the parts that require async (this function) and
/// the parts that require a lock (Ledger::archive_blocks).
async fn archive_blocks() {
    let (mut blocks_to_archive, archive) = {
        let mut state = LEDGER
            .try_write()
            .expect("Failed to get a lock on the ledger");

        match state.archive_blocks() {
            Some((bta, lock)) => (bta, lock),
            None => return,
        }
    };
    // ^ Drop the write lock on the ledger

    while !blocks_to_archive.is_empty() {
        let chunk = get_chain_prefix(
            &mut blocks_to_archive,
            *MAX_MESSAGE_SIZE_BYTES.read().unwrap(),
        );
        assert!(!chunk.is_empty());

        print(format!(
            "[ledger] archiving a chunk of blocks of size {}",
            chunk.len(),
        ));

        let chunk = VecDeque::from(chunk);

        if let Err(FailedToArchiveBlocks(err)) = archive
            .try_write()
            .expect("Failed to get write lock on archive")
            .as_mut()
            .expect("Archiving is not enabled")
            .archive_blocks(chunk.clone())
            .await
        {
            print(format!(
                "[ledger] Failed to archive {} blocks with error {}",
                chunk.len(),
                err
            ));
            // We're in real trouble if we can't acquire this lock
            let blockchain = &mut LEDGER
                .try_write()
                .expect("Failed to get a lock on the ledger")
                .blockchain;

            // Revert the change to the index of blocks not on this canister that was made
            // in archive_blocks
            blockchain.sub_num_archived_blocks(chunk.len() as u64);
            // Add the blocks back to the local blockchain
            recover_from_failed_archive(&mut blockchain.blocks, blocks_to_archive, chunk);
            return;
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
         }| { send(memo, amount, fee, from_subaccount, to, created_at_time) },
    );
}

/// Do not use call this from code, this is only here so dfx has something to
/// call when making a payment. This will be changed in ways that are not
/// backwards compatible with previous interfaces.
///
/// I STRONGLY recommend that you use "send_pb" instead.
#[export_name = "canister_update send_dfx"]
fn send_dfx_() {
    over_async(
        candid_one,
        |SendArgs {
             memo,
             amount,
             fee,
             from_subaccount,
             to,
             created_at_time,
         }| { send(memo, amount, fee, from_subaccount, to, created_at_time) },
    );
}

#[export_name = "canister_update notify_pb"]
fn notify_() {
    // we use over_init because it doesn't reply automatically so we can do explicit
    // replys in the callback
    over_async_may_reject_explicit(
        |ProtoBuf(NotifyCanisterArgs {
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
                true,
            )
        },
    );
}

/// See caveats of use on send_dfx
#[export_name = "canister_update notify_dfx"]
fn notify_dfx_() {
    // we use over_init because it doesn't reply automatically so we can do explicit
    // replys in the callback
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

/// See caveats of use on send_dfx
#[export_name = "canister_query account_balance_dfx"]
fn account_balance_dfx_() {
    over(candid_one, |AccountBalanceArgs { account }| {
        account_balance(account)
    })
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
        ledger_canister::iter_blocks(&blocks, start, length)
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
    over(dfn_candid::candid, |()| -> Vec<CanisterId> {
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
        "archive_node_stable_memory_pages",
        dfn_core::api::stable_memory_size_in_pages() as f64,
        "The size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;

    w.encode_gauge(
        "ledger_transactions_by_hash_cache_size",
        ledger.transactions_by_hash_len() as f64,
        "The total number of entries in the transactions_by_hash cache.",
    )?;
    w.encode_gauge(
        "ledger_transactions_by_height_size",
        ledger.transactions_by_height_len() as f64,
        "The total number of entries in the transaction_by_height queue.",
    )?;
    w.encode_gauge(
        "ledger_blocks_notified_total",
        ledger.transactions_by_height_len() as f64,
        "The total number of blockheights that have been notified.",
    )?;
    w.encode_gauge(
        "ledger_blocks_count",
        ledger.blockchain.blocks.len() as f64,
        "The total number of blocks stored in the main memory.",
    )?;
    w.encode_gauge(
        "ledger_archived_blocks_count",
        ledger.blockchain.num_archived_blocks as f64,
        "The total number of blocks sent the archive.",
    )?;
    w.encode_gauge(
        "ledger_archive_locked",
        ledger.blockchain.archive.try_read().map(|_| 0).unwrap_or(1) as f64,
        "Whether the archiving is in process.",
    )?;
    w.encode_gauge(
        "ledger_balances_icpt_pool_total",
        ledger.balances.icpt_pool.get_icpts() as f64,
        "The total number of ICPTs in the pool.",
    )?;
    w.encode_gauge(
        "ledger_balance_store_size",
        ledger.balances.store.len() as f64,
        "The total number of accounts in the balance store.",
    )?;
    w.encode_gauge(
        "ledger_most_recent_block_timestamp",
        ledger.blockchain.last_timestamp.timestamp_nanos as f64,
        "The IC timestamp (in nanoseconds) of the most recent block.",
    )?;
    Ok(())
}

#[export_name = "canister_query http_request"]
fn http_request() {
    ledger_canister::http_request::serve_metrics(encode_metrics);
}
