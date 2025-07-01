#[cfg(feature = "canbench-rs")]
mod canbench;

#[cfg(not(feature = "canbench-rs"))]
use candid::Decode;
use candid::{candid_method, Nat, Principal};
#[cfg(feature = "notify-method")]
use dfn_candid::CandidOne;
#[cfg(feature = "notify-method")]
use dfn_core::BytesS;
#[cfg(feature = "notify-method")]
use dfn_protobuf::protobuf;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::{LogEntry, Sink};
use ic_cdk::api::{
    call::{arg_data_raw, reply_raw},
    caller, data_certificate, instruction_counter, print, set_certified_data, time, trap,
};
use ic_cdk::{post_upgrade, pre_upgrade, query, update};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_icrc1::endpoints::{convert_transfer_error, StandardRecord};
use ic_ledger_canister_core::ledger::LedgerContext;
use ic_ledger_canister_core::runtime::heap_memory_size_bytes;
use ic_ledger_canister_core::{
    archive::{Archive, ArchiveOptions},
    ledger::{
        apply_transaction, archive_blocks, block_locations, find_block_in_archive, LedgerAccess,
        TransferError as CoreTransferError,
    },
    range_utils,
};
use ic_ledger_core::{
    block::{BlockIndex, BlockType, EncodedBlock},
    timestamp::TimeStamp,
    tokens::{Tokens, DECIMAL_PLACES},
};
use ic_stable_structures::reader::{BufferedReader, Reader};
use ic_stable_structures::writer::{BufferedWriter, Writer};
#[cfg(feature = "notify-method")]
use icp_ledger::BlockRes;
#[cfg(feature = "icp-allowance-getter")]
use icp_ledger::IcpAllowanceArgs;
#[cfg(not(feature = "canbench-rs"))]
use icp_ledger::InitArgs;
use icp_ledger::{
    from_proto_bytes, max_blocks_per_request, protobuf, to_proto_bytes, tokens_into_proto,
    AccountBalanceArgs, AccountIdBlob, AccountIdentifier, AccountIdentifierByteBuf, Allowances,
    ArchiveInfo, ArchivedBlocksRange, ArchivedEncodedBlocksRange, Archives,
    BinaryAccountBalanceArgs, Block, BlockArg, CandidBlock, Decimals, FeatureFlags,
    GetAllowancesArgs, GetBlocksArgs, GetBlocksRes, IterBlocksArgs, IterBlocksRes,
    LedgerCanisterPayload, Memo, Name, Operation, PaymentError, QueryBlocksResponse,
    QueryEncodedBlocksResponse, SendArgs, Subaccount, Symbol, TipOfChainRes, TotalSupplyArgs,
    Transaction, TransferArgs, TransferError, TransferFee, TransferFeeArgs, MEMO_SIZE_BYTES,
};
use icrc_ledger_types::icrc1::transfer::TransferError as Icrc1TransferError;
use icrc_ledger_types::icrc2::allowance::{Allowance, AllowanceArgs};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue as Value,
    icrc21::lib::build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints,
    icrc3::archive::QueryArchiveFn,
};
use icrc_ledger_types::{
    icrc1::account::Account, icrc2::transfer_from::TransferFromArgs,
    icrc2::transfer_from::TransferFromError,
};
use icrc_ledger_types::{
    icrc1::transfer::TransferArg,
    icrc21::{errors::Icrc21Error, requests::ConsentMessageRequest, responses::ConsentInfo},
};
use ledger_canister::{
    balances_len, get_allowances_list, Ledger, LEDGER, LEDGER_VERSION, MAX_MESSAGE_SIZE_BYTES,
    UPGRADES_MEMORY,
};
use num_traits::cast::ToPrimitive;
#[allow(unused_imports)]
use on_wire::IntoWire;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Duration,
};

#[derive(Clone)]
struct DebugOutSink;

impl Sink for DebugOutSink {
    fn append(&self, entry: LogEntry) {
        print!("{}", entry.message)
    }
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
/// * `transfer_fee` - The fee to pay to perform a transaction.
/// * `token_symbol` - Token symbol.
/// * `token_name` - Token name.
/// * `feature_flags` - Features that are enabled on the ledger.
#[allow(clippy::too_many_arguments)]
fn init(
    minting_account: AccountIdentifier,
    icrc1_minting_account: Option<Account>,
    initial_values: HashMap<AccountIdentifier, Tokens>,
    max_message_size_bytes: Option<usize>,
    transaction_window: Option<Duration>,
    archive_options: Option<ArchiveOptions>,
    send_whitelist: HashSet<CanisterId>,
    transfer_fee: Option<Tokens>,
    token_symbol: Option<String>,
    token_name: Option<String>,
    feature_flags: Option<FeatureFlags>,
) {
    print(format!(
        "[ledger] init(): minting account is {}",
        minting_account
    ));
    LEDGER.write().unwrap().from_init(
        initial_values,
        minting_account,
        icrc1_minting_account,
        TimeStamp::from_nanos_since_unix_epoch(time()),
        transaction_window,
        send_whitelist,
        transfer_fee,
        token_symbol,
        token_name,
        feature_flags,
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
    #[cfg(not(feature = "canbench-rs"))]
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
            Arc::new(RwLock::new(Some(Archive::new(archive_options))))
    }
}

#[cfg(feature = "notify-method")]
fn add_payment(
    memo: Memo,
    operation: Operation,
    created_at_time: Option<TimeStamp>,
) -> (BlockIndex, ic_ledger_hash_of::HashOf<EncodedBlock>) {
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
///   required fee will be paid.
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
) -> Result<BlockIndex, TransferError> {
    let caller_principal_id = PrincipalId::from(caller());

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
        let min_burn_amount = LEDGER.read().unwrap().transfer_fee;
        if amount < min_burn_amount {
            panic!("Burns lower than {} are not allowed", min_burn_amount);
        }
        Operation::Burn {
            from,
            amount,
            spender: None,
        }
    } else {
        let transfer_fee = LEDGER.read().unwrap().transfer_fee;
        if fee != transfer_fee {
            return Err(TransferError::BadFee {
                expected_fee: transfer_fee,
            });
        }
        Operation::Transfer {
            from,
            to,
            spender: None,
            amount,
            fee,
        }
    };
    let (height, hash) = match LEDGER
        .write()
        .unwrap()
        .add_payment(memo, transfer, created_at_time)
    {
        Ok((height, hash)) => (height, hash),
        Err(PaymentError::TransferError(transfer_error)) => return Err(transfer_error),
        Err(PaymentError::Reject(msg)) => panic!("{}", msg),
    };
    set_certified_data(&hash.into_bytes());

    // Don't put anything that could ever trap after this call or people using this
    // endpoint. If something did panic the payment would appear to fail, but would
    // actually succeed on chain.
    let max_msg_size = *MAX_MESSAGE_SIZE_BYTES.read().unwrap();
    archive_blocks::<Access>(DebugOutSink, max_msg_size as u64).await;
    Ok(height)
}

fn icrc1_send_not_async(
    memo: Option<icrc_ledger_types::icrc1::transfer::Memo>,
    amount: Nat,
    fee: Option<Nat>,
    from_account: Account,
    to_account: Account,
    spender_account: Option<Account>,
    created_at_time: Option<u64>,
) -> Result<BlockIndex, CoreTransferError<Tokens>> {
    let from = AccountIdentifier::from(from_account);
    let to = AccountIdentifier::from(to_account);
    match memo.as_ref() {
        Some(memo) if memo.0.len() > MEMO_SIZE_BYTES => trap("the memo field is too large"),
        _ => {}
    };
    let amount = match amount.0.to_u64() {
        Some(n) => Tokens::from_e8s(n),
        None => {
            // No one can have so many tokens
            let balance = account_balance(from);
            assert!(balance.get_e8s() < amount);
            return Err(CoreTransferError::InsufficientFunds { balance });
        }
    };
    let created_at_time = created_at_time.map(TimeStamp::from_nanos_since_unix_epoch);
    let minting_acc = LEDGER
        .read()
        .unwrap()
        .minting_account_id
        .expect("Minting canister id not initialized");
    let now = TimeStamp::from_nanos_since_unix_epoch(time());
    let (operation, effective_fee) = if to == minting_acc {
        if fee.is_some() && fee.as_ref() != Some(&Nat::from(0u64)) {
            return Err(CoreTransferError::BadFee {
                expected_fee: Tokens::ZERO,
            });
        }
        let ledger = LEDGER.read().unwrap();
        let balance = ledger.balances().account_balance(&from);
        let min_burn_amount = ledger.transfer_fee.min(balance);
        if amount < min_burn_amount {
            return Err(CoreTransferError::BadBurn { min_burn_amount });
        }
        if amount == Tokens::ZERO {
            return Err(CoreTransferError::BadBurn {
                min_burn_amount: ledger.transfer_fee,
            });
        }
        (
            Operation::Burn {
                from,
                amount,
                spender: spender_account.map(AccountIdentifier::from),
            },
            Tokens::ZERO,
        )
    } else if from == minting_acc {
        if spender_account.is_some() {
            trap("the minter account cannot delegate mints");
        }
        if fee.is_some() && fee.as_ref() != Some(&Nat::from(0u64)) {
            return Err(CoreTransferError::BadFee {
                expected_fee: Tokens::ZERO,
            });
        }
        (Operation::Mint { to, amount }, Tokens::ZERO)
    } else {
        let expected_fee = LEDGER.read().unwrap().transfer_fee;
        if fee.is_some() && fee.as_ref() != Some(&Nat::from(expected_fee.get_e8s())) {
            return Err(CoreTransferError::BadFee { expected_fee });
        }
        (
            Operation::Transfer {
                from,
                to,
                spender: spender_account.map(AccountIdentifier::from),
                amount,
                fee: expected_fee,
            },
            expected_fee,
        )
    };

    let block_index = {
        let mut ledger = LEDGER.write().unwrap();
        let tx = Transaction {
            operation,
            memo: Memo(0),
            icrc1_memo: memo.map(|x| x.0),
            created_at_time,
        };

        #[cfg(not(feature = "canbench-rs"))]
        let (block_index, hash) = apply_transaction(&mut *ledger, tx, now, effective_fee)?;

        #[cfg(feature = "canbench-rs")]
        let (block_index, _hash) = apply_transaction(&mut *ledger, tx, now, effective_fee)?;

        #[cfg(not(feature = "canbench-rs"))]
        set_certified_data(&hash.into_bytes());

        block_index
    };
    Ok(block_index)
}

async fn icrc1_send(
    memo: Option<icrc_ledger_types::icrc1::transfer::Memo>,
    amount: Nat,
    fee: Option<Nat>,
    from_account: Account,
    to_account: Account,
    spender_account: Option<Account>,
    created_at_time: Option<u64>,
) -> Result<BlockIndex, CoreTransferError<Tokens>> {
    let block_index = icrc1_send_not_async(
        memo,
        amount,
        fee,
        from_account,
        to_account,
        spender_account,
        created_at_time,
    )?;

    let max_msg_size = *MAX_MESSAGE_SIZE_BYTES.read().unwrap();
    archive_blocks::<Access>(DebugOutSink, max_msg_size as u64).await;
    Ok(block_index)
}

thread_local! {
    static NOTIFY_METHOD_CALLS: RefCell<u64> = const { RefCell::new(0) };
    static PRE_UPGRADE_INSTRUCTIONS_CONSUMED: RefCell<u64> = const { RefCell::new(0) };
    static POST_UPGRADE_INSTRUCTIONS_CONSUMED: RefCell<u64> = const { RefCell::new(0) };
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
#[cfg(feature = "notify-method")]
pub async fn notify(
    block_height: BlockIndex,
    max_fee: Tokens,
    from_subaccount: Option<Subaccount>,
    to_canister: CanisterId,
    to_subaccount: Option<Subaccount>,
    notify_using_protobuf: bool,
) -> Result<BytesS, String> {
    use dfn_core::api::{call_bytes_with_cleanup, call_with_cleanup, Funds};
    use dfn_protobuf::ProtoBuf;

    NOTIFY_METHOD_CALLS.with(|n| *n.borrow_mut() += 1);

    let caller_principal_id = PrincipalId::from(caller());

    print(format!(
        "[ledger] notify method called by [{}]",
        caller_principal_id
    ));

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

    let transfer_fee = LEDGER.read().unwrap().transfer_fee;

    if max_fee != transfer_fee {
        panic!("Transfer fee should be {}", transfer_fee);
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

    let block = Block::decode(raw_block).unwrap();

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

    let transaction_notification_args = icp_ledger::TransactionNotification {
        from: caller_principal_id,
        from_subaccount,
        to: to_canister,
        to_subaccount,
        block_height,
        amount,
        memo: block.transaction().memo,
    };

    let block_timestamp = block.timestamp();

    ledger_canister::change_notification_state(block_height, block_timestamp, true)
        .expect("Notification failed");

    // This transaction provides an on chain record that a notification was
    // attempted
    let transfer = Operation::Transfer {
        from: expected_from,
        to: expected_to,
        spender: None,
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
                let caller = PrincipalId::from(caller());
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
            let _ =
                ledger_canister::change_notification_state(block_height, block_timestamp, false);
            if err.len() > MAX_LENGTH {
                let caller = PrincipalId::from(caller());
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
fn block(block_index: BlockIndex) -> Option<Result<EncodedBlock, CanisterId>> {
    let state = LEDGER.read().unwrap();
    if block_index < state.blockchain.num_archived_blocks() {
        // The block we are looking for better be in the archive because it has
        // a height smaller than the number of blocks we've archived so far
        let result =
            find_block_in_archive(&*state, block_index).expect("block not found in the archive");
        Some(Err(result))
    // Or the block may be in the ledger, or the block may not exist
    } else {
        state.blockchain.get(block_index).map(Ok)
    }
}

/// Get an account balance.
/// If the account does not exist it will return 0 Tokens
fn account_balance(account: AccountIdentifier) -> Tokens {
    LEDGER.read().unwrap().balances().account_balance(&account)
}

#[query]
#[candid_method(query)]
fn icrc1_balance_of(acc: Account) -> Nat {
    Nat::from(account_balance(AccountIdentifier::from(acc)).get_e8s())
}

#[query]
#[candid_method(query)]
fn icrc1_supported_standards() -> Vec<StandardRecord> {
    let mut standards = vec![StandardRecord {
        name: "ICRC-1".to_string(),
        url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1".to_string(),
    }];
    if LEDGER.read().unwrap().feature_flags.icrc2 {
        standards.push(StandardRecord {
            name: "ICRC-2".to_string(),
            url: "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2".to_string(),
        });
    }
    standards.push(
        StandardRecord {
            name: "ICRC-21".to_string(),
            url: "https://github.com/dfinity/wg-identity-authentication/blob/main/topics/ICRC-21/icrc_21_consent_msg.md".to_string(),
        }
    );

    standards
}

#[query]
#[candid_method(query)]
fn icrc1_minting_account() -> Option<Account> {
    LEDGER.read().unwrap().icrc1_minting_account
}

#[query]
#[candid_method(query)]
fn transfer_fee(_: TransferFeeArgs) -> TransferFee {
    LEDGER.read().unwrap().transfer_fee()
}

#[query]
#[candid_method(query)]
fn icrc1_metadata() -> Vec<(String, Value)> {
    vec![
        Value::entry("icrc1:decimals", DECIMAL_PLACES as u64),
        Value::entry("icrc1:name", LEDGER.read().unwrap().token_name.to_string()),
        Value::entry(
            "icrc1:symbol",
            LEDGER.read().unwrap().token_symbol.to_string(),
        ),
        Value::entry("icrc1:fee", LEDGER.read().unwrap().transfer_fee.get_e8s()),
    ]
}

#[query]
#[candid_method(query)]
fn icrc1_fee() -> Nat {
    Nat::from(LEDGER.read().unwrap().transfer_fee.get_e8s())
}

/// The total number of Tokens not inside the minting canister
fn total_supply() -> Tokens {
    LEDGER.read().unwrap().balances().total_supply()
}

#[query]
#[candid_method(query)]
fn icrc1_total_supply() -> Nat {
    Nat::from(LEDGER.read().unwrap().balances().total_supply().get_e8s())
}

#[query(name = "symbol")]
#[candid_method(query, rename = "symbol")]
fn token_symbol() -> Symbol {
    Symbol {
        symbol: LEDGER.read().unwrap().token_symbol.clone(),
    }
}

#[query(name = "name")]
#[candid_method(query, rename = "name")]
fn token_name() -> Name {
    Name {
        name: LEDGER.read().unwrap().token_name.clone(),
    }
}

#[query]
#[candid_method(query)]
fn icrc1_name() -> String {
    LEDGER.read().unwrap().token_name.clone()
}

#[query]
#[candid_method(query)]
fn icrc1_symbol() -> String {
    LEDGER.read().unwrap().token_symbol.to_string()
}

#[query(name = "decimals")]
#[candid_method(query, rename = "decimals")]
fn token_decimals() -> Decimals {
    Decimals {
        decimals: DECIMAL_PLACES,
    }
}

#[query]
#[candid_method(query)]
fn icrc1_decimals() -> u8 {
    debug_assert!(ic_ledger_core::tokens::DECIMAL_PLACES <= u8::MAX as u32);
    ic_ledger_core::tokens::DECIMAL_PLACES as u8
}

#[candid_method(init)]
fn canister_init(arg: LedgerCanisterPayload) {
    match arg {
        LedgerCanisterPayload::Init(arg) => init(
            arg.minting_account,
            arg.icrc1_minting_account,
            arg.initial_values,
            arg.max_message_size_bytes,
            arg.transaction_window,
            arg.archive_options,
            arg.send_whitelist,
            arg.transfer_fee,
            arg.token_symbol,
            arg.token_name,
            arg.feature_flags,
        ),
        LedgerCanisterPayload::Upgrade(_) => {
            trap("Cannot initialize the canister with an Upgrade argument. Please provide an Init argument.");
        }
    }
}

#[cfg(not(feature = "canbench-rs"))]
#[export_name = "canister_init"]
fn main() {
    ic_cdk::setup();
    let bytes = arg_data_raw();
    // We support the old init argument for backward
    // compatibility. If decoding the bytes as the new
    // init arguments fails then we fallback to the old
    // init arguments.
    match Decode!(&bytes, LedgerCanisterPayload) {
        Ok(arg) => canister_init(arg),
        Err(new_err) => {
            // fallback to old init
            match Decode!(&bytes, InitArgs) {
                    Ok(arg) => init(
                        arg.minting_account,
                        arg.icrc1_minting_account,
                        arg.initial_values,
                        arg.max_message_size_bytes,
                        arg.transaction_window,
                        arg.archive_options,
                        arg.send_whitelist,
                        arg.transfer_fee,
                        arg.token_symbol,
                        arg.token_name,
                        arg.feature_flags,
                    ),
                    Err(old_err) =>
                    trap(&format!("Unable to decode init argument.\nDecode as new init returned the error {}\nDecode as old init returned the error {}", new_err, old_err))
                }
        }
    }
}

#[cfg(feature = "canbench-rs")]
fn main() {}

// We use 8MiB buffer
const BUFFER_SIZE: usize = 8388608;

#[post_upgrade]
fn post_upgrade(args: Option<LedgerCanisterPayload>) {
    let start = instruction_counter();

    let mut magic_bytes_reader = ic_cdk::api::stable::StableReader::default();
    const MAGIC_BYTES: &[u8; 3] = b"MGR";
    let mut first_bytes = [0u8; 3];
    let memory_manager_found = match magic_bytes_reader.read_exact(&mut first_bytes) {
        Ok(_) => first_bytes == *MAGIC_BYTES,
        Err(_) => false,
    };

    let mut pre_upgrade_instructions_consumed = 0;
    {
        let mut ledger = LEDGER.write().unwrap();
        if !memory_manager_found {
            let msg =
                "Cannot upgrade from scratch stable memory, please upgrade to memory manager first.";
            print(msg);
            panic!("{msg}");
        }
        *ledger = UPGRADES_MEMORY.with_borrow(|bs| {
            let reader = Reader::new(bs, 0);
            let mut buffered_reader = BufferedReader::new(BUFFER_SIZE, reader);
            let ledger_state = ciborium::de::from_reader(&mut buffered_reader).expect(
                "Failed to read the Ledger state from memory manager managed stable memory",
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
            ledger_state
        });

        if ledger.ledger_version > LEDGER_VERSION {
            panic!(
                "Trying to downgrade from incompatible version {}. Current version is {}.",
                ledger.ledger_version, LEDGER_VERSION
            );
        }
        if ledger.ledger_version < LEDGER_VERSION {
            panic!("Migration to stable structures not supported in this version, please upgrade to git revision 3ae3649a2366aaca83404b692fc58e4c6e604a25 (https://github.com/dfinity/ic/releases/tag/ledger-suite-icp-2025-03-26) first.");
        }

        if let Some(args) = args {
            match args {
            LedgerCanisterPayload::Init(_) => trap("Cannot upgrade the canister with an Init argument. Please provide an Upgrade argument."),
            LedgerCanisterPayload::Upgrade(upgrade_args) => {
                if let Some(upgrade_args) = upgrade_args {
                    ledger.upgrade(upgrade_args);
                }
        }
    }
        }
        set_certified_data(
            &ledger
                .blockchain
                .last_hash
                .map(|h| h.into_bytes())
                .unwrap_or([0u8; 32]),
        );
        PRE_UPGRADE_INSTRUCTIONS_CONSUMED
            .with(|n| *n.borrow_mut() = pre_upgrade_instructions_consumed);
    }

    let end = instruction_counter();
    let post_upgrade_instructions_consumed = end - start;
    POST_UPGRADE_INSTRUCTIONS_CONSUMED
        .with(|n| *n.borrow_mut() = post_upgrade_instructions_consumed);
}

#[pre_upgrade]
fn pre_upgrade() {
    let start = instruction_counter();

    let ledger = LEDGER
        .read()
        // This should never happen, but it's better to be safe than sorry
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    UPGRADES_MEMORY.with_borrow_mut(|bs| {
        let writer = Writer::new(bs, 0);
        let mut buffered_writer = BufferedWriter::new(BUFFER_SIZE, writer);
        ciborium::ser::into_writer(&*ledger, &mut buffered_writer)
            .expect("Failed to write the Ledger state to memory manager managed stable memory");
        let end = instruction_counter();
        let instructions_consumed = end - start;
        let counter_bytes: [u8; 8] = instructions_consumed.to_le_bytes();
        buffered_writer
            .write_all(&counter_bytes)
            .expect("failed to write instructions consumed to UPGRADES_MEMORY");
    });
}

struct Access;

impl LedgerAccess for Access {
    type Ledger = Ledger;

    fn with_ledger<R>(f: impl FnOnce(&Self::Ledger) -> R) -> R {
        let ledger_guard = LEDGER.try_read().expect("Failed to get ledger read lock");
        f(&ledger_guard)
    }

    fn with_ledger_mut<R>(f: impl FnOnce(&mut Self::Ledger) -> R) -> R {
        let mut ledger = LEDGER.write().expect("Failed to get ledger write lock");
        f(&mut ledger)
    }
}

/// Canister endpoints
#[export_name = "canister_update send_pb"]
fn send_() {
    ic_cdk::spawn(async move {
        ic_cdk::setup();

        let SendArgs {
            memo,
            amount,
            fee,
            from_subaccount,
            to,
            created_at_time,
        } = from_proto_bytes(arg_data_raw()).expect("failed to decode send_pb argument");

        let res = send(memo, amount, fee, from_subaccount, to, created_at_time)
            .await
            .unwrap_or_else(|e| trap(&e.to_string()));

        let res_proto = to_proto_bytes(res).expect("failed to encode send_pb response");
        reply_raw(&res_proto)
    })
}

/// Do not use call this from code, this is only here so dfx has something to
/// call when making a payment. This will be changed in ways that are not
/// backwards compatible with previous interfaces.
///
/// I STRONGLY recommend that you use "send_pb" instead.
#[update]
#[candid_method(update)]
async fn send_dfx(arg: SendArgs) -> BlockIndex {
    transfer(TransferArgs::from(arg)).await.unwrap_or_else(|e| {
        trap(&e.to_string());
    })
}

#[cfg(feature = "notify-method")]
#[export_name = "canister_update notify_pb"]
fn notify_() {
    use dfn_core::endpoint::over_async_may_reject_explicit;
    use dfn_protobuf::ProtoBuf;

    // we use over_init because it doesn't reply automatically so we can do explicit
    // replies in the callback
    over_async_may_reject_explicit(
        |ProtoBuf(icp_ledger::NotifyCanisterArgs {
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

#[update]
#[candid_method(update)]
async fn transfer(arg: TransferArgs) -> Result<BlockIndex, TransferError> {
    let to_account = AccountIdentifier::from_address(arg.to).unwrap_or_else(|e| {
        trap(&format!("Invalid account identifier: {}", e));
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

#[update]
#[candid_method(update)]
async fn icrc1_transfer(
    arg: TransferArg,
) -> Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError> {
    if !LEDGER
        .read()
        .unwrap()
        .can_send(&PrincipalId::from(caller()))
    {
        trap("Anonymous principal cannot hold tokens on the ledger.");
    }

    let from_account = Account {
        owner: caller(),
        subaccount: arg.from_subaccount,
    };
    Ok(Nat::from(
        icrc1_send(
            arg.memo,
            arg.amount,
            arg.fee,
            from_account,
            arg.to,
            None,
            arg.created_at_time,
        )
        .await
        .map_err(convert_transfer_error)
        .map_err(|err| {
            let err: Icrc1TransferError = match Icrc1TransferError::try_from(err) {
                Ok(err) => err,
                Err(err) => trap(&err),
            };
            err
        })?,
    ))
}

#[update]
#[candid_method(update)]
async fn icrc2_transfer_from(arg: TransferFromArgs) -> Result<Nat, TransferFromError> {
    if !LEDGER
        .read()
        .unwrap()
        .can_send(&PrincipalId::from(caller()))
    {
        trap("Anonymous principal cannot hold tokens on the ledger.");
    }

    if !LEDGER.read().unwrap().feature_flags.icrc2 {
        trap("ICRC-2 features are not enabled on the ledger.");
    }
    let spender_account = Account {
        owner: caller(),
        subaccount: arg.spender_subaccount,
    };
    Ok(Nat::from(
        icrc1_send(
            arg.memo,
            arg.amount,
            arg.fee,
            arg.from,
            arg.to,
            Some(spender_account),
            arg.created_at_time,
        )
        .await
        .map_err(convert_transfer_error)
        .map_err(|err| {
            let err: TransferFromError = match TransferFromError::try_from(err) {
                Ok(err) => err,
                Err(err) => trap(&err),
            };
            err
        })?,
    ))
}

/// See caveats of use on send_dfx
#[cfg(feature = "notify-method")]
#[export_name = "canister_update notify_dfx"]
fn notify_dfx_() {
    use dfn_core::endpoint::over_async_may_reject_explicit;

    // we use over_init because it doesn't reply automatically so we can do explicit
    // replies in the callback
    over_async_may_reject_explicit(
        |CandidOne(icp_ledger::NotifyCanisterArgs {
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
    ic_cdk::setup();
    let arg: BlockArg =
        from_proto_bytes(arg_data_raw()).expect("failed to decode block_pb argument");
    let res = to_proto_bytes(icp_ledger::BlockRes(block(arg.0)))
        .expect("failed to encode block_pb response");
    reply_raw(&res)
}

#[export_name = "canister_query tip_of_chain_pb"]
fn tip_of_chain_() {
    ic_cdk::setup();
    let _: protobuf::TipOfChainRequest =
        from_proto_bytes(arg_data_raw()).expect("failed to decode tip_of_chain_pb argument");
    let res = to_proto_bytes(tip_of_chain()).expect("failed to encode tip_of_chain_pb response");
    reply_raw(&res)
}

#[export_name = "canister_query get_archive_index_pb"]
fn get_archive_index_() {
    ic_cdk::setup();
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
    let res = to_proto_bytes(protobuf::ArchiveIndexResponse { entries })
        .expect("failed to encode get_archive_index_pb response");
    reply_raw(&res);
}

#[export_name = "canister_query account_balance_pb"]
fn account_balance_() {
    ic_cdk::setup();
    let args: AccountBalanceArgs =
        from_proto_bytes(arg_data_raw()).expect("failed to decode account_balance_pb argument");
    let res = tokens_into_proto(account_balance(args.account));
    let res_proto = to_proto_bytes(res).expect("failed to encode account_balance_pb response");
    reply_raw(&res_proto)
}

#[query(name = "account_balance")]
#[candid_method(query, rename = "account_balance")]
fn account_balance_candid_(arg: AccountIdentifierByteBuf) -> Tokens {
    match BinaryAccountBalanceArgs::try_from(arg) {
        Ok(arg) => {
            let account = AccountIdentifier::from_address(arg.account).unwrap_or_else(|e| {
                trap(&format!("Invalid account identifier: {}", e));
            });
            account_balance(account)
        }
        Err(_) => Tokens::ZERO,
    }
}

/// See caveats of use on send_dfx
#[query(name = "account_balance_dfx")]
#[candid_method(query, rename = "account_balance_dfx")]
fn account_balance_dfx_(args: AccountBalanceArgs) -> Tokens {
    account_balance(args.account)
}

#[query(name = "account_identifier")]
#[candid_method(query, rename = "account_identifier")]
fn compute_account_identifier(arg: Account) -> AccountIdBlob {
    AccountIdentifier::from(arg).to_address()
}

#[export_name = "canister_query transfer_fee_pb"]
fn transfer_fee_() {
    ic_cdk::setup();
    let args: TransferFeeArgs =
        from_proto_bytes(arg_data_raw()).expect("failed to decode transfer_fee_pb argument");
    let fee = transfer_fee(args);
    let res = to_proto_bytes(fee).expect("failed to encpde transfer_fee_pb response");
    reply_raw(&res)
}

#[export_name = "canister_query total_supply_pb"]
fn total_supply_() {
    ic_cdk::setup();
    let _: TotalSupplyArgs =
        from_proto_bytes(arg_data_raw()).expect("failed to decode total_supply_pb args");
    let res = tokens_into_proto(total_supply());
    let res_proto = to_proto_bytes(res).expect("failed encode total_supply_pb response");
    reply_raw(&res_proto)
}

/// Get multiple blocks by *offset into the container* (not BlockIndex) and
/// length. Note that this simply iterates the blocks available in the Ledger
/// without taking into account the archive. For example, if the ledger contains
/// blocks with heights [100, 199] then iter_blocks(0, 1) will return the block
/// with height 100.
#[export_name = "canister_query iter_blocks_pb"]
fn iter_blocks_() {
    ic_cdk::setup();
    let args: IterBlocksArgs =
        from_proto_bytes(arg_data_raw()).expect("failed to decode iter_blocks_pb argument");

    let length = std::cmp::min(
        args.length,
        max_blocks_per_request(&PrincipalId::from(caller())),
    ) as u64;
    let archived_len = LEDGER.read().unwrap().blockchain.num_archived_blocks;
    let start = archived_len + args.start as u64;
    let end = start + length;
    let blocks = LEDGER.read().unwrap().blockchain.get_blocks(start..end);
    let res =
        to_proto_bytes(IterBlocksRes(blocks)).expect("failed to encode iter_blocks_pb response");
    reply_raw(&res)
}

/// Get multiple blocks by BlockIndex and length. If the query is outside the
/// range stored in the Node the result is an error.
#[export_name = "canister_query get_blocks_pb"]
fn get_blocks_() {
    ic_cdk::setup();
    let args: GetBlocksArgs =
        from_proto_bytes(arg_data_raw()).expect("failed to decode get_blocks_pb argument");

    let length = std::cmp::min(
        args.length,
        max_blocks_per_request(&PrincipalId::from(caller())) as u64,
    );
    let blockchain = &LEDGER.read().unwrap().blockchain;
    let local_blocks_range = blockchain.num_archived_blocks..blockchain.chain_length();
    let requested_range = args.start..args.start + length;
    let res = if !range_utils::is_subrange(&requested_range, &local_blocks_range) {
        GetBlocksRes(Err(format!("Requested blocks outside the range stored in the ledger node. Requested [{} .. {}]. Available [{} .. {}].",
            requested_range.start, requested_range.end, local_blocks_range.start, local_blocks_range.end)))
    } else {
        GetBlocksRes(Ok(blockchain.get_blocks(requested_range)))
    };
    let res_proto = to_proto_bytes(res).expect("failed to encode get_blocks_pb respone");
    reply_raw(&res_proto)
}

#[query]
#[candid_method(query)]
fn query_blocks(GetBlocksArgs { start, length }: GetBlocksArgs) -> QueryBlocksResponse {
    let ledger = LEDGER.read().unwrap();
    let locations = block_locations(&*ledger, start, length.min(usize::MAX as u64) as usize);

    let local_blocks = range_utils::take(
        &locations.local_blocks,
        max_blocks_per_request(&PrincipalId::from(caller())),
    );

    let blocks: Vec<CandidBlock> = ledger
        .blockchain
        .get_blocks(local_blocks.clone())
        .iter()
        .map(|enc_block| {
            CandidBlock::from(
                Block::decode(enc_block.clone()).expect("bug: failed to decode encoded block"),
            )
        })
        .collect();

    let archived_blocks = locations
        .archived_blocks
        .into_iter()
        .map(|(canister_id, slice)| ArchivedBlocksRange {
            start: slice.start,
            length: range_utils::range_len(&slice),
            callback: QueryArchiveFn::new(Principal::from(canister_id), "get_blocks".to_string()),
        })
        .collect();

    let chain_length = ledger.blockchain.chain_length();

    QueryBlocksResponse {
        chain_length,
        certificate: data_certificate().map(serde_bytes::ByteBuf::from),
        blocks,
        first_block_index: local_blocks.start as BlockIndex,
        archived_blocks,
    }
}

#[query]
#[candid_method(query)]
fn archives() -> Archives {
    let ledger_guard = LEDGER.try_read().expect("Failed to get ledger read lock");
    let archive_guard = ledger_guard.blockchain.archive.read().unwrap();
    let archives = archive_guard
        .as_ref()
        .iter()
        .flat_map(|archive| {
            archive
                .nodes()
                .iter()
                .map(|cid| ArchiveInfo { canister_id: *cid })
        })
        .collect();
    Archives { archives }
}

#[export_name = "canister_query get_nodes"]
fn get_nodes_() {
    ic_cdk::setup();
    let result = archives()
        .archives
        .iter()
        .map(|archive| archive.canister_id)
        .collect::<Vec<CanisterId>>();
    ic_cdk::api::call::reply((result,));
}

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    let ledger = LEDGER.try_read().map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to get a LEDGER for read: {}", err),
        )
    })?;
    let archive_guard = ledger.blockchain.archive.read().unwrap();
    let num_archives = archive_guard
        .as_ref()
        .iter()
        .fold(0, |sum, archive| sum + archive.nodes().iter().len());
    w.encode_gauge(
        "ledger_max_message_size_bytes",
        *MAX_MESSAGE_SIZE_BYTES.read().unwrap() as f64,
        "Maximum inter-canister message size in bytes.",
    )?;
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
        ledger.blockchain.num_unarchived_blocks() as f64,
        "Total number of blocks stored in the main memory.",
    )?;
    // This value can go down -- the number is increased before archiving, and if
    // archiving fails it is decremented.
    w.encode_gauge(
        "ledger_archived_blocks",
        ledger.blockchain.num_archived_blocks as f64,
        "Total number of blocks sent to the archive.",
    )?;
    // The sum of the two gauges above. It is necessary to have this metric explicitly exported in
    // order to be able to accurately calculate the total block rate.
    w.encode_gauge(
        "ledger_total_blocks",
        ledger.blockchain.num_archived_blocks.saturating_add(ledger.blockchain.num_unarchived_blocks()) as f64,
        "Total number of blocks stored in the main memory, plus total number of blocks sent to the archive.",
    )?;
    w.encode_gauge(
        "ledger_balances_token_pool",
        ledger.balances().token_pool.get_tokens() as f64,
        "Total number of Tokens in the pool.",
    )?;
    w.encode_gauge(
        "ledger_balance_store_entries",
        balances_len() as f64,
        "Total number of accounts in the balance store.",
    )?;
    w.encode_gauge(
        "ledger_most_recent_block_time_seconds",
        ledger.blockchain.last_timestamp.as_nanos_since_unix_epoch() as f64 / 1_000_000_000.0,
        "IC timestamp of the most recent block.",
    )?;
    w.encode_gauge(
        "ledger_notify_method_calls",
        NOTIFY_METHOD_CALLS.with(|n| *n.borrow()) as f64,
        "Total number of calls to the notify-method method.",
    )?;
    w.encode_counter(
        "ledger_num_archives",
        num_archives as f64,
        "Total number of archives.",
    )?;
    w.encode_gauge(
        "ledger_num_approvals",
        ledger.approvals().get_num_approvals() as f64,
        "Total number of approvals.",
    )?;
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
    Ok(())
}

#[query(hidden = true, decoding_quota = 10000)]
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
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                    .build()
            }
        }
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

#[query]
#[candid_method(query)]
fn query_encoded_blocks(
    GetBlocksArgs { start, length }: GetBlocksArgs,
) -> QueryEncodedBlocksResponse {
    let ledger = LEDGER.read().unwrap();
    let locations = block_locations(&*ledger, start, length.min(usize::MAX as u64) as usize);

    let local_blocks = range_utils::take(
        &locations.local_blocks,
        max_blocks_per_request(&PrincipalId::from(caller())),
    );

    let blocks = ledger.blockchain.get_blocks(local_blocks.clone()).to_vec();

    let archived_blocks = locations
        .archived_blocks
        .into_iter()
        .map(|(canister_id, slice)| ArchivedEncodedBlocksRange {
            start: slice.start,
            length: range_utils::range_len(&slice),
            callback: icrc_ledger_types::icrc3::archive::QueryArchiveFn::new(
                Principal::from(canister_id),
                "get_encoded_blocks".to_string(),
            ),
        })
        .collect();

    let chain_length = ledger.blockchain.chain_length();

    QueryEncodedBlocksResponse {
        chain_length,
        certificate: data_certificate().map(serde_bytes::ByteBuf::from),
        blocks,
        first_block_index: local_blocks.start as BlockIndex,
        archived_blocks,
    }
}

fn icrc2_approve_not_async(caller: Principal, arg: ApproveArgs) -> Result<Nat, ApproveError> {
    if !LEDGER.read().unwrap().can_send(&PrincipalId::from(caller)) {
        trap("Anonymous principal cannot approve token transfers on the ledger.");
    }

    if !LEDGER.read().unwrap().feature_flags.icrc2 {
        trap("ICRC-2 features are not enabled on the ledger.");
    }
    let now = TimeStamp::from_nanos_since_unix_epoch(time());

    let from_account = Account {
        owner: caller,
        subaccount: arg.from_subaccount,
    };
    let from = AccountIdentifier::from(from_account);
    if from_account.owner == arg.spender.owner {
        trap("self approval is not allowed");
    }
    let spender = AccountIdentifier::from(arg.spender);
    let minting_acc = LEDGER
        .read()
        .unwrap()
        .minting_account_id
        .expect("Minting canister id not initialized");

    if from == minting_acc {
        trap("the minting account cannot delegate mints")
    }
    match arg.memo.as_ref() {
        Some(memo) if memo.0.len() > MEMO_SIZE_BYTES => trap("the memo field is too large"),
        _ => {}
    };

    let allowance = Tokens::from_e8s(arg.amount.0.to_u64().unwrap_or(u64::MAX));
    let expected_allowance = match arg.expected_allowance {
        Some(n) => match n.0.to_u64() {
            Some(n) => Some(Tokens::from_e8s(n)),
            None => {
                let current_allowance = LEDGER
                    .read()
                    .unwrap()
                    .approvals()
                    .allowance(&from, &spender, now)
                    .amount;
                return Err(ApproveError::AllowanceChanged {
                    current_allowance: Nat::from(current_allowance.get_e8s()),
                });
            }
        },
        None => None,
    };

    let expected_fee = LEDGER.read().unwrap().transfer_fee;
    if arg.fee.is_some() && arg.fee.as_ref() != Some(&Nat::from(expected_fee.get_e8s())) {
        return Err(ApproveError::BadFee {
            expected_fee: Nat::from(expected_fee.get_e8s()),
        });
    }

    let block_index = {
        let mut ledger = LEDGER.write().unwrap();
        let tx = Transaction {
            operation: Operation::Approve {
                from,
                spender,
                allowance,
                expected_allowance,
                expires_at: arg.expires_at.map(TimeStamp::from_nanos_since_unix_epoch),
                fee: expected_fee,
            },
            created_at_time: arg
                .created_at_time
                .map(TimeStamp::from_nanos_since_unix_epoch),
            memo: Memo(0),
            icrc1_memo: arg.memo.map(|x| x.0),
        };
        let result = apply_transaction(&mut *ledger, tx, now, expected_fee)
            .map_err(convert_transfer_error)
            .map_err(|err| {
                let err: ApproveError = match ApproveError::try_from(err) {
                    Ok(err) => err,
                    Err(err) => trap(&err),
                };
                err
            })?;

        #[cfg(not(feature = "canbench-rs"))]
        let (block_index, hash) = result;

        #[cfg(feature = "canbench-rs")]
        let (block_index, _hash) = result;

        #[cfg(not(feature = "canbench-rs"))]
        set_certified_data(&hash.into_bytes());

        block_index
    };

    Ok(Nat::from(block_index))
}

#[update]
#[candid_method(update)]
async fn icrc2_approve(arg: ApproveArgs) -> Result<Nat, ApproveError> {
    let block_index = icrc2_approve_not_async(caller(), arg)?;

    let max_msg_size = *MAX_MESSAGE_SIZE_BYTES.read().unwrap();
    archive_blocks::<Access>(DebugOutSink, max_msg_size as u64).await;
    Ok(block_index)
}

fn get_allowance(from: AccountIdentifier, spender: AccountIdentifier) -> Allowance {
    let now = TimeStamp::from_nanos_since_unix_epoch(time());
    let ledger = LEDGER.read().unwrap();
    let allowance = ledger.approvals().allowance(&from, &spender, now);
    Allowance {
        allowance: Nat::from(allowance.amount.get_e8s()),
        expires_at: allowance.expires_at.map(|t| t.as_nanos_since_unix_epoch()),
    }
}

#[query]
#[candid_method(query)]
fn icrc2_allowance(arg: AllowanceArgs) -> Allowance {
    if !LEDGER.read().unwrap().feature_flags.icrc2 {
        trap("ICRC-2 features are not enabled on the ledger.");
    }
    let from = AccountIdentifier::from(arg.account);
    let spender = AccountIdentifier::from(arg.spender);
    get_allowance(from, spender)
}

#[cfg(feature = "icp-allowance-getter")]
#[query(name = "allowance")]
#[candid_method(query, rename = "allowance")]
fn icp_allowance(arg: IcpAllowanceArgs) -> Allowance {
    get_allowance(arg.account, arg.spender)
}

#[update]
#[candid_method(update)]
fn icrc21_canister_call_consent_message(
    consent_msg_request: ConsentMessageRequest,
) -> Result<ConsentInfo, Icrc21Error> {
    let caller_principal = caller();
    let ledger_fee = Nat::from(LEDGER.read().unwrap().transfer_fee.get_e8s());
    let token_symbol = LEDGER.read().unwrap().token_symbol.clone();
    let decimals = ic_ledger_core::tokens::DECIMAL_PLACES as u8;

    build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints(
        consent_msg_request,
        caller_principal,
        ledger_fee,
        token_symbol,
        decimals,
    )
}

#[query]
#[candid_method(query)]
fn icrc10_supported_standards() -> Vec<StandardRecord> {
    icrc1_supported_standards()
}

#[query]
#[candid_method(query)]
fn is_ledger_ready() -> bool {
    true
}

/// Get allowances where the approver is `arg.from_account_id`. If `arg.prev_spender_id`
/// is not specified, the list starts from the first allowance from `arg.from_account_id`.
/// If `arg.prev_spender_id` is specified, the list starts with allowance that is lexicographically
/// larger than (`arg.from_account_id`, `arg.prev_spender_id`). This way `arg.prev_spender_id`
/// can be used for pagination - the user can specify which allowance they already saw.
/// `arg.take` can be used to limit the number of returned allowances. If not specified,
/// at most 500 allowances will be returned.
#[query]
#[candid_method(query)]
fn get_allowances(arg: GetAllowancesArgs) -> Allowances {
    let max_take_allowances = Access::with_ledger(|ledger| ledger.max_take_allowances());
    let max_results = arg
        .take
        .map(|take| std::cmp::min(take, max_take_allowances))
        .unwrap_or(max_take_allowances);
    get_allowances_list(
        arg.from_account_id,
        arg.prev_spender_id,
        max_results,
        ic_cdk::api::time(),
    )
}

candid::export_service!();

#[query]
fn __get_candid_interface_tmp_hack() -> String {
    __export_service()
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid_parser::utils::{service_compatible, service_equal, CandidSource};
    use std::path::PathBuf;

    #[test]
    fn check_candid_interface_compatibility() {
        let new_interface = __export_service();
        let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let old_interface = manifest_dir.join("../ledger.did");

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
    // FI-510 Backwards compatibility testing for Candid and Protobuf
    #[test]
    fn check_candid_interface_backwards_compatibility() {
        candid::export_service!();
        let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let old_candid_file = manifest_dir.join("./ledger_candid_backwards_compatible.did");
        let new_candid_file = manifest_dir.join("../ledger.did");
        service_compatible(
            CandidSource::File(new_candid_file.as_path()),
            CandidSource::File(old_candid_file.as_path()),
        )
        .unwrap_or_else(|e| {
            panic!(
                "the ledger interface is not backwards compatible {}: {:?}",
                new_candid_file.display(),
                e
            )
        });
    }

    #[test]
    fn check_archive_and_ledger_interface_compatibility() {
        // check that ledger.did and ledger_archive.did agree on the block format
        let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let ledger_did_file = manifest_dir.join("../ledger.did");
        let archive_did_file = manifest_dir.join("../ledger_archive.did");
        let mut ledger_env = CandidSource::File(ledger_did_file.as_path())
            .load()
            .unwrap()
            .0;
        let archive_env = CandidSource::File(archive_did_file.as_path())
            .load()
            .unwrap()
            .0;
        let ledger_block_type = ledger_env.find_type("Block").unwrap().to_owned();
        let archive_block_type = archive_env.find_type("Block").unwrap().to_owned();

        let mut gamma = std::collections::HashSet::new();
        let archive_block_type = ledger_env.merge_type(archive_env, archive_block_type.clone());
        candid::types::subtype::equal(
            &mut gamma,
            &ledger_env,
            &ledger_block_type,
            &archive_block_type,
        )
        .expect("Ledger and Archive Block type are different");
    }
}
