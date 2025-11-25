use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ic_btc_interface::{OutPoint, Utxo};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use lazy_static::lazy_static;
use tla_instrumentation::{
    GlobalState, TlaConstantAssignment, TlaValue, ToTla, Update, UpdateTrace, VarAssignment,
};

use crate::state::{self, CkBtcMinterState};
use crate::updates::get_btc_address::account_to_p2wpkh_address_from_state;

mod store;

pub use store::{TLA_INSTRUMENTATION_STATE, TLA_TRACES_LKEY, TLA_TRACES_MUTEX};
pub use tla_instrumentation::checker::{check_tla_code_link, PredicateDescription};

const UPDATE_BALANCE_PROCESS_ID: &str = "Update_Balance";
pub const UPDATE_BALANCE_START: &str = "Update_Balance_Start";

lazy_static! {
    pub static ref UPDATE_BALANCE_DESC: Update = {
        let default_locals = VarAssignment::new()
            .add("caller_account", default_ckbtc_address())
            .add("utxos", TlaValue::Set(BTreeSet::new()))
            .add("utxo", dummy_utxo());
        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: tla_instrumentation::Label::new(UPDATE_BALANCE_START),
            end_label: tla_instrumentation::Label::new(UPDATE_BALANCE_START),
            process_id: UPDATE_BALANCE_PROCESS_ID.to_string(),
            canister_name: "minter".to_string(),
            post_process: |trace| post_process_update_balance(trace),
        }
    };
}

pub fn update_balance_desc() -> Update {
    UPDATE_BALANCE_DESC.clone()
}

pub fn account_to_tla(account: &Account) -> TlaValue {
    TlaValue::Record(BTreeMap::from([
        ("owner".to_string(), account.owner.to_tla_value()),
        (
            "subaccount".to_string(),
            opt_subaccount_to_tla(account.subaccount),
        ),
    ]))
}

pub fn btc_address_to_tla(address: &str) -> TlaValue {
    TlaValue::Literal(address.to_string())
}

pub fn utxo_to_tla(utxo: &Utxo, owner_address: &str) -> TlaValue {
    TlaValue::Record(BTreeMap::from([
        ("id".to_string(), outpoint_to_id(&utxo.outpoint)),
        ("owner".to_string(), btc_address_to_tla(owner_address)),
        ("value".to_string(), utxo.value.to_tla_value()),
    ]))
}

pub fn utxo_set_to_tla(utxos: &[Utxo], owner_address: &str) -> TlaValue {
    TlaValue::Set(
        utxos
            .iter()
            .map(|u| utxo_to_tla(u, owner_address))
            .collect(),
    )
}

pub fn get_tla_globals() -> GlobalState {
    state::read_state(snapshot_state)
}

pub fn take_traces() -> Vec<UpdateTrace> {
    let traces = TLA_TRACES_LKEY.get();
    let mut guard = traces
        .lock()
        .expect("Couldn't lock the traces in take_traces");
    std::mem::take(&mut *guard)
}

pub fn check_traces() {
    perform_trace_check(take_traces())
}

pub fn perform_trace_check(traces: Vec<UpdateTrace>) {
    if std::env::var("TEST_TMPDIR").is_err() {
        let tmp = std::env::temp_dir();
        let _ = std::fs::create_dir_all(&tmp);
        // Setting environment variables is considered unsafe on some platforms.
        unsafe {
            std::env::set_var("TEST_TMPDIR", tmp.to_string_lossy().into_owned());
        }
    }
    let tla_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tla");
    if std::env::var("TLA_MODULES").is_err() {
        let modules = [
            "Apalache.tla",
            "TypeAliases.tla",
            "Variants.tla",
            "TLA_Hash.tla",
            "Ckbtc_Common.tla",
            "Update_Balance.tla",
            "Update_Balance_Apalache.tla",
        ]
        .iter()
        .map(|f| tla_dir.join(f).to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
        unsafe {
            std::env::set_var("TLA_MODULES", modules);
        }
    }

    let apalache_bin = std::env::var("TLA_APALACHE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("..")
                .join("..")
                .join("tlatools")
                .join("apalache")
                .join("bin")
                .join("apalache-mc")
        });
    let module = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tla")
        .join("Update_Balance_Apalache.tla");

    for trace in traces {
        for pair in trace.state_pairs {
            check_tla_code_link(
                &apalache_bin,
                PredicateDescription {
                    tla_module: module.clone(),
                    transition_predicate: "Next".to_string(),
                    predicate_parameters: vec![],
                },
                pair,
                trace.constants.clone(),
            )
            .expect("TLA code link check failed");
        }
    }
}

fn snapshot_state(state: &CkBtcMinterState) -> GlobalState {
    let mut gs = GlobalState::new();

    let update_balance_locks = principals_from_accounts(state.update_balance_accounts.iter());
    let retrieve_btc_locks = principals_from_accounts(state.retrieve_btc_accounts.iter());

    gs.add(
        "update_balance_locks",
        TlaValue::Set(update_balance_locks),
    );
    gs.add(
        "retrieve_btc_locks",
        TlaValue::Set(retrieve_btc_locks),
    );
    gs.add("locks", TlaValue::Set(BTreeSet::new()));
    gs.add(
        "pending",
        pending_requests_to_tla(state),
    );
    gs.add(
        "submitted_transactions",
        submitted_transactions_to_tla(&state.submitted_transactions),
    );
    gs.add(
        "utxos_state_addresses",
        utxos_state_addresses_to_tla(state),
    );
    gs.add("available_utxos", available_utxos_to_tla(state));
    gs.add("finalized_utxos", finalized_utxos_to_tla(state));
    gs.add("check_fee", state.check_fee.to_tla_value());

    gs
}

fn post_process_update_balance(trace: &mut Vec<tla_instrumentation::ResolvedStatePair>) -> TlaConstantAssignment {
    let mut principals = BTreeSet::new();
    let mut subaccounts = BTreeSet::new();
    let mut deposit_addresses = BTreeMap::new();
    let mut check_fee = None;

    for pair in trace.iter_mut() {
        for state in [&mut pair.start, &mut pair.end] {
            if let Some(TlaValue::Function(accounts)) = state.get("caller_account") {
                if let Some(TlaValue::Function(addresses)) = state.get("btc_address") {
                    for (pid, account_val) in accounts {
                        if let Some(addr) = addresses.get(pid) {
                            deposit_addresses.insert(account_val.clone(), addr.clone());
                        }
                    }
                }
                for account_val in accounts.values() {
                    if let TlaValue::Record(map) = account_val {
                        if let Some(owner) = map.get("owner") {
                            principals.insert(owner.clone());
                        }
                        if let Some(sub) = map.get("subaccount") {
                            subaccounts.insert(sub.clone());
                        }
                    }
                }
            }
            if let Some(fee) = state.0 .0.remove("check_fee") {
                check_fee = Some(fee);
            }
            state.0 .0.remove("btc_address");
            state
                .0
                .0
                .entry("minter_to_btc_canister".to_string())
                .or_insert_with(|| TlaValue::Seq(Vec::new()));
            state
                .0
                .0
                .entry("btc_canister_to_minter".to_string())
                .or_insert_with(|| TlaValue::Set(BTreeSet::new()));
            state
                .0
                .0
                .entry("minter_to_ledger".to_string())
                .or_insert_with(|| TlaValue::Seq(Vec::new()));
            state
                .0
                .0
                .entry("ledger_to_minter".to_string())
                .or_insert_with(|| TlaValue::Set(BTreeSet::new()));
            let mut utxo_owner_map: BTreeMap<TlaValue, TlaValue> = BTreeMap::new();
            if let Some(TlaValue::Function(addrs)) = state.get("utxos_state_addresses") {
                for (acct, utxos) in addrs {
                    if let Some(addr) = deposit_addresses.get(acct) {
                        if let TlaValue::Set(us) = utxos {
                            for u in us {
                                if let TlaValue::Record(r) = u {
                                    if let Some(id) = r.get("id") {
                                        utxo_owner_map.insert(id.clone(), addr.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(TlaValue::Function(addrs)) = state.get("utxos_state_addresses") {
                let remapped: BTreeMap<_, _> = addrs
                    .iter()
                    .map(|(acct, utxos)| {
                        let addr = deposit_addresses
                            .get(acct)
                            .cloned()
                            .unwrap_or(TlaValue::Literal(String::new()));
                        let utxos = match utxos {
                            TlaValue::Set(us) => TlaValue::Set(
                                us.iter()
                                    .map(|u| match u {
                                        TlaValue::Record(r) => {
                                            let mut r = r.clone();
                                            r.insert("owner".to_string(), addr.clone());
                                            TlaValue::Record(r)
                                        }
                                        other => other.clone(),
                                    })
                                    .collect(),
                            ),
                            other => other.clone(),
                        };
                        (acct.clone(), utxos)
                    })
                    .collect();
                state
                    .0
                    .0
                    .insert("utxos_state_addresses".to_string(), TlaValue::Function(remapped));
            }
            if let Some(TlaValue::Set(avail)) = state.get("available_utxos") {
                let remapped: BTreeSet<_> = avail
                    .iter()
                    .map(|u| match u {
                        TlaValue::Record(r) => {
                            let mut r = r.clone();
                            if let Some(id) = r.get("id") {
                                if let Some(owner) = utxo_owner_map.get(id) {
                                    r.insert("owner".to_string(), owner.clone());
                                }
                            }
                            TlaValue::Record(r)
                        }
                        other => other.clone(),
                    })
                    .collect();
                state
                    .0
                    .0
                    .insert("available_utxos".to_string(), TlaValue::Set(remapped));
            }
            if let Some(TlaValue::Seq(reqs)) = state.get("minter_to_btc_canister") {
                let mapped: Vec<_> = reqs
                    .iter()
                    .filter_map(|req| match req {
                        TlaValue::Record(r) => {
                            Some(TlaValue::Record(BTreeMap::from([
                                ("caller_id".to_string(), r.get("caller")?.clone()),
                                ("request".to_string(), r.get("method_and_args")?.clone()),
                            ])))
                        }
                        _ => None,
                    })
                    .collect();
                state
                    .0
                    .0
                    .insert("minter_to_btc_canister".to_string(), TlaValue::Seq(mapped));
            }
            if let Some(TlaValue::Seq(reqs)) = state.get("minter_to_ledger") {
                let mapped: Vec<_> = reqs
                    .iter()
                    .filter_map(|req| match req {
                        TlaValue::Record(r) => {
                            Some(TlaValue::Record(BTreeMap::from([
                                ("caller_id".to_string(), r.get("caller")?.clone()),
                                ("request".to_string(), r.get("method_and_args")?.clone()),
                            ])))
                        }
                        _ => None,
                    })
                    .collect();
                state
                    .0
                    .0
                    .insert("minter_to_ledger".to_string(), TlaValue::Seq(mapped));
            }
            if let Some(TlaValue::Set(resps)) = state.get("btc_canister_to_minter") {
                let mapped: BTreeSet<_> = resps
                    .iter()
                    .filter_map(|resp| match resp {
                        TlaValue::Record(r) => {
                            Some(TlaValue::Record(BTreeMap::from([
                                ("caller_id".to_string(), r.get("caller")?.clone()),
                                ("response".to_string(), r.get("response")?.clone()),
                            ])))
                        }
                        _ => None,
                    })
                    .collect();
                state.0 .0.insert(
                    "btc_canister_to_minter".to_string(),
                    TlaValue::Set(mapped),
                );
            }
            if let Some(TlaValue::Set(resps)) = state.get("ledger_to_minter") {
                let mapped: BTreeSet<_> = resps
                    .iter()
                    .filter_map(|resp| match resp {
                        TlaValue::Record(r) => {
                            Some(TlaValue::Record(BTreeMap::from([
                                ("caller_id".to_string(), r.get("caller")?.clone()),
                                ("status".to_string(), r.get("response")?.clone()),
                            ])))
                        }
                        _ => None,
                    })
                    .collect();
                state
                    .0
                    .0
                    .insert("ledger_to_minter".to_string(), TlaValue::Set(mapped));
            }
        }
    }

    let mut constants = BTreeMap::new();
    constants.insert(
        "PRINCIPALS".to_string(),
        TlaValue::Set(principals.into_iter().collect()),
    );
    constants.insert(
        "SUBACCOUNTS".to_string(),
        TlaValue::Set(subaccounts.into_iter().collect()),
    );
    constants.insert(
        "MINTER_PRINCIPAL".to_string(),
        TlaValue::Literal("minter".to_string()),
    );
    constants.insert(
        "MINTER_SUBACCOUNT".to_string(),
        TlaValue::Literal(String::new()),
    );
    constants.insert(
        "UPDATE_BALANCE_PROCESS_IDS".to_string(),
        TlaValue::Set(BTreeSet::from([UPDATE_BALANCE_PROCESS_ID.to_tla_value()])),
    );
    constants.insert(
        "DEPOSIT_ADDRESS".to_string(),
        TlaValue::Function(deposit_addresses),
    );
    constants.insert(
        "TX_HASH_OP".to_string(),
        TlaValue::Variant {
            tag: "TextHash".to_string(),
            value: Box::new(TlaValue::Constant("UNIT".to_string())),
        },
    );
    constants.insert(
        "CHECK_FEE".to_string(),
        check_fee.unwrap_or_else(|| 0_u64.to_tla_value()),
    );

    TlaConstantAssignment { constants }
}

fn principals_from_accounts<'a, I>(iter: I) -> BTreeSet<TlaValue>
where
    I: IntoIterator<Item = &'a Account>,
{
    iter.into_iter()
        .map(|account| account.owner.to_tla_value())
        .collect()
}

fn opt_subaccount_to_tla(subaccount: Option<Subaccount>) -> TlaValue {
    match subaccount {
        Some(sub) => TlaValue::Literal(hex::encode(sub)),
        None => TlaValue::Literal(String::new()),
    }
}

fn pending_requests_to_tla(state: &CkBtcMinterState) -> TlaValue {
    TlaValue::Seq(
        state
            .pending_retrieve_btc_requests
            .iter()
            .map(|req| {
                TlaValue::Record(BTreeMap::from([
                    ("request_id".to_string(), req.block_index.to_tla_value()),
                    (
                        "address".to_string(),
                        btc_address_to_tla(&req.address.display(state.btc_network)),
                    ),
                    ("value".to_string(), req.amount.to_tla_value()),
                ]))
            })
            .collect(),
    )
}

fn submitted_transactions_to_tla(
    transactions: &[crate::state::SubmittedBtcTransaction],
) -> TlaValue {
    TlaValue::Set(
        transactions
            .iter()
            .map(|tx| {
                TlaValue::Record(BTreeMap::from([
                    (
                        "requests".to_string(),
                        TlaValue::Seq(
                            tx.requests
                                .iter()
                                .map(|req| req.block_index.to_tla_value())
                                .collect(),
                        ),
                    ),
                    ("txid".to_string(), tx.txid.to_string().to_tla_value()),
                    (
                        "used_utxos".to_string(),
                        TlaValue::Set(
                            tx.used_utxos
                                .iter()
                                .map(|u| utxo_to_tla(u, ""))
                                .collect(),
                        ),
                    ),
                    (
                        "change_output".to_string(),
                        tx.change_output
                            .as_ref()
                            .map(|c| {
                                TlaValue::Record(BTreeMap::from([
                                    ("vout".to_string(), c.vout.to_tla_value()),
                                    ("value".to_string(), c.value.to_tla_value()),
                                ]))
                            })
                            .unwrap_or_else(|| {
                                TlaValue::Record(BTreeMap::from([
                                    ("vout".to_string(), 0_u64.to_tla_value()),
                                    ("value".to_string(), 0_u64.to_tla_value()),
                                ]))
                            }),
                    ),
                ]))
            })
            .collect(),
    )
}

fn utxos_state_addresses_to_tla(state: &CkBtcMinterState) -> TlaValue {
    let map: BTreeMap<_, _> = state
        .utxos_state_addresses
        .iter()
        .map(|(account, utxos)| {
            let address = account_to_p2wpkh_address_from_state(state, account);
            (
                account_to_tla(account),
                TlaValue::Set(
                    utxos
                        .iter()
                        .map(|u| utxo_to_tla(u, &address))
                        .collect(),
                ),
            )
        })
        .collect();
    TlaValue::Function(map)
}

fn available_utxos_to_tla(state: &CkBtcMinterState) -> TlaValue {
    let utxos: BTreeSet<_> = state
        .available_utxos
        .iter()
        .map(|u| {
            let address = state
                .outpoint_account
                .get(&u.outpoint)
                .map(|account| account_to_p2wpkh_address_from_state(state, account))
                .unwrap_or_default();
            utxo_to_tla(u, &address)
        })
        .collect();
    TlaValue::Set(utxos)
}

fn finalized_utxos_to_tla(state: &CkBtcMinterState) -> TlaValue {
    let map: BTreeMap<_, _> = state
        .finalized_utxos
        .iter()
        .map(|(account, utxos)| {
            let address = account_to_p2wpkh_address_from_state(state, account);
            (
                account.owner.to_tla_value(),
                TlaValue::Set(
                    utxos
                        .iter()
                        .map(|u| utxo_to_tla(u, &address))
                        .collect(),
                ),
            )
        })
        .collect();
    TlaValue::Function(map)
}

fn outpoint_to_id(outpoint: &OutPoint) -> TlaValue {
    TlaValue::Seq(vec![
        outpoint.txid.to_string().to_tla_value(),
        outpoint.vout.to_tla_value(),
    ])
}

pub fn dummy_utxo() -> TlaValue {
    TlaValue::Record(BTreeMap::from([
        (
            "id".to_string(),
            TlaValue::Seq(vec![
                TlaValue::Literal("x".to_string()),
                0_u64.to_tla_value(),
            ]),
        ),
        ("owner".to_string(), TlaValue::Literal("dummy_address".to_string())),
        ("value".to_string(), 0_u64.to_tla_value()),
    ]))
}

fn default_ckbtc_address() -> TlaValue {
    TlaValue::Record(BTreeMap::from([
        ("owner".to_string(), TlaValue::Literal("minter".to_string())),
        ("subaccount".to_string(), TlaValue::Literal(String::new())),
    ]))
}
