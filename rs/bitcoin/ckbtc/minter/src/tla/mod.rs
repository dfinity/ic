use ic_btc_interface::{OutPoint, Utxo};
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use lazy_static::lazy_static;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::Hash;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use tla_instrumentation::{
    GlobalState, ResolvedStatePair, TlaConstantAssignment, TlaValue, ToTla, Update, VarAssignment,
};

use crate::state::{self, CkBtcMinterState};
use crate::updates::get_btc_address::account_to_p2wpkh_address_from_state;

mod store;

pub use store::{TLA_INSTRUMENTATION_STATE, TLA_TRACES_LKEY, TLA_TRACES_MUTEX};
pub use tla_instrumentation::checker::{PredicateDescription, check_tla_code_link};
pub use tla_instrumentation::{UpdateTrace, disable_tla, enable_tla};

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

pub fn retrieve_btc_desc() -> Update {
    let default_locals = VarAssignment::new()
        .add("caller_account", default_ckbtc_address())
        .add("utxos", TlaValue::Set(BTreeSet::new()))
        .add("utxo", dummy_utxo());
    Update {
        default_start_locals: default_locals.clone(),
        default_end_locals: default_locals,
        start_label: tla_instrumentation::Label::new("Retrieve_BTC_Start"),
        end_label: tla_instrumentation::Label::new("Retrieve_BTC_Start"),
        process_id: "Retrieve_BTC".to_string(),
        canister_name: "minter".to_string(),
        post_process: |trace| post_process_update_balance(trace),
    }
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

fn dedup_by_key<E, K, F>(vec: &mut Vec<E>, mut key_selector: F)
where
    F: FnMut(&E) -> K,
    K: Eq + Hash,
{
    let mut seen_keys = HashSet::new();
    vec.retain(|element| seen_keys.insert(key_selector(element)));
}

// Add JAVABASE/bin to PATH to make the Bazel-provided JRE available to scripts
fn set_java_path() {
    let current_path = std::env::var("PATH").expect("PATH is not set");
    let bazel_java = std::env::var("JAVABASE")
        .expect("JAVABASE is not set; have you added the bazel tools toolchain?");
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var("PATH", format!("{current_path}:{bazel_java}/bin")) };
}

/// Returns the path to the TLA module (e.g. `Foo.tla` -> `/home/me/tla/Foo.tla`)
/// TLA modules are read from $TLA_MODULES (space-separated list)
/// NOTE: this assumes unique basenames amongst the modules
fn get_tla_module_path(module: &str) -> PathBuf {
    let modules = std::env::var("TLA_MODULES").expect(
        "environment variable 'TLA_MODULES' should be a space-separated list of TLA modules",
    );

    modules
        .split(" ")
        .map(|f| f.into()) /* str -> PathBuf */
        .find(|f: &PathBuf| f.file_name().is_some_and(|file_name| file_name == module))
        .unwrap_or_else(|| {
            panic!("Could not find TLA module {module}, check 'TLA_MODULES' is set correctly")
        })
}
pub fn perform_trace_check(traces: Vec<UpdateTrace>) {
    // Large states make Apalache time and memory consumption explode. We'll look at
    // improving that later, for now we introduce a hard limit on the state size, and
    // skip checking states larger than the limit. The limit is a somewhat arbitrary
    // number based on what we observed in the tests. We saw that states with 1000+ atoms take
    // a long time to process, whereas most manual tests yield states of size 100 or so.
    const STATE_SIZE_LIMIT: u64 = 500;
    // Proptests generate lots of traces (and thus state pairs) that make the Apalache testing very long.
    // Again, limit this to some arbitrary number where checking is still reasonably fast.
    // Note that this is effectively a per-test limit due to how `check_traces` is normally used.
    const STATE_PAIR_COUNT_LIMIT: usize = 30;
    fn is_under_limit(p: &ResolvedStatePair) -> bool {
        p.start.size() < STATE_SIZE_LIMIT && p.end.size() < STATE_SIZE_LIMIT
    }

    fn print_stats(traces: &Vec<UpdateTrace>) {
        let mut total_pairs = 0;
        ic_cdk::println!("Checking {} traces with TLA/Apalache", traces.len());
        for t in traces {
            let total_len = t.state_pairs.len();
            total_pairs += total_len;
            let under_limit_len = t.state_pairs.iter().filter(|p| is_under_limit(p)).count();
            ic_cdk::println!(
                "TLA/Apalache checks: keeping {}/{} state pairs for update {}",
                under_limit_len,
                total_len,
                t.model_name
            );
        }
        ic_cdk::println!(
            "Total of {} state pairs to be checked with Apalache; will retain at most {}",
            total_pairs,
            STATE_PAIR_COUNT_LIMIT
        )
    }
    print_stats(&traces);

    let mut all_pairs = traces
        .into_iter()
        .flat_map(|t| {
            t.state_pairs
                .into_iter()
                .filter(is_under_limit)
                .map(move |p| (t.model_name.clone(), t.constants.clone(), p))
        })
        .collect();

    // A quick check that we don't have any duplicate state pairs. We assume the constants should
    // be the same anyways and look at just the model name and the state sthemselves.
    dedup_by_key(&mut all_pairs, |(model_name, _c, p)| {
        (model_name.clone(), p.start.clone(), p.end.clone())
    });

    all_pairs.truncate(STATE_PAIR_COUNT_LIMIT);

    set_java_path();

    let apalache = std::env::var("TLA_APALACHE_BIN")
        .expect("environment variable 'TLA_APALACHE_BIN' should point to the apalache binary");
    let apalache = PathBuf::from(apalache);

    if !apalache.as_path().is_file() {
        panic!("bad apalache bin from 'TLA_APALACHE_BIN': '{apalache:?}'");
    }

    // A poor man's parallel_map; process up to MAX_THREADS state pairs in parallel. Use mpsc channels
    // to signal threads becoming available. Additionally, use the channels to signal any errors while
    // performing the Apalache checks.
    const MAX_THREADS: usize = 20;
    let mut running_threads = 0;
    let (thread_freed_tx, thread_freed_rx) = mpsc::channel::<bool>();
    for (i, (model_name, constants, pair)) in all_pairs.iter().enumerate() {
        ic_cdk::println!("Checking state pair #{}", i + 1);
        if running_threads >= MAX_THREADS {
            if thread_freed_rx
                .recv()
                .expect("Error while waiting for the thread completion signal")
            {
                panic!("An Apalache thread signalled an error")
            }
            running_threads -= 1;
        }

        let thread_freed_rx = thread_freed_tx.clone();
        let apalache = apalache.clone();
        let constants = constants.clone();
        let pair = pair.clone();
        // NOTE: We adopt the convention to reuse the 'process_id" as the tla module name
        let tla_module = format!("{model_name}_Apalache.tla");
        let tla_module = get_tla_module_path(&tla_module);

        running_threads += 1;
        let _handle = thread::spawn(move || {
            let res = check_tla_code_link(
                &apalache,
                PredicateDescription {
                    tla_module,
                    transition_predicate: "Next".to_string(),
                    predicate_parameters: Vec::new(),
                },
                pair,
                constants,
            ).map_err(|e| {
                if e.apalache_error.is_likely_mismatch() {
                    ic_cdk::println!("Possible divergence from the TLA model detected when interacting with the ledger!");
                    ic_cdk::println!("If you did not expect to change the interaction between governance and the ledger, reconsider whether your change is safe. You can find additional data on the step that triggered the error below.");
                    ic_cdk::println!("If you are confident that your change is correct, please contact the #formal-models Slack channel and describe the problem.");
                } else {
                    ic_cdk::println!("An error detected while checking the TLA model.");
                    ic_cdk::println!("The types may have diverged, or there might be something wrong with the TLA/Apalache setup");
                }
                ic_cdk::println!("You can edit nns/governance/feature_flags.bzl to disable TLA checks in the CI and get on with your business.");
                ic_cdk::println!("-------------------");
                ic_cdk::println!("Error occured in TLA model {:?} and state pair:\n{:#?}\nwith constants:\n{:#?}", e.model, e.pair, e.constants);
                let diff = e.pair.diff();
                if !diff.is_empty() {
                    ic_cdk::println!("Diff between states: {:#?}", diff);
                }
                ic_cdk::println!("Apalache returned:\n{:#?}", e.apalache_error);
            });
            thread_freed_rx
                .send(res.is_err())
                .expect("Couldn't send the thread completion signal");
        });
    }

    while running_threads > 0 {
        if thread_freed_rx
            .recv()
            .expect("Error while waiting for the thread completion signal")
        {
            panic!("An Apalache thread signalled an error")
        }
        running_threads -= 1;
    }
}

fn snapshot_state(state: &CkBtcMinterState) -> GlobalState {
    let mut gs = GlobalState::new();

    let update_balance_locks = principals_from_accounts(state.update_balance_accounts.iter());
    let retrieve_btc_locks = principals_from_accounts(state.retrieve_btc_accounts.iter());

    gs.add("update_balance_locks", TlaValue::Set(update_balance_locks));
    gs.add("retrieve_btc_locks", TlaValue::Set(retrieve_btc_locks));
    gs.add("locks", TlaValue::Set(BTreeSet::new()));
    gs.add("pending", pending_requests_to_tla(state));
    gs.add(
        "submitted_transactions",
        submitted_transactions_to_tla(&state.submitted_transactions),
    );
    gs.add("utxos_state_addresses", utxos_state_addresses_to_tla(state));
    gs.add("available_utxos", available_utxos_to_tla(state));
    gs.add("finalized_utxos", finalized_utxos_to_tla(state));
    gs.add("check_fee", state.check_fee.to_tla_value());

    gs
}

fn post_process_update_balance(
    trace: &mut [tla_instrumentation::ResolvedStatePair],
) -> TlaConstantAssignment {
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
            if let Some(fee) = state.0.0.remove("check_fee") {
                check_fee = Some(fee);
            }
            state.0.0.remove("btc_address");
            // If locals were missing, infer deposit address from any recorded utxos.
            if let Some(TlaValue::Function(addrs)) = state.get("utxos_state_addresses") {
                for (acct, utxos) in addrs {
                    if deposit_addresses.contains_key(acct) {
                        continue;
                    }
                    if let TlaValue::Set(us) = utxos
                        && let Some(TlaValue::Record(first)) = us.iter().next()
                        && let Some(owner) = first.get("owner")
                    {
                        deposit_addresses.insert(acct.clone(), owner.clone());
                    }
                }
            }
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
                    if let Some(addr) = deposit_addresses.get(acct)
                        && let TlaValue::Set(us) = utxos
                    {
                        for u in us {
                            if let TlaValue::Record(r) = u
                                && let Some(id) = r.get("id")
                            {
                                utxo_owner_map.insert(id.clone(), addr.clone());
                            }
                        }
                    }
                }
            }
            if let Some(TlaValue::Function(addrs)) = state.get("utxos_state_addresses") {
                let remapped: BTreeMap<_, _> = addrs
                    .iter()
                    .map(|(acct, utxos)| {
                        if let Some(addr) = deposit_addresses.get(acct) {
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
                        } else {
                            (acct.clone(), utxos.clone())
                        }
                    })
                    .collect();
                state.0.0.insert(
                    "utxos_state_addresses".to_string(),
                    TlaValue::Function(remapped),
                );
            }
            if let Some(TlaValue::Set(avail)) = state.get("available_utxos") {
                let remapped: BTreeSet<_> = avail
                    .iter()
                    .map(|u| match u {
                        TlaValue::Record(r) => {
                            let mut r = r.clone();
                            if let Some(id) = r.get("id")
                                && let Some(owner) = utxo_owner_map.get(id)
                            {
                                r.insert("owner".to_string(), owner.clone());
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
                        TlaValue::Record(r) => Some(TlaValue::Record(BTreeMap::from([
                            ("caller_id".to_string(), r.get("caller")?.clone()),
                            ("request".to_string(), r.get("method_and_args")?.clone()),
                        ]))),
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
                        TlaValue::Record(r) => Some(TlaValue::Record(BTreeMap::from([
                            ("caller_id".to_string(), r.get("caller")?.clone()),
                            ("request".to_string(), r.get("method_and_args")?.clone()),
                        ]))),
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
                        TlaValue::Record(r) => Some(TlaValue::Record(BTreeMap::from([
                            ("caller_id".to_string(), r.get("caller")?.clone()),
                            ("response".to_string(), r.get("response")?.clone()),
                        ]))),
                        _ => None,
                    })
                    .collect();
                state
                    .0
                    .0
                    .insert("btc_canister_to_minter".to_string(), TlaValue::Set(mapped));
            }
            if let Some(TlaValue::Set(resps)) = state.get("ledger_to_minter") {
                let mapped: BTreeSet<_> = resps
                    .iter()
                    .filter_map(|resp| match resp {
                        TlaValue::Record(r) => Some(TlaValue::Record(BTreeMap::from([
                            ("caller_id".to_string(), r.get("caller")?.clone()),
                            ("status".to_string(), r.get("response")?.clone()),
                        ]))),
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
                        TlaValue::Set(tx.used_utxos.iter().map(|u| utxo_to_tla(u, "")).collect()),
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
            let address = account_address_from_state_or_empty(state, account);
            (
                account_to_tla(account),
                TlaValue::Set(utxos.iter().map(|u| utxo_to_tla(u, &address)).collect()),
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
                .map(|account| account_address_from_state_or_empty(state, account))
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
            let address = account_address_from_state_or_empty(state, account);
            (
                account.owner.to_tla_value(),
                TlaValue::Set(utxos.iter().map(|u| utxo_to_tla(u, &address)).collect()),
            )
        })
        .collect();
    TlaValue::Function(map)
}

fn account_address_from_state_or_empty(state: &CkBtcMinterState, account: &Account) -> String {
    state
        .ecdsa_public_key
        .as_ref()
        .map(|_| account_to_p2wpkh_address_from_state(state, account))
        .unwrap_or_default()
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
        (
            "owner".to_string(),
            TlaValue::Literal("dummy_address".to_string()),
        ),
        ("value".to_string(), 0_u64.to_tla_value()),
    ]))
}

fn default_ckbtc_address() -> TlaValue {
    TlaValue::Record(BTreeMap::from([
        ("owner".to_string(), TlaValue::Literal("minter".to_string())),
        ("subaccount".to_string(), TlaValue::Literal(String::new())),
    ]))
}
