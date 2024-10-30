use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::Hash;
use std::sync::mpsc;
use std::thread;

use super::Governance;
use crate::storage::{with_stable_neuron_indexes, with_stable_neuron_store};

pub use tla_instrumentation::{
    Destination, GlobalState, InstrumentationState, Label, ResolvedStatePair,
    TlaConstantAssignment, TlaValue, ToTla, Update, UpdateTrace, VarAssignment,
};
pub use tla_instrumentation_proc_macros::tla_update_method;

pub use tla_instrumentation::checker::{check_tla_code_link, PredicateDescription};

use std::path::PathBuf;

use icp_ledger::Subaccount;
mod common;
mod store;

pub use common::{account_to_tla, opt_subaccount_to_tla, subaccount_to_tla};
use common::{function_domain_union, governance_account_id};
pub use store::{TLA_INSTRUMENTATION_STATE, TLA_TRACES_LKEY, TLA_TRACES_MUTEX};

mod claim_neuron;
mod merge_neurons;
mod split_neuron;

pub use claim_neuron::claim_neuron_desc;
pub use merge_neurons::merge_neurons_desc;
pub use split_neuron::split_neuron_desc;

fn neuron_global(gov: &Governance) -> TlaValue {
    let neuron_map: BTreeMap<u64, TlaValue> = with_stable_neuron_store(|store| {
        gov.neuron_store
            .active_neurons_iter()
            .cloned()
            .chain(store.range_neurons(std::ops::RangeFull))
            .map(|neuron| {
                (
                    neuron.id().id,
                    TlaValue::Record(BTreeMap::from([
                        (
                            "cached_stake".to_string(),
                            neuron.cached_neuron_stake_e8s.to_tla_value(),
                        ),
                        (
                            "account".to_string(),
                            subaccount_to_tla(&neuron.subaccount()),
                        ),
                        ("fees".to_string(), neuron.neuron_fees_e8s.to_tla_value()),
                        (
                            "maturity".to_string(),
                            neuron.maturity_e8s_equivalent.to_tla_value(),
                        ),
                    ])),
                )
            })
            .collect()
    });
    neuron_map.to_tla_value()
}

fn raw_subaccount_to_tla_value(account: [u8; 32]) -> TlaValue {
    subaccount_to_tla(
        &Subaccount::try_from(&account[..]).expect("Couldn't parse the array as a subaccount"),
    )
}

fn neuron_id_by_account() -> TlaValue {
    with_stable_neuron_indexes(|index| {
        let map: BTreeMap<TlaValue, u64> = index
            .subaccounts()
            .iter()
            .map(|(k, v)| (raw_subaccount_to_tla_value(k), v.id))
            .collect();
        map.to_tla_value()
    })
}

pub fn get_tla_globals(gov: &Governance) -> GlobalState {
    let mut state = GlobalState::new();
    state.add(
        "locks",
        TlaValue::Set(
            gov.heap_data
                .in_flight_commands
                .keys()
                .map(|v| v.to_tla_value())
                .collect(),
        ),
    );
    state.add("neuron", neuron_global(gov));
    state.add("neuron_id_by_account", neuron_id_by_account());
    state.add(
        "min_stake",
        gov.heap_data
            .economics
            .as_ref()
            .expect("Governance must have economics.")
            .neuron_minimum_stake_e8s
            .to_tla_value(),
    );
    state.add("transaction_fee", gov.transaction_fee().to_tla_value());
    state
}

fn extract_common_constants(pid: &str, trace: &[ResolvedStatePair]) -> Vec<(String, TlaValue)> {
    vec![
        (
            format!("{}_Process_Ids", pid),
            BTreeSet::from([pid]).to_tla_value(),
        ),
        (
            "Neuron_Ids".to_string(),
            function_domain_union(trace, "neuron").to_tla_value(),
        ),
        (
            "MIN_STAKE".to_string(),
            trace
                .first()
                .map(|pair| {
                    pair.start
                        .get("min_stake")
                        .expect("min_stake not recorded")
                        .clone()
                })
                .unwrap_or(0_u64.to_tla_value()),
        ),
        (
            "TRANSACTION_FEE".to_string(),
            trace
                .first()
                .map(|pair| {
                    pair.start
                        .get("transaction_fee")
                        .expect("transaction_fee not recorded")
                        .clone()
                })
                .unwrap_or(0_u64.to_tla_value()),
        ),
        ("Governance_Account_Ids".to_string(), {
            let mut ids = function_domain_union(trace, "neuron_id_by_account");
            ids.insert(governance_account_id());
            ids.to_tla_value()
        }),
    ]
}

fn post_process_trace(trace: &mut Vec<ResolvedStatePair>) {
    for ResolvedStatePair {
        ref mut start,
        ref mut end,
        ..
    } in trace
    {
        for state in &mut [start, end] {
            state
                .0
                 .0
                .remove("transaction_fee")
                .expect("Didn't record the transaction fee");
            state
                .0
                 .0
                .remove("min_stake")
                .expect("Didn't record the min stake");
            if !state.0 .0.contains_key("governance_to_ledger") {
                state.0 .0.insert(
                    "governance_to_ledger".to_string(),
                    TlaValue::Seq(Vec::new()),
                );
            }
            if !state.0 .0.contains_key("ledger_to_governance") {
                state.0 .0.insert(
                    "ledger_to_governance".to_string(),
                    TlaValue::Set(BTreeSet::new()),
                );
            }
        }
    }
}

// Add JAVABASE/bin to PATH to make the Bazel-provided JRE available to scripts
fn set_java_path() {
    let current_path = std::env::var("PATH").expect("PATH is not set");
    let bazel_java = std::env::var("JAVABASE")
        .expect("JAVABASE is not set; have you added the bazel tools toolchain?");
    std::env::set_var("PATH", format!("{current_path}:{bazel_java}/bin"));
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

fn dedup_by_key<E, K, F>(vec: &mut Vec<E>, mut key_selector: F)
where
    F: FnMut(&E) -> K,
    K: Eq + Hash,
{
    let mut seen_keys = HashSet::new();
    vec.retain(|element| seen_keys.insert(key_selector(element)));
}

/// Checks a trace against the model.
///
/// It's assumed that the corresponding model is called `<PID>_Apalache.tla`, where PID is the
/// `process_id`` field used in the `Update` value for the corresponding method.
pub fn check_traces() {
    // Large states make Apalache time and memory consumption explode. We'll look at
    // improving that later, for now we introduce a hard limit on the state size, and
    // skip checking states larger than the limit. The limit is a somewhat arbitrary
    // number based on what we observed in the tests. States with 1000+ atoms take
    // a long time to process, whereas most manual tests yield states of size 100 or so.
    const STATE_SIZE_LIMIT: u64 = 500;
    // Proptests generate lots of traces that make the Apalache testing very long.
    // Again, limit this to some arbitrary number where checking is still reasonably fast.
    const STATE_PAIR_COUNT_LIMIT: usize = 30;
    fn is_under_limit(p: &ResolvedStatePair) -> bool {
        p.start.size() < STATE_SIZE_LIMIT && p.end.size() < STATE_SIZE_LIMIT
    }

    fn print_stats(traces: &Vec<UpdateTrace>) {
        let mut total_pairs = 0;
        println!("Checking {} traces with TLA/Apalache", traces.len());
        for t in traces {
            let total_len = t.state_pairs.len();
            total_pairs += total_len;
            let under_limit_len = t.state_pairs.iter().filter(|p| is_under_limit(p)).count();
            println!(
                "TLA/Apalache checks: keeping {}/{} state pairs for update {}",
                under_limit_len, total_len, t.update.process_id
            );
        }
        println!(
            "Total of {} state pairs to be checked with Apalache; will retain {}",
            total_pairs, STATE_PAIR_COUNT_LIMIT
        )
    }

    let traces = {
        let t = TLA_TRACES_LKEY.get();
        let mut t = t.borrow_mut();
        std::mem::take(&mut (*t))
    };

    print_stats(&traces);

    let mut all_pairs = traces
        .into_iter()
        .flat_map(|t| {
            t.state_pairs
                .into_iter()
                .filter(is_under_limit)
                .map(move |p| (t.update.clone(), t.constants.clone(), p))
        })
        .collect();

    // A quick check that we don't have any duplicate state pairs. We assume the constants should
    // be the same anyways and look at just the process ID and the state sthemselves.
    dedup_by_key(&mut all_pairs, |(u, _c, p)| {
        (u.process_id.clone(), p.start.clone(), p.end.clone())
    });

    all_pairs.truncate(STATE_PAIR_COUNT_LIMIT);

    set_java_path();

    let apalache = std::env::var("TLA_APALACHE_BIN")
        .expect("environment variable 'TLA_APALACHE_BIN' should point to the apalache binary");
    let apalache = PathBuf::from(apalache);

    if !apalache.as_path().is_file() {
        panic!("bad apalache bin from 'TLA_APALACHE_BIN': '{:?}'", apalache);
    }

    // A poor man's parallel_map; process up to 20 state pairs in parallel. Use mpsc channels
    // to signal threads becoming available.
    const MAX_THREADS: usize = 20;
    let mut running_threads = 0;
    let (tx, rx) = mpsc::channel::<()>();
    for (i, (update, constants, pair)) in all_pairs.iter().enumerate() {
        println!("Checking state pair #{}", i + 1);
        if running_threads >= MAX_THREADS {
            rx.recv()
                .expect("Error while waiting for the thread completion signal");
            running_threads -= 1;
        }

        let tx = tx.clone();
        let apalache = apalache.clone();
        let constants = constants.clone();
        let pair = pair.clone();
        // NOTE: We adopt the convention to reuse the 'process_id" as the tla module name
        let tla_module = format!("{}_Apalache.tla", update.process_id);
        let tla_module = get_tla_module_path(&tla_module);

        running_threads += 1;
        let _handle = thread::spawn(move || {
            let _ = check_tla_code_link(
                &apalache,
                PredicateDescription {
                    tla_module,
                    transition_predicate: "Next".to_string(),
                    predicate_parameters: Vec::new(),
                },
                pair,
                constants,
            ).map_err(|e| {
                println!("Possible divergence from the TLA model detected when interacting with the ledger!");
                println!("If you did not expect to change the interaction between governance and the ledger, reconsider whether your change is safe. You can find additional data on the step that triggered the error below.");
                println!("If you are confident that your change is correct, please contact the #formal-models Slack channel and describe the problem.");
                println!("You can edit nns/governance/feature_flags.bzl to disable TLA checks in the CI and get on with your business.");
                println!("-------------------");
                println!("Error occured while checking the state pair:\n{:#?}\nwith constants:\n{:#?}", e.pair, e.constants);
                println!("Apalache returned:\n{:#?}", e.apalache_error);
                panic!("Apalache check failed")
            });
            tx.send(())
                .expect("Couldn't send the thread completion signal");
        });
    }

    while running_threads > 0 {
        rx.recv()
            .expect("Error while waiting for the thread completion signal");
        running_threads -= 1;
    }
}
