use itertools::Itertools;
use std::collections::{BTreeMap, BTreeSet};
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
pub use store::{TLA_INSTRUMENTATION_STATE, TLA_TRACES};

mod split_neuron;
pub use split_neuron::split_neuron_desc;
mod claim_neuron;
pub use claim_neuron::claim_neuron_desc;

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

/// Checks a trace against the model.
///
/// It's assumed that the corresponding model is called `<PID>_Apalache.tla`, where PID is the
/// `process_id`` field used in the `Update` value for the corresponding method.
pub fn check_traces() {
    let traces = {
        // Introduce a scope to drop the write lock immediately, in order
        // not to poison the lock if we panic later
        let mut t = TLA_TRACES.write().unwrap();
        std::mem::take(&mut (*t))
    };

    set_java_path();

    let apalache = std::env::var("TLA_APALACHE_BIN")
        .expect("environment variable 'TLA_APALACHE_BIN' should point to the apalache binary");
    let apalache = PathBuf::from(apalache);

    if !apalache.as_path().is_file() {
        panic!("bad apalache bin from 'TLA_APALACHE_BIN': '{:?}'", apalache);
    }

    let chunk_size = 20;
    let all_pairs = traces.into_iter().flat_map(|t| {
        t.state_pairs
            .into_iter()
            .map(move |p| (t.update.clone(), t.constants.clone(), p))
    });
    let chunks = all_pairs.chunks(chunk_size);
    for chunk in &chunks {
        let mut handles = vec![];
        for (update, constants, pair) in chunk {
            let apalache = apalache.clone();
            let constants = constants.clone();
            let pair = pair.clone();
            // NOTE: We adopt the convention to reuse the 'process_id" as the tla module name
            let tla_module = format!("{}_Apalache.tla", update.process_id);
            let tla_module = get_tla_module_path(&tla_module);
            let handle = thread::spawn(move || {
                check_tla_code_link(
                    &apalache,
                    PredicateDescription {
                        tla_module,
                        transition_predicate: "Next".to_string(),
                        predicate_parameters: Vec::new(),
                    },
                    pair,
                    constants,
                )
            });
            handles.push(handle);
        }
        for handle in handles {
            handle.join().unwrap().unwrap_or_else(|e| {
                println!("Possible divergence from the TLA model detected when interacting with the ledger!");
                println!("If you did not expect to change the interaction between governance and the ledger, reconsider whether your change is safe. You can find additional data on the step that triggered the error below.");
                println!("If you are confident that your change is correct, please contact the #formal-models Slack channel and describe the problem.");
                println!("You can edit nervous_system/tla/feature_flags.bzl to disable TLA checks in the CI and get on with your business.");
                println!("-------------------");
                println!("Error occured while checking the state pair:\n{:#?}\nwith constants:\n{:#?}", e.pair, e.constants);
                println!("Apalache returned:\n{:#?}", e.apalache_error);
                panic!("Apalache check failed")
            });
        }
    }
}
