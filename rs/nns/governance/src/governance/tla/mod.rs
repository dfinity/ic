use itertools::Itertools;
use std::collections::BTreeMap;
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
pub use store::{TLA_INSTRUMENTATION_STATE, TLA_TRACES};

mod split_neuron;
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

// Add JAVABASE/bin to PATH to make the Bazel-provided JRE available to scripts
fn set_java_path() {
    let current_path = std::env::var("PATH").expect("PATH is not set");
    let bazel_java = std::env::var("JAVABASE")
        .expect("JAVABASE is not set; have you added the bazel tools toolchain?");
    std::env::set_var("PATH", format!("{current_path}:{bazel_java}/bin"));
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
    let runfiles_dir = std::env::var("RUNFILES_DIR").expect("RUNFILES_DIR is not set");

    // Construct paths to the data files
    let apalache = PathBuf::from(&runfiles_dir).join("tla_apalache/bin/apalache-mc");
    let tla_models_path = PathBuf::from(&runfiles_dir).join("ic/rs/nns/governance/tla");

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
            let tla_module = tla_models_path.join(format!("{}_Apalache.tla", update.process_id));
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
