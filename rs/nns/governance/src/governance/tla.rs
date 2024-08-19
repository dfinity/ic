use itertools::Itertools;
use std::collections::{BTreeMap, BTreeSet};
use std::thread;

use super::Governance;
use crate::storage::with_stable_neuron_indexes;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;

pub use tla_instrumentation::{
    Destination, GlobalState, InstrumentationState, Label, ResolvedStatePair,
    TlaConstantAssignment, TlaValue, ToTla, Update, UpdateTrace, VarAssignment,
};
pub use tla_instrumentation_proc_macros::tla_update_method;

pub use tla_instrumentation::checker::{check_tla_code_link, PredicateDescription};

pub use ic_nervous_system_common::tla::{
    account_to_tla, opt_subaccount_to_tla, TLA_INSTRUMENTATION_STATE, TLA_TRACES,
};
pub use ic_nervous_system_common::{tla_log_locals, tla_log_request, tla_log_response};

use std::path::PathBuf;

use icp_ledger::{AccountIdentifier, Subaccount};

fn neuron_global(gov: &Governance) -> TlaValue {
    let neuron_map: BTreeMap<u64, TlaValue> = gov
        .neuron_store
        .heap_neurons()
        .iter()
        .map(|(neuron_id, neuron)| {
            (
                neuron_id.clone(),
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
        .collect();
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

#[macro_export]
macro_rules! tla_get_globals {
    ($self:expr) => {
        tla::get_tla_globals($self)
    };
}

fn function_domain_union(
    state_pairs: &Vec<ResolvedStatePair>,
    field_name: &str,
) -> BTreeSet<TlaValue> {
    state_pairs.iter().flat_map(|pair| {
        match (pair.start.get(field_name), pair.end.get(field_name)) {
            (Some(TlaValue::Function(sf)), Some(TlaValue::Function(ef))) => {
                sf.keys().chain(ef.keys()).cloned()
            }
            _ => {
                panic!("Field {} not found in the start or end state, or not a function, when computing the union", field_name)
            }
        }
    }
    ).collect()
}

fn governance_account_id() -> TlaValue {
    AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        None,
    )
    .to_string()
    .as_str()
    .to_tla_value()
}

fn default_account() -> TlaValue {
    "".to_tla_value()
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

fn extract_split_neuron_constants(
    pid: &str,
    trace: &Vec<ResolvedStatePair>,
) -> TlaConstantAssignment {
    let constants = BTreeMap::from([
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
        ("Minting_Account_Id".to_string(), governance_account_id()),
        (
            "Split_Neuron_Process_Ids".to_string(),
            BTreeSet::from([pid]).to_tla_value(),
        ),
        ("Governance_Account_Ids".to_string(), {
            let mut ids = function_domain_union(trace, "neuron_id_by_account");
            ids.insert(governance_account_id());
            ids.to_tla_value()
        }),
    ]);
    TlaConstantAssignment { constants }
}

pub fn split_neuron_desc() -> Update {
    const PID: &str = "Split_Neuron_PID";
    let default_locals = VarAssignment::new()
        .add("sn_amount", 0_u64.to_tla_value())
        .add("sn_parent_neuron_id", 0_u64.to_tla_value())
        .add("sn_child_neuron_id", 0_u64.to_tla_value())
        .add("sn_child_account_id", default_account());

    Update {
        default_start_locals: default_locals.clone(),
        default_end_locals: default_locals,
        start_label: Label::new("SplitNeuron1"),
        end_label: Label::new("Done"),
        process_id: PID.to_string(),
        canister_name: "governance".to_string(),
        post_process: |trace| {
            let constants = extract_split_neuron_constants(PID, trace);
            post_process_trace(trace);
            constants
        },
    }
}

// TODO: use a different model for each update
pub fn check_traces() {
    let mut traces = TLA_TRACES.write().unwrap();
    let traces = std::mem::take(&mut (*traces));

    let runfiles_dir = std::env::var("RUNFILES_DIR").expect("RUNFILES_DIR is not set");

    // Construct paths to the data files
    let apalache = PathBuf::from(&runfiles_dir).join("tla_apalache/bin/apalache-mc");
    let tla_models_path = PathBuf::from(&runfiles_dir).join("ic/rs/nns/governance/tla");
    let split_neuron_model = tla_models_path.join("Split_Neuron_Apalache.tla");

    let chunk_size = 20;
    let all_pairs = traces.into_iter().flat_map(|t| {
        t.state_pairs
            .into_iter()
            .map(move |p| (t.constants.clone(), p))
    });
    let chunks = all_pairs.chunks(chunk_size);
    for chunk in &chunks {
        let mut handles = vec![];
        for (constants, pair) in chunk {
            let apalache = apalache.clone();
            let constants = constants.clone();
            let pair = pair.clone();
            let tla_module = split_neuron_model.clone();
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
            handle.join().unwrap().expect("Apalache call failed");
        }
    }
}
