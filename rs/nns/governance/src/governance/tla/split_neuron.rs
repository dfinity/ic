use std::collections::{BTreeMap, BTreeSet};
use tla_instrumentation::{
    Label, ResolvedStatePair, TlaConstantAssignment, TlaValue, ToTla, Update, VarAssignment,
};

use super::common::{default_account, function_domain_union, governance_account_id};

pub fn split_neuron_desc() -> Update {
    const PID: &str = "Split_Neuron";
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
