use std::collections::{BTreeMap, BTreeSet};
use tla_instrumentation::{
    Label, ResolvedStatePair, TlaConstantAssignment, TlaValue, ToTla, Update, VarAssignment,
};

pub fn claim_neuron_desc() -> Update {
    const PID: &str = "Claim_Neuron";
    let default_locals = VarAssignment::new()
        .add("account_id", default_account())
        .add("balance", 0_u64.to_tla_value())
        .add("neuron_id", 0_u64.to_tla_value());

    Update {
        default_start_locals: default_locals.clone(),
        default_end_locals: default_locals,
        start_label: Label::new("ClaimNeuron1"),
        end_label: Label::new("Done"),
        process_id: PID.to_string(),
        canister_name: "governance".to_string(),
        post_process: |trace| {
            let constants = extract_claim_neuron_constants(PID, trace);
            post_process_trace(trace);
            constants
        },
    }
}

fn extract_claim_neuron_constants(pid: &str, trace: &[ResolvedStatePair]) -> TlaConstantAssignment {
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
            "Claim_Neuron_Process_Ids".to_string(),
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
    //TODO
}
