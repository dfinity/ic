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
        start_label: Label::new("ClaimNeuron1"),  // TODO: sync this label
        end_label: Label::new("Done"), // TODO: sync this label
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
    //TODO
}

fn post_process_trace(trace: &mut Vec<ResolvedStatePair>) {
    //TODO
}
