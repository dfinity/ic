use lazy_static::lazy_static;
use tla_instrumentation::{Label, ResolvedStatePair, TlaConstantAssignment, Update, VarAssignment};

use super::common::governance_account_id;
use super::{extract_common_constants, post_process_trace};

lazy_static! {
    pub static ref SPAWN_NEURON_DESC: Update = {
        const PID: &str = "Spawn_Neuron";
        let default_locals = VarAssignment::new();

        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: Label::new("SpawnNeuronStart"),
            end_label: Label::new("SpawnNeuronStart"),
            process_id: PID.to_string(),
            canister_name: "governance".to_string(),
            post_process: |trace| {
                let constants = extract_spawn_neuron_constants(PID, trace);
                post_process_trace(trace);
                constants
            },
        }
    };
}

fn extract_spawn_neuron_constants(pid: &str, trace: &[ResolvedStatePair]) -> TlaConstantAssignment {
    TlaConstantAssignment {
        constants: extract_common_constants(pid, trace)
            .into_iter()
            .chain([("Minting_Account_Id".to_string(), governance_account_id())])
            .collect(),
    }
}
