use super::{extract_common_constants, post_process_trace};
use lazy_static::lazy_static;
use tla_instrumentation::{Label, TlaConstantAssignment, ToTla, Update, VarAssignment};

const PID: &str = "Disburse_To_Neuron";
lazy_static! {
    pub static ref DISBURSE_TO_NEURON_DESC: Update = {
        let default_locals = VarAssignment::new()
            .add("parent_neuron_id", 0_u64.to_tla_value())
            .add("disburse_amount", 0_u64.to_tla_value())
            .add("child_account_id", "".to_tla_value())
            .add("child_neuron_id", 0_u64.to_tla_value());
        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: Label::new("DisburseToNeuron"),
            end_label: Label::new("Done"),
            process_id: PID.to_string(),
            canister_name: "governance".to_string(),
            post_process: |trace| {
                let constants = TlaConstantAssignment {
                    constants: extract_common_constants(PID, trace).into_iter().collect(),
                };
                post_process_trace(trace);
                constants
            },
        }
    };
}
