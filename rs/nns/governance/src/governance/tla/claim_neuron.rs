use lazy_static::lazy_static;
use tla_instrumentation::{Label, TlaConstantAssignment, ToTla, Update, VarAssignment};

use super::common::default_account;
use super::{extract_common_constants, post_process_trace};

lazy_static! {
    pub static ref CLAIM_NEURON_DESC: Update = {
        const PID: &str = "Claim_Neuron";
        let default_locals = VarAssignment::new()
            .add("account", default_account())
            .add("neuron_id", 0_u64.to_tla_value());

        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: Label::new("ClaimNeuron1"),
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
