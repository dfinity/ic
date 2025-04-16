use super::{account_to_tla, extract_common_constants, post_process_trace};
use crate::governance::governance_minting_account;
use lazy_static::lazy_static;
use tla_instrumentation::{Label, TlaConstantAssignment, ToTla, Update, VarAssignment};

const PID: &str = "Merge_Neurons";
lazy_static! {
    pub static ref MERGE_NEURONS_DESC: Update = {
        let default_locals = VarAssignment::new()
            .add("source_neuron_id", 0_u64.to_tla_value())
            .add("target_neuron_id", 0_u64.to_tla_value())
            .add("fees_amount", 0_u64.to_tla_value())
            .add("amount_to_target", 0_u64.to_tla_value());
        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: Label::new("MergeNeurons_Start"),
            end_label: Label::new("Done"),
            process_id: PID.to_string(),
            canister_name: "governance".to_string(),
            post_process: |trace| {
                let mut constants = TlaConstantAssignment {
                    constants: extract_common_constants(PID, trace).into_iter().collect(),
                };
                post_process_trace(trace);
                constants.constants.insert(
                    "Minting_Account_Id".to_string(),
                    account_to_tla(governance_minting_account()),
                );
                constants
            },
        }
    };
}
