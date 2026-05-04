use lazy_static::lazy_static;
use tla_instrumentation::{
    Label, ResolvedStatePair, TlaConstantAssignment, ToTla, Update, VarAssignment,
};

use super::common::{default_account, governance_account_id};
use super::{extract_common_constants, post_process_trace};

const PID: &str = "Split_Neuron";
lazy_static! {
    pub static ref SPLIT_NEURON_DESC: Update = {
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
    };
}

fn extract_split_neuron_constants(pid: &str, trace: &[ResolvedStatePair]) -> TlaConstantAssignment {
    TlaConstantAssignment {
        constants: extract_common_constants(pid, trace)
            .into_iter()
            .chain([("Minting_Account_Id".to_string(), governance_account_id())])
            .collect(),
    }
}
