use super::{
    account_to_tla, extract_common_constants, function_domain_union, function_range_union,
    post_process_trace,
};
use crate::governance::governance_minting_account;
use lazy_static::lazy_static;
use std::collections::BTreeSet;
use std::iter::once;
use tla_instrumentation::{Label, TlaConstantAssignment, TlaValue, ToTla, Update, VarAssignment};

const PID: &str = "Disburse_Neuron";
lazy_static! {
    pub static ref DISBURSE_NEURON_DESC: Update = {
        let default_locals = VarAssignment::new()
            .add("neuron_id", 0_u64.to_tla_value())
            .add("disburse_amount", 0_u64.to_tla_value())
            .add("to_account", "".to_tla_value())
            .add("fees_amount", 0_u64.to_tla_value());
        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: Label::new("DisburseNeuron1"),
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
                let all_accounts = function_range_union(trace, "to_account")
                    .union(&function_domain_union(trace, "neuron_id_by_account"))
                    .filter(|account| **account != "".to_tla_value())
                    .chain(once(&account_to_tla(governance_minting_account())))
                    .cloned()
                    .collect::<BTreeSet<TlaValue>>();

                constants
                    .constants
                    .insert("Account_Ids".to_string(), all_accounts.to_tla_value());
                constants
            },
        }
    };
}
