use super::common::get_maturity_disbursement_in_progress_account_ids;
use super::{account_to_tla, extract_common_constants, function_domain_union, post_process_trace};
use crate::governance::governance_minting_account;
use lazy_static::lazy_static;
use std::collections::BTreeSet;
use std::iter::once;
use tla_instrumentation::{Label, TlaConstantAssignment, TlaValue, ToTla, Update, VarAssignment};

const PID: &str = "Disburse_Maturity";
lazy_static! {
    pub static ref DISBURSE_MATURITY_DESC: Update = {
        let default_locals = VarAssignment::new();
        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: Label::new("DisburseMaturityStart"),
            end_label: Label::new("DisburseMaturityStart"),
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
                constants.constants.insert(
                    "MIN_DISBURSEMENT".to_string(),
                    crate::governance::disburse_maturity::MINIMUM_DISBURSEMENT_E8S.to_tla_value(),
                );
                let disbursements_in_progress_account_ids: BTreeSet<TlaValue> = trace
                    .iter()
                    .flat_map(get_maturity_disbursement_in_progress_account_ids)
                    .collect();

                let all_accounts = function_domain_union(trace, "neuron_id_by_account")
                    .iter()
                    .filter(|account| **account != "".to_tla_value())
                    .chain(once(&account_to_tla(governance_minting_account())))
                    .chain(disbursements_in_progress_account_ids.iter())
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
