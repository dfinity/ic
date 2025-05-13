use super::{
    account_to_tla, extract_common_constants, function_domain_union, function_range_union,
    post_process_trace,
};
use crate::governance::governance_minting_account;
use lazy_static::lazy_static;
use std::collections::BTreeSet;
use std::iter::once;
use tla_instrumentation::{
    Label, ResolvedStatePair, TlaConstantAssignment, TlaValue, ToTla, Update, VarAssignment,
};

fn get_maturity_disbursement_in_progress_account_ids(
    pair: &ResolvedStatePair,
) -> BTreeSet<TlaValue> {
    match (pair.start.get("neuron"), pair.end.get("neuron")) {
        (Some(TlaValue::Record(start)), Some(TlaValue::Record(end))) => {
            let neurons = start.values().chain(end.values());
            neurons
                .map(|n| match n {
                    TlaValue::Record(r) => match r.get("maturity_disbursements_in_progress") {
                        Some(TlaValue::Seq(vs)) => vs,
                        _ => panic!(
                            "maturity_disbursements_in_progress not found in the neuron record {}",
                            n
                        ),
                    },
                    _ => panic!("Field neuron not a record: {}", n),
                })
                .flatten()
                .cloned()
                .collect()
        }
        _ => {
            panic!(
                "Field neuron not found in the start or end state, or not a record, in pair {:?}",
                pair
            );
        }
    }
}

// TODO: document the convention that the model has to be called Disburse_Maturity.tla
const PID: &str = "Disburse_Maturity_Timer";
lazy_static! {
    pub static ref FINALIZE_MATURITY_DISBURSEMENT_DESC: Update = {
        let default_locals = VarAssignment::new();
        Update {
            default_start_locals: default_locals.clone(),
            default_end_locals: default_locals,
            start_label: Label::new("Disburse_Maturity_Timer_Start"),
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
                constants.constants.insert(
                    "MIN_DISBURSEMENT".to_string(),
                    crate::governance::disburse_maturity::MINIMUM_DISBURSEMENT_E8S.to_tla_value(),
                );
                // TODO: need to include all the account_ids from maturity_disbursements_in_progress of all neurons
                let disbursements_in_progress_account_ids: BTreeSet<TlaValue> = trace.iter().map(
                    get_maturity_disbursement_in_progress_account_ids).flatten().collect();

                let all_accounts = function_range_union(trace, "to_account")
                    .union(&function_domain_union(trace, "neuron_id_by_account"))
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
