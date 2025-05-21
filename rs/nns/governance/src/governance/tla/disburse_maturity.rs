use super::{account_to_tla, extract_common_constants, function_domain_union, post_process_trace};
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
        (Some(TlaValue::Function(start)), Some(TlaValue::Function(end))) => {
            let neurons = start.values().chain(end.values());
            neurons
                .map(|n| match n {
                    TlaValue::Record(r) => match r.get("maturity_disbursements_in_progress") {
                        Some(TlaValue::Seq(vs)) => vs.iter().map(|v| match v {
                            TlaValue::Record(r) => r
                                .get("account_id")
                                .expect("account_id not found in the record")
                                .clone(),
                            _ => panic!("Field account_id not a record: {}", v),
                        }),
                        _ => panic!(
                            "maturity_disbursements_in_progress not found in the neuron record {}",
                            n
                        ),
                    },
                    _ => panic!("Field neuron not a record: {}", n),
                })
                .flatten()
                .collect()
        }
        _ => {
            panic!(
                "Error getting maturity_disbursement_in_progress_acount_ids; field neuron not found in the start or end state, or not a function, in pair {:?}",
                pair
            );
        }
    }
}

// TODO: document the convention that the model has to be called Disburse_Maturity.tla
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
                // TODO: need to include all the account_ids from maturity_disbursements_in_progress of all neurons
                let disbursements_in_progress_account_ids: BTreeSet<TlaValue> = trace.iter().map(
                    get_maturity_disbursement_in_progress_account_ids).flatten().collect();

                let all_accounts = function_domain_union(trace, "neuron_id_by_account").iter()
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
