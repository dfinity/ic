use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use icp_ledger::{AccountIdentifier, Subaccount};

use std::collections::BTreeSet;
pub use tla_instrumentation::{ResolvedStatePair, TlaValue, ToTla};

pub(super) fn default_account() -> TlaValue {
    "".to_tla_value()
}

pub(super) fn governance_account_id() -> TlaValue {
    AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        None,
    )
    .to_string()
    .as_str()
    .to_tla_value()
}

pub fn subaccount_to_tla(subaccount: &Subaccount) -> TlaValue {
    opt_subaccount_to_tla(&Some(*subaccount))
}

pub fn opt_subaccount_to_tla(subaccount: &Option<Subaccount>) -> TlaValue {
    let account = AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        *subaccount,
    );
    TlaValue::Literal(account.to_string())
}

pub fn account_to_tla(account: AccountIdentifier) -> TlaValue {
    account.to_string().as_str().to_tla_value()
}

/// Compute the union of the domain of the function field `field_name` in the
/// start and end states of the given state pairs.
pub fn function_domain_union(
    state_pairs: &[ResolvedStatePair],
    field_name: &str,
) -> BTreeSet<TlaValue> {
    state_pairs.iter().flat_map(|pair| {
        match (pair.start.get(field_name), pair.end.get(field_name)) {
            (Some(TlaValue::Function(sf)), Some(TlaValue::Function(ef))) => {
                sf.keys().chain(ef.keys()).cloned()
            }
            _ => {
                panic!("Field {field_name} not found in the start or end state, or not a function, when computing the union")
            }
        }
    }
    ).collect()
}

pub fn function_range_union(
    state_pairs: &[ResolvedStatePair],
    field_name: &str,
) -> BTreeSet<TlaValue> {
    state_pairs.iter().flat_map(|pair| {
        match (pair.start.get(field_name), pair.end.get(field_name)) {
            (Some(TlaValue::Function(sf)), Some(TlaValue::Function(ef))) => {
                sf.values().chain(ef.values()).cloned()
            }
            _ => {
                panic!("Field {field_name} not found in the start or end state, or not a function, when computing the union")
            }
        }
    }
    ).collect()
}

pub fn get_maturity_disbursement_in_progress_account_ids(
    pair: &ResolvedStatePair,
) -> BTreeSet<TlaValue> {
    match (pair.start.get("neuron"), pair.end.get("neuron")) {
        (Some(TlaValue::Function(start)), Some(TlaValue::Function(end))) => {
            let neurons = start.values().chain(end.values());
            neurons
                .flat_map(|n| match n {
                    TlaValue::Record(r) => match r.get("maturity_disbursements_in_progress") {
                        Some(TlaValue::Seq(vs)) => vs.iter().map(|v| match v {
                            TlaValue::Record(r) => r
                                .get("account_id")
                                .expect("account_id not found in the record")
                                .clone(),
                            _ => panic!("Field account_id not a record: {v}"),
                        }),
                        _ => panic!(
                            "maturity_disbursements_in_progress not found in the neuron record {n}"
                        ),
                    },
                    _ => panic!("Field neuron not a record: {n}"),
                })
                .collect()
        }
        _ => {
            panic!(
                "Error getting maturity_disbursement_in_progress_acount_ids; field neuron not found in the start or end state, or not a function, in pair {pair:?}"
            );
        }
    }
}
