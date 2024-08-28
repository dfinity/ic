use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use icp_ledger::AccountIdentifier;

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

/// Compute the union of the domain of the function field `field_name` in the
/// start and end states of the given state pairs.
pub fn function_domain_union(
    state_pairs: &Vec<ResolvedStatePair>,
    field_name: &str,
) -> BTreeSet<TlaValue> {
    state_pairs.iter().flat_map(|pair| {
        match (pair.start.get(field_name), pair.end.get(field_name)) {
            (Some(TlaValue::Function(sf)), Some(TlaValue::Function(ef))) => {
                sf.keys().chain(ef.keys()).cloned()
            }
            _ => {
                panic!("Field {} not found in the start or end state, or not a function, when computing the union", field_name)
            }
        }
    }
    ).collect()
}
