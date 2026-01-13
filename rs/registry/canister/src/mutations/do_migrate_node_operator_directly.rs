use std::fmt::Display;

use candid::CandidType;
use ic_types::PrincipalId;
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::registry::Registry;

impl Registry {
    pub fn do_migrate_node_operator_directly(&mut self, payload: MigrateNodeOperatorPayload) {
        self.migrate_node_operator_inner(payload, dfn_core::api::caller())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    fn migrate_node_operator_inner(
        &mut self,
        payload: MigrateNodeOperatorPayload,
        _caller: PrincipalId,
    ) -> Result<(), MigrateError> {
        // Check if the payload is valid by itself.
        payload.validate()?;

        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, CandidType, Deserialize, Message, Serialize)]
pub struct MigrateNodeOperatorPayload {
    /// Represents the principal of the target node operator to which
    /// the migration is being executed.
    ///
    /// If this node operator exists, it will just be updated to match
    /// the data present in the old node operator record.
    ///
    /// If this node operator doesn't exist, it will be created.
    #[prost(message, optional, tag = "1")]
    pub new_operator_id: Option<PrincipalId>,

    /// Represents the principal of the current node operator from which
    /// the migration is being executed.
    ///
    /// This node operator record will be removed if the migration is
    /// successful.
    #[prost(message, optional, tag = "2")]
    pub old_operator_id: Option<PrincipalId>,
}

#[derive(Debug, PartialEq, Eq)]
enum MigrateError {
    MissingInput,
    SamePrincipals,
}

impl Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MigrateError::MissingInput => "The provided payload has missing data".to_string(),
                MigrateError::SamePrincipals =>
                    "`new_operator_id` and `old_operator_id` must differ".to_string(),
            }
        )
    }
}

impl MigrateNodeOperatorPayload {
    fn validate(&self) -> Result<(), MigrateError> {
        let (old_node_operator_id, new_node_operator_id) =
            match (&self.old_operator_id, &self.new_operator_id) {
                (Some(old_node_operator_id), Some(new_node_operator_id)) => {
                    (old_node_operator_id, new_node_operator_id)
                }
                _ => return Err(MigrateError::MissingInput),
            };

        if old_node_operator_id == new_node_operator_id {
            return Err(MigrateError::SamePrincipals);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ic_types::PrincipalId;

    use crate::{
        mutations::do_migrate_node_operator_directly::{MigrateError, MigrateNodeOperatorPayload},
        registry::Registry,
    };

    fn invalid_payloads_with_expected_errors() -> Vec<(MigrateNodeOperatorPayload, MigrateError)> {
        vec![]
    }

    #[test]
    fn invalid_payloads() {
        let mut registry = Registry::new();

        for (payload, expected_err) in invalid_payloads_with_expected_errors() {
            let output =
                registry.migrate_node_operator_inner(payload, PrincipalId::new_user_test_id(1));

            let expected: Result<(), MigrateError> = Err(expected_err);
            assert_eq!(
                output, expected,
                "Expected: {expected:?} but found result: {output:?}"
            );
        }
    }
}
