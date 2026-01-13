use std::fmt::Display;

use candid::{CandidType, Principal};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use ic_registry_transport::{delete, pb::v1::RegistryMutation, upsert};
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
        caller: PrincipalId,
    ) -> Result<(), MigrateError> {
        // Check if the payload is valid by itself.
        payload.validate()?;
        let (old_node_operator_id, new_node_operator_id) = (
            payload.old_node_operator_id.unwrap(),
            payload.new_node_operator_id.unwrap(),
        );

        let _node_operator_migrations = self.get_operator_migrations_if_bussiness_rules_are_valid(
            old_node_operator_id,
            new_node_operator_id,
            caller,
        )?;

        Ok(())
    }

    fn get_operator_migrations_if_bussiness_rules_are_valid(
        &self,
        old_node_operator_id: PrincipalId,
        new_node_operator_id: PrincipalId,
        caller: PrincipalId,
    ) -> Result<Vec<RegistryMutation>, MigrateError> {
        // Old node operator record must exist
        let old_node_operator_record = self
            .get(
                make_node_operator_record_key(old_node_operator_id).as_bytes(),
                self.latest_version(),
            )
            .ok_or(MigrateError::MissingNodeOperator {
                principal: old_node_operator_id,
            })
            .map(|registry_value| {
                NodeOperatorRecord::decode(registry_value.value.as_slice()).unwrap()
            })?;

        // New node operator record can exist, but doesn't have to.
        //
        // If it doesn't exist it should be created on the fly.
        let mut new_node_operator_record = self
            .get(
                make_node_operator_record_key(new_node_operator_id).as_bytes(),
                self.latest_version(),
            )
            .map(|registry_value| {
                NodeOperatorRecord::decode(registry_value.value.as_slice()).unwrap()
            })
            .unwrap_or(NodeOperatorRecord {
                node_operator_principal_id: new_node_operator_id.to_vec(),
                node_provider_principal_id: old_node_operator_record
                    .node_provider_principal_id
                    .clone(),
                dc_id: old_node_operator_record.dc_id.clone(),
                // Other fields will be handled later
                ..Default::default()
            });

        // Both records must be owned by the same node provider.
        if old_node_operator_record.node_provider_principal_id
            != new_node_operator_record.node_provider_principal_id
        {
            return Err(MigrateError::NodeProviderMismatch {
                old: PrincipalId(Principal::from_slice(
                    &old_node_operator_record.node_provider_principal_id,
                )),
                new: PrincipalId(Principal::from_slice(
                    &new_node_operator_record.node_provider_principal_id,
                )),
            });
        }

        // Both records must be within the same data center.
        //
        // This is needed to not allow nodes to be transfered to different
        // locations with this feature.
        //
        // Transfering still must be done with redeployments.
        if old_node_operator_record.dc_id != new_node_operator_record.dc_id {
            return Err(MigrateError::DataCenterMismatch {
                old: old_node_operator_record.dc_id.clone(),
                new: new_node_operator_record.dc_id.clone(),
            });
        }

        // The caller must be the owner of both of the node operator
        // records.
        if caller.as_slice()
            != old_node_operator_record
                .node_operator_principal_id
                .as_slice()
        {
            return Err(MigrateError::CallerMismatch {
                caller,
                expected: PrincipalId(Principal::from_slice(
                    &old_node_operator_record.node_provider_principal_id,
                )),
            });
        }

        // Bussiness rules hold. We can update the records.
        Self::update_new_node_operator_record(
            &old_node_operator_record,
            &mut new_node_operator_record,
        );

        Ok(vec![
            upsert(
                make_node_operator_record_key(new_node_operator_id).as_bytes(),
                new_node_operator_record.encode_to_vec(),
            ),
            delete(make_node_operator_record_key(old_node_operator_id).as_bytes()),
        ])
    }

    fn update_new_node_operator_record(
        old_node_operator_record: &NodeOperatorRecord,
        new_node_operator_record: &mut NodeOperatorRecord,
    ) {
        new_node_operator_record.node_allowance += old_node_operator_record.node_allowance;

        // In theory these should be the same for the same datacenter.
        new_node_operator_record.ipv6 = old_node_operator_record.ipv6.clone();

        for (node_reward_type, value) in &old_node_operator_record.rewardable_nodes {
            *new_node_operator_record
                .rewardable_nodes
                .entry(node_reward_type.to_string())
                .or_insert(0) += value;
        }

        for (node_reward_type, value) in &old_node_operator_record.max_rewardable_nodes {
            *new_node_operator_record
                .max_rewardable_nodes
                .entry(node_reward_type.to_string())
                .or_insert(0) += value;
        }
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
    pub new_node_operator_id: Option<PrincipalId>,

    /// Represents the principal of the current node operator from which
    /// the migration is being executed.
    ///
    /// This node operator record will be removed if the migration is
    /// successful.
    #[prost(message, optional, tag = "2")]
    pub old_node_operator_id: Option<PrincipalId>,
}

#[derive(Debug, PartialEq, Eq)]
enum MigrateError {
    MissingInput,
    SamePrincipals,
    MissingNodeOperator {
        principal: PrincipalId,
    },
    NodeProviderMismatch {
        old: PrincipalId,
        new: PrincipalId,
    },
    DataCenterMismatch {
        old: String,
        new: String,
    },
    CallerMismatch {
        caller: PrincipalId,
        expected: PrincipalId,
    },
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

                MigrateError::MissingNodeOperator { principal } =>
                    format!("Expected node operator {principal} to exist, but it doesn't"),
                MigrateError::NodeProviderMismatch { old, new } => format!(
                    "Node operator migration can take place only if both node operators are controlled by the same node provider. Instead got old node provider principal: {old}, new node provider principal: {new}"
                ),
                MigrateError::DataCenterMismatch { old, new } => format!(
                    "Node operator migration can take place only if both node operators are within the same data center. Instead got old data center: {old}, new data center: {new}"
                ),
                MigrateError::CallerMismatch { caller, expected } => format!(
                    "Caller doesn't seem to be the node provider owning the operator records that are being changed. Expected {expected}, got {caller}"
                ),
            }
        )
    }
}

impl MigrateNodeOperatorPayload {
    fn validate(&self) -> Result<(), MigrateError> {
        let (old_node_operator_id, new_node_operator_id) =
            match (&self.old_node_operator_id, &self.new_node_operator_id) {
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
