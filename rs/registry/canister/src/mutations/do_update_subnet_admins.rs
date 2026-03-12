use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
use ic_base_types::{PrincipalId, SubnetId};
use ic_protobuf::{
    registry::subnet::v1::CanisterCyclesCostSchedule, types::v1::PrincipalId as PrincipalIdPb,
};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::upsert;
use prost::Message;
use serde::Serialize;
use std::collections::HashSet;

const MAX_SUBNET_ADMINS: usize = 10;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct EmptyRecord {}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum OperationType {
    Add(Vec<PrincipalId>),
    Remove(Vec<PrincipalId>),
    Clear(EmptyRecord),
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateSubnetAdminsPayload {
    pub subnet_id: SubnetId,
    pub operation_type: Option<OperationType>,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum UpdateSubnetAdminsError {
    TooManySubnetAdmins {
        provided: u64,
        existing: u64,
        max_allowed: u64,
    },
    PrincipalListEmpty,
    UnknownOperationType,
}

impl std::fmt::Display for UpdateSubnetAdminsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateSubnetAdminsError::TooManySubnetAdmins {
                provided,
                existing,
                max_allowed,
            } => write!(
                f,
                "Too many subnet admins. Provided: {provided}, Existing: {existing}, Max allowed: {max_allowed}."
            ),
            UpdateSubnetAdminsError::PrincipalListEmpty => {
                write!(f, "The list of provided principals cannot be empty.")
            }
            UpdateSubnetAdminsError::UnknownOperationType => {
                write!(
                    f,
                    "The operation type provided is unknown. Expected one of: Add, Remove, Clear."
                )
            }
        }
    }
}

impl Registry {
    pub fn do_update_subnet_admins(&mut self, payload: UpdateSubnetAdminsPayload) {
        println!("{}do_update_subnet_admins: {:?}", LOG_PREFIX, payload);

        let subnet_id = payload.subnet_id;
        let mut subnet_record = self.get_subnet_or_panic(subnet_id);

        // Check pre-conditions that a subnet is rented before allowing subnet admin updates.
        // The check is based on the expectation that a rented subnet must be an application
        // subnet and must be on a "free" cycles cost schedule.
        assert_eq!(
            subnet_record.subnet_type,
            i32::from(SubnetType::Application),
            "Only application subnets are expected to be rented or have subnet admins."
        );
        assert_eq!(
            subnet_record.canister_cycles_cost_schedule,
            i32::from(CanisterCyclesCostSchedule::Free),
            "Only rented subnets, which are expected to be on a free cycles cost schedule, are expected to have subnet admins."
        );

        let current_subnet_admins = subnet_record.subnet_admins;

        let res = match payload.operation_type {
            Some(operation_type) => {
                match self.compute_new_subnet_admins(current_subnet_admins, operation_type) {
                    Ok(new_subnet_admins) => {
                        subnet_record.subnet_admins = new_subnet_admins;

                        let subnet_record_mutation = upsert(
                            make_subnet_record_key(subnet_id).into_bytes(),
                            subnet_record.encode_to_vec(),
                        );
                        let mutations = vec![subnet_record_mutation];

                        // Check invariants before applying mutations
                        self.maybe_apply_mutation_internal(mutations);

                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            None => Err(UpdateSubnetAdminsError::UnknownOperationType),
        };

        match res {
            Ok(()) => {}
            Err(err) => {
                panic!(
                    "{LOG_PREFIX}do_update_subnet_admins: Error while updating subnet admins of {subnet_id}: {err}",
                );
            }
        }
    }

    fn compute_new_subnet_admins(
        &self,
        current_subnet_admins: Vec<PrincipalIdPb>,
        operation_type: OperationType,
    ) -> Result<Vec<PrincipalIdPb>, UpdateSubnetAdminsError> {
        let deduped_current_subnet_admins = current_subnet_admins
            .into_iter()
            .collect::<HashSet<PrincipalIdPb>>();

        let new_subnet_admins = match operation_type {
            OperationType::Add(principal_ids) => {
                if principal_ids.is_empty() {
                    return Err(UpdateSubnetAdminsError::PrincipalListEmpty);
                }

                if deduped_current_subnet_admins.len() + principal_ids.len() > MAX_SUBNET_ADMINS {
                    return Err(UpdateSubnetAdminsError::TooManySubnetAdmins {
                        provided: principal_ids.len() as u64,
                        existing: deduped_current_subnet_admins.len() as u64,
                        max_allowed: MAX_SUBNET_ADMINS as u64,
                    });
                }

                let deduped_provided_principal_ids = principal_ids
                    .into_iter()
                    .map(PrincipalIdPb::from)
                    .collect::<HashSet<PrincipalIdPb>>();

                deduped_current_subnet_admins
                    .union(&deduped_provided_principal_ids)
                    .cloned()
                    .collect()
            }
            OperationType::Remove(principal_ids) => {
                if principal_ids.is_empty() {
                    return Err(UpdateSubnetAdminsError::PrincipalListEmpty);
                }

                if principal_ids.len() > MAX_SUBNET_ADMINS {
                    return Err(UpdateSubnetAdminsError::TooManySubnetAdmins {
                        provided: principal_ids.len() as u64,
                        existing: deduped_current_subnet_admins.len() as u64,
                        max_allowed: MAX_SUBNET_ADMINS as u64,
                    });
                }

                let deduped_provided_principal_ids = principal_ids
                    .into_iter()
                    .map(PrincipalIdPb::from)
                    .collect::<HashSet<PrincipalIdPb>>();

                deduped_current_subnet_admins
                    .difference(&deduped_provided_principal_ids)
                    .cloned()
                    .collect()
            }
            OperationType::Clear(_) => vec![],
        };

        Ok(new_subnet_admins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes,
    };
    use ic_test_utilities_types::ids::{subnet_test_id, user_test_id};
    use maplit::btreemap;
    use pretty_assertions::assert_eq;

    fn prepare_registry_for_update_subnet_admins_test(subnet_id: SubnetId) -> Registry {
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let mut subnet_list_record = registry.get_subnet_list_record();
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID and key");
        let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);

        // Ensure subnet is considered rented.
        subnet_record.subnet_type = i32::from(SubnetType::Application);
        subnet_record.canister_cycles_cost_schedule = i32::from(CanisterCyclesCostSchedule::Free);

        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        registry
    }

    // For the purposes of the below tests, the updated subnet admins list matches
    // the expected one if the contain exactly the same elements regardless of order.
    //
    // Useful in cases the list contains more than 1 element (otherwise direct equality
    // check is enough).
    #[track_caller]
    fn assert_updated_subnet_admins_match_expected(
        updated_subnet_admins: &[PrincipalIdPb],
        expected_subnet_admins: &[PrincipalIdPb],
    ) {
        let updated_subnet_admins = updated_subnet_admins
            .iter()
            .collect::<HashSet<&PrincipalIdPb>>();
        let expected_subnet_admins = expected_subnet_admins
            .iter()
            .collect::<HashSet<&PrincipalIdPb>>();
        assert_eq!(updated_subnet_admins, expected_subnet_admins);
    }

    #[test]
    fn can_add_or_remove_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let user1 = user_test_id(100).get();
        let user2 = user_test_id(101).get();

        // Add two subnet admins, `user1` and `user2`.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user2])),
        };

        registry.do_update_subnet_admins(payload);

        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &[PrincipalIdPb::from(user1), PrincipalIdPb::from(user2)],
        );

        // Remove `user1` from the subnet admins list.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user1])),
        };

        registry.do_update_subnet_admins(payload);
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &[PrincipalIdPb::from(user2)],
        );
    }

    #[test]
    fn can_clear_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let user1 = user_test_id(100).get();
        let user2 = user_test_id(101).get();
        let user3 = user_test_id(102).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user2, user3])),
        };

        registry.do_update_subnet_admins(payload);

        let updated_subnet_admins = registry.get_subnet_or_panic(subnet_id).subnet_admins;
        let expected_subnet_admins = vec![
            PrincipalIdPb::from(user1),
            PrincipalIdPb::from(user2),
            PrincipalIdPb::from(user3),
        ];
        assert_updated_subnet_admins_match_expected(
            &updated_subnet_admins,
            &expected_subnet_admins,
        );

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Clear(EmptyRecord {})),
        };

        registry.do_update_subnet_admins(payload);

        assert_eq!(
            registry.get_subnet_or_panic(subnet_id).subnet_admins,
            vec![]
        );
    }

    #[test]
    #[should_panic(expected = "The list of provided principals cannot be empty")]
    fn can_not_add_or_remove_empty_list_of_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![])),
        };

        registry.do_update_subnet_admins(payload);
    }

    #[test]
    #[should_panic(expected = "The list of provided principals cannot be empty")]
    fn can_not_remove_empty_list_of_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![])),
        };

        registry.do_update_subnet_admins(payload);
    }

    #[test]
    fn can_dedup_input_when_adding_or_removing_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let user1 = user_test_id(100).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user1])),
        };

        registry.do_update_subnet_admins(payload);
        assert_eq!(
            registry.get_subnet_or_panic(subnet_id).subnet_admins,
            vec![PrincipalIdPb::from(user1)]
        );

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user1, user1])),
        };

        registry.do_update_subnet_admins(payload);
        assert_eq!(
            registry.get_subnet_or_panic(subnet_id).subnet_admins,
            vec![]
        );
    }

    #[test]
    #[should_panic(
        expected = "Too many subnet admins. Provided: 11, Existing: 0, Max allowed: 10."
    )]
    fn can_not_add_too_many_subnet_admins_no_existing_ones() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let mut users_to_add = Vec::new();
        for i in 0..(MAX_SUBNET_ADMINS + 1) {
            users_to_add.push(user_test_id(100 + i as u64).get());
        }

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(users_to_add)),
        };

        registry.do_update_subnet_admins(payload);
    }

    #[test]
    #[should_panic(expected = "Too many subnet admins. Provided: 3, Existing: 9, Max allowed: 10.")]
    fn can_not_add_too_many_subnet_admins_with_existing_ones() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let mut users_to_add = Vec::new();
        let mut expected_subnet_admins = Vec::new();
        for i in 0..(MAX_SUBNET_ADMINS - 1) {
            let principal = user_test_id(100 + i as u64).get();
            users_to_add.push(principal);
            expected_subnet_admins.push(PrincipalIdPb::from(principal));
        }

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(users_to_add)),
        };
        registry.do_update_subnet_admins(payload);
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &expected_subnet_admins,
        );

        let mut users_to_add = Vec::new();
        for i in 0..3 {
            users_to_add.push(user_test_id(200 + i as u64).get());
        }

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(users_to_add)),
        };

        registry.do_update_subnet_admins(payload);
    }

    #[test]
    #[should_panic(
        expected = "Too many subnet admins. Provided: 11, Existing: 0, Max allowed: 10."
    )]
    fn can_not_remove_too_many_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let mut users_to_remove = Vec::new();
        for i in 0..(MAX_SUBNET_ADMINS + 1) {
            users_to_remove.push(user_test_id(100 + i as u64).get());
        }

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(users_to_remove)),
        };

        registry.do_update_subnet_admins(payload);
    }

    #[test]
    fn can_not_add_existing_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let user1 = user_test_id(100).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1])),
        };

        registry.do_update_subnet_admins(payload.clone());
        let expected_subnet_admins = vec![PrincipalIdPb::from(user1)];
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &expected_subnet_admins,
        );

        // Attempt to add the same user again. Should be a no-op.
        registry.do_update_subnet_admins(payload);
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &expected_subnet_admins,
        );
    }

    #[test]
    fn can_not_remove_non_existing_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let user1 = user_test_id(100).get();
        let user2 = user_test_id(101).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user2])),
        };
        registry.do_update_subnet_admins(payload);
        let expected_subnet_admins = vec![PrincipalIdPb::from(user1), PrincipalIdPb::from(user2)];

        // Attempt to remove a user that is not in the subnet admins list. Should be a no-op.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user_test_id(200).get()])),
        };
        registry.do_update_subnet_admins(payload);
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &expected_subnet_admins,
        );
    }
}
