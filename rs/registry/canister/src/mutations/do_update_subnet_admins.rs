use crate::{common::LOG_PREFIX, mutations::common::has_duplicates, registry::Registry};
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

const MAX_SUBNET_ADMINS: usize = 10;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum OperationType {
    Add(Vec<PrincipalId>),
    Remove(Vec<PrincipalId>),
    Clear(candid::Reserved),
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateSubnetAdminsPayload {
    pub subnet_id: SubnetId,
    pub operation_type: Option<OperationType>,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum UpdateSubnetAdminsError {
    TooManySubnetAdmins { provided: u64, max_allowed: u64 },
    PrincipalListEmpty,
    SubnetAdminsNotInList,
    SubnetAdminsInCurrentList,
    HasDuplicates,
    UnknownOperationType,
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub enum UpdateSubnetAdminsResult {
    Ok,
    Err(Option<UpdateSubnetAdminsError>),
}

impl Registry {
    pub fn do_update_subnet_admins(
        &mut self,
        payload: UpdateSubnetAdminsPayload,
    ) -> UpdateSubnetAdminsResult {
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

        let new_subnet_admins = match payload.operation_type {
            Some(OperationType::Add(principal_ids)) => {
                if let Err(e) = Self::has_duplicates(&principal_ids) {
                    return UpdateSubnetAdminsResult::Err(Some(e));
                }

                if principal_ids.is_empty() {
                    println!(
                        "{}do_update_subnet_admins: Error: No subnet admins provided to add.",
                        LOG_PREFIX
                    );
                    return UpdateSubnetAdminsResult::Err(Some(
                        UpdateSubnetAdminsError::PrincipalListEmpty,
                    ));
                }

                if current_subnet_admins.len() + principal_ids.len() > MAX_SUBNET_ADMINS {
                    println!(
                        "{}do_update_subnet_admins: Error: Too many subnet admins to add: {}",
                        LOG_PREFIX,
                        principal_ids.len()
                    );
                    return UpdateSubnetAdminsResult::Err(Some(
                        UpdateSubnetAdminsError::TooManySubnetAdmins {
                            provided: current_subnet_admins.len() as u64
                                + principal_ids.len() as u64,
                            max_allowed: MAX_SUBNET_ADMINS as u64,
                        },
                    ));
                }

                let mut new_subnet_admins = Vec::new();

                for principal_id in principal_ids {
                    let principal_id_proto = PrincipalIdPb::from(principal_id);
                    if current_subnet_admins.contains(&principal_id_proto) {
                        println!(
                            "{}do_update_subnet_admins: Error: Subnet admin {:?} is already in current list, so it cannot be added.",
                            LOG_PREFIX, principal_id
                        );
                        return UpdateSubnetAdminsResult::Err(Some(
                            UpdateSubnetAdminsError::SubnetAdminsInCurrentList,
                        ));
                    } else {
                        new_subnet_admins.push(principal_id_proto);
                    }
                }

                new_subnet_admins.extend(current_subnet_admins.iter().cloned());
                new_subnet_admins
            }
            Some(OperationType::Remove(principal_ids)) => {
                if let Err(e) = Self::has_duplicates(&principal_ids) {
                    return UpdateSubnetAdminsResult::Err(Some(e));
                }

                if principal_ids.is_empty() {
                    println!(
                        "{}do_update_subnet_admins: Error: No subnet admins provided to remove.",
                        LOG_PREFIX
                    );
                    return UpdateSubnetAdminsResult::Err(Some(
                        UpdateSubnetAdminsError::PrincipalListEmpty,
                    ));
                }

                if principal_ids.len() > MAX_SUBNET_ADMINS {
                    println!(
                        "{}do_update_subnet_admins: Error: Too many subnet admins to remove: {}",
                        LOG_PREFIX,
                        principal_ids.len()
                    );
                    return UpdateSubnetAdminsResult::Err(Some(
                        UpdateSubnetAdminsError::TooManySubnetAdmins {
                            provided: principal_ids.len() as u64,
                            max_allowed: MAX_SUBNET_ADMINS as u64,
                        },
                    ));
                }

                let mut subnet_admins_to_be_removed = Vec::new();

                for principal_id in principal_ids {
                    let principal_id_proto = PrincipalIdPb::from(principal_id);
                    if !current_subnet_admins.contains(&principal_id_proto) {
                        println!(
                            "{}do_update_subnet_admins: Error: Subnet admin {:?} is not in current list, so it cannot be removed.",
                            LOG_PREFIX, principal_id
                        );
                        return UpdateSubnetAdminsResult::Err(Some(
                            UpdateSubnetAdminsError::SubnetAdminsNotInList,
                        ));
                    } else {
                        subnet_admins_to_be_removed.push(principal_id_proto);
                    }
                }

                current_subnet_admins
                    .iter()
                    .filter(|p| !subnet_admins_to_be_removed.contains(p))
                    .cloned()
                    .collect()
            }
            Some(OperationType::Clear(_)) => Vec::new(),
            None => {
                return UpdateSubnetAdminsResult::Err(Some(
                    UpdateSubnetAdminsError::UnknownOperationType,
                ));
            }
        };

        subnet_record.subnet_admins = new_subnet_admins;
        let subnet_record_mutation = upsert(
            make_subnet_record_key(subnet_id).into_bytes(),
            subnet_record.encode_to_vec(),
        );
        let mutations = vec![subnet_record_mutation];

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);

        UpdateSubnetAdminsResult::Ok
    }

    fn has_duplicates(principal_ids: &Vec<PrincipalId>) -> Result<(), UpdateSubnetAdminsError> {
        if has_duplicates(principal_ids) {
            println!(
                "{}do_update_subnet_admins: Error: Duplicate subnet admins found.",
                LOG_PREFIX
            );
            return Err(UpdateSubnetAdminsError::HasDuplicates);
        }
        Ok(())
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

    #[test]
    fn can_add_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let user1 = user_test_id(100).get();
        let user2 = user_test_id(101).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user2])),
        };

        registry.do_update_subnet_admins(payload);

        let updated_subnet_admins = registry.get_subnet_or_panic(subnet_id).subnet_admins;
        assert_eq!(updated_subnet_admins.len(), 2);
        assert!(updated_subnet_admins.contains(&PrincipalIdPb::from(user1)));
        assert!(updated_subnet_admins.contains(&PrincipalIdPb::from(user2)));
    }

    #[test]
    fn can_remove_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let user1 = user_test_id(100).get();
        let user2 = user_test_id(101).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user2])),
        };

        registry.do_update_subnet_admins(payload);

        let updated_subnet_admins = registry.get_subnet_or_panic(subnet_id).subnet_admins;
        assert_eq!(updated_subnet_admins.len(), 2);
        assert!(updated_subnet_admins.contains(&PrincipalIdPb::from(user1)));
        assert!(updated_subnet_admins.contains(&PrincipalIdPb::from(user2)));

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user1])),
        };

        registry.do_update_subnet_admins(payload);

        let updated_subnet_admins = registry.get_subnet_or_panic(subnet_id).subnet_admins;
        assert_eq!(updated_subnet_admins, vec![PrincipalIdPb::from(user2)]);
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
        assert_eq!(updated_subnet_admins.len(), 3);
        assert!(updated_subnet_admins.contains(&PrincipalIdPb::from(user1)));
        assert!(updated_subnet_admins.contains(&PrincipalIdPb::from(user2)));
        assert!(updated_subnet_admins.contains(&PrincipalIdPb::from(user3)));

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Clear(candid::Reserved {})),
        };

        registry.do_update_subnet_admins(payload);

        let updated_subnet_admins = registry.get_subnet_or_panic(subnet_id).subnet_admins;
        assert_eq!(updated_subnet_admins, vec![]);
    }

    #[test]
    fn can_not_add_or_remove_empty_list_of_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![])),
        };

        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::PrincipalListEmpty))
        );

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![])),
        };

        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::PrincipalListEmpty))
        );
    }

    #[test]
    fn can_not_add_or_remove_duplicate_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(subnet_id);

        let user1 = user_test_id(100).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user1])),
        };

        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::HasDuplicates))
        );

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user1, user1])),
        };
        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::HasDuplicates))
        );
    }

    #[test]
    fn can_not_add_too_many_subnet_admins() {
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

        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::TooManySubnetAdmins {
                provided: (MAX_SUBNET_ADMINS + 1) as u64,
                max_allowed: MAX_SUBNET_ADMINS as u64,
            }))
        );

        let mut users_to_add = Vec::new();
        for i in 0..(MAX_SUBNET_ADMINS - 1) {
            users_to_add.push(user_test_id(100 + i as u64).get());
        }

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(users_to_add)),
        };
        registry.do_update_subnet_admins(payload);

        let mut users_to_add = Vec::new();
        for i in 0..3 {
            users_to_add.push(user_test_id(200 + i as u64).get());
        }

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(users_to_add)),
        };

        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::TooManySubnetAdmins {
                // We had already added MAX_subnet_admins_PER_SUBNET - 1 users
                // and now we're trying to add 3 more, which would put us
                // at MAX_subnet_admins_PER_SUBNET + 2.
                provided: (MAX_SUBNET_ADMINS + 2) as u64,
                max_allowed: MAX_SUBNET_ADMINS as u64,
            }))
        );
    }

    #[test]
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

        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::TooManySubnetAdmins {
                provided: (MAX_SUBNET_ADMINS + 1) as u64,
                max_allowed: MAX_SUBNET_ADMINS as u64,
            }))
        );
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
        assert_eq!(
            registry.get_subnet_or_panic(subnet_id).subnet_admins,
            vec![PrincipalIdPb::from(user1)]
        );

        // Attempt to add the same user again.
        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::SubnetAdminsInCurrentList))
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

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user_test_id(200).get()])),
        };

        let result = registry.do_update_subnet_admins(payload);
        assert_eq!(
            result,
            UpdateSubnetAdminsResult::Err(Some(UpdateSubnetAdminsError::SubnetAdminsNotInList))
        );
    }
}
