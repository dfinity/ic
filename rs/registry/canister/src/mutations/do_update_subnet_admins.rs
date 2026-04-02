use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
use ic_base_types::{PrincipalId, SubnetId};
use ic_nervous_system_time_helpers::now_system_time;
use ic_nns_constants::SUBNET_RENTAL_CANISTER_ID;
use ic_protobuf::{
    registry::subnet::v1::{CanisterCyclesCostSchedule, SubnetRecord},
    types::v1::PrincipalId as PrincipalIdPb,
};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::upsert;
use prost::Message;
use serde::Serialize;

use std::cell::RefCell;
use std::collections::HashSet;

mod rate_limits;
use rate_limits::UpdateSubnetAdminsRateLimiter;

const MAX_SUBNET_ADMINS: usize = 10;
pub const MAX_SUSTAINED_SUBNET_ADMINS_PER_DAY: u64 = 10;

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
    RateLimited {
        subnet_id: SubnetId,
    },
    CallerNotAuthorized {
        caller: PrincipalId,
        subnet_id: SubnetId,
    },
    UnsupportedSubnetType {
        subnet_id: SubnetId,
        subnet_type: i32,
    },
    WouldRemoveAllCloudEngineAdmins {
        subnet_id: SubnetId,
    },
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
            UpdateSubnetAdminsError::RateLimited { subnet_id } => {
                write!(
                    f,
                    "Subnet {subnet_id} is being rate limited due to too many subnet admin updates in a \
                    short period of time. Please try again later."
                )
            }
            UpdateSubnetAdminsError::CallerNotAuthorized { caller, subnet_id } => {
                write!(
                    f,
                    "Caller {caller} is not authorized to update subnet admins of subnet {subnet_id}."
                )
            }
            UpdateSubnetAdminsError::UnsupportedSubnetType {
                subnet_id,
                subnet_type,
            } => {
                write!(
                    f,
                    "Subnet {subnet_id} has unsupported subnet type {subnet_type} for subnet admin updates. \
                    Only Application and CloudEngine subnets are supported."
                )
            }
            UpdateSubnetAdminsError::WouldRemoveAllCloudEngineAdmins { subnet_id } => {
                write!(
                    f,
                    "Cannot remove all subnet admins from CloudEngine subnet {subnet_id}. \
                    At least one admin must remain."
                )
            }
        }
    }
}

thread_local! {
    static UPDATE_SUBNET_ADMINS_RATE_LIMITER: RefCell<UpdateSubnetAdminsRateLimiter> = RefCell::new(UpdateSubnetAdminsRateLimiter::new());
}

impl Registry {
    pub fn do_update_subnet_admins(
        &mut self,
        caller: PrincipalId,
        payload: UpdateSubnetAdminsPayload,
    ) {
        println!("{}do_update_subnet_admins: {:?}", LOG_PREFIX, payload);

        let subnet_id = payload.subnet_id;
        let now = now_system_time();
        let reservation = match UPDATE_SUBNET_ADMINS_RATE_LIMITER
            .with_borrow_mut(|limiter| limiter.try_reserve(subnet_id, now))
        {
            Ok(reservation) => reservation,
            Err(err) => panic!(
                "{}do_update_subnet_admins: Error while reserving capacity for subnet admin update of {subnet_id}: {err}",
                LOG_PREFIX
            ),
        };

        let mut subnet_record = self.get_subnet_or_panic(subnet_id);

        self.check_update_subnet_admins_caller_authorization(caller, &subnet_record, subnet_id);

        let subnet_type = subnet_record.subnet_type();
        let current_subnet_admins = subnet_record.subnet_admins;

        let res = match payload.operation_type {
            Some(operation_type) => {
                match self.compute_new_subnet_admins(current_subnet_admins, operation_type) {
                    Ok(new_subnet_admins)
                        if subnet_type == SubnetType::CloudEngine.into()
                            && new_subnet_admins.is_empty() =>
                    {
                        // CloudEngine subnets must always have at least one admin,
                        // otherwise there is no way to recover.
                        Err(UpdateSubnetAdminsError::WouldRemoveAllCloudEngineAdmins { subnet_id })
                    }
                    Ok(new_subnet_admins) => {
                        subnet_record.subnet_admins = new_subnet_admins;

                        let subnet_record_mutation = upsert(
                            make_subnet_record_key(subnet_id).into_bytes(),
                            subnet_record.encode_to_vec(),
                        );
                        let mutations = vec![subnet_record_mutation];

                        // Check invariants before applying mutations
                        self.maybe_apply_mutation_internal(mutations);

                        UPDATE_SUBNET_ADMINS_RATE_LIMITER
                            .with_borrow_mut(|limiter| limiter.commit(reservation, now));

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

    fn check_update_subnet_admins_caller_authorization(
        &self,
        caller: PrincipalId,
        subnet_record: &SubnetRecord,
        subnet_id: SubnetId,
    ) {
        assert_eq!(
            subnet_record.canister_cycles_cost_schedule,
            i32::from(CanisterCyclesCostSchedule::Free),
            "Only subnets on a free cycles cost schedule are allowed to have subnet admins."
        );

        // Authorization depends on subnet type:
        // - Application subnets: caller must be the subnet rental canister.
        // - CloudEngine subnets: caller must be one of the existing subnet admins.
        match SubnetType::try_from(subnet_record.subnet_type) {
            Ok(SubnetType::Application) => {
                assert_eq!(
                    caller,
                    PrincipalId::from(SUBNET_RENTAL_CANISTER_ID),
                    "{}",
                    UpdateSubnetAdminsError::CallerNotAuthorized { caller, subnet_id },
                );
            }
            Ok(SubnetType::CloudEngine) => {
                assert!(
                    subnet_record
                        .subnet_admins
                        .contains(&PrincipalIdPb::from(caller)),
                    "{}",
                    UpdateSubnetAdminsError::CallerNotAuthorized { caller, subnet_id },
                );
            }
            _ => {
                panic!(
                    "{}",
                    UpdateSubnetAdminsError::UnsupportedSubnetType {
                        subnet_id,
                        subnet_type: subnet_record.subnet_type,
                    },
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

    fn prepare_registry_for_update_subnet_admins_test(
        subnet_id: SubnetId,
        subnet_type: SubnetType,
        initial_subnet_admins: Vec<PrincipalIdPb>,
    ) -> Registry {
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let mut subnet_list_record = registry.get_subnet_list_record();
        let (first_node_id, first_dkg_pk) = node_ids_and_dkg_pks
            .iter()
            .next()
            .expect("should contain at least one node ID and key");
        let mut subnet_record = get_invariant_compliant_subnet_record(vec![*first_node_id]);

        subnet_record.subnet_type = i32::from(subnet_type);
        subnet_record.canister_cycles_cost_schedule = i32::from(CanisterCyclesCostSchedule::Free);
        subnet_record.subnet_admins = initial_subnet_admins;

        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &btreemap!(*first_node_id => first_dkg_pk.clone()),
        ));

        registry
    }

    // For the purposes of the below tests, the updated subnet admins list matches
    // the expected one if they contain exactly the same elements regardless of order.
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
    fn rented_subnet_authorizes_subnet_rental_canister() {
        let subnet_id = subnet_test_id(1);
        let registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        // Should not panic.
        registry.check_update_subnet_admins_caller_authorization(caller, &subnet_record, subnet_id);
    }

    #[test]
    #[should_panic(expected = "is not authorized to update subnet admins")]
    fn rented_subnet_rejects_non_rental_canister_caller() {
        let subnet_id = subnet_test_id(1);
        let registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        let unauthorized_caller = user_test_id(999).get();

        registry.check_update_subnet_admins_caller_authorization(
            unauthorized_caller,
            &subnet_record,
            subnet_id,
        );
    }

    #[test]
    fn cloud_engine_authorizes_existing_admin() {
        let subnet_id = subnet_test_id(1);
        let admin = user_test_id(100).get();
        let registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::CloudEngine,
            vec![PrincipalIdPb::from(admin)],
        );
        let subnet_record = registry.get_subnet_or_panic(subnet_id);

        // Should not panic.
        registry.check_update_subnet_admins_caller_authorization(admin, &subnet_record, subnet_id);
    }

    #[test]
    #[should_panic(expected = "is not authorized to update subnet admins")]
    fn cloud_engine_rejects_non_admin_caller() {
        let subnet_id = subnet_test_id(1);
        let admin = user_test_id(100).get();
        let registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::CloudEngine,
            vec![PrincipalIdPb::from(admin)],
        );
        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        let non_admin = user_test_id(999).get();

        registry.check_update_subnet_admins_caller_authorization(
            non_admin,
            &subnet_record,
            subnet_id,
        );
    }

    #[test]
    #[should_panic(expected = "is not authorized to update subnet admins")]
    fn cloud_engine_rejects_subnet_rental_canister_caller() {
        let subnet_id = subnet_test_id(1);
        let admin = user_test_id(100).get();
        let registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::CloudEngine,
            vec![PrincipalIdPb::from(admin)],
        );
        let subnet_record = registry.get_subnet_or_panic(subnet_id);

        registry.check_update_subnet_admins_caller_authorization(
            PrincipalId::from(SUBNET_RENTAL_CANISTER_ID),
            &subnet_record,
            subnet_id,
        );
    }

    #[test]
    #[should_panic(expected = "Only subnets on a free cycles cost schedule")]
    fn non_free_cycles_schedule_rejects_authorization() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );

        // Override the cycles cost schedule to Normal to simulate a non-rented subnet.
        let mut subnet_record = registry.get_subnet_or_panic(subnet_id);
        subnet_record.canister_cycles_cost_schedule = i32::from(CanisterCyclesCostSchedule::Normal);
        registry.maybe_apply_mutation_internal(vec![upsert(
            make_subnet_record_key(subnet_id).into_bytes(),
            subnet_record.encode_to_vec(),
        )]);

        let subnet_record = registry.get_subnet_or_panic(subnet_id);
        registry.check_update_subnet_admins_caller_authorization(
            PrincipalId::from(SUBNET_RENTAL_CANISTER_ID),
            &subnet_record,
            subnet_id,
        );
    }

    #[test]
    #[should_panic(expected = "unsupported subnet type")]
    fn unsupported_subnet_type_rejects_authorization() {
        let subnet_id = subnet_test_id(1);
        // Create a valid Application subnet, then override its type to
        // VerifiedApplication to bypass registry invariant checks during setup.
        let registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let mut subnet_record = registry.get_subnet_or_panic(subnet_id);
        subnet_record.subnet_type = i32::from(SubnetType::VerifiedApplication);

        registry.check_update_subnet_admins_caller_authorization(
            PrincipalId::from(SUBNET_RENTAL_CANISTER_ID),
            &subnet_record,
            subnet_id,
        );
    }

    #[test]
    fn rented_subnet_can_add_or_remove_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let user1 = user_test_id(100).get();
        let user2 = user_test_id(101).get();

        // Add two subnet admins, `user1` and `user2`.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user2])),
        };

        registry.do_update_subnet_admins(caller, payload);

        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &[PrincipalIdPb::from(user1), PrincipalIdPb::from(user2)],
        );

        // Remove `user1` from the subnet admins list.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user1])),
        };

        registry.do_update_subnet_admins(caller, payload);
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &[PrincipalIdPb::from(user2)],
        );
    }

    #[test]
    fn rented_subnet_can_clear_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let user1 = user_test_id(100).get();
        let user2 = user_test_id(101).get();
        let user3 = user_test_id(102).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user2, user3])),
        };

        registry.do_update_subnet_admins(caller, payload);

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

        registry.do_update_subnet_admins(caller, payload);

        assert_eq!(
            registry.get_subnet_or_panic(subnet_id).subnet_admins,
            vec![]
        );
    }

    #[test]
    #[should_panic(expected = "The list of provided principals cannot be empty")]
    fn can_not_add_empty_list_of_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![])),
        };

        registry.do_update_subnet_admins(caller, payload);
    }

    #[test]
    #[should_panic(expected = "The list of provided principals cannot be empty")]
    fn can_not_remove_empty_list_of_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![])),
        };

        registry.do_update_subnet_admins(caller, payload);
    }

    #[test]
    fn can_dedup_input_when_adding_or_removing_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let user1 = user_test_id(100).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user1])),
        };

        registry.do_update_subnet_admins(caller, payload);
        assert_eq!(
            registry.get_subnet_or_panic(subnet_id).subnet_admins,
            vec![PrincipalIdPb::from(user1)]
        );

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user1, user1])),
        };

        registry.do_update_subnet_admins(caller, payload);
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
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let mut users_to_add = Vec::new();
        for i in 0..(MAX_SUBNET_ADMINS + 1) {
            users_to_add.push(user_test_id(100 + i as u64).get());
        }

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(users_to_add)),
        };

        registry.do_update_subnet_admins(caller, payload);
    }

    #[test]
    #[should_panic(expected = "Too many subnet admins. Provided: 3, Existing: 9, Max allowed: 10.")]
    fn can_not_add_too_many_subnet_admins_with_existing_ones() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

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
        registry.do_update_subnet_admins(caller, payload);
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

        registry.do_update_subnet_admins(caller, payload);
    }

    #[test]
    #[should_panic(
        expected = "Too many subnet admins. Provided: 11, Existing: 0, Max allowed: 10."
    )]
    fn can_not_remove_too_many_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let mut users_to_remove = Vec::new();
        for i in 0..(MAX_SUBNET_ADMINS + 1) {
            users_to_remove.push(user_test_id(100 + i as u64).get());
        }

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(users_to_remove)),
        };

        registry.do_update_subnet_admins(caller, payload);
    }

    #[test]
    fn can_not_add_existing_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let user1 = user_test_id(100).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1])),
        };

        registry.do_update_subnet_admins(caller, payload.clone());
        let expected_subnet_admins = vec![PrincipalIdPb::from(user1)];
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &expected_subnet_admins,
        );

        // Attempt to add the same user again. Should be a no-op.
        registry.do_update_subnet_admins(caller, payload);
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &expected_subnet_admins,
        );
    }

    #[test]
    fn can_not_remove_non_existing_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::Application,
            vec![],
        );
        let caller = PrincipalId::from(SUBNET_RENTAL_CANISTER_ID);

        let user1 = user_test_id(100).get();
        let user2 = user_test_id(101).get();
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user1, user2])),
        };
        registry.do_update_subnet_admins(caller, payload);
        let expected_subnet_admins = vec![PrincipalIdPb::from(user1), PrincipalIdPb::from(user2)];

        // Attempt to remove a user that is not in the subnet admins list. Should be a no-op.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user_test_id(200).get()])),
        };
        registry.do_update_subnet_admins(caller, payload);
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &expected_subnet_admins,
        );
    }

    // =====================================================================
    // Core logic tests for CloudEngine subnets
    //
    // These tests verify add/remove/clear logic specific to CloudEngine
    // and do not re-test authorization — they use an existing admin as
    // the caller.
    // =====================================================================

    #[test]
    fn cloud_engine_admin_can_add_or_remove_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let admin = user_test_id(100).get();
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::CloudEngine,
            vec![PrincipalIdPb::from(admin)],
        );

        let user2 = user_test_id(101).get();

        // Admin adds another subnet admin.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Add(vec![user2])),
        };

        registry.do_update_subnet_admins(admin, payload);

        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &[PrincipalIdPb::from(admin), PrincipalIdPb::from(user2)],
        );

        // Admin removes the other subnet admin.
        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![user2])),
        };

        registry.do_update_subnet_admins(admin, payload);
        assert_updated_subnet_admins_match_expected(
            &registry.get_subnet_or_panic(subnet_id).subnet_admins,
            &[PrincipalIdPb::from(admin)],
        );
    }

    #[test]
    #[should_panic(expected = "Cannot remove all subnet admins from CloudEngine subnet")]
    fn cloud_engine_cannot_clear_all_subnet_admins() {
        let subnet_id = subnet_test_id(1);
        let admin = user_test_id(100).get();
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::CloudEngine,
            vec![PrincipalIdPb::from(admin)],
        );

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Clear(EmptyRecord {})),
        };

        registry.do_update_subnet_admins(admin, payload);
    }

    #[test]
    #[should_panic(expected = "Cannot remove all subnet admins from CloudEngine subnet")]
    fn cloud_engine_cannot_remove_last_admin() {
        let subnet_id = subnet_test_id(1);
        let admin = user_test_id(100).get();
        let mut registry = prepare_registry_for_update_subnet_admins_test(
            subnet_id,
            SubnetType::CloudEngine,
            vec![PrincipalIdPb::from(admin)],
        );

        let payload = UpdateSubnetAdminsPayload {
            subnet_id,
            operation_type: Some(OperationType::Remove(vec![admin])),
        };

        registry.do_update_subnet_admins(admin, payload);
    }
}
