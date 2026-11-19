//! Unit tests
use crate::migration_canister::MigrationCanisterInitArgs;
use crate::privileged::MigrationCanisterError;
use crate::{
    MEMORY_RESERVED_FOR_CANISTER_HISTORY, MigrateCanisterArgs, MigrationStatus, ValidationError,
};
use candid::Principal;
use candid_parser::utils::{CandidSource, service_equal};
use ic_base_types::PrincipalId;
use ic_config::execution_environment::MAX_ALLOWED_CONTROLLERS_COUNT;
use ic_limits::MAX_CANISTER_HISTORY_CHANGES;
use ic_management_canister_types_private::{
    CanisterChange, CanisterChangeDetails, CanisterChangeOrigin,
};

use crate::{
    Request, RequestState,
    canister_state::requests::{find_request, insert_request},
};

/// The migration canister checks that the memory usage of the migrated and replaced canisters
/// excluding their canister history did not grow since validation once it is their exclusive
/// controller (see `memory_usage_did_not_grow`). Hence, the memory that the migration canister reserves on
/// top of that memory usage only needs to cover the canister history of those canisters, whose
/// size is bounded because the system only retains the most recent `MAX_CANISTER_HISTORY_CHANGES`
/// canister changes and a single canister change is bounded by the number of controllers
/// it may contain.
#[test]
fn memory_reserved_for_canister_history_covers_maximum_canister_history_size() {
    // The memory usage of a canister change is determined by `CanisterChange::count_bytes`,
    // i.e., the very function the system uses to account for canister history. It only depends
    // on the number of controllers stored in the canister change and thus we take the maximum
    // over all kinds of canister changes storing controllers, each of which is subject to
    // the limit on the number of controllers.
    let max_controllers = vec![PrincipalId::new_anonymous(); MAX_ALLOWED_CONTROLLERS_COUNT];
    let max_canister_change_size = [
        CanisterChangeDetails::canister_creation(max_controllers.clone(), Some([0; 32])),
        CanisterChangeDetails::controllers_change(max_controllers.clone()),
        CanisterChangeDetails::settings_change(Some(max_controllers), Some([0; 32])),
    ]
    .into_iter()
    .map(|details| {
        let origin = CanisterChangeOrigin::from_canister(PrincipalId::new_anonymous(), Some(0));
        CanisterChange::new(0, 0, origin, details)
            .count_bytes()
            .get() as usize
    })
    .max()
    .unwrap();
    let max_canister_history_size =
        MAX_CANISTER_HISTORY_CHANGES as usize * max_canister_change_size;
    assert!(
        MEMORY_RESERVED_FOR_CANISTER_HISTORY as usize >= max_canister_history_size,
        "MEMORY_RESERVED_FOR_CANISTER_HISTORY ({}) must cover the maximum canister history size \
         ({} = {} * {})",
        MEMORY_RESERVED_FOR_CANISTER_HISTORY,
        max_canister_history_size,
        MAX_CANISTER_HISTORY_CHANGES,
        max_canister_change_size,
    );
}

#[test]
fn test() {
    let migrated_canister = Principal::self_authenticating(vec![1]);
    let replaced_canister = Principal::self_authenticating(vec![2]);
    let migrated_canister_subnet = Principal::self_authenticating(vec![3]);
    let replaced_canister_subnet = Principal::self_authenticating(vec![4]);
    let caller = Principal::self_authenticating(vec![5]);

    let request = Request::new(
        migrated_canister,
        migrated_canister_subnet,
        vec![],
        None,
        replaced_canister,
        replaced_canister_subnet,
        vec![],
        None,
        caller,
    );
    insert_request(RequestState::Accepted { request });
    assert!(find_request(migrated_canister, replaced_canister).is_some());
}

#[test]
fn test_implemented_interface_matches_declared_interface_exactly() {
    let declared_interface = CandidSource::Text(include_str!("../migration_canister.did"));

    // The line below generates did types and service definition.
    // The service definition is then obtained with `__export_service()`.
    candid::export_service!();
    let implemented_interface_str = __export_service();
    let implemented_interface = CandidSource::Text(&implemented_interface_str);

    let result = service_equal(declared_interface, implemented_interface);
    assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
}
