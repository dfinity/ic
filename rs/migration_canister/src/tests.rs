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
use ic_management_canister_types_private::CanisterChange;
use ic_replicated_state::canister_state::system_state::MAX_CANISTER_HISTORY_CHANGES;

use crate::{
    Request, RequestState,
    canister_state::requests::{find_request, insert_request},
};

/// The migration canister checks that the memory usage of the migrated and replaced canisters
/// excluding their canister history does not change while it is their exclusive controller
/// (see `memory_usage_unchanged`). Hence, the memory that the migration canister reserves on
/// top of that memory usage only needs to cover the canister history of those canisters, whose
/// size is bounded because the system only retains the most recent `MAX_CANISTER_HISTORY_CHANGES`
/// canister changes and a single canister change is bounded by the number of controllers
/// it may contain.
#[test]
fn memory_reserved_for_canister_history_covers_maximum_canister_history_size() {
    // The memory usage of a canister change is `size_of::<CanisterChange>()` plus
    // `size_of::<PrincipalId>()` for every controller stored in it (the controllers are stored
    // on heap and thus not accounted for in `size_of::<CanisterChange>()`); the only canister
    // changes containing controllers are canister creation, controllers change, and settings
    // change, all of which are subject to the limit on the number of controllers.
    let max_canister_change_size =
        size_of::<CanisterChange>() + MAX_ALLOWED_CONTROLLERS_COUNT * size_of::<PrincipalId>();
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
        Some(false),
        replaced_canister,
        replaced_canister_subnet,
        vec![],
        None,
        Some(false),
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
