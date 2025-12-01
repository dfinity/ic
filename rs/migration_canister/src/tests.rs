//! Unit tests
use crate::migration_canister::MigrationCanisterInitArgs;
use crate::privileged::MigrationCanisterError;
use crate::{MigrateCanisterArgs, MigrationStatus, ValidationError};
use candid::Principal;
use candid_parser::utils::{CandidSource, service_equal};

use crate::{
    Request, RequestState,
    canister_state::requests::{find_request, insert_request},
};

#[test]
fn test() {
    let source = Principal::self_authenticating(vec![1]);
    let target = Principal::self_authenticating(vec![2]);
    let source_subnet = Principal::self_authenticating(vec![3]);
    let target_subnet = Principal::self_authenticating(vec![4]);
    let caller = Principal::self_authenticating(vec![5]);

    let request = Request::new(
        source,
        source_subnet,
        vec![],
        target,
        target_subnet,
        vec![],
        caller,
    );
    insert_request(RequestState::Accepted { request });
    assert!(find_request(source, target).len() == 1);
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
