use dfn_core::api::caller;
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::BuildHasherDefault;
use std::sync::RwLock;

use lazy_static::lazy_static;

use ic_base_types::PrincipalId;
use ic_nervous_system_common::{AuthzChangeOp, MethodAuthzChange};

use crate::pb::v1::{CanisterAuthzInfo, MethodAuthzInfo};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

pub type AuthzMap = HashMap<String, MethodAuthzInfo, BuildHasherDefault<DefaultHasher>>;

lazy_static! {
    /// The authorization map to be used by each NNS canister.
    ///
    /// It lives here as to avoid the repetition of having each canister declare its own.
    static ref AUTHZ_MAP: RwLock<AuthzMap> = RwLock::new(AuthzMap::default());
}

/// Initializes authorization for a canister based on the arguments passed at
/// initialization time.
pub fn init_canister_authz(canister_authz: CanisterAuthzInfo) {
    let mut authz = AUTHZ_MAP.write().unwrap();
    authz.clear();
    for method_authz in canister_authz.methods_authz {
        authz.insert(method_authz.method_name.clone(), method_authz);
    }
}

/// Returns the current canister authz information.
pub fn current_canister_authz() -> CanisterAuthzInfo {
    let authz = AUTHZ_MAP.read().unwrap();
    let mut methods_authz = Vec::new();
    for method_authz in authz.values() {
        methods_authz.push(method_authz.clone());
    }
    CanisterAuthzInfo { methods_authz }
}

/// Updates this canister's authz.
pub fn update_methods_authz(methods_authz_change: Vec<MethodAuthzChange>, log_prefix: &str) {
    println!(
        "{}Changing authz. Previous: {:?}. Changes: {:?}",
        log_prefix,
        current_canister_authz(),
        methods_authz_change
    );
    let mut authz = AUTHZ_MAP.write().unwrap();
    for method_authz_change in methods_authz_change {
        // Note that we always expect a principal here.
        // The root canister is responsible for setting the right principal
        // before it gets here, if 'Authorize::add_self' was true.
        let principal = method_authz_change
            .principal
            .expect("Expected to receive a principal.");
        let method_name = method_authz_change.method_name;
        match method_authz_change.operation {
            AuthzChangeOp::Authorize { add_self: _ } => {
                let method_authz = authz.entry(method_name.clone()).or_insert(MethodAuthzInfo {
                    method_name,
                    principal_ids: Vec::new(),
                });
                method_authz.principal_ids.push(principal.to_vec());
            }
            AuthzChangeOp::Deauthorize => {
                // Remove the principal, if it exists.
                // If the method doesn't have any authorized principals, remove the
                // MethodsAuthzInfo
                if let Some(method_authz) = authz.get_mut(&method_name) {
                    method_authz
                        .principal_ids
                        .retain(|p| *p != principal.to_vec());
                }
            }
        }
    }
}

/// Checks whether the given principal has access to the given method.
pub fn is_authorized(method_name: &str, principal_id: PrincipalId) -> bool {
    let authz = AUTHZ_MAP.read().unwrap();
    match authz.get(method_name) {
        // Test whether the (string representation) of the principal is registered
        // as having access to this method.
        Some(method_authz) => {
            let authorized = method_authz.principal_ids.contains(&principal_id.to_vec());
            if !authorized {
                println!(
                    "Principal: {} not authorized to access method: {}",
                    principal_id, method_name
                );
            }
            authorized
        }
        // If a method is not in access control, then by default it is authorized
        None => true,
    }
}

pub fn check_caller_is_root() {
    if caller() != PrincipalId::from(ic_nns_constants::ROOT_CANISTER_ID) {
        panic!("Only the root canister is allowed to call this method.");
    }
}

pub fn check_caller_is_ledger() {
    if caller() != PrincipalId::from(ic_nns_constants::LEDGER_CANISTER_ID) {
        panic!("Only the ledger canister is allowed to call this method.");
    }
}

pub fn check_caller_is_gtc() {
    if caller() != PrincipalId::from(ic_nns_constants::GENESIS_TOKEN_CANISTER_ID) {
        panic!("Only the GTC is allowed to call this method.");
    }
}

pub fn check_caller_is_governance() {
    if caller() != PrincipalId::from(ic_nns_constants::GOVERNANCE_CANISTER_ID) {
        panic!("Only the Governance canister is allowed to call this method");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::CanisterId;
    use serial_test::serial;
    use std::convert::TryFrom;
    use std::str::FromStr;

    const CANISTER_TEST_METHOD: &str = "canister_test_method";
    const USER_TEST_METHOD: &str = "user_test_method";

    fn init_user_authz_test() {
        let mut canister_authz = CanisterAuthzInfo::default();
        canister_authz.methods_authz.push(MethodAuthzInfo {
            method_name: USER_TEST_METHOD.to_string(),
            principal_ids: vec![
                PrincipalId::from_str("2chl6-4hpzw-vqaaa-aaaaa-c")
                    .unwrap()
                    .to_vec(),
                PrincipalId::from_str(
                    "bngem-gzprz-dtr6o-xnali-fgmfi-fjgpb-rya7j-x2idk-3eh6u-4v7tx-hqe",
                )
                .unwrap()
                .to_vec(),
            ],
        });
        init_canister_authz(canister_authz);
    }

    fn init_canister_authz_test() {
        let mut canister_authz = CanisterAuthzInfo::default();
        canister_authz.methods_authz.push(MethodAuthzInfo {
            method_name: CANISTER_TEST_METHOD.to_string(),
            principal_ids: vec![
                PrincipalId::try_from(ic_nns_constants::GOVERNANCE_CANISTER_ID)
                    .unwrap()
                    .to_vec(),
            ],
        });
        init_canister_authz(canister_authz);
    }

    #[test]
    #[serial]
    fn test_add_remove_principals() {
        init_canister_authz_test();
        let existing_principal = PrincipalId::from(ic_nns_constants::GOVERNANCE_CANISTER_ID);
        let new_principal = PrincipalId::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
        assert!(is_authorized(CANISTER_TEST_METHOD, existing_principal));
        assert!(!is_authorized(CANISTER_TEST_METHOD, new_principal));
        update_methods_authz(
            vec![MethodAuthzChange {
                canister: CanisterId::from(0),
                method_name: CANISTER_TEST_METHOD.to_string(),
                principal: Some(existing_principal),
                operation: AuthzChangeOp::Deauthorize,
            }],
            "TEST",
        );
        assert!(!is_authorized(CANISTER_TEST_METHOD, existing_principal));
        assert!(!is_authorized(CANISTER_TEST_METHOD, new_principal));
        // Now add one principal to the list of authorized principals
        update_methods_authz(
            vec![MethodAuthzChange {
                canister: CanisterId::from(0),
                method_name: CANISTER_TEST_METHOD.to_string(),
                principal: Some(new_principal),
                operation: AuthzChangeOp::Authorize { add_self: false },
            }],
            "TEST",
        );
        // The new principal should be authorized while the existing one shouldn't.
        assert!(is_authorized(CANISTER_TEST_METHOD, new_principal));
        assert!(!is_authorized(CANISTER_TEST_METHOD, existing_principal));
        // Switch the principals
        update_methods_authz(
            vec![
                MethodAuthzChange {
                    canister: CanisterId::from(0),
                    method_name: CANISTER_TEST_METHOD.to_string(),
                    principal: Some(existing_principal),
                    operation: AuthzChangeOp::Authorize { add_self: false },
                },
                MethodAuthzChange {
                    canister: CanisterId::from(0),
                    method_name: CANISTER_TEST_METHOD.to_string(),
                    principal: Some(new_principal),
                    operation: AuthzChangeOp::Deauthorize,
                },
            ],
            "TEST",
        );
        assert!(!is_authorized(CANISTER_TEST_METHOD, new_principal));
        assert!(is_authorized(CANISTER_TEST_METHOD, existing_principal));
    }

    #[test]
    #[serial]
    fn test_user_is_authorized_opaque() {
        init_user_authz_test();
        assert!(is_authorized(
            USER_TEST_METHOD,
            PrincipalId::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap()
        ));
    }

    #[test]
    #[serial]
    fn test_user_is_authorized_derived() {
        init_user_authz_test();
        assert!(is_authorized(
            USER_TEST_METHOD,
            PrincipalId::from_str(
                "bngem-gzprz-dtr6o-xnali-fgmfi-fjgpb-rya7j-x2idk-3eh6u-4v7tx-hqe"
            )
            .unwrap()
        ));
    }

    #[test]
    #[serial]
    fn test_user_is_authorized_non_specified_method() {
        init_user_authz_test();
        assert!(is_authorized(
            "unknown_method",
            PrincipalId::from_str("2vxsx-fae").unwrap()
        ));
    }

    #[test]
    #[serial]
    fn test_user_is_not_authorized_not_in_list() {
        init_user_authz_test();
        assert!(!is_authorized(
            USER_TEST_METHOD,
            PrincipalId::from_str("2vxsx-fae").unwrap()
        ));
    }

    #[test]
    #[serial]
    fn test_canister_is_authorized() {
        init_canister_authz_test();
        assert!(is_authorized(
            CANISTER_TEST_METHOD,
            PrincipalId::from(ic_nns_constants::GOVERNANCE_CANISTER_ID)
        ));
    }

    #[test]
    #[serial]
    fn test_canister_is_not_authorized() {
        init_canister_authz_test();
        assert!(!is_authorized(
            CANISTER_TEST_METHOD,
            PrincipalId::from(ic_nns_constants::ROOT_CANISTER_ID)
        ));
    }
}
