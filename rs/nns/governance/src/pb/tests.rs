use super::*;

use crate::pb::v1 as pb;
use ic_base_types::PrincipalId;
use ic_nns_governance_api::pb::v1 as pb_api;

#[test]
fn install_code_internal_to_api() {
    let test_cases = vec![
        (
            pb::InstallCode {
                canister_id: Some(PrincipalId::new_user_test_id(1)),
                install_mode: Some(pb::install_code::CanisterInstallMode::Install as i32),
                skip_stopping_before_installing: None,
                wasm_module: Some(vec![1, 2, 3]),
                arg: Some(vec![]),
            },
            pb_api::InstallCode {
                canister_id: Some(PrincipalId::new_user_test_id(1)),
                install_mode: Some(pb_api::install_code::CanisterInstallMode::Install as i32),
                skip_stopping_before_installing: None,
                wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
                arg_hash: Some(vec![]),
            },
        ),
        (
            pb::InstallCode {
                canister_id: Some(PrincipalId::new_user_test_id(1)),
                install_mode: Some(pb::install_code::CanisterInstallMode::Upgrade as i32),
                skip_stopping_before_installing: Some(true),
                wasm_module: Some(vec![1, 2, 3]),
                arg: Some(vec![4, 5, 6]),
            },
            pb_api::InstallCode {
                canister_id: Some(PrincipalId::new_user_test_id(1)),
                install_mode: Some(pb_api::install_code::CanisterInstallMode::Upgrade as i32),
                skip_stopping_before_installing: Some(true),
                wasm_module_hash: Some(Sha256::hash(&[1, 2, 3]).to_vec()),
                arg_hash: Some(Sha256::hash(&[4, 5, 6]).to_vec()),
            },
        ),
    ];

    for (internal, api) in test_cases {
        assert_eq!(pb_api::InstallCode::from(internal), api);
    }
}
