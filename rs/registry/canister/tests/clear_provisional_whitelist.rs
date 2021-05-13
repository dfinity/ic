use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid;
use ic_base_types::PrincipalId;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_utils::registry::invariant_compliant_mutation_as_atomic_req;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::get_value,
};
use ic_protobuf::registry::provisional_whitelist::v1::ProvisionalWhitelist;
use ic_registry_keys::make_provisional_whitelist_record_key;
use ic_registry_transport::pb::v1::{
    registry_mutation::Type, RegistryAtomicMutateRequest, RegistryMutation,
};
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

use std::str::FromStr;

#[test]
fn anonymous_user_cannot_clear_the_provisional_whitelist() {
    local_test_on_nns_subnet(|runtime| async move {
        let principal_id = PrincipalId::from_str(
            "5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae",
        )
        .unwrap();

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![RegistryMutation {
                        mutation_type: Type::Insert as i32,
                        key: make_provisional_whitelist_record_key().as_bytes().to_vec(),
                        value: encode_or_panic(&ProvisionalWhitelist {
                            list_type: 2,
                            set: vec![principal_id.into()],
                        }),
                    }],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // The anonymous end-user tries to clear the provisional whitelist, bypassing
        // the proposals.
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("clear_provisional_whitelist", candid, ())
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: clear_provisional_whitelist"));

        // Confirm the provisional whitelist is unchanged.
        let provisional_whitelist = get_value::<ProvisionalWhitelist>(
            &registry,
            make_provisional_whitelist_record_key().as_bytes(),
        )
        .await;
        assert_eq!(provisional_whitelist.set, vec![principal_id.into()]);

        Ok(())
    });
}

#[test]
fn a_canister_other_than_the_governance_canister_cannot_change_the_provisional_whitelist() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let principal_id = PrincipalId::from_str(
            "5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae",
        )
        .unwrap();

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![RegistryMutation {
                        mutation_type: Type::Insert as i32,
                        key: make_provisional_whitelist_record_key().as_bytes().to_vec(),
                        value: encode_or_panic(&ProvisionalWhitelist {
                            list_type: 2,
                            set: vec![principal_id.into()],
                        }),
                    }],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // The attacker canister tries to change the provisional whitelist, pretending
        // to be the governance canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "clear_provisional_whitelist",
                Encode!(&()).unwrap()
            )
            .await
        );

        // Confirm that the provisional whitelist is unchanged.
        let provisional_whitelist = get_value::<ProvisionalWhitelist>(
            &registry,
            make_provisional_whitelist_record_key().as_bytes(),
        )
        .await;
        assert_eq!(provisional_whitelist.set, vec![principal_id.into()]);

        Ok(())
    });
}

#[test]
fn clear_provisional_whitelist_succeeds() {
    local_test_on_nns_subnet(|runtime| async move {
        let principal_id = PrincipalId::from_str(
            "5o66h-77qch-43oup-7aaui-kz5ty-tww4j-t2wmx-e3lym-cbtct-l3gpw-wae",
        )
        .unwrap();

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![RegistryMutation {
                        mutation_type: Type::Insert as i32,
                        key: make_provisional_whitelist_record_key().as_bytes().to_vec(),
                        value: encode_or_panic(&ProvisionalWhitelist {
                            list_type: 2,
                            set: vec![principal_id.into()],
                        }),
                    }],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can
        // impersonate it.
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "clear_provisional_whitelist",
                Encode!(&()).unwrap()
            )
            .await
        );

        // Check that the provisional whitelist is empty after the update.
        let provisional_whitelist = get_value::<ProvisionalWhitelist>(
            &registry,
            make_provisional_whitelist_record_key().as_bytes(),
        )
        .await;
        assert_eq!(provisional_whitelist.set, vec![]);

        Ok(())
    });
}
