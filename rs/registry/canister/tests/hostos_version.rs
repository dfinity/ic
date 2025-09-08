use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::{hostos_version::v1::HostosVersionRecord, node::v1::NodeRecord};
use ic_registry_keys::{make_hostos_version_key, make_node_record_key};
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use prost::Message;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_update_elected_hostos_versions::UpdateElectedHostosVersionsPayload,
        do_update_nodes_hostos_version::UpdateNodesHostosVersionPayload,
    },
};

mod common;
use common::test_helpers::{
    prepare_registry_with_nodes, prepare_registry_with_nodes_from_template,
};

const GOOD_PACKAGE_URL: &str = "http://release_package.tar.zst";
const GOOD_SHA256_HEX: &str = "C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEED00D";

// ~~~~~~~~~~ Adding versions ~~~~~~~~~~

#[test]
fn test_the_anonymous_user_cannot_add_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        let hostos_version_id = "1".to_string();
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: Some(GOOD_SHA256_HEX.to_string()),
            hostos_version_to_elect: Some(hostos_version_id.clone()),
            hostos_versions_to_unelect: Vec::new(),
        };

        // The anonymous end-user tries to add a version, bypassing governance.
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_elected_hostos_versions", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_elected_hostos_versions"));
        // .. And the HostOS version should not exist.
        assert!(
            get_value::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await
            .is_none()
        );

        // Go through an upgrade cycle, and verify that it still works the
        // same.
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("update_elected_hostos_versions", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_elected_hostos_versions"));
        assert!(
            get_value::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await
            .is_none()
        );

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_add_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID.
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        let hostos_version_id = "1".to_string();
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: Some(GOOD_SHA256_HEX.to_string()),
            hostos_version_to_elect: Some(hostos_version_id.clone()),
            hostos_versions_to_unelect: Vec::new(),
        };

        // The attacker canister tries to add a version, pretending to be the
        // governance canister.
        // This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        // But there should be no HostOS versions.
        assert!(
            get_value::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await
            .is_none()
        );

        Ok(())
    });
}

#[test]
fn test_the_governance_canister_can_add_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let hostos_version_id = "1".to_string();
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: Some(GOOD_SHA256_HEX.to_string()),
            hostos_version_to_elect: Some(hostos_version_id.clone()),
            hostos_versions_to_unelect: Vec::new(),
        };
        let target_version_record = HostosVersionRecord {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
            hostos_version_id: hostos_version_id.clone(),
        };

        // We can add a new version.
        assert!(
            forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        Ok(())
    });
}

#[test]
fn test_cannot_add_duplicate_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let hostos_version_id = "1".to_string();
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: Some(GOOD_SHA256_HEX.to_string()),
            hostos_version_to_elect: Some(hostos_version_id.clone()),
            hostos_versions_to_unelect: Vec::new(),
        };
        let target_version_record = HostosVersionRecord {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
            hostos_version_id: hostos_version_id.clone(),
        };

        // We can add a new version.
        assert!(
            forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        // Trying to add or update the same version should fail.
        // (Use a different hash to differentiate in test.)
        let mutant_payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: Some(
                "BEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFD00D".to_string(),
            ),
            hostos_version_to_elect: Some(hostos_version_id.clone()),
            hostos_versions_to_unelect: Vec::new(),
        };
        assert!(
            !forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&mutant_payload).unwrap(),
            )
            .await
        );
        // The record in the registry should still the old one.
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        Ok(())
    });
}

#[test]
fn test_cannot_add_invalid_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // We can't add a version with a bad hash.
        let hostos_version_id = "1".to_string();
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: Some("invalid hash".to_string()),
            hostos_version_to_elect: Some(hostos_version_id.clone()),
            hostos_versions_to_unelect: Vec::new(),
        };
        assert!(
            !forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert!(
            get_value::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await
            .is_none()
        );

        // We can't add a version without any URLs.
        let hostos_version_id = "1".to_string();
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: Vec::new(),
            release_package_sha256_hex: Some(GOOD_SHA256_HEX.to_string()),
            hostos_version_to_elect: Some(hostos_version_id.clone()),
            hostos_versions_to_unelect: Vec::new(),
        };
        assert!(
            !forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert!(
            get_value::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await
            .is_none()
        );

        // We can't add a version with a bad URL.
        let hostos_version_id = "1".to_string();
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: vec!["invalid url".to_string()],
            release_package_sha256_hex: Some(GOOD_SHA256_HEX.to_string()),
            hostos_version_to_elect: Some(hostos_version_id.clone()),
            hostos_versions_to_unelect: Vec::new(),
        };
        assert!(
            !forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert!(
            get_value::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await
            .is_none()
        );

        Ok(())
    });
}

// ~~~~~~~~~~ Removing versions ~~~~~~~~~~

#[test]
fn test_the_anonymous_user_cannot_remove_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        // Set up with existing version
        let hostos_version_id = "1".to_string();
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_hostos_version_key(&hostos_version_id),
                        HostosVersionRecord {
                            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
                            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
                            hostos_version_id: hostos_version_id.clone(),
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Confirm version does exist
        let target_version_record = HostosVersionRecord {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
            hostos_version_id: hostos_version_id.clone(),
        };
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: Vec::new(),
            release_package_sha256_hex: None,
            hostos_version_to_elect: None,
            hostos_versions_to_unelect: vec![hostos_version_id.clone()],
        };

        // The anonymous end-user tries to remove a version, bypassing
        // governance.
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_elected_hostos_versions", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_elected_hostos_versions"));
        // .. And the HostOS version should still exist.
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        // Go through an upgrade cycle, and verify that it still works the
        // same.
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("update_elected_hostos_versions", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_elected_hostos_versions"));
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_remove_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID.
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // Set up with existing version
        let hostos_version_id = "1".to_string();
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_hostos_version_key(&hostos_version_id),
                        HostosVersionRecord {
                            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
                            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
                            hostos_version_id: hostos_version_id.clone(),
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Confirm version does exist
        let target_version_record = HostosVersionRecord {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
            hostos_version_id: hostos_version_id.clone(),
        };
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: Vec::new(),
            release_package_sha256_hex: None,
            hostos_version_to_elect: None,
            hostos_versions_to_unelect: vec![hostos_version_id.clone()],
        };

        // The attacker canister tries to remove a version, pretending to be
        // the governance canister.
        // This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        // But there should still be a HostOS version.
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        Ok(())
    });
}

#[test]
fn test_the_governance_canister_can_remove_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        // Set up with existing version
        let hostos_version_id = "1".to_string();
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_hostos_version_key(&hostos_version_id),
                        HostosVersionRecord {
                            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
                            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
                            hostos_version_id: hostos_version_id.clone(),
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .build(),
        )
        .await;

        // Confirm version does exist
        let hostos_version_id = "1".to_string();
        let target_version_record = HostosVersionRecord {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
            hostos_version_id: hostos_version_id.clone(),
        };
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: Vec::new(),
            release_package_sha256_hex: None,
            hostos_version_to_elect: None,
            hostos_versions_to_unelect: vec![hostos_version_id.clone()],
        };

        // We can remove an existing version.
        assert!(
            forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert!(
            get_value::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await
            .is_none()
        );

        Ok(())
    });
}

#[test]
fn test_cannot_remove_nonexistent_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let hostos_version_id = "1".to_string();
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: Vec::new(),
            release_package_sha256_hex: None,
            hostos_version_to_elect: None,
            hostos_versions_to_unelect: vec![hostos_version_id.clone()],
        };

        // Trying to remove a nonexistent version should fail.
        assert!(
            !forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );

        Ok(())
    });
}

#[test]
fn test_cannot_remove_used_version() {
    local_test_on_nns_subnet(|runtime| async move {
        // Set up with existing version
        let hostos_version_id = "1".to_string();
        let (add_node_mutation, _) = prepare_registry_with_nodes_from_template(
            1,
            1,
            NodeRecord {
                hostos_version_id: Some(hostos_version_id.clone()),
                ..Default::default()
            },
        );
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_hostos_version_key(&hostos_version_id),
                        HostosVersionRecord {
                            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
                            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
                            hostos_version_id: hostos_version_id.clone(),
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .push_init_mutate_request(add_node_mutation)
                .build(),
        )
        .await;

        // Confirm version does exist
        let hostos_version_id = "1".to_string();
        let target_version_record = HostosVersionRecord {
            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
            hostos_version_id: hostos_version_id.clone(),
        };
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // Trying to remove a version that is in use should fail.
        let payload = UpdateElectedHostosVersionsPayload {
            release_package_urls: Vec::new(),
            release_package_sha256_hex: None,
            hostos_version_to_elect: None,
            hostos_versions_to_unelect: vec![hostos_version_id.clone()],
        };
        assert!(
            !forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_elected_hostos_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // .. And the HostOS version should still exist.
        assert_eq!(
            get_value_or_panic::<HostosVersionRecord>(
                &registry,
                make_hostos_version_key(&hostos_version_id).as_bytes()
            )
            .await,
            target_version_record
        );

        Ok(())
    });
}

// ~~~~~~~~~~ Update version ~~~~~~~~~~

#[test]
fn test_the_anonymous_user_cannot_update_hostos_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let hostos_version_id = "1".to_string();
        let (add_node_mutation, node_ids) = prepare_registry_with_nodes(1, 1);
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_hostos_version_key(&hostos_version_id),
                        HostosVersionRecord {
                            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
                            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
                            hostos_version_id: hostos_version_id.clone(),
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .push_init_mutate_request(add_node_mutation)
                .build(),
        )
        .await;

        let node_id = node_ids.first().unwrap().to_owned();
        let initial_node_record =
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await;
        let payload = UpdateNodesHostosVersionPayload {
            node_ids: vec![node_id],
            hostos_version_id: Some(hostos_version_id),
        };

        // The anonymous end-user tries to update a nodes's HostOS version,
        // bypassing governance.
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_nodes_hostos_version", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_nodes_hostos_version"));

        // .. And no change should have happened to the node record.
        assert_eq!(
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await,
            initial_node_record
        );

        // Go through an upgrade cycle, and verify that it still works the
        // same.
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("update_nodes_hostos_version", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_nodes_hostos_version"));
        assert_eq!(
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await,
            initial_node_record
        );

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_update_hostos_version() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID.
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let hostos_version_id = "1".to_string();
        let (add_node_mutation, node_ids) = prepare_registry_with_nodes(1, 1);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_hostos_version_key(&hostos_version_id),
                        HostosVersionRecord {
                            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
                            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
                            hostos_version_id: hostos_version_id.clone(),
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .push_init_mutate_request(add_node_mutation)
                .build(),
        )
        .await;

        let node_id = node_ids.first().unwrap().to_owned();
        let initial_node_record =
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await;
        let payload = UpdateNodesHostosVersionPayload {
            node_ids: vec![node_id],
            hostos_version_id: Some(hostos_version_id),
        };

        // The attacker canister tries to update the node's HostOS version,
        // pretending to be the governance canister.
        // This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "update_nodes_hostos_version",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await,
            initial_node_record
        );

        Ok(())
    });
}

#[test]
fn test_the_governance_canister_can_update_hostos_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let hostos_version_id = "1".to_string();
        let (add_node_mutation, node_ids) = prepare_registry_with_nodes(1, 1);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_hostos_version_key(&hostos_version_id),
                        HostosVersionRecord {
                            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
                            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
                            hostos_version_id: hostos_version_id.clone(),
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .push_init_mutate_request(add_node_mutation)
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let node_id = node_ids.first().unwrap().to_owned();
        let initial_node_record =
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await;
        let payload = UpdateNodesHostosVersionPayload {
            node_ids: vec![node_id],
            hostos_version_id: Some(hostos_version_id.clone()),
        };
        let target_node_record = NodeRecord {
            hostos_version_id: Some(hostos_version_id),
            ..initial_node_record
        };

        // We can update HostOS versions.
        assert!(
            forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_nodes_hostos_version",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await,
            target_node_record
        );

        Ok(())
    });
}

#[test]
fn test_can_unset_nodes_hostos_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let hostos_version_id = "1".to_string();
        let (add_node_mutation, node_ids) = prepare_registry_with_nodes(1, 1);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(
                        make_hostos_version_key(&hostos_version_id),
                        HostosVersionRecord {
                            release_package_urls: vec![GOOD_PACKAGE_URL.to_string()],
                            release_package_sha256_hex: GOOD_SHA256_HEX.to_string(),
                            hostos_version_id: hostos_version_id.clone(),
                        }
                        .encode_to_vec(),
                    )],
                    preconditions: vec![],
                })
                .push_init_mutate_request(add_node_mutation)
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let node_id = node_ids.first().unwrap().to_owned();
        let initial_node_record =
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await;
        let payload = UpdateNodesHostosVersionPayload {
            node_ids: vec![node_id],
            hostos_version_id: Some(hostos_version_id.clone()),
        };
        let target_node_record = NodeRecord {
            hostos_version_id: Some(hostos_version_id),
            ..initial_node_record.clone()
        };

        // We can update HostOS versions.
        assert!(
            forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_nodes_hostos_version",
                Encode!(&payload).unwrap()
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await,
            target_node_record
        );

        // We can also unset the version.
        let unset_payload = UpdateNodesHostosVersionPayload {
            node_ids: vec![node_id],
            hostos_version_id: None,
        };
        assert!(
            forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_nodes_hostos_version",
                Encode!(&unset_payload).unwrap(),
            )
            .await
        );
        // The version for the node should now be removed.
        assert_eq!(
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await,
            initial_node_record
        );

        Ok(())
    });
}

#[test]
fn test_cannot_update_to_invalid_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let (add_node_mutation, node_ids) = prepare_registry_with_nodes(1, 1);
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .push_init_mutate_request(add_node_mutation)
                .build(),
        )
        .await;

        // Install the universal canister in place of the governance canister.
        let governance_canister = set_up_universal_canister(&runtime).await;
        assert_eq!(
            governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // We can't update to a version that does not exist.
        let node_id = node_ids.first().unwrap().to_owned();
        let initial_node_record =
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await;
        let payload = UpdateNodesHostosVersionPayload {
            node_ids: vec![node_id],
            hostos_version_id: Some("invalid version".to_string()),
        };
        assert!(
            !forward_call_via_universal_canister(
                &governance_canister,
                &registry,
                "update_nodes_hostos_version",
                Encode!(&payload).unwrap()
            )
            .await
        );
        // The record in the registry should still the old one.
        assert_eq!(
            get_value_or_panic::<NodeRecord>(&registry, make_node_record_key(node_id).as_bytes())
                .await,
            initial_node_record
        );

        Ok(())
    });
}
