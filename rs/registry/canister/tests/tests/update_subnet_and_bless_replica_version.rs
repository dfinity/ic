use candid::Encode;
use dfn_candid::candid;

use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value_or_panic, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::{
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    subnet::v1::SubnetRecord,
};
use ic_registry_keys::{
    make_blessed_replica_version_key, make_replica_version_key, make_subnet_record_key,
};
use ic_test_utilities::types::ids::subnet_test_id;

use assert_matches::assert_matches;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_bless_replica_version::BlessReplicaVersionPayload,
        do_update_subnet_replica::UpdateSubnetReplicaVersionPayload,
    },
};

#[test]
fn test_the_anonymous_user_cannot_bless_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        let payload = BlessReplicaVersionPayload {
            replica_version_id: "version_43".to_string(),
            binary_url: "".into(),
            sha256_hex: "".into(),
            node_manager_binary_url: "".into(),
            node_manager_sha256_hex: "".into(),
            release_package_url: "".into(),
            release_package_sha256_hex: "".into(),
        };
        // The anonymous end-user tries to bless a version, bypassing the proposals
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("bless_replica_version", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: bless_replica_version"));
        // .. And there should therefore be no blessed version
        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &registry,
                make_blessed_replica_version_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec!["version_42".to_string()]
            }
        );

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("bless_replica_version", candid, (payload.clone(),))
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: bless_replica_version"));
        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &registry,
                make_blessed_replica_version_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec!["version_42".to_string()]
            }
        );

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_proposals_canister_cannot_bless_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the proposals
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;
        let payload = BlessReplicaVersionPayload {
            replica_version_id: "version_43".to_string(),
            binary_url: "".into(),
            sha256_hex: "".into(),
            node_manager_binary_url: "".into(),
            node_manager_sha256_hex: "".into(),
            release_package_url: "".into(),
            release_package_sha256_hex: "".into(),
        };
        // The attacker canister tries to bless a version, pretending to be the
        // proposals canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "bless_replica_version",
                Encode!(&payload).unwrap()
            )
            .await
        );
        // But there should be no blessed version
        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &registry,
                make_blessed_replica_version_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec!["version_42".to_string()]
            }
        );
        Ok(())
    });
}

#[test]
fn test_accepted_proposal_mutates_the_registry() {
    local_test_on_nns_subnet(|runtime| async move {
        // Add an empty routing table to the registry
        let init_payload = RegistryCanisterInitPayloadBuilder::new()
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
            .build();
        let registry = set_up_registry_canister(&runtime, init_payload).await;

        // Install the universal canister in place of the proposals canister
        let fake_proposal_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            fake_proposal_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        const MOCK_HASH: &str = "d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1";

        // We can bless a new version, the version already in the registry is 42
        let payload_v43 = BlessReplicaVersionPayload {
            replica_version_id: "version_43".to_string(),
            binary_url: "".into(),
            sha256_hex: "".into(),
            node_manager_binary_url: "".into(),
            node_manager_sha256_hex: "".into(),
            release_package_url: "http://release_package.tar.gz".into(),
            release_package_sha256_hex: MOCK_HASH.into(),
        };
        assert!(
            forward_call_via_universal_canister(
                &fake_proposal_canister,
                &registry,
                "bless_replica_version",
                Encode!(&payload_v43).unwrap()
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &registry,
                make_blessed_replica_version_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec!["version_42".to_string(), "version_43".to_string()]
            }
        );

        // Trying to mutate an existing record should have no effect.
        let payload_v42_mutate = BlessReplicaVersionPayload {
            replica_version_id: "version_42".to_string(),
            binary_url: "".into(),
            sha256_hex: "".into(),
            node_manager_binary_url: "".into(),
            node_manager_sha256_hex: "".into(),
            release_package_url: "".into(),
            release_package_sha256_hex: "".into(),
        };
        assert!(
            !forward_call_via_universal_canister(
                &fake_proposal_canister,
                &registry,
                "bless_replica_version",
                Encode!(&payload_v42_mutate).unwrap(),
            )
            .await
        );
        // The URL in the registry should still the old one.
        assert_eq!(
            get_value_or_panic::<ReplicaVersionRecord>(
                &registry,
                make_replica_version_key("version_42").as_bytes()
            )
            .await,
            ReplicaVersionRecord {
                release_package_url: "http://release_package.tar.gz".into(),
                release_package_sha256_hex: MOCK_HASH.into(),
            }
        );

        // Let's now try to upgrade a subnet.
        // The subnet was added at the beginning of the test

        // Set the subnet to a blessed version: it should work
        let set_to_blessed_ = UpdateSubnetReplicaVersionPayload {
            subnet_id: subnet_test_id(999).get(),
            replica_version_id: "version_42".to_string(),
        };
        assert!(
            forward_call_via_universal_canister(
                &fake_proposal_canister,
                &registry,
                "update_subnet_replica_version",
                Encode!(&set_to_blessed_).unwrap(),
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_test_id(999)).as_bytes()
            )
            .await
            .replica_version_id,
            "version_42"
        );

        // Try to set the subnet to an unblessed version: it should fail
        let try_set_to_unblessed = UpdateSubnetReplicaVersionPayload {
            subnet_id: subnet_test_id(999).get(),
            replica_version_id: "unblessed".to_string(),
        };
        assert!(
            !forward_call_via_universal_canister(
                &fake_proposal_canister,
                &registry,
                "update_subnet_replica_version",
                Encode!(&try_set_to_unblessed).unwrap(),
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_test_id(999)).as_bytes()
            )
            .await
            .replica_version_id,
            "version_42"
        );

        Ok(())
    });
}
