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
    make_blessed_replica_versions_key, make_replica_version_key, make_subnet_record_key,
};
use ic_test_utilities_types::ids::subnet_test_id;

use assert_matches::assert_matches;
use ic_protobuf::registry::replica_version::v1::{
    GuestLaunchMeasurement, GuestLaunchMeasurementMetadata, GuestLaunchMeasurements,
};
use ic_types::ReplicaVersion;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::{
        do_deploy_guestos_to_all_subnet_nodes::DeployGuestosToAllSubnetNodesPayload,
        do_revise_elected_replica_versions::ReviseElectedGuestosVersionsPayload,
    },
};

const MOCK_HASH: &str = "acdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdcacdc";

fn guest_launch_measurements_for_test() -> Option<GuestLaunchMeasurements> {
    Some(GuestLaunchMeasurements {
        guest_launch_measurements: vec![
            GuestLaunchMeasurement {
                #[allow(deprecated)]
                measurement: vec![0x01, 0x02, 0x03],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "foo=bar".into(),
                }),
                encoded_measurement: Some(hex::encode(vec![0x01, 0x02, 0x03])),
            },
            GuestLaunchMeasurement {
                #[allow(deprecated)]
                measurement: vec![0x04, 0x05, 0x06],
                metadata: Some(GuestLaunchMeasurementMetadata {
                    kernel_cmdline: "hello=world".into(),
                }),
                encoded_measurement: Some(hex::encode(vec![0x04, 0x05, 0x06])),
            },
        ],
    })
}

#[test]
fn test_the_anonymous_user_cannot_elect_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;

        let payload = ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: Some("version_43".into()),
            release_package_sha256_hex: None,
            release_package_urls: vec![],
            guest_launch_measurements: None,
            replica_versions_to_unelect: vec![],
        };
        // The anonymous end-user tries to bless a version, bypassing the proposals
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_(
                "revise_elected_replica_versions",
                candid,
                (payload.clone(),),
            )
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: revise_elected_replica_versions"));
        // .. And there should therefore be no blessed version
        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &registry,
                make_blessed_replica_versions_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec![ReplicaVersion::default().into()]
            }
        );

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_(
                "revise_elected_replica_versions",
                candid,
                (payload.clone(),),
            )
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: revise_elected_replica_versions"));
        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &registry,
                make_blessed_replica_versions_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec![ReplicaVersion::default().into()]
            }
        );

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_bless_a_version() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the governance
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
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
                .build(),
        )
        .await;
        let payload = ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: Some("version_43".into()),
            release_package_sha256_hex: Some(MOCK_HASH.into()),
            release_package_urls: vec!["http://release_package.tar.zst".into()],
            guest_launch_measurements: None,
            replica_versions_to_unelect: vec![],
        };
        // The attacker canister tries to bless a version, pretending to be the
        // governance canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "revise_elected_replica_versions",
                Encode!(&payload).unwrap()
            )
            .await
        );
        // But there should be no blessed version
        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &registry,
                make_blessed_replica_versions_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec![ReplicaVersion::default().into()]
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
            .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0))
            .build();
        let registry = set_up_registry_canister(&runtime, init_payload).await;

        // Install the universal canister in place of the governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can impersonate
        // it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        // We can bless a new version, the version already in the registry is 42
        let payload_v43 = ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: Some("version_43".into()),
            release_package_sha256_hex: Some(MOCK_HASH.into()),
            release_package_urls: vec!["http://release_package.tar.zst".into()],
            guest_launch_measurements: guest_launch_measurements_for_test(),
            replica_versions_to_unelect: vec![],
        };
        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "revise_elected_replica_versions",
                Encode!(&payload_v43).unwrap()
            )
            .await
        );
        assert_eq!(
            get_value_or_panic::<BlessedReplicaVersions>(
                &registry,
                make_blessed_replica_versions_key().as_bytes()
            )
            .await,
            BlessedReplicaVersions {
                blessed_version_ids: vec![
                    ReplicaVersion::default().into(),
                    "version_43".to_string()
                ]
            }
        );

        // Trying to mutate an existing record should have no effect.
        let payload_v42_mutate = ReviseElectedGuestosVersionsPayload {
            replica_version_to_elect: Some("version_43".into()),
            release_package_sha256_hex: None,
            release_package_urls: vec![],
            guest_launch_measurements: guest_launch_measurements_for_test(),
            replica_versions_to_unelect: vec![],
        };
        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "revise_elected_replica_versions",
                Encode!(&payload_v42_mutate).unwrap(),
            )
            .await
        );
        // The URL in the registry should still the old one.
        let release_package_url = "http://release_package.tar.zst".to_string();
        assert_eq!(
            get_value_or_panic::<ReplicaVersionRecord>(
                &registry,
                make_replica_version_key("version_43").as_bytes()
            )
            .await,
            ReplicaVersionRecord {
                release_package_sha256_hex: MOCK_HASH.into(),
                release_package_urls: vec![release_package_url.clone()],
                guest_launch_measurements: guest_launch_measurements_for_test(),
            }
        );

        // Let's now try to upgrade a subnet.
        // The subnet was added at the beginning of the test

        // Set the subnet to a blessed version: it should work
        let set_to_blessed_ = DeployGuestosToAllSubnetNodesPayload {
            subnet_id: subnet_test_id(999).get(),
            replica_version_id: ReplicaVersion::default().into(),
        };
        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "deploy_guestos_to_all_subnet_nodes",
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
            ReplicaVersion::default().to_string(),
        );

        // Try to set the subnet to an unblessed version: it should fail
        let try_set_to_unblessed = DeployGuestosToAllSubnetNodesPayload {
            subnet_id: subnet_test_id(999).get(),
            replica_version_id: "unblessed".to_string(),
        };
        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "deploy_guestos_to_all_subnet_nodes",
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
            ReplicaVersion::default().to_string(),
        );

        Ok(())
    });
}
