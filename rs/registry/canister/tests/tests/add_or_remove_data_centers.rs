use assert_matches::assert_matches;
use candid::Encode;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::dc::v1::{
    AddOrRemoveDataCentersProposalPayload, DataCenterRecord, Gps, MAX_DC_ID_LENGTH,
    MAX_DC_OWNER_LENGTH, MAX_DC_REGION_LENGTH,
};
use ic_registry_keys::make_data_center_record_key;
use ic_registry_transport::{deserialize_get_value_response, serialize_get_value_request};
use ic_registry_transport::{Error, Error::KeyNotPresent};
use registry_canister::init::RegistryCanisterInitPayloadBuilder;

/// Attempt to get a value from the Registry and return the error if one
/// occurs, or else panic!
async fn get_value_and_unwrap_error(registry: &Canister<'_>, key: &str) -> Error {
    deserialize_get_value_response(
        registry
            .query_(
                "get_value",
                on_wire::bytes,
                serialize_get_value_request(
                    make_data_center_record_key(key).as_bytes().to_vec(),
                    None,
                )
                .unwrap(),
            )
            .await
            .unwrap(),
    )
    .unwrap_err()
}

#[test]
fn test_the_anonymous_user_cannot_add_or_remove_data_centers() {
    local_test_on_nns_subnet(|runtime| async move {
        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        let data_centers = vec![DataCenterRecord {
            id: "AN1".into(),
            region: "BEL".into(),
            owner: "Alice".into(),
            gps: None,
        }];

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: data_centers,
            data_centers_to_remove: vec![],
        };

        // The anonymous end-user tries to add data centers, bypassing
        // the Governance canister. This should be rejected.
        let response: Result<(), String> = registry
            .update_("add_or_remove_data_centers", candid_one, payload.clone())
            .await;

        assert_matches!(
            response,
            Err(s) if s.contains("is not authorized to call this method: add_or_remove_data_centers")
        );

        // .. And no data centers should have been added
        let error = get_value_and_unwrap_error(&registry, "AN1").await;
        assert_matches!(error, KeyNotPresent(_));

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("add_or_remove_data_centers", candid_one, payload.clone())
            .await;

        assert_matches!(
            response,
            Err(s) if s.contains("is not authorized to call this method: add_or_remove_data_centers")
        );

        let error = get_value_and_unwrap_error(&registry, "AN1").await;
        assert_matches!(error, KeyNotPresent(_));

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_add_or_remove_data_centers() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the Governance
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

        let data_centers = vec![DataCenterRecord {
            id: "AN1".into(),
            region: "BEL".into(),
            owner: "Alice".into(),
            gps: None,
        }];

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: data_centers,
            data_centers_to_remove: vec![],
        };

        // The attacker canister tries to add data centers, pretending
        // to be the Governance canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "add_or_remove_data_centers",
                Encode!(&payload).unwrap(),
            )
            .await
        );

        // No data centers should have been added
        let error = get_value_and_unwrap_error(&registry, "AN1").await;
        assert_matches!(error, KeyNotPresent(_));

        Ok(())
    });
}

#[test]
fn test_the_governance_canister_can_add_or_remove_data_centers() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        // Install the universal canister in place of the Governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can
        // impersonate it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let invalid_dc_id = String::from_utf8(vec![b'0'; MAX_DC_ID_LENGTH + 1]).unwrap();
        let invalid_region = String::from_utf8(vec![b'0'; MAX_DC_REGION_LENGTH + 1]).unwrap();
        let invalid_owner = String::from_utf8(vec![b'0'; MAX_DC_OWNER_LENGTH + 1]).unwrap();

        let data_centers = vec![
            DataCenterRecord {
                id: "AN1".into(),
                region: "BEL".into(),
                owner: "Alice".into(),
                gps: Some(Gps {
                    latitude: 1.0,
                    longitude: 2.0,
                }),
            },
            DataCenterRecord {
                id: invalid_dc_id.clone(),
                region: "CAN".into(),
                owner: "Bob".into(),
                gps: None,
            },
            DataCenterRecord {
                id: "Invalid region".into(),
                region: invalid_region.clone(),
                owner: "Carol".into(),
                gps: None,
            },
            DataCenterRecord {
                id: "Invalid owner".into(),
                region: "CH".into(),
                owner: invalid_owner.clone(),
                gps: None,
            },
        ];

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: data_centers,
            data_centers_to_remove: vec![],
        };

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "add_or_remove_data_centers",
                Encode!(&payload).unwrap(),
            )
            .await
        );

        // A data center should have been added
        let dc =
            get_value::<DataCenterRecord>(&registry, make_data_center_record_key("AN1").as_bytes())
                .await;

        assert_eq!(&dc.id, "AN1");
        assert_eq!(&dc.region, "BEL");
        assert_eq!(&dc.owner, "Alice");
        assert_eq!(
            &dc.gps.unwrap(),
            &Gps {
                latitude: 1.0,
                longitude: 2.0
            }
        );

        // Invalid DataCenterRecords should not have been added
        let error = get_value_and_unwrap_error(&registry, &invalid_dc_id).await;
        assert_matches!(error, KeyNotPresent(_));

        let error = get_value_and_unwrap_error(&registry, "Invalid region").await;
        assert_matches!(error, KeyNotPresent(_));

        let error = get_value_and_unwrap_error(&registry, "Invalid owner").await;
        assert_matches!(error, KeyNotPresent(_));

        // Data center records cannot be overwritten
        let data_centers = vec![DataCenterRecord {
            id: "AN1".into(),
            region: "Not BEL".into(),
            owner: "Bob".into(),
            gps: Some(Gps {
                latitude: 4.0,
                longitude: 5.0,
            }),
        }];

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: data_centers,
            data_centers_to_remove: vec![],
        };

        // asserting the call returns an error
        assert!(
            !forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "add_or_remove_data_centers",
                Encode!(&payload).unwrap(),
            )
            .await
        );

        let dc =
            get_value::<DataCenterRecord>(&registry, make_data_center_record_key("AN1").as_bytes())
                .await;

        // original values are still there
        assert_eq!(&dc.id, "AN1");
        assert_eq!(&dc.region, "BEL");
        assert_eq!(&dc.owner, "Alice");
        assert_eq!(
            &dc.gps.unwrap(),
            &Gps {
                latitude: 1.0,
                longitude: 2.0
            }
        );

        // Data center records can be deleted
        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![],
            data_centers_to_remove: vec!["AN1".to_string()],
        };

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "add_or_remove_data_centers",
                Encode!(&payload).unwrap(),
            )
            .await
        );

        // Assert that the data center was deleted
        let error = get_value_and_unwrap_error(&registry, "AN1").await;
        assert_matches!(error, KeyNotPresent(_));

        // Data centers that are deleted can be re-added
        let data_centers = vec![DataCenterRecord {
            id: "AN1".into(),
            region: "Not BEL".into(),
            owner: "Bob".into(),
            gps: Some(Gps {
                latitude: 4.0,
                longitude: 5.0,
            }),
        }];

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: data_centers,
            data_centers_to_remove: vec![],
        };

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "add_or_remove_data_centers",
                Encode!(&payload).unwrap(),
            )
            .await
        );

        let dc =
            get_value::<DataCenterRecord>(&registry, make_data_center_record_key("AN1").as_bytes())
                .await;
        // new values are there
        assert_eq!(&dc.id, "AN1");
        assert_eq!(&dc.region, "Not BEL");
        assert_eq!(&dc.owner, "Bob");
        assert_eq!(
            &dc.gps.unwrap(),
            &Gps {
                latitude: 4.0,
                longitude: 5.0
            }
        );

        Ok(())
    });
}
