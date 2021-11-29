use assert_matches::assert_matches;
use ic_canister_client::Sender;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::ids::{TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_2_OWNER_KEYPAIR};
use ic_nns_governance::pb::v1::{GovernanceError, NnsFunction, ProposalStatus};
use ic_nns_test_utils::governance::{
    submit_external_update_proposal, submit_external_update_proposal_allowing_error,
};
use ic_nns_test_utils::ids::TEST_NEURON_2_ID;
use ic_nns_test_utils::registry::get_value;
use ic_nns_test_utils::{
    governance::{get_pending_proposals, wait_for_final_state},
    ids::TEST_NEURON_1_ID,
    itest_helpers::{local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder},
};
use ic_protobuf::registry::dc::v1::{
    AddOrRemoveDataCentersProposalPayload, DataCenterRecord, Gps, MAX_DC_OWNER_LENGTH,
};
use ic_registry_keys::make_data_center_record_key;
use ic_registry_transport::{
    deserialize_get_value_response, serialize_get_value_request, Error::KeyNotPresent,
};

#[test]
fn test_submit_add_or_remove_data_centers_proposal() {
    local_test_on_nns_subnet(|runtime| async move {
        let nns_init_payload = NnsInitPayloadsBuilder::new()
            .with_initial_invariant_compliant_mutations()
            .with_test_neurons()
            .build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        // Submitting a proposal with valid DataCenterRecords should succeed
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
                id: "BC1".into(),
                region: "CAN".into(),
                owner: "Bob".into(),
                gps: None,
            },
            DataCenterRecord {
                id: "FM1".into(),
                region: "Fremont".into(),
                owner: "Carol".into(),
                gps: None,
            },
        ];

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: data_centers,
            data_centers_to_remove: vec![],
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::AddOrRemoveDataCenters,
            payload.clone(),
            "<proposal created by test_submit_add_or_remove_data_centers_proposal>".to_string(),
            "".to_string(),
        )
        .await;

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, proposal_id)
                .await
                .status(),
            ProposalStatus::Executed
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let an1_dc = get_value::<DataCenterRecord>(
            &nns_canisters.registry,
            make_data_center_record_key("AN1").as_bytes(),
        )
        .await;

        assert_eq!(&an1_dc.id, "AN1");
        assert_eq!(&an1_dc.region, "BEL");
        assert_eq!(&an1_dc.owner, "Alice");
        assert_eq!(
            &an1_dc.gps.unwrap(),
            &Gps {
                latitude: 1.0,
                longitude: 2.0
            }
        );

        let bc1_dc = get_value::<DataCenterRecord>(
            &nns_canisters.registry,
            make_data_center_record_key("BC1").as_bytes(),
        )
        .await;

        assert_eq!(&bc1_dc.id, "BC1");
        assert_eq!(&bc1_dc.region, "CAN");
        assert_eq!(&bc1_dc.owner, "Bob");
        assert!(&bc1_dc.gps.is_none());

        let fm1_dc = get_value::<DataCenterRecord>(
            &nns_canisters.registry,
            make_data_center_record_key("FM1").as_bytes(),
        )
        .await;

        assert_eq!(&fm1_dc.id, "FM1");
        assert_eq!(&fm1_dc.region, "Fremont");
        assert_eq!(&fm1_dc.owner, "Carol");
        assert!(&fm1_dc.gps.is_none());

        // Data center records can be deleted
        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![],
            data_centers_to_remove: vec!["AN1".to_string()],
        };

        let proposal_id: ProposalId = submit_external_update_proposal(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::AddOrRemoveDataCenters,
            payload.clone(),
            "<proposal created by test_submit_add_or_remove_data_centers_proposal>".to_string(),
            "".to_string(),
        )
        .await;

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&nns_canisters.governance, proposal_id)
                .await
                .status(),
            ProposalStatus::Executed
        );

        // No proposals should be pending now.
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals, vec![]);

        let get_value_result = deserialize_get_value_response(
            nns_canisters
                .registry
                .query_(
                    "get_value",
                    on_wire::bytes,
                    serialize_get_value_request(
                        make_data_center_record_key("AN1").as_bytes().to_vec(),
                        None,
                    )
                    .unwrap(),
                )
                .await
                .unwrap(),
        )
        .unwrap_err();

        assert_matches!(get_value_result, KeyNotPresent(_));

        // Submitting a proposal with an invalid DataCenterRecord should fail
        let invalid_owner = String::from_utf8(vec![b'0'; MAX_DC_OWNER_LENGTH + 1]).unwrap();

        let data_centers = vec![DataCenterRecord {
            id: "AN1".into(),
            region: "BEL".into(),
            owner: invalid_owner,
            gps: Some(Gps {
                latitude: 1.0,
                longitude: 2.0,
            }),
        }];

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: data_centers,
            data_centers_to_remove: vec![],
        };

        let response: GovernanceError = submit_external_update_proposal_allowing_error(
            &nns_canisters.governance,
            Sender::from_keypair(&TEST_NEURON_2_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_2_ID),
            NnsFunction::AddOrRemoveDataCenters,
            payload.clone(),
            "<proposal created by test_submit_add_or_remove_data_centers_proposal>".to_string(),
            "".to_string(),
        )
        .await
        .unwrap_err();

        assert!(response
            .error_message
            .contains("owner must not be longer than"));

        // Should have 0 pending proposals
        let pending_proposals = get_pending_proposals(&nns_canisters.governance).await;
        assert_eq!(pending_proposals.len(), 0);

        Ok(())
    });
}
