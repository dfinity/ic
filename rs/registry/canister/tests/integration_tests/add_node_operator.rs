use candid::Encode;
use dfn_candid::candid;
use dfn_core::api::PrincipalId;

use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nns_test_utils::registry::invariant_compliant_mutation_as_atomic_req;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::get_value,
};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
use registry_canister::{
    init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder},
    mutations::do_add_node_operator::AddNodeOperatorPayload,
};

use assert_matches::assert_matches;
use std::collections::BTreeMap;

#[test]
fn test_the_anonymous_user_cannot_add_a_node_operator() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry =
            set_up_registry_canister(&runtime, RegistryCanisterInitPayload::default()).await;

        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(PrincipalId::new_anonymous()),
            node_allowance: 5,
            node_provider_principal_id: Some(PrincipalId::new_anonymous()),
            dc_id: "AN1".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: None,
        };

        // The anonymous end-user tries to add a node operator, bypassing the proposals
        // This should be rejected.
        let response: Result<(), String> = registry
            .update_("add_node_operator", candid, (payload.clone(),))
            .await;

        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: add_node_operator"));

        let key = make_node_operator_record_key(PrincipalId::new_anonymous()).into_bytes();
        // .. And there should therefore be no node operator record
        assert_eq!(
            get_value::<NodeOperatorRecord>(&registry, &key).await,
            NodeOperatorRecord::default()
        );

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_add_a_node_operator() {
    local_test_on_nns_subnet(|runtime| async move {
        // An attacker got a canister that is trying to pass for the proposals
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let registry =
            set_up_registry_canister(&runtime, RegistryCanisterInitPayload::default()).await;

        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(PrincipalId::new_anonymous()),
            node_allowance: 5,
            node_provider_principal_id: Some(PrincipalId::new_anonymous()),
            dc_id: "AN1".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: None,
        };

        // The attacker canister tries to add a node operator, pretending to be the
        // proposals canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "add_node_operator",
                Encode!(&payload).unwrap()
            )
            .await
        );

        let key = make_node_operator_record_key(PrincipalId::new_anonymous()).into_bytes();

        // But there should be no node operator record
        assert_eq!(
            get_value::<NodeOperatorRecord>(&registry, &key).await,
            NodeOperatorRecord::default()
        );

        Ok(())
    });
}

#[test]
fn test_accepted_proposal_mutates_the_registry() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        // Install the universal canister in place of the proposals canister
        let fake_proposal_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the proposal canister, it can impersonate
        // it
        assert_eq!(
            fake_proposal_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(PrincipalId::new_anonymous()),
            node_allowance: 5,
            node_provider_principal_id: Some(PrincipalId::new_anonymous()),
            dc_id: "AN1".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: None,
        };

        assert!(
            forward_call_via_universal_canister(
                &fake_proposal_canister,
                &registry,
                "add_node_operator",
                Encode!(&payload).unwrap()
            )
            .await
        );

        // Now let's check directly in the registry that the mutation actually happened
        // The node operator record should be associated with that ID.
        assert_eq!(
            get_value::<NodeOperatorRecord>(
                &registry,
                make_node_operator_record_key(PrincipalId::new_anonymous()).as_bytes()
            )
            .await,
            NodeOperatorRecord {
                node_operator_principal_id: PrincipalId::new_anonymous().to_vec(),
                node_allowance: 5,
                node_provider_principal_id: PrincipalId::new_anonymous().to_vec(),
                dc_id: "AN1".into(),
                rewardable_nodes: BTreeMap::new(),
                ipv6: None,
            }
        );

        // We can add another node operator, and it should work too.
        let payload2 = AddNodeOperatorPayload {
            node_operator_principal_id: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            node_allowance: 120,
            node_provider_principal_id: Some(PrincipalId::new_anonymous()),
            dc_id: "BC1".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: None,
        };

        assert!(
            forward_call_via_universal_canister(
                &fake_proposal_canister,
                &registry,
                "add_node_operator",
                Encode!(&payload2).unwrap()
            )
            .await
        );

        assert_eq!(
            get_value::<NodeOperatorRecord>(
                &registry,
                make_node_operator_record_key(*TEST_NEURON_1_OWNER_PRINCIPAL).as_bytes()
            )
            .await,
            NodeOperatorRecord {
                node_operator_principal_id: TEST_NEURON_1_OWNER_PRINCIPAL.to_vec(),
                node_allowance: 120,
                node_provider_principal_id: PrincipalId::new_anonymous().to_vec(),
                dc_id: "BC1".into(),
                rewardable_nodes: BTreeMap::new(),
                ipv6: None,
            }
        );

        // Trying to overwrite an existing record should fail
        let payload3 = AddNodeOperatorPayload {
            node_operator_principal_id: Some(PrincipalId::new_anonymous()),
            node_allowance: 567,
            node_provider_principal_id: Some(PrincipalId::new_anonymous()),
            dc_id: "CA1".into(),
            rewardable_nodes: BTreeMap::new(),
            ipv6: None,
        };

        assert!(
            !forward_call_via_universal_canister(
                &fake_proposal_canister,
                &registry,
                "add_node_operator",
                Encode!(&payload3).unwrap()
            )
            .await
        );

        Ok(())
    });
}
