//! This is a suite of tests that call the Governance Canister methods with bad
//! input.

use assert_matches::assert_matches;
use dfn_candid::candid;
use ic_base_types::PrincipalId;
use ic_nns_common::types::ProposalId;
use ic_nns_governance_api::{GovernanceError, NeuronInfo, ProposalInfo};
use ic_nns_governance_init::GovernanceCanisterInitPayloadBuilder;
use ic_nns_test_utils::itest_helpers::{
    set_up_governance_canister, state_machine_test_on_nns_subnet,
};
use on_wire::bytes;

#[test]
fn test_skipping_quota() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let canister = set_up_governance_canister(
            &runtime,
            GovernanceCanisterInitPayloadBuilder::new().build(),
        )
        .await;

        // the skipping quota is set to 10_000 by `ic-cdk` macros
        let skipped: Vec<u8> = vec![42; 9_042];
        let res: Result<Result<NeuronInfo, GovernanceError>, String> = canister
            .query_("get_full_neuron", candid, (0u64, Some(skipped)))
            .await;
        let _ = res.unwrap();

        // but the next one is rejected
        let skipped: Vec<u8> = vec![42; 10_042];
        let res: Result<Result<NeuronInfo, GovernanceError>, String> = canister
            .query_("get_full_neuron", candid, (0u64, Some(skipped)))
            .await;
        let err = res.unwrap_err();
        let expected_err = "Skipping cost exceeds the limit";
        assert!(
            err.contains(expected_err),
            "Expected `{expected_err}` did not occur within the observed error:\n{err}"
        );

        Ok(())
    });
}

#[test]
fn test_bad_proposal_id_candid_type() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let canister = set_up_governance_canister(
            &runtime,
            GovernanceCanisterInitPayloadBuilder::new().build(),
        )
        .await;

        // get_proposal_info requires a ProposalId argument. Here instead the caller is
        // sending a PrincipalId. This is also valid Candid, but with the
        // wrong type.
        let principal = PrincipalId::new_user_test_id(53);
        let res: Result<Option<ProposalInfo>, String> = canister
            .query_("get_proposal_info", candid, (principal,))
            .await;
        assert_matches!(res, Err(_));

        Ok(())
    });
}

#[test]
fn test_bad_proposal_id_candid_encoding() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let canister = set_up_governance_canister(
            &runtime,
            GovernanceCanisterInitPayloadBuilder::new().build(),
        )
        .await;

        let res: Result<Vec<u8>, String> = canister
            .query_(
                "get_proposal_info",
                bytes,
                b"This is not valid candid!".to_vec(),
            )
            .await;
        assert_matches!(res, Err(_));

        Ok(())
    });
}

#[test]
fn test_inexistent_proposal_id_is_not_a_bad_input() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let canister = set_up_governance_canister(
            &runtime,
            GovernanceCanisterInitPayloadBuilder::new().build(),
        )
        .await;

        // There is no proposal 23. This should NOT return an error: it should
        // simply return None.
        let res: Result<Option<ProposalInfo>, String> = canister
            .query_("get_proposal_info", candid, (ProposalId(23),))
            .await;
        assert_eq!(res, Ok(None));
        Ok(())
    });
}
