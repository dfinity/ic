//! This is a suite of tests that call the Governance Canister methods with bad
//! input.

use assert_matches::assert_matches;

use canister_test::local_test_e;
use dfn_candid::candid;
use on_wire::bytes;

use ic_base_types::PrincipalId;
use ic_nns_common::types::ProposalId;
use ic_nns_governance::{init::GovernanceCanisterInitPayloadBuilder, pb::v1::ProposalInfo};
use ic_nns_test_utils::itest_helpers::set_up_governance_canister;

#[test]
fn test_bad_proposal_id_candid_type() {
    local_test_e(|runtime| async move {
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
    local_test_e(|runtime| async move {
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
    local_test_e(|runtime| async move {
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
