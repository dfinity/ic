use dfn_candid::candid_one;
use ic_sns_governance::pb::v1::{
    GetSnsInitializationParametersRequest, GetSnsInitializationParametersResponse,
};
use ic_sns_init::{SnsCanisterIds, pb::v1::SnsInitPayload};
use ic_sns_test_utils::itest_helpers::{SnsCanisters, local_test_on_sns_subnet};
use ic_types::PrincipalId;

#[test]
fn test_sns_initialization_parameters_are_set() {
    local_test_on_sns_subnet(|runtime| async move {
        let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();

        let sns_canisters_init_payload = sns_init_payload
            .build_canister_payloads(
                &SnsCanisterIds {
                    governance: PrincipalId::new_user_test_id(1),
                    ledger: PrincipalId::new_user_test_id(2),
                    root: PrincipalId::new_user_test_id(3),
                    swap: PrincipalId::new_user_test_id(4),
                    index: PrincipalId::new_user_test_id(5),
                },
                None,
                false,
            )
            .unwrap();
        let sns_canisters = SnsCanisters::set_up(&runtime, sns_canisters_init_payload).await;

        let get_sns_initialization_parameters_response: GetSnsInitializationParametersResponse =
            sns_canisters
                .governance
                .query_(
                    "get_sns_initialization_parameters",
                    candid_one,
                    GetSnsInitializationParametersRequest {},
                )
                .await
                .expect("Error calling get_sns_initialization_parameters api");

        let expected_initialization_parameters =
            sns_init_payload.stringify_without_logos().unwrap();

        assert_eq!(
            get_sns_initialization_parameters_response.sns_initialization_parameters,
            expected_initialization_parameters
        );

        Ok(())
    });
}
