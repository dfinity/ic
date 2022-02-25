use dfn_candid::candid_one;
use ic_sns_governance::pb::v1::NervousSystemParameters;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};

/// Tests that Governance can be initialized with `NervousSystemParameters` and that any
/// unspecified fields are populated by defaults.
#[test]
fn test_init_with_sys_params() {
    local_test_on_sns_subnet(|runtime| async move {
        let system_params = NervousSystemParameters {
            transaction_fee_e8s: Some(100_000),
            reject_cost_e8s: Some(0),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_nervous_system_parameters(system_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let live_sys_params: NervousSystemParameters = sns_canisters
            .governance
            .query_("get_nervous_system_parameters", candid_one, ())
            .await?;

        assert_eq!(live_sys_params, system_params);

        Ok(())
    });
}
