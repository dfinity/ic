use candid::Encode;

use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::conversion_rate::v1::IcpXdrConversionRateRecord;
use ic_registry_keys::XDR_PER_ICP_KEY;
use registry_canister::{
    init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder},
    mutations::do_update_icp_xdr_conversion_rate::UpdateIcpXdrConversionRatePayload,
};

use assert_matches::assert_matches;

const TEST_VAL1: u64 = 1234;
const TEST_VAL2: u64 = 5678;

#[test]
fn test_anonymous_and_unauthorized_users_cannot_update_icp_xdr_coversion_rate() {
    local_test_on_nns_subnet(|runtime| async move {
        let attacker_fake = set_up_universal_canister(&runtime).await;
        assert_ne!(
            attacker_fake.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let registry =
            set_up_registry_canister(&runtime, RegistryCanisterInitPayload::default()).await;

        let payload = UpdateIcpXdrConversionRatePayload {
            data_source: "".to_string(),
            timestamp_seconds: 0,
            xdr_permyriad_per_icp: TEST_VAL1,
        };
        // The anonymous end-user tries to change the conversion rate
        let response: Result<(), String> = registry
            .update_(
                "update_icp_xdr_conversion_rate",
                dfn_candid::candid,
                (&payload,),
            )
            .await;
        assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: update_icp_xdr_conversion_rate"));

        // There should therefore be no new conversion rate record
        assert_eq!(
            get_value::<IcpXdrConversionRateRecord>(&registry, &XDR_PER_ICP_KEY.as_bytes()).await,
            IcpXdrConversionRateRecord::default()
        );

        // A non-governance canister tries to change the conversion rate
        assert!(
            !forward_call_via_universal_canister(
                &attacker_fake,
                &registry,
                "update_icp_xdr_conversion_rate",
                Encode!(&payload).unwrap()
            )
            .await
        );
        // There should therefore be no new conversion rate record
        assert_eq!(
            get_value::<IcpXdrConversionRateRecord>(&registry, &XDR_PER_ICP_KEY.as_bytes()).await,
            IcpXdrConversionRateRecord::default()
        );

        Ok(())
    });
}

#[test]
fn test_governance_canister_icp_xdr_conversion_rate() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                    .build(),
            )
            .await;

            let governance_fake = set_up_universal_canister(&runtime).await;
            assert_eq!(
                governance_fake.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            let mut payload = UpdateIcpXdrConversionRatePayload {
                data_source: "".to_string(),
                timestamp_seconds: 0,
                xdr_permyriad_per_icp: TEST_VAL1,
            };
            // The governance canister tries to change the conversion rate (i.e. after a
            // proposal has passed)
            assert!(
                forward_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "update_icp_xdr_conversion_rate",
                    Encode!(&payload).unwrap()
                )
                .await
            );
            assert_eq!(
                get_value::<IcpXdrConversionRateRecord>(&registry, XDR_PER_ICP_KEY.as_bytes())
                    .await
                    .xdr_permyriad_per_icp,
                TEST_VAL1
            );

            payload.timestamp_seconds = 1;
            payload.xdr_permyriad_per_icp = TEST_VAL2;
            assert!(
                forward_call_via_universal_canister(
                    &governance_fake,
                    &registry,
                    "update_icp_xdr_conversion_rate",
                    Encode!(&payload).unwrap()
                )
                .await
            );
            assert_eq!(
                get_value::<IcpXdrConversionRateRecord>(&registry, XDR_PER_ICP_KEY.as_bytes())
                    .await
                    .xdr_permyriad_per_icp,
                TEST_VAL2
            );

            Ok(())
        }
    })
}
