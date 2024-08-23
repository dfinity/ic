use canister_test::Canister;
use dfn_candid::candid_one;
use ic_canisters_http_types::{HttpRequest, HttpResponse};
use ic_sns_governance::pb::v1::{
    NervousSystemParameters, NeuronPermissionList, NeuronPermissionType,
};
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsTestsInitPayloadBuilder,
};
use serde_bytes::ByteBuf;

async fn test_http_request_decoding_quota_for_canister(canister: &Canister<'_>) {
    // The anonymous end-user sends a small HTTP request. This should succeed.
    let http_request = HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: vec![],
        body: ByteBuf::from(vec![42; 1_000]),
    };
    let response: HttpResponse = canister
        .update_(
            "http_request",
            candid_one::<HttpResponse, _>,
            http_request.clone(),
        )
        .await
        .unwrap();
    assert_eq!(response.status_code, 200);

    // The anonymous end-user sends a large HTTP request. This should be rejected.
    let mut large_http_request = http_request;
    large_http_request.body = ByteBuf::from(vec![42; 1_000_000]);
    let err = canister
        .update_(
            "http_request",
            candid_one::<HttpResponse, _>,
            large_http_request,
        )
        .await
        .unwrap_err();
    assert!(
        err.contains("Deserialization Failed") || err.contains("Decoding cost exceeds the limit")
    );
}

#[test]
fn test_http_request_decoding_quota() {
    local_test_on_sns_subnet(|runtime| async move {
        let system_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_nervous_system_parameters(system_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        for canister in [
            &sns_canisters.root,
            &sns_canisters.governance,
            &sns_canisters.ledger,
            &sns_canisters.swap,
            &sns_canisters.index,
        ] {
            test_http_request_decoding_quota_for_canister(canister).await;
        }

        Ok(())
    })
}
